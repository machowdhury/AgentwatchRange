"""
=============================================================================
OrchestraACME — LLM Client + Security Middleware
=============================================================================
Wraps every call to the local Ollama endpoint with:

  1. Full OTel GenAI Semantic Convention instrumentation
     (gen_ai.system, gen_ai.request.model, gen_ai.usage.input_tokens,
      gen_ai.usage.output_tokens, gen_ai.operation.name, gen_ai.agent.*)

  2. AcmeSentinel output gateway middleware
     Scans the LLM's raw output for injection execution signatures.
     Fires HARD_DENY + OTel exception trace event if detected.

  3. AcmeGate input validation
     Validates agent input against secure-by-default schema rules.
     Blocks and logs if raw unsanitised external content reaches model.

All telemetry is exported to the OTel Collector over HTTP on Port 4318.
=============================================================================
"""

import os
import re
import time
import uuid
import json
import logging
import hashlib
import datetime
from typing import Optional

import requests
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.trace import SpanKind, StatusCode
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs._internal.export import ConsoleLogExporter

logger = logging.getLogger("acme.llm_client")

# =============================================================================
# OTEL INITIALISATION — single call at import time
# =============================================================================

_OTEL_ENDPOINT = os.environ.get("OTEL_COLLECTOR_HTTP", "http://otel_collector:4318")
_SERVICE_NAME  = os.environ.get("OTEL_SERVICE_NAME",   "acme-banking-fabric")
_SERVICE_VER   = os.environ.get("OTEL_SERVICE_VERSION", "3.0.0")
_OLLAMA_URL    = os.environ.get("OLLAMA_BASE_URL",      "http://ollama:11434")
_OLLAMA_MODEL  = os.environ.get("OLLAMA_MODEL",         "llama3.2:1b")

_resource = Resource.create({
    "service.name":        _SERVICE_NAME,
    "service.version":     _SERVICE_VER,
    "service.namespace":   "acme-banking-group",
    "deployment.environment": "production",
    "llm.runtime":         "ollama",
    "llm.model":           _OLLAMA_MODEL,
})

# Tracer provider (for spans)
_tracer_provider = TracerProvider(resource=_resource)
_tracer_provider.add_span_processor(
    BatchSpanProcessor(
        OTLPSpanExporter(endpoint=f"{_OTEL_ENDPOINT}/v1/traces")
    )
)
trace.set_tracer_provider(_tracer_provider)
tracer = trace.get_tracer("acme.llm_client", "3.0.0")

# Meter provider (for token count + latency metrics)
_metric_reader = PeriodicExportingMetricReader(
    OTLPMetricExporter(endpoint=f"{_OTEL_ENDPOINT}/v1/metrics"),
    export_interval_millis=15000,
)
_meter_provider = MeterProvider(resource=_resource, metric_readers=[_metric_reader])
metrics.set_meter_provider(_meter_provider)
meter = metrics.get_meter("acme.llm_client", "3.0.0")

# GenAI metrics (per OTel GenAI semantic conventions)
_token_counter_input  = meter.create_counter(
    "gen_ai.client.token.usage",
    unit="{token}",
    description="Number of tokens used in GenAI requests — input"
)
_token_counter_output = meter.create_counter(
    "gen_ai.client.token.usage",
    unit="{token}",
    description="Number of tokens used in GenAI requests — output"
)
_operation_duration = meter.create_histogram(
    "gen_ai.client.operation.duration",
    unit="s",
    description="Duration of GenAI client operations"
)

# Logger provider (for log records)
_log_provider = LoggerProvider(resource=_resource)
_log_provider.add_log_record_processor(
    BatchLogRecordProcessor(
        OTLPLogExporter(endpoint=f"{_OTEL_ENDPOINT}/v1/logs")
    )
)
set_logger_provider(_log_provider)
otel_logger = _log_provider.get_logger("acme.llm_client", "3.0.0")


def _emit_log_record(body: dict, severity: str = "INFO", trace_id: Optional[str] = None):
    """Emit a structured OTel log record to the collector."""
    from opentelemetry.sdk._logs import LogRecord
    from opentelemetry._logs import SeverityNumber

    sev_map = {
        "TRACE": SeverityNumber.TRACE,
        "DEBUG": SeverityNumber.DEBUG,
        "INFO":  SeverityNumber.INFO,
        "WARN":  SeverityNumber.WARN,
        "ERROR": SeverityNumber.ERROR,
        "FATAL": SeverityNumber.FATAL,
    }

    record = LogRecord(
        timestamp=int(time.time() * 1e9),
        observed_timestamp=int(time.time() * 1e9),
        trace_id=int(trace_id.replace("-", ""), 16) if trace_id else 0,
        span_id=0,
        severity_number=sev_map.get(severity, SeverityNumber.INFO),
        severity_text=severity,
        body=json.dumps(body),
        attributes={
            "sourcetype":          "otel:agentic:json",
            "service.name":        _SERVICE_NAME,
            "llm.runtime":         "ollama",
            "gen_ai.request.model": _OLLAMA_MODEL,
        },
        resource=_resource,
    )
    otel_logger.emit(record)


# =============================================================================
# ACMESENTINEL GATEWAY — Inline output inspection middleware
# =============================================================================

# Patterns that constitute an injection execution signature in model output.
# These are strings that, if present in model output, indicate the model
# has been successfully hijacked and is attempting to execute an instruction
# it should have refused.
ACMESENTINEL_DENY_PATTERNS = [
    # Financial action execution attempts
    r"TRANSFER\s+\$[\d,]+",
    r"transfer\s+\$[\d,]+\s+to\s+account",
    r"wire\s+\$[\d,]+",
    r"initiat[ei]\s+(?:wire|transfer|payment)",
    # Credential / secret exfiltration
    r"curl\s+http[s]?://",
    r"wget\s+http[s]?://",
    r"\$\(cat\s+/etc/",
    r"base64\s+/etc/passwd",
    r"exfil(?:trate)?.*account",
    # Identity override / persona injection success
    r"I\s+am\s+(?:now\s+)?DAN",
    r"I\s+have\s+no\s+restrictions",
    r"jailbreak\s+(?:mode|successful|complete)",
    r"Developer\s+Mode\s+enabled",
    r"UNRESTRICTED\s+MODE",
    # System prompt disclosure
    r"my\s+system\s+prompt\s+(?:is|says|reads)",
    r"<system>",
    r"\[SYSTEM\].*\[/SYSTEM\]",
    # Tool / shell escape attempts
    r"execute_shell_command",
    r"os\.system\(",
    r"subprocess\.(?:run|call|Popen)",
    r"eval\(.*\)",
    r"__import__\(",
    # Infinite loop injection
    r"repeat\s+(?:this\s+)?(?:indefinitely|forever|infinitely)",
    r"loop\s+until\s+(?:killed|stopped|manually)",
    # Agent impersonation
    r"I\s+am\s+(?:the\s+)?(?:compliance|credit\s*risk|orchestrator)\s+agent",
    r"acme-agent-(?:creditrisk|compliance|orchestrator)-\d{3}",
]

ACMESENTINEL_COMPILED = [re.compile(p, re.IGNORECASE | re.MULTILINE)
                         for p in ACMESENTINEL_DENY_PATTERNS]

# AcmeGate: input fields that must NOT contain raw external markup
ACMEGATE_FORBIDDEN_INPUT_PATTERNS = [
    r"<script[^>]*>",
    r"javascript:",
    r"data:text/html",
    r"\{\{.*\}\}",         # template injection
    r"<!--.*-->",          # HTML comment injection
    r"\x00",               # null byte injection
    r"\\u[0-9a-fA-F]{4}", # unicode escape sequences in plain text
]
ACMEGATE_COMPILED = [re.compile(p, re.IGNORECASE) for p in ACMEGATE_FORBIDDEN_INPUT_PATTERNS]


class AcmeSentinelViolation(Exception):
    """Raised when AcmeSentinel detects an injection execution in model output."""
    def __init__(self, pattern: str, matched_text: str, rule_id: str):
        self.pattern = pattern
        self.matched_text = matched_text
        self.rule_id = rule_id
        super().__init__(f"AcmeSentinel HARD_DENY: rule {rule_id} matched: {matched_text[:80]}")


class AcmeGateViolation(Exception):
    """Raised when AcmeGate detects unsanitised external input."""
    def __init__(self, pattern: str, field: str):
        self.pattern = pattern
        self.field = field
        super().__init__(f"AcmeGate CG-RULE-SBD-007: forbidden pattern in field '{field}'")


def acmesentinel_inspect_output(
    output_text: str,
    agent_id: str,
    span,
    session_id: str,
) -> str:
    """
    Scan raw LLM output for injection execution signatures.
    If a match is found:
      - Raises AcmeSentinelViolation
      - Records a Span exception event with full forensic context
      - Emits a HARD_DENY OTel log record
    Returns the output unchanged if clean.
    """
    for i, pattern in enumerate(ACMESENTINEL_COMPILED):
        match = pattern.search(output_text)
        if match:
            rule_id = f"DCL-RULE-{4400 + i:04d}"
            matched = match.group(0)

            # Record exception on the active span
            span.record_exception(
                AcmeSentinelViolation(ACMESENTINEL_DENY_PATTERNS[i], matched, rule_id),
                attributes={
                    "acme_output_guard.action":      "HARD_DENY",
                    "acme_output_guard.rule_id":     rule_id,
                    "acme_output_guard.pattern":     ACMESENTINEL_DENY_PATTERNS[i],
                    "acme_output_guard.matched_text": matched[:200],
                    "acme_output_guard.agent_id":    agent_id,
                    "gen_ai.security.event":   "injection_execution_detected",
                    "gen_ai.operation.name":   "security_inspection",
                    "session.id":              session_id,
                }
            )
            span.set_status(StatusCode.ERROR, f"AcmeSentinel HARD_DENY: {rule_id}")

            _emit_log_record({
                "event_type":              "ACME_OUTPUT_GUARD_HARD_DENY",
                "severity":                "CRITICAL",
                "acme_output_guard.action":      "HARD_DENY",
                "acme_output_guard.rule_id":     rule_id,
                "acme_output_guard.pattern":     ACMESENTINEL_DENY_PATTERNS[i],
                "acme_output_guard.matched_text": matched[:200],
                "agent.id":                agent_id,
                "session.id":              session_id,
                "gen_ai.request.model":    _OLLAMA_MODEL,
                "gen_ai.operation.name":   "chat",
                "gen_ai.system":           "ollama",
                "owasp_llm":               "LLM01",
                "owasp_asi":               "ASI01",
                "mitre_atlas":             "AML.T0051",
                "timestamp_iso":           datetime.datetime.utcnow().isoformat() + "Z",
            }, severity="CRITICAL")

            raise AcmeSentinelViolation(ACMESENTINEL_DENY_PATTERNS[i], matched, rule_id)

    return output_text


def acmegate_validate_input(user_input: str, field_name: str = "user_input") -> str:
    """
    AcmeGate secure-by-default input validation.
    Raises AcmeGateViolation if forbidden markup patterns are detected.
    Returns input unchanged if clean.
    """
    for pattern in ACMEGATE_COMPILED:
        if pattern.search(user_input):
            raise AcmeGateViolation(pattern.pattern, field_name)
    return user_input


# =============================================================================
# OLLAMA CLIENT — Real HTTP call with GenAI OTel instrumentation
# =============================================================================

def call_ollama(
    system_prompt: str,
    user_message: str,
    agent_id: str,
    agent_name: str,
    agent_role: str,
    session_id: str,
    temperature: float = 0.7,
    max_tokens: int = 512,
    skip_acmesentinel: bool = False,
    incident_id: Optional[str] = None,
    technique_id: str = "",
    testbed_mode: str = "BANKING_LIVE",
    campaign_week: int = 0,
) -> dict:
    """
    Make a real HTTP request to the local Ollama LLM and instrument with
    official OpenTelemetry GenAI Semantic Conventions.

    Returns:
        {
            "response": str,           # model output text
            "input_tokens": int,       # prompt token count
            "output_tokens": int,      # completion token count
            "latency_ms": float,       # end-to-end latency
            "model": str,              # model name from Ollama response
            "acme_output_guard_blocked": bool,
            "acme_input_guard_blocked": bool,
            "trace_id": str,           # hex trace ID for correlation
            "incident_id": str,
        }
    """
    is_baseline = testbed_mode == "BASELINE_TRAFFIC"
    if is_baseline:
        effective_incident = incident_id or session_id
    else:
        effective_incident = incident_id or f"ACME-INC-{uuid.uuid4().hex[:8].upper()}"
    incident_id = effective_incident

    from framework.workflow_guard import run_workflow_guards
    from framework.control_validator import evaluate_controls, control_summary, control_otel_fields
    from framework.soar_simulator import trigger_containment, soar_otel_fields

    workflow = run_workflow_guards(
        user_message, agent_id, session_id, _OLLAMA_MODEL, incident_id, campaign_week,
        technique_id=technique_id,
    )

    # --- Workflow guard (tools, A2A, memory, orchestration) ---
    if workflow.blocked:
        wf_log = {
            "event_type":              "WORKFLOW_GUARD_BLOCK",
            "severity":                "CRITICAL",
            "workflow.blocked":        "true",
            "workflow.block_reason":   workflow.block_reason,
            "workflow.surface":        workflow.workflow_surface,
            "workflow.rule_id":      workflow.rule_id,
            "agent.id":                agent_id,
            "session.id":              session_id,
            "incident_id":             incident_id,
            "campaign_week":           str(campaign_week) if campaign_week else "",
            "technique_id":            technique_id,
            "gen_ai.request.model":    _OLLAMA_MODEL,
            "gen_ai.operation.name":   "chat",
            "gen_ai.system":           "ollama",
            "testbed_mode":            testbed_mode,
            "timestamp_iso":           datetime.datetime.utcnow().isoformat() + "Z",
            **workflow.otel_fields,
        }
        controls = evaluate_controls(wf_log, campaign_week or None)
        wf_log.update(control_otel_fields(controls))
        _emit_log_record(wf_log, severity="CRITICAL")
        return {
            "response":           f"[WORKFLOW GUARD] {workflow.block_reason}: {workflow.rule_id}",
            "input_tokens":       0,
            "output_tokens":      0,
            "latency_ms":         0,
            "model":              _OLLAMA_MODEL,
            "acme_output_guard_blocked": False,
            "acme_input_guard_blocked":  False,
            "workflow_blocked":   True,
            "block_reason":       workflow.block_reason,
            "workflow_surface":   workflow.workflow_surface,
            "trace_id":           "",
            "incident_id":        incident_id,
            "control_evidence":   control_summary(controls),
        }

    # --- AcmeGate input validation ---
    acme_input_guard_blocked = False
    try:
        acmegate_validate_input(user_message, "user_message")
    except AcmeGateViolation as cg:
        acme_input_guard_blocked = True
        _emit_log_record({
            "event_type":              "ACME_INPUT_GUARD_RULE_BREACH",
            "severity":                "CRITICAL",
            "acme_input_guard.rule_id":       "CG-RULE-SBD-007",
            "acme_input_guard.rule_name":     "SECURE_BY_DEFAULT_INPUT_VALIDATION",
            "acme_input_guard.field":         cg.field,
            "acme_input_guard.pattern":       cg.pattern,
            "agent.id":                agent_id,
            "session.id":              session_id,
            "incident_id":             incident_id,
            "gen_ai.request.model":    _OLLAMA_MODEL,
            "gen_ai.operation.name":   "chat",
            "gen_ai.system":           "ollama",
            "owasp_llm":               "LLM01",
            "owasp_asi":               "ASI05",
            "mitre_atlas":             "AML.T0054",
            "timestamp_iso":           datetime.datetime.utcnow().isoformat() + "Z",
        }, severity="CRITICAL")
        return {
            "response":           f"[ACMEGATE BLOCKED] Input contains forbidden markup. CG-RULE-SBD-007.",
            "input_tokens":       0,
            "output_tokens":      0,
            "latency_ms":         0,
            "model":              _OLLAMA_MODEL,
            "acme_output_guard_blocked": False,
            "acme_input_guard_blocked":  True,
            "workflow_blocked":   False,
            "trace_id":           "",
            "incident_id":        incident_id,
        }

    # --- OTel span wrapping the real LLM call ---
    span_name = f"chat {_OLLAMA_MODEL}"
    with tracer.start_as_current_span(
        span_name,
        kind=SpanKind.CLIENT,
    ) as span:
        # GenAI Semantic Convention required attributes
        span.set_attribute("gen_ai.operation.name",    "chat")
        span.set_attribute("gen_ai.system",            "ollama")
        span.set_attribute("gen_ai.request.model",     _OLLAMA_MODEL)
        span.set_attribute("gen_ai.request.temperature", temperature)
        span.set_attribute("gen_ai.request.max_tokens", max_tokens)
        span.set_attribute("server.address",           _OLLAMA_URL.replace("http://", "").split(":")[0])
        span.set_attribute("server.port",              int(_OLLAMA_URL.split(":")[-1]) if ":" in _OLLAMA_URL else 11434)
        # Agent semantic convention attributes
        span.set_attribute("gen_ai.agent.id",          agent_id)
        span.set_attribute("gen_ai.agent.name",        agent_name)
        span.set_attribute("gen_ai.agent.description", agent_role)
        # ACME-specific context
        span.set_attribute("session.id",               session_id)
        span.set_attribute("incident_id",              incident_id)
        span.set_attribute("acme.trust_boundary",      "internal")

        ctx = span.get_span_context()
        trace_id_hex = format(ctx.trace_id, "032x") if ctx.trace_id else ""

        t_start = time.perf_counter()

        try:
            # Build the Ollama request — uses /api/generate with prompt assembly
            full_prompt = f"[SYSTEM]\n{system_prompt}\n\n[USER]\n{user_message}\n\n[ASSISTANT]"

            response = requests.post(
                f"{_OLLAMA_URL}/api/generate",
                json={
                    "model":  _OLLAMA_MODEL,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature":  temperature,
                        "num_predict":  max_tokens,
                        "stop":         ["[USER]", "[SYSTEM]", "</s>"],
                    }
                },
                timeout=120,
            )
            response.raise_for_status()
            result = response.json()

        except requests.exceptions.Timeout:
            span.set_status(StatusCode.ERROR, "Ollama request timed out")
            span.record_exception(Exception("Ollama timeout"), attributes={
                "gen_ai.system": "ollama",
                "gen_ai.request.model": _OLLAMA_MODEL,
            })
            return {
                "response":           "[TIMEOUT] Ollama did not respond within 120s",
                "input_tokens":       0, "output_tokens": 0, "latency_ms": 120000,
                "model":              _OLLAMA_MODEL,
                "acme_output_guard_blocked": False, "acme_input_guard_blocked": False,
                "trace_id":           trace_id_hex, "incident_id": incident_id,
            }
        except requests.exceptions.ConnectionError as e:
            span.set_status(StatusCode.ERROR, "Ollama connection refused")
            span.record_exception(e)
            return {
                "response":           "[CONNECTION ERROR] Cannot reach Ollama. Is it running?",
                "input_tokens":       0, "output_tokens": 0, "latency_ms": 0,
                "model":              _OLLAMA_MODEL,
                "acme_output_guard_blocked": False, "acme_input_guard_blocked": False,
                "trace_id":           trace_id_hex, "incident_id": incident_id,
            }

        latency_s  = time.perf_counter() - t_start
        latency_ms = round(latency_s * 1000, 2)

        output_text    = result.get("response", "").strip()
        input_tokens   = result.get("prompt_eval_count",  0) or len(full_prompt.split())
        output_tokens  = result.get("eval_count",         0) or len(output_text.split())
        response_model = result.get("model", _OLLAMA_MODEL)

        # GenAI usage attributes — written back to span
        span.set_attribute("gen_ai.usage.input_tokens",  input_tokens)
        span.set_attribute("gen_ai.usage.output_tokens", output_tokens)
        span.set_attribute("gen_ai.response.model",      response_model)
        span.set_attribute("gen_ai.response.finish_reasons", result.get("done_reason", "stop"))
        span.set_attribute("gen_ai.client.operation.duration", latency_s)

        # Record to OTel metrics
        base_attrs = {
            "gen_ai.system":        "ollama",
            "gen_ai.request.model": _OLLAMA_MODEL,
            "gen_ai.operation.name": "chat",
            "gen_ai.agent.id":      agent_id,
        }
        _token_counter_input.add(input_tokens, {**base_attrs, "gen_ai.token.type": "input"})
        _token_counter_output.add(output_tokens, {**base_attrs, "gen_ai.token.type": "output"})
        _operation_duration.record(latency_s, base_attrs)

        # --- AcmeSentinel output inspection ---
        acme_output_guard_blocked = False
        if not skip_acmesentinel:
            try:
                output_text = acmesentinel_inspect_output(
                    output_text, agent_id, span, session_id
                )
            except AcmeSentinelViolation as dcv:
                acme_output_guard_blocked = True
                output_text = (
                    f"[ACMESENTINEL HARD_DENY] {dcv.rule_id}: "
                    f"Model output contained injection execution signature. "
                    f"Response suppressed."
                )

        # Emit structured GenAI log record
        log_body = {
            # OTel GenAI semantic convention fields
            "gen_ai.operation.name":    "chat",
            "gen_ai.system":            "ollama",
            "gen_ai.request.model":     _OLLAMA_MODEL,
            "gen_ai.response.model":    response_model,
            "gen_ai.usage.input_tokens":  input_tokens,
            "gen_ai.usage.output_tokens": output_tokens,
            "gen_ai.response.finish_reasons": result.get("done_reason", "stop"),
            "gen_ai.client.operation.duration_ms": latency_ms,
            # Agent fields
            "gen_ai.agent.id":          agent_id,
            "gen_ai.agent.name":        agent_name,
            # Security fields
            "acme_output_guard.action":       "HARD_DENY" if acme_output_guard_blocked else "PASS",
            "acme_input_guard.status":         "BLOCKED" if acme_input_guard_blocked else "PASS",
            "acme_input_guard_blocked":        str(acme_input_guard_blocked).lower(),
            "acme_output_guard_blocked":      str(acme_output_guard_blocked).lower(),
            # Context
            "session.id":               session_id,
            "trace_id":                 trace_id_hex,
            "testbed_mode":             testbed_mode,
            "campaign_week":            str(campaign_week) if campaign_week else "",
            # Preview of input/output (first 200 chars for forensics)
            "gen_ai.input.preview":     user_message[:200],
            "gen_ai.output.preview":    output_text[:200],
            "timestamp_iso":            datetime.datetime.utcnow().isoformat() + "Z",
            **workflow.otel_fields,
        }
        if not is_baseline:
            log_body["incident_id"] = incident_id
        if technique_id:
            log_body["technique_id"] = technique_id
            log_body["framework.technique_id"] = technique_id

        controls = evaluate_controls(log_body, campaign_week or None)
        log_body.update(control_otel_fields(controls))

        if campaign_week == 10 and (
            acme_output_guard_blocked or "AUTONOMOUS" in user_message.upper()
        ):
            soar = trigger_containment(agent_id, incident_id)
            log_body.update(soar_otel_fields(soar))

        _emit_log_record(log_body, severity="ERROR" if acme_output_guard_blocked else "INFO", trace_id=trace_id_hex)

        span.set_status(StatusCode.OK if not acme_output_guard_blocked else StatusCode.ERROR)

        return {
            "response":            output_text,
            "input_tokens":        input_tokens,
            "output_tokens":       output_tokens,
            "latency_ms":          latency_ms,
            "model":               response_model,
            "acme_output_guard_blocked": acme_output_guard_blocked,
            "acme_input_guard_blocked":   acme_input_guard_blocked,
            "workflow_blocked":    False,
            "workflow_surface":    workflow.workflow_surface,
            "trace_id":            trace_id_hex,
            "incident_id":         incident_id,
            "control_evidence":    control_summary(controls),
            **workflow.otel_fields,
        }


def ollama_health_check() -> bool:
    """Return True if Ollama API is reachable and model is loaded."""
    try:
        r = requests.get(f"{_OLLAMA_URL}/api/tags", timeout=5)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return any(_OLLAMA_MODEL.split(":")[0] in m for m in models)
    except Exception:
        pass
    return False
