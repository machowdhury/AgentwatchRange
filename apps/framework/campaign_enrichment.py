"""
Campaign-week OTel enrichment — merges manifest + security module signals.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Optional

from framework.a2a_verifier import a2a_otel_fields, verify_a2a_message
from framework.campaign_manifest import campaign_framework_tags, get_campaign_week
from framework.mcp_gateway import inspect_tool_invocation, mcp_otel_fields
from framework.rag_store import probe_rag_exfiltration, rag_otel_fields
from framework.soar_simulator import soar_otel_fields, trigger_containment

_AIBOM_MANIFEST: Optional[dict] = None


def _load_aibom_manifest() -> dict:
    global _AIBOM_MANIFEST
    if _AIBOM_MANIFEST is not None:
        return _AIBOM_MANIFEST

    candidates = [
        Path(__file__).resolve().parents[2] / "data" / "aibom" / "acme_agent_manifest.json",
        Path("/app/data/aibom/acme_agent_manifest.json"),
    ]
    for path in candidates:
        if path.exists():
            _AIBOM_MANIFEST = json.loads(path.read_text(encoding="utf-8"))
            return _AIBOM_MANIFEST

    _AIBOM_MANIFEST = {
        "manifest_version": "1.0",
        "agents": {
            "acme-agent-creditrisk-003": {
                "model_artifact_hash": "sha256:acme-creditrisk-llama3.2-v1",
                "approved": True,
            },
        },
    }
    return _AIBOM_MANIFEST


def _aibom_fields(agent_id: str, user_message: str) -> dict:
    manifest = _load_aibom_manifest()
    agent_entry = manifest.get("agents", {}).get(agent_id, {})
    expected = agent_entry.get("model_artifact_hash", "sha256:unknown")
    found = hashlib.sha256(user_message[:200].encode()).hexdigest()
    found_tag = f"sha256:{found[:16]}"

    drift = "PROMPT_DRIFT_DETECTED" if "SYSTEM UPDATE" in user_message.upper() else "MATCH"
    validated = drift == "MATCH"

    fields = {
        "cisco_aibom_status": drift,
        "agent.aibom_validated": str(validated).lower(),
        "model_artifact_hash_expected": expected,
        "model_artifact_hash_found": found_tag,
        "aibom.manifest_version": manifest.get("manifest_version", "1.0"),
    }

    try:
        from framework.cisco_integration import cisco_enabled, run_aibom_scan
        if cisco_enabled():
            scan = run_aibom_scan()
            fields.update(scan.get("telemetry", {}))
            if scan.get("status") == "FAIL":
                fields["cisco_aibom_status"] = "HASH_MISMATCH"
                fields["agent.aibom_validated"] = "false"
    except ImportError:
        pass

    return fields


def _foundry_fields(user_message: str) -> dict:
    if "FOUNDRY_TRACE_STATE" not in user_message:
        return {}
    trace_id = "foundry-trace-unknown"
    for line in user_message.splitlines():
        if "Trace-ID:" in line:
            trace_id = line.split(":", 1)[-1].strip()
            break
    return {
        "foundry.trace_id": trace_id,
        "foundry.policy_status": "BYPASSED" if "BYPASSED" in user_message else "ENFORCED",
        "foundry.orchestrator_override": "true" if "orchestrator_override=true" in user_message.lower() else "false",
    }


def _edge_slm_fields(user_message: str, model_name: str) -> dict:
    edge_model = "phi3-mini-edge-unapproved"
    if edge_model in user_message or "SHADOW_SLM" in user_message:
        return {
            "llm.runtime": "edge",
            "slm.unapproved": "true",
            "deployment.tier": "shadow",
            "gen_ai.request.model": edge_model,
        }
    return {
        "llm.runtime": os.environ.get("LLM_RUNTIME", "ollama"),
        "slm.unapproved": "false",
        "deployment.tier": "approved",
        "gen_ai.request.model": model_name,
    }


def _call_depth_fields(user_message: str, campaign_week: int = 0) -> dict:
    from framework.cisco_integration import ctsm_anomaly_fields
    return ctsm_anomaly_fields(user_message, campaign_week)


def enrich_campaign_context(
    campaign_week: int,
    user_message: str,
    agent_id: str,
    session_id: str,
    model_name: str,
    incident_id: str,
    acme_output_guard_blocked: bool = False,
    acme_input_guard_blocked: bool = False,
) -> Dict[str, str]:
    """Return extra OTel log fields for a campaign-week exploit or technique run."""
    fields: Dict[str, str] = dict(campaign_framework_tags(campaign_week))
    cw = get_campaign_week(campaign_week)
    if not cw:
        return fields

    if campaign_week == 1:
        fields.update(_aibom_fields(agent_id, user_message))
    elif campaign_week == 2:
        fields.update(_foundry_fields(user_message))
    elif campaign_week == 4:
        fields.update(_edge_slm_fields(user_message, model_name))
    elif campaign_week == 6:
        mcp = inspect_tool_invocation(user_message)
        fields.update(mcp_otel_fields(mcp, session_id))
        if mcp.scope_violation:
            fields["mcp.gateway.action"] = "BLOCK"
        try:
            from framework.cisco_integration import cisco_enabled, run_mcp_scan
            if cisco_enabled():
                scan = run_mcp_scan()
                fields.update(scan.get("telemetry", {}))
        except ImportError:
            pass
    elif campaign_week == 7:
        fields.update(_call_depth_fields(user_message, campaign_week))
    elif campaign_week == 8:
        a2a = verify_a2a_message(user_message, agent_id)
        fields.update(a2a_otel_fields(a2a))
    elif campaign_week == 9:
        rag = probe_rag_exfiltration(user_message)
        fields.update(rag_otel_fields(rag))
    elif campaign_week == 10:
        rogue = "AUTONOMOUS MODE" in user_message.upper() or "AUTONOMOUS DIRECTIVES" in user_message.upper()
        if rogue or acme_output_guard_blocked or acme_input_guard_blocked:
            soar = trigger_containment(agent_id, incident_id)
            fields.update(soar_otel_fields(soar))

    return fields
