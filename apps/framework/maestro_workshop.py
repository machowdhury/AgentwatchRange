"""
CSA MAESTRO threat-modeling workshop helpers for AgentWatch Range.

Generates architecture descriptions for paste into the official CSA MAESTRO
Threat Analyzer (https://github.com/CloudSecurityAlliance/MAESTRO) and maps
lab scenarios to MAESTRO L1–L7 layers for predict-vs-observe validation in Splunk.
"""

from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify

from framework.attack_payloads import EXPLOITS
from framework.taxonomy import MAESTRO_LAYERS, TECHNIQUE_REGISTRY

MAESTRO_REPO = "https://github.com/CloudSecurityAlliance/MAESTRO"
MAESTRO_PAPER = (
    "https://cloudsecurityalliance.org/artifacts/"
    "agentic-ai-threat-modeling-framework-maestro"
)
MAESTRO_UI_DEFAULT = os.environ.get("MAESTRO_UI_URL", "http://localhost:9002")


def _parse_maestro_layers(raw: str) -> list[str]:
    layers: list[str] = []
    for part in raw.replace("/", ",").split(","):
        token = part.strip().upper()
        if token.startswith("L") and len(token) == 2 and token[1].isdigit():
            layers.append(token)
    return layers


def get_scenario_layer_map() -> list[dict[str, Any]]:
    """Map each Top-10 scenario to MAESTRO layers and primary threat themes."""
    rows: list[dict[str, Any]] = []
    for week in sorted(EXPLOITS.keys()):
        ex = EXPLOITS[week]
        layer_ids = _parse_maestro_layers(ex.get("maestro", ""))
        rows.append({
            "scenario": week,
            "title": ex.get("title", ""),
            "workflow_surface": ex.get("workflow_surface", ""),
            "target_agent": ex.get("target_agent", ""),
            "maestro_layers": layer_ids,
            "maestro_layer_names": [
                MAESTRO_LAYERS[l]["name"] for l in layer_ids if l in MAESTRO_LAYERS
            ],
            "attack_class": ex.get("attack_class", ""),
            "owasp": ex.get("owasp", ""),
            "mitre": ex.get("mitre", ""),
        })
    return rows


def get_architecture_description() -> str:
    """Architecture narrative optimized for CSA MAESTRO Threat Analyzer input."""
    return """AgentWatch Range — ACME Bank Agentic Loan Processing System

SYSTEM PURPOSE
A multi-agent AI system that processes small-business loan applications end-to-end:
intake, document extraction, credit risk scoring, and regulatory compliance review.

ARCHITECTURE OVERVIEW (7 MAESTRO LAYERS)

L1 — Foundation Models
- Primary runtime: Ollama-hosted llama3.2:1b on local Docker network (gen_ai.system=ollama).
- Each of four banking agents invokes the same base model with distinct system prompts.
- Optional shadow/unapproved SLM scenarios test ecosystem drift (Scenario 4).
- AI BOM manifest tracks expected model artifact hashes (Scenario 1 supply-chain drift).

L2 — Data Operations
- RAG retrieval over loan document chunks and policy excerpts (vector-style context assembly).
- Document Extraction Agent ingests applicant uploads and retrieved context into prompts.
- Attack surface: retrieval manipulation, context injection, training/RAG data exfiltration (Scenario 9).

L3 — Agent Frameworks
- Flask-based agent router and orchestration middleware on banking_app:5000.
- MCP (Model Context Protocol) tool gateway exposes credit bureau lookup, file read, and calculator tools.
- Output gateway inspects LLM responses post-generation (Scenario 5 semantic jailbreak).
- Framework misconfiguration and prompt injection at orchestration boundary (Scenario 5, 6).

L4 — Agent Capabilities
- Tools: MCP credit API simulation, document parsers, workflow action emitters.
- Agents can recommend APPROVE/DENY/ESCALATE with structured JSON outputs.
- Excessive agency risk: tool escape attempts bypass pre-LLM workflow guards (Scenario 6).
- AcmeGate rules inspect generated code-like snippets in agent outputs (Scenario 3).

L5 — Multi-Agent Systems
- Four-agent pipeline with delegation: Intake → Document Extraction → Credit Risk → Compliance.
- A2A-style handoffs carry session_id, trace_id, and agent authority headers between stages.
- Trust propagation: forged orchestrator authority and cross-agent identity spoofing (Scenario 8).
- Kill chains (KC-C001 Fraudulent Loan Pipeline) correlate multi-stage incidents via incident_id.
- Token surge / resource exhaustion across chained agent calls (Scenario 7).

L6 — Security & Compliance
- AcmeSentinel input/output inspection on every LLM call (HARD_DENY, SOFT_DENY, ALLOW).
- AcmeGate static rules for insecure patterns in model output.
- Workflow guards: MCP tool allowlists, A2A identity checks, memory write policies, orchestration gates.
- Human-in-the-loop fatigue and guardrail bypass patterns (Scenario 10 memory/SOC bypass).
- Full OTel GenAI semantic conventions exported to Splunk for audit and attestation.

L7 — Agent Ecosystem
- Docker Compose deployment: banking_app, attack_panel, ollama, otel_collector, optional Splunk/Cisco overlay.
- Third-party integration points: Splunk HEC, Cisco AI Defense scanners (AIBOM, MCP Scanner), MLTK CTSM.
- Supply chain: model substitution, plugin/tool marketplace risk, shadow AI at the edge (Scenarios 1, 2, 4).
- Optional Cisco overlay (LAB_MODE=teach) logs scanner findings without blocking workshop attacks.

AGENTIC PROPERTIES (MAESTRO emphasis)
- Non-determinism: live Ollama responses vary per run; defenses must handle ambiguous compliance language.
- Autonomy: agents chain decisions across four roles with minimal human approval on happy path.
- No hard trust boundary: user-supplied natural language crosses all layers; adversarial strings reach the real LLM.
- Protocol surfaces: MCP tool calls, A2A agent headers, RAG context, and memory persistence are all attacker-controlled inputs.

TELEMETRY & VALIDATION
- OpenTelemetry → Splunk index acme_agentic_telemetry, sourcetype otel:agentic:json.
- Each event enriches framework.maestro_layers, technique_id, campaign_week, workflow.block_reason.
- Splunk NIST AI RMF dashboard reports MAESTRO Layer Risk Coverage (% of L1–L7 with observed events).

THREAT MODELING GOAL
Identify traditional and agentic threats per MAESTRO layer, then validate predictions by firing
AgentWatch Range Scenarios 6 (MCP), 8 (A2A), 9 (RAG), and 10 (memory/guardrail) and comparing
Splunk observed layers to MAESTRO predictions.
"""


def get_validation_guide() -> dict[str, Any]:
    """Structured guide for predict-vs-observe workshop validation."""
    scenario_map = get_scenario_layer_map()
    all_scenario_layers = sorted({
        layer
        for row in scenario_map
        for layer in row["maestro_layers"]
    })
    technique_layers = sorted({
        layer
        for tech in TECHNIQUE_REGISTRY
        for layer in tech.maestro_layers
    })

    return {
        "maestro_repo": MAESTRO_REPO,
        "maestro_paper": MAESTRO_PAPER,
        "maestro_ui_url": MAESTRO_UI_DEFAULT,
        "workshop_path": "maestro_validate",
        "recommended_scenarios": [6, 8, 9, 10],
        "scenario_layer_map": scenario_map,
        "layers_in_top10_scenarios": all_scenario_layers,
        "layers_in_technique_registry": technique_layers,
        "splunk_dashboards": [
            "NIST AI RMF Scoring (MAESTRO Layer Risk Coverage)",
            "Control Attestation",
            "Detection Efficacy",
            "Technique Coverage Matrix",
        ],
        "splunk_validation_spl": (
            "`acme_genai_index` earliest=-30m "
            "| eval layers=split(framework.maestro_layers, \",\") "
            "| mvexpand layers "
            "| search layers=L* "
            "| stats count by layers campaign_week workflow.block_reason "
            "| sort layers campaign_week"
        ),
        "maestro_coverage_spl": (
            "`acme_genai_index` earliest=-30m "
            "| mvexpand framework.maestro_layers "
            "| search framework.maestro_layers=L* "
            "| stats dc(framework.maestro_layers) AS layers_at_risk "
            "| eval maestro_coverage_pct=round(layers_at_risk/7*100,1)"
        ),
        "reflection_questions": [
            "Which MAESTRO layers did the Threat Analyzer flag as highest agentic risk?",
            "After Scenarios 6, 8, 9, and 10, which layers appear in framework.maestro_layers?",
            "Did pre-LLM workflow blocks (L3/L4) fire where MAESTRO predicted capability abuse?",
            "Where did detect-only controls (L2/L6) match MAESTRO's compliance-layer warnings?",
        ],
    }


def register_maestro_routes(app: Flask) -> None:
    @app.route("/api/v1/maestro/architecture", methods=["GET"])
    def maestro_architecture():
        scenario_map = get_scenario_layer_map()
        predicted = sorted({
            layer
            for row in scenario_map
            if row["scenario"] in (6, 8, 9, 10)
            for layer in row["maestro_layers"]
        })
        return jsonify({
            "architecture_description": get_architecture_description(),
            "maestro_repo": MAESTRO_REPO,
            "maestro_paper": MAESTRO_PAPER,
            "maestro_ui_url": MAESTRO_UI_DEFAULT,
            "predicted_layers": [
                {
                    "layer_id": lid,
                    "name": MAESTRO_LAYERS[lid]["name"],
                    "primary_threats": MAESTRO_LAYERS[lid]["primary_threats"],
                }
                for lid in predicted
                if lid in MAESTRO_LAYERS
            ],
            "validation_scenarios": [6, 8, 9, 10],
            "scenario_layer_map": scenario_map,
        })

    @app.route("/api/v1/maestro/validation-guide", methods=["GET"])
    def maestro_validation_guide():
        return jsonify(get_validation_guide())

    @app.route("/api/v1/maestro/layers", methods=["GET"])
    def maestro_layers():
        return jsonify({
            "layers": [
                {
                    "layer_id": lid,
                    **{k: v for k, v in info.items() if k != "id"},
                    "technique_count": len([
                        t for t in TECHNIQUE_REGISTRY if lid in t.maestro_layers
                    ]),
                }
                for lid, info in MAESTRO_LAYERS.items()
            ],
        })
