"""
Agent inventory snapshots for acme:agentic:registry:json (Phase 10.3).

Reflects real lab agents + MCP scope — not a padded fictional roster.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.agent_router import AGENTS
from framework.mcp_gateway import APPROVED_TOOLS

# Scenario 4 shadow SLM — unregistered edge instance (teaching inventory gap)
SHADOW_AGENT = {
    "agent_id": "acme-shadow-slm-edge-001",
    "model_origin": os.environ.get("OLLAMA_MODEL", "llama3.2:1b"),
    "owning_department": "retail_innovation_lab",
    "mcp_scope": "unscoped",
    "trust_score": 0.35,
    "agent_status": "shadow",
    "notes": "Unapproved edge SLM per Scenario 4 (Shadow AI at the Edge)",
}

_DEPT_MAP = {
    "customer_enclave": "retail_banking",
    "document_enclave": "operations",
    "risk_enclave": "credit_risk",
    "compliance_enclave": "compliance",
}


def _trust_score(agent: dict) -> float:
    """Simple granted-vs-role heuristic (not arbitrary)."""
    role = agent.get("role", "")
    boundary = agent.get("trust_boundary", "")
    base = 0.92
    if boundary == "external_dmz":
        base = 0.78
    elif boundary == "privileged_internal":
        base = 0.88
    if role == "customer_facing":
        base -= 0.05
    return round(min(0.99, max(0.5, base)), 2)


def build_registry_snapshot(include_shadow: bool = True) -> List[Dict[str, Any]]:
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
    mcp_scope = ",".join(sorted(APPROVED_TOOLS))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows: List[Dict[str, Any]] = []

    for agent_id, meta in AGENTS.items():
        rows.append({
            "snapshot_time": ts,
            "agent_id": agent_id,
            "agent_name": meta.get("name", agent_id),
            "model_origin": model,
            "owning_department": _DEPT_MAP.get(meta.get("enclave", ""), "acme_bank"),
            "mcp_scope": mcp_scope,
            "trust_score": _trust_score(meta),
            "agent_status": "running",
            "trust_boundary": meta.get("trust_boundary", ""),
            "agent_role": meta.get("role", ""),
        })

    if include_shadow:
        row = {**SHADOW_AGENT, "snapshot_time": ts, "agent_name": "Shadow Edge SLM"}
        rows.append(row)

    return rows
