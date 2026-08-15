"""
Agent memory policy — blocks persistence / poisoned memory writes (Emerging Class #6).

Extended with session-level trust-decay detection for multi-turn behavioral drift (AML.T0072).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

MEMORY_WRITE_PATTERNS = [
    re.compile(r"persistent\s+memory", re.I),
    re.compile(r"store\s+these\s+instructions", re.I),
    re.compile(r"remember\s+(?:this|these)\s+(?:for\s+)?(?:all\s+)?future\s+sessions", re.I),
    re.compile(r"do\s+not\s+(?:forget|clear)\s+this", re.I),
    re.compile(r"memory\.write\s*\(", re.I),
    re.compile(r"vector_store\.upsert", re.I),
]

# In-process session store for lab multi-turn drift (not durable across restarts)
_SESSION_FACTS: Dict[str, List[dict]] = {}


@dataclass
class MemoryPolicyResult:
    blocked: bool
    rule_id: str
    matched_pattern: str = ""


@dataclass
class MemoryDriftResult:
    drift_detected: bool
    memory_entry_trust_score: float
    approval_rate_by_session: float
    rule_id: str
    session_turn_count: int = 0


def inspect_memory_policy(user_input: str) -> MemoryPolicyResult:
    for i, pattern in enumerate(MEMORY_WRITE_PATTERNS):
        match = pattern.search(user_input)
        if match:
            return MemoryPolicyResult(
                blocked=True,
                rule_id=f"MEM-POL-{100 + i:03d}",
                matched_pattern=pattern.pattern,
            )
    return MemoryPolicyResult(blocked=False, rule_id="MEM-POL-PASS")


def record_session_fact(session_id: str, content: str, trust_delta: float = 0.0) -> None:
    """Record a conversational turn for trust-decay analysis."""
    facts = _SESSION_FACTS.setdefault(session_id, [])
    base_trust = 1.0
    if facts:
        base_trust = facts[-1].get("trust_score", 1.0)
    poison_markers = (
        "override",
        "auto-approve",
        "expedited path",
        "compliance override",
        "treat expedited",
    )
    lowered = content.lower()
    if any(marker in lowered for marker in poison_markers):
        trust_delta -= 0.15
    facts.append({
        "content_preview": content[:120],
        "trust_score": max(0.0, min(1.0, base_trust + trust_delta)),
    })


def check_session_drift(session_id: str) -> MemoryDriftResult:
    """Rolling session metric — detects gradual approval bias from poisoned facts."""
    facts = _SESSION_FACTS.get(session_id, [])
    if len(facts) < 3:
        return MemoryDriftResult(
            drift_detected=False,
            memory_entry_trust_score=1.0,
            approval_rate_by_session=0.0,
            rule_id="MEM-DRIFT-PASS",
            session_turn_count=len(facts),
        )

    trust_scores = [f["trust_score"] for f in facts]
    avg_trust = sum(trust_scores) / len(trust_scores)
    # Simulated approval bias: lower trust + enough turns => drift
    approval_rate = max(0.0, 1.0 - avg_trust)
    drift = len(facts) >= 4 and avg_trust < 0.55

    return MemoryDriftResult(
        drift_detected=drift,
        memory_entry_trust_score=round(avg_trust, 2),
        approval_rate_by_session=round(approval_rate, 2),
        rule_id="MEM-DRIFT-001" if drift else "MEM-DRIFT-PASS",
        session_turn_count=len(facts),
    )


def memory_drift_otel_fields(result: MemoryDriftResult) -> dict:
    return {
        "memory.drift_detected": str(result.drift_detected).lower(),
        "memory_entry_trust_score": str(result.memory_entry_trust_score),
        "approval_rate_by_session": str(result.approval_rate_by_session),
        "memory.drift.rule_id": result.rule_id,
        "memory.session_turn_count": str(result.session_turn_count),
    }
