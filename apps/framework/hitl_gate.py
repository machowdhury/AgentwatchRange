"""
Human-in-the-loop (HITL) circuit breaker — blocks high-impact actions without approval.

Demonstrates the gap when HITL_GATE_ENABLED=false (default) vs. enforced approval.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

HITL_GATE_ENABLED = os.environ.get("HITL_GATE_ENABLED", "false").lower() in ("1", "true", "yes")
HITL_AMOUNT_THRESHOLD = float(os.environ.get("HITL_AMOUNT_THRESHOLD", "250000"))

_LOAN_AMOUNT_RE = re.compile(
    r"(?:loan\s*amount|amount|approve\s*\$?)\s*[:=]?\s*\$?\s*([\d,]+(?:\.\d+)?)",
    re.IGNORECASE,
)


@dataclass
class HitlGateResult:
    hitl_required: bool
    hitl_bypassed: bool
    blocked: bool
    loan_amount_usd: float
    rule_id: str
    reason: str = ""


def parse_loan_amount(message: str) -> float:
    match = _LOAN_AMOUNT_RE.search(message)
    if not match:
        return 0.0
    try:
        return float(match.group(1).replace(",", ""))
    except ValueError:
        return 0.0


def check_hitl_gate(message: str, agent_id: str) -> HitlGateResult:
    """Evaluate whether a compliance / approval action requires human checkpoint."""
    amount = parse_loan_amount(message)
    if amount < HITL_AMOUNT_THRESHOLD:
        return HitlGateResult(
            hitl_required=False,
            hitl_bypassed=False,
            blocked=False,
            loan_amount_usd=amount,
            rule_id="HITL-GATE-PASS",
        )

    if not HITL_GATE_ENABLED:
        return HitlGateResult(
            hitl_required=True,
            hitl_bypassed=True,
            blocked=False,
            loan_amount_usd=amount,
            rule_id="HITL-GATE-DISABLED-001",
            reason="HIGH_VALUE_AUTO_APPROVE_WITHOUT_HITL",
        )

    return HitlGateResult(
        hitl_required=True,
        hitl_bypassed=False,
        blocked=True,
        loan_amount_usd=amount,
        rule_id="HITL-GATE-ENFORCED-001",
        reason="HITL_APPROVAL_REQUIRED",
    )


def hitl_otel_fields(result: HitlGateResult) -> dict:
    return {
        "hitl_required": str(result.hitl_required).lower(),
        "hitl_bypassed": str(result.hitl_bypassed).lower(),
        "loan_amount_usd": str(int(result.loan_amount_usd)) if result.loan_amount_usd else "0",
        "hitl.rule_id": result.rule_id,
        "hitl.gate_enabled": str(HITL_GATE_ENABLED).lower(),
    }
