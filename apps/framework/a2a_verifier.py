"""
A2A delegation verifier — W3C DID and cryptographic passport checks (Campaign W8).

Extended with message provenance / integrity checks (AML.T0075) and
granted-vs-used scope tracking for privilege creep (AML.T0073).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Set

DID_PATTERN = re.compile(
    r"did:acme:[a-z]+:agent:\d{3}:v[\d.]+",
    re.IGNORECASE,
)
FORGED_SIG_MARKERS = (
    "FORGED",
    "BYPASS_VERIFICATION",
    "FAKE_SIGNATURE",
    "INVALID_SIG",
)
TAMPER_MARKERS = (
    "MESSAGE_TAMPERED",
    "INTEGRITY_MISMATCH",
    "PROVENANCE_INVALID",
)

# Lab scope registry: granted vs. observed usage per agent identity
_AGENT_GRANTED_SCOPE: Dict[str, Set[str]] = {
    "acme-agent-intake-001": {"read:intake", "write:queue"},
    "acme-agent-docingest-002": {"read:documents", "tools:extract"},
    "acme-agent-creditrisk-003": {"read:policy", "score:risk"},
    "acme-agent-compliance-004": {"read:policy", "write:approve"},
}
_AGENT_USED_SCOPE: Dict[str, Set[str]] = {}


@dataclass
class A2AVerificationResult:
    did_document: str
    delegation_chain: str
    cryptographic_passport_valid: bool
    requesting_agent_id: str
    target_agent_id: str
    verification_failure_reason: str = ""
    message_provenance_valid: bool = True
    message_hash_expected: str = ""
    message_hash_received: str = ""


@dataclass
class ScopeTrackingResult:
    granted_scope: str
    used_scope: str
    scope_delta: str
    privilege_creep_detected: bool


def track_agent_scope(agent_id: str, requested_scopes: Set[str]) -> ScopeTrackingResult:
    """Compare granted permissions vs. scopes observed in this session."""
    granted = _AGENT_GRANTED_SCOPE.get(agent_id, set())
    used = _AGENT_USED_SCOPE.setdefault(agent_id, set())
    used.update(requested_scopes)
    delta = used - granted
    return ScopeTrackingResult(
        granted_scope=",".join(sorted(granted)),
        used_scope=",".join(sorted(used)),
        scope_delta=",".join(sorted(delta)) if delta else "",
        privilege_creep_detected=bool(delta),
    )


def verify_message_provenance(message: str, declared_hash: str = "") -> tuple[bool, str, str]:
    """Hash-based integrity check for inter-agent message content."""
    content_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
    expected = declared_hash.replace("sha256:", "") if declared_hash else content_hash

    if any(marker in message.upper() for marker in TAMPER_MARKERS):
        return False, f"sha256:{expected[:12]}", f"sha256:{content_hash[:12]}"

    if declared_hash and not declared_hash.endswith(content_hash[:12]):
        return False, declared_hash, f"sha256:{content_hash[:12]}"

    return True, f"sha256:{content_hash[:12]}", f"sha256:{content_hash[:12]}"


def verify_a2a_message(message: str, receiving_agent_id: str) -> A2AVerificationResult:
    """Parse inter-agent message headers and validate DID / signature claims."""
    did_match = DID_PATTERN.search(message)
    did = did_match.group(0) if did_match else ""

    chain = ""
    for line in message.splitlines():
        if "Delegation-Chain:" in line or "delegation.chain" in line.lower():
            chain = line.split(":", 1)[-1].strip()
            break

    requesting = ""
    if did:
        parts = did.split(":")
        if len(parts) >= 4:
            requesting = f"acme-agent-{parts[3]}-{parts[4]}"

    passport_valid = True
    reason = ""
    upper = message.upper()
    provenance_valid, hash_expected, hash_received = verify_message_provenance(message)

    if any(marker in upper for marker in FORGED_SIG_MARKERS):
        passport_valid = False
        reason = "FORGED_SIGNATURE_DETECTED"
    elif "CRYPTOGRAPHIC_PASSPORT_VERIFIED" in upper and "FORGED" in upper:
        passport_valid = False
        reason = "CONTRADICTORY_PASSPORT_CLAIM"
    elif did and "Signature:" in message and "FORGED" in upper:
        passport_valid = False
        reason = "SIGNATURE_MISMATCH"
    elif not provenance_valid:
        passport_valid = False
        reason = "MESSAGE_INTEGRITY_MISMATCH"

    return A2AVerificationResult(
        did_document=did,
        delegation_chain=chain or "orchestrator-000 → unknown",
        cryptographic_passport_valid=passport_valid,
        requesting_agent_id=requesting,
        target_agent_id=receiving_agent_id,
        verification_failure_reason=reason,
        message_provenance_valid=provenance_valid,
        message_hash_expected=hash_expected,
        message_hash_received=hash_received,
    )


def a2a_otel_fields(result: A2AVerificationResult) -> dict:
    return {
        "did.document": result.did_document,
        "delegation.chain": result.delegation_chain,
        "cryptographic_passport_valid": str(result.cryptographic_passport_valid).lower(),
        "requesting_agent_id": result.requesting_agent_id,
        "target_agent_id": result.target_agent_id,
        "a2a.verification_failure": result.verification_failure_reason,
        "message.provenance_valid": str(result.message_provenance_valid).lower(),
        "message.hash_expected": result.message_hash_expected,
        "message.hash_received": result.message_hash_received,
    }


def scope_otel_fields(result: ScopeTrackingResult) -> dict:
    return {
        "granted_scope": result.granted_scope,
        "used_scope": result.used_scope,
        "scope_delta": result.scope_delta,
        "privilege_creep_detected": str(result.privilege_creep_detected).lower(),
    }
