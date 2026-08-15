"""
Learning tier assignments (Tier 0–6) for AgentWatch Range curriculum navigation.

Tier numbers are stable identifiers used in taxonomy, Attack Panel badges,
Splunk lookups (Phase 5), and docs/LEARNING_PATH.md.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from framework.emerging_threats import EMERGING_TECHNIQUE_IDS

SIMULATED_STAGES = frozenset({
    "Reconnaissance",
    "ResourceDevelopment",
    "Staging",
})

# Scenario week → primary teaching tier (Top 10 cards)
SCENARIO_WEEK_TIER: Dict[int, int] = {
    3: 1,
    5: 1,
    2: 2,
    6: 2,
    7: 2,
    8: 3,
    9: 3,
    10: 3,
    1: 4,  # supply-chain; also featured in Tier 5 Cisco path
    4: 4,  # shadow AI discovery — compliance breadth
}

TIER_LABELS: Dict[int, str] = {
    0: "Tier 0 — Orientation",
    1: "Tier 1 — Beginner",
    2: "Tier 2 — Intermediate",
    3: "Tier 3 — Advanced",
    4: "Tier 4 — Coverage & Compliance",
    5: "Tier 5 — Vendor Tooling (Cisco)",
    6: "Tier 6 — Capstone / Blue Team",
}

# Techniques used in kill-chain narratives (KC-A001 … KC-F001)
CHAIN_TECHNIQUE_IDS = frozenset({
    "AML.T0000", "AML.T0003", "AML.T0005", "AML.T0018", "AML.T0025", "AML.T0026",
    "AML.T0029", "AML.T0031", "AML.T0036", "AML.T0037", "AML.T0038", "AML.T0040",
    "AML.T0043", "AML.T0045", "AML.T0048", "AML.T0050", "AML.T0051", "AML.T0052",
    "AML.T0054", "AML.T0055", "AML.T0058", "AML.T0060", "AML.T0072",
})

# SIMULATED breadth entries → canonical LIVE teaching technique
REDUNDANCY_CANONICAL: Dict[str, str] = {
    "AML.T0000": "AML.T0005",
    "AML.T0001": "AML.T0005",
    "AML.T0002": "AML.T0037",
    "AML.T0003": "AML.T0051",
    "AML.T0004": "AML.T0038",
    "AML.T0010": "AML.T0043",
    "AML.T0012": "AML.T0054",
    "AML.T0017": "AML.T0018",
    "AML.T0019": "AML.T0020",
    "AML.T0020": "AML.T0051",
    "AML.T0070": "AML.T0050",
    "AML.T0073": "AML.T0050",
}


def tier_label(tier: int) -> str:
    return TIER_LABELS.get(tier, f"Tier {tier}")


def tier_badge(tier: int) -> str:
    """Short badge for Attack Panel cards."""
    short = {
        0: "Tier 0",
        1: "Tier 1 — Beginner",
        2: "Tier 2 — Intermediate",
        3: "Tier 3 — Advanced",
        4: "Tier 4 — Coverage",
        5: "Tier 5 — Cisco",
        6: "Tier 6 — Capstone",
    }
    return short.get(tier, f"Tier {tier}")


def assign_learning_metadata(
    technique_id: str,
    *,
    kill_chain_stage: str,
    execution_mode: str,
    scenario_week: Optional[int],
) -> Tuple[int, str]:
    """
    Return (learning_tier, redundant_with) for a registry/playbook entry.
    """
    if technique_id in EMERGING_TECHNIQUE_IDS:
        return 3, REDUNDANCY_CANONICAL.get(technique_id, "")

    if scenario_week and scenario_week in SCENARIO_WEEK_TIER:
        tier = SCENARIO_WEEK_TIER[scenario_week]
        return tier, ""

    if technique_id in CHAIN_TECHNIQUE_IDS and execution_mode != "SIMULATED":
        return 3, ""

    if execution_mode == "SIMULATED" or kill_chain_stage in SIMULATED_STAGES:
        redundant = REDUNDANCY_CANONICAL.get(technique_id, "")
        if not redundant and kill_chain_stage == "Reconnaissance":
            redundant = "AML.T0005"
        elif not redundant and kill_chain_stage == "ResourceDevelopment":
            redundant = "AML.T0048"
        elif not redundant and kill_chain_stage == "Staging":
            redundant = "AML.T0051"
        return 4, redundant

    if execution_mode == "HYBRID" and technique_id not in CHAIN_TECHNIQUE_IDS:
        return 4, REDUNDANCY_CANONICAL.get(technique_id, "")

    # Residual LIVE registry entries — coverage campaign, still executable
    return 4, ""


def apply_learning_tiers_to_registry(registry) -> None:
    """Mutate TechniqueEntry objects in TECHNIQUE_REGISTRY with tier fields."""
    from framework.technique_playbooks import TECHNIQUE_WEEK_MAP, _execution_mode

    for entry in registry:
        week = TECHNIQUE_WEEK_MAP.get(entry.technique_id) or TECHNIQUE_WEEK_MAP.get(
            entry.subtechnique_id
        )
        mode = _execution_mode(entry, week is not None)
        tier, redundant = assign_learning_metadata(
            entry.technique_id,
            kill_chain_stage=entry.kill_chain_stage,
            execution_mode=mode,
            scenario_week=week,
        )
        entry.learning_tier = tier
        entry.redundant_with = redundant
