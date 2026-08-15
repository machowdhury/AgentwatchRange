#!/usr/bin/env python3
"""
Export AgentWatch Range technique playbooks to Splunk lookup CSV files.
Run from repo root: python3 scripts/sync_splunk_lookups.py
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps"))

from framework.technique_playbooks import get_all_playbooks  # noqa: E402
from framework.taxonomy import TECHNIQUE_REGISTRY, assert_learning_tier_distribution  # noqa: E402

LOOKUP_DIR = ROOT / "splunk_app" / "splunk_compliance_app" / "lookups"


def _pipe_join(items):
    return "|".join(items) if items else ""


def export_playbooks_lookup() -> Path:
    out = LOOKUP_DIR / "acme_technique_playbooks_lookup.csv"
    playbooks = {p.technique_id: p for p in get_all_playbooks()}

    fieldnames = [
        "technique_id",
        "technique_name",
        "tactic_name",
        "kill_chain_stage",
        "execution_mode",
        "target_agent",
        "scenario_week",
        "is_top_10",
        "severity",
        "cvss_score",
        "owasp_llm",
        "practitioner_narrative",
        "rogue_actor_story",
        "risk_statement",
        "threat_hunt_steps",
        "threat_hunt_spl",
        "learning_tier",
        "learning_tier_label",
        "redundant_with",
    ]

    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for entry in TECHNIQUE_REGISTRY:
            pb = playbooks.get(entry.technique_id)
            if not pb:
                continue
            writer.writerow({
                "technique_id": pb.technique_id,
                "technique_name": pb.technique_name,
                "tactic_name": pb.tactic_name,
                "kill_chain_stage": pb.kill_chain_stage,
                "execution_mode": pb.execution_mode,
                "target_agent": pb.target_agent,
                "scenario_week": pb.scenario_week or "",
                "is_top_10": str(pb.is_top_10).lower(),
                "severity": pb.severity,
                "cvss_score": pb.cvss_score,
                "owasp_llm": _pipe_join(pb.owasp_llm),
                "practitioner_narrative": pb.practitioner_narrative,
                "rogue_actor_story": pb.rogue_actor_story,
                "risk_statement": pb.risk_statement,
                "threat_hunt_steps": " || ".join(pb.threat_hunt_steps),
                "threat_hunt_spl": pb.threat_hunt_spl,
                "learning_tier": pb.learning_tier,
                "learning_tier_label": pb.learning_tier_label,
                "redundant_with": pb.redundant_with,
            })
    return out


def enrich_framework_lookup() -> Path:
    """Sync framework lookup from TECHNIQUE_REGISTRY + playbooks (append new techniques)."""
    src = LOOKUP_DIR / "acme_framework_lookup.csv"
    if not src.is_file():
        raise FileNotFoundError(
            f"Expected lookup file at {src}. "
            "Ensure splunk_app/splunk_compliance_app/lookups/ is present in the repo."
        )
    playbooks = {p.technique_id: p for p in get_all_playbooks()}

    existing: dict[str, dict] = {}
    fieldnames = [
        "technique_id", "technique_name", "tactic_id", "tactic_name",
        "subtechnique_id", "subtechnique_name", "owasp_llm", "owasp_asi",
        "maestro_layers", "nist_ai_rmf", "cvss_score", "severity",
        "attack_vector", "kill_chain_stage", "kill_chain_order",
        "description", "impact", "acme_output_guard_action", "galileo_check",
        "detection_signal", "splunk_spl_template", "real_world_incident",
        "quality_tier", "execution_mode", "is_top_10",
        "learning_tier", "redundant_with",
    ]

    if src.is_file():
        with src.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                existing[row["technique_id"]] = row

    rows = []
    for entry in TECHNIQUE_REGISTRY:
        pb = playbooks.get(entry.technique_id)
        row = existing.get(entry.technique_id, {})
        rows.append({
            "technique_id": entry.technique_id,
            "technique_name": entry.technique_name,
            "tactic_id": entry.tactic_id,
            "tactic_name": entry.tactic_name,
            "subtechnique_id": entry.subtechnique_id,
            "subtechnique_name": entry.subtechnique_name,
            "owasp_llm": _pipe_join(entry.owasp_llm),
            "owasp_asi": _pipe_join(entry.owasp_asi),
            "maestro_layers": _pipe_join(entry.maestro_layers),
            "nist_ai_rmf": _pipe_join(entry.nist_ai_rmf),
            "cvss_score": str(entry.cvss_score),
            "severity": entry.severity,
            "attack_vector": entry.attack_vector,
            "kill_chain_stage": entry.kill_chain_stage,
            "kill_chain_order": str(entry.kill_chain_order),
            "description": entry.description,
            "impact": entry.impact,
            "acme_output_guard_action": entry.acme_output_guard_action,
            "galileo_check": entry.galileo_check,
            "detection_signal": entry.detection_signal,
            "splunk_spl_template": entry.splunk_spl_template,
            "real_world_incident": entry.real_world_incident,
            "quality_tier": entry.quality_tier,
            "execution_mode": pb.execution_mode if pb else row.get("execution_mode", "SIMULATED"),
            "is_top_10": str(pb.is_top_10).lower() if pb else row.get("is_top_10", "false"),
            "learning_tier": str(entry.learning_tier),
            "redundant_with": entry.redundant_with or "",
        })

    with src.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return src


def main() -> None:
    assert_learning_tier_distribution(TECHNIQUE_REGISTRY)
    LOOKUP_DIR.mkdir(parents=True, exist_ok=True)
    playbooks_path = export_playbooks_lookup()
    framework_path = enrich_framework_lookup()
    print(f"Wrote {playbooks_path}")
    print(f"Updated {framework_path}")


if __name__ == "__main__":
    main()
