#!/usr/bin/env python3
"""
Export OrchestraACME technique playbooks to Splunk lookup CSV files.
Run from repo root: python3 scripts/sync_splunk_lookups.py
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps"))

from framework.technique_playbooks import get_all_playbooks  # noqa: E402
from framework.taxonomy import TECHNIQUE_REGISTRY  # noqa: E402

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
            })
    return out


def enrich_framework_lookup() -> Path:
    """Add execution_mode column to framework lookup from playbooks."""
    src = LOOKUP_DIR / "acme_framework_lookup.csv"
    if not src.is_file():
        raise FileNotFoundError(
            f"Expected lookup file at {src}. "
            "Ensure splunk_app/splunk_compliance_app/lookups/ is present in the repo."
        )
    playbooks = {p.technique_id: p for p in get_all_playbooks()}

    rows = []
    with src.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fieldnames = list(reader.fieldnames or [])
        if "execution_mode" not in fieldnames:
            fieldnames.append("execution_mode")
        if "is_top_10" not in fieldnames:
            fieldnames.append("is_top_10")
        for row in reader:
            pb = playbooks.get(row.get("technique_id", ""))
            row["execution_mode"] = pb.execution_mode if pb else "SIMULATED"
            row["is_top_10"] = str(pb.is_top_10).lower() if pb else "false"
            rows.append(row)

    with src.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return src


def main() -> None:
    LOOKUP_DIR.mkdir(parents=True, exist_ok=True)
    playbooks_path = export_playbooks_lookup()
    framework_path = enrich_framework_lookup()
    print(f"Wrote {playbooks_path}")
    print(f"Updated {framework_path}")


if __name__ == "__main__":
    main()
