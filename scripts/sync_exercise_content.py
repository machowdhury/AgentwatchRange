#!/usr/bin/env python3
"""
Generate splunk_compliance_app/lookups/exercise_content.csv for the Exercise Runner dashboard.

Run from repo root: python3 scripts/sync_exercise_content.py
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps"))

from framework.emerging_threats import EMERGING_TECHNIQUE_IDS  # noqa: E402
from framework.technique_playbooks import get_all_playbooks  # noqa: E402
from framework.taxonomy import TECHNIQUE_REGISTRY  # noqa: E402

LOOKUP_DIR = ROOT / "splunk_app" / "splunk_compliance_app" / "lookups"
OUT = LOOKUP_DIR / "exercise_content.csv"
PROGRESS = LOOKUP_DIR / "exercise_progress.csv"

FIELDNAMES = [
    "technique_id",
    "learning_tier",
    "title",
    "instructions_text",
    "spl_query",
    "chart_type",
    "explanation_text",
    "framework_mapping",
    "mitigation_text",
    "execution_mode",
    "triage_runbook_text",
    "expected_outcome",
]


def _csv_escape(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def _infer_chart_type(spl: str) -> str:
    s = spl.lower()
    if "timechart" in s:
        return "line"
    if re.search(r"\|\s*stats\s+count\s*$", s) or re.search(r"\|\s*stats\s+count\s*\|", s):
        return "single"
    if "| stats " in s and " by " in s:
        return "bar"
    return "table"


def _infer_expected_outcome(technique, playbook) -> str:
    if playbook.execution_mode == "SIMULATED":
        return "SIMULATED"
    if technique.technique_id in ("AML.T0072", "AML.T0074"):
        return "VARIES"
    if technique.technique_id == "AML.T0038" or (playbook.scenario_week == 9):
        return "INJECTED"
    if technique.acme_output_guard_action == "HARD_DENY":
        return "BLOCKED"
    if technique.technique_id in ("AML.T0050", "AML.T0015", "AML.T0054", "AML.T0051"):
        return "BLOCKED"
    if playbook.execution_mode == "HYBRID":
        return "VARIES"
    if playbook.is_top_10 and playbook.scenario_week in (3, 5, 6):
        return "BLOCKED"
    return "VARIES"


def _triage_runbook(technique, playbook) -> str:
    steps = []
    if technique.acme_output_guard_action:
        steps.append(
            f"1. Check `acme_output_guard_action` / `acme_output_guard_blocked` — "
            f"expect `{technique.acme_output_guard_action}` when output-side control fires."
        )
    else:
        steps.append(
            "1. Check `acme_input_guard_blocked` and `workflow.blocked` — confirm which control layer engaged."
        )
    steps.append(
        "2. Pivot on `incident_id` and `agent.id` — look for multi-stage correlation in Kill-Chain Timeline."
    )
    if technique.detection_signal:
        steps.append(
            f"3. Validate detection signal `{technique.detection_signal}` in raw events."
        )
    steps.append(
        f"4. Map to frameworks: OWASP {', '.join(technique.owasp_llm) or 'N/A'}; "
        f"severity {technique.severity} (CVSS {technique.cvss_score})."
    )
    steps.append(
        "5. Escalate if Critical severity repeats for the same agent within 1 hour, "
        "or if `incident_id` ties to an active kill-chain."
    )
    if playbook.execution_mode == "SIMULATED":
        steps.append(
            "6. SIMULATED mode — no live LLM harm; confirm hunt fields populated for compliance matrix."
        )
    return " ".join(steps)


def _instructions(technique, playbook) -> str:
    week = f"Scenario {playbook.scenario_week}" if playbook.scenario_week else "All 51 Techniques tab"
    return _csv_escape(
        f"**Objective:** Practice detecting {technique.technique_name} ({technique.technique_id}).\n\n"
        f"**Lab path:** Attack Panel → {week} → EXECUTE (mode: {playbook.execution_mode}).\n\n"
        f"**Before you run SPL:** Predict BLOCKED vs INJECTED (or SIMULATED for hunt-only techniques).\n\n"
        f"**Story:** {playbook.rogue_actor_story}\n\n"
        f"**Risk:** {playbook.risk_statement}"
    )


def _framework_mapping(technique) -> str:
    owasp = ", ".join(technique.owasp_llm) or "N/A"
    asi = ", ".join(technique.owasp_asi) or "N/A"
    nist = ", ".join(technique.nist_ai_rmf) or "N/A"
    maestro = ", ".join(technique.maestro_layers) or "N/A"
    return (
        f"MITRE ATLAS: {technique.technique_id} — {technique.technique_name} "
        f"({technique.tactic_name} / {technique.kill_chain_stage}) | "
        f"OWASP LLM: {owasp} | OWASP ASI: {asi} | NIST AI RMF: {nist} | MAESTRO: {maestro}"
    )


def _mitigation_text(technique) -> str:
    if technique.mitigations:
        return " | ".join(technique.mitigations[:4])
    return "Review agent tool scope, memory policy, HITL gates, and output-side validation per ACME architecture."


def _spl_query(playbook) -> str:
    spl = playbook.threat_hunt_spl.strip()
    if "earliest=" not in spl:
        spl = spl.replace("`acme_genai_index`", "`acme_genai_index` earliest=-30m latest=now", 1)
    return spl


def _explanation(technique, playbook) -> str:
    return _csv_escape(
        f"{technique.description}\n\n"
        f"**Impact:** {technique.impact}\n\n"
        f"**Execution mode in lab:** {playbook.execution_mode}. "
        f"{'This is a SIMULATED/breadth technique — focus on hunt fields, not live model behavior.' if playbook.execution_mode == 'SIMULATED' else ''}"
        f"{' HYBRID emits both live and simulated telemetry legs.' if playbook.execution_mode == 'HYBRID' else ''}\n\n"
        f"**Honest limitation:** Small-model (llama3.2:1b) responses may vary run-to-run; "
        f"use control telemetry (`acme_output_guard_blocked`, `acme_input_guard_blocked`, `workflow.blocked`) "
        f"as ground truth, not model wording alone."
    )


def export_exercise_content() -> Path:
    playbooks = {p.technique_id: p for p in get_all_playbooks()}
    rows = []
    for entry in TECHNIQUE_REGISTRY:
        pb = playbooks.get(entry.technique_id)
        if not pb:
            continue
        spl = _spl_query(pb)
        rows.append({
            "technique_id": entry.technique_id,
            "learning_tier": str(entry.learning_tier),
            "title": f"{entry.technique_id}: {entry.technique_name}",
            "instructions_text": _instructions(entry, pb),
            "spl_query": spl,
            "chart_type": _infer_chart_type(spl),
            "explanation_text": _explanation(entry, pb),
            "framework_mapping": _framework_mapping(entry),
            "mitigation_text": _mitigation_text(entry),
            "execution_mode": pb.execution_mode,
            "triage_runbook_text": _triage_runbook(entry, pb),
            "expected_outcome": _infer_expected_outcome(entry, pb),
        })

    LOOKUP_DIR.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)

    if not PROGRESS.is_file():
        with PROGRESS.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["learner_id", "technique_id", "run_at", "explanation_revealed"],
            )
            writer.writeheader()

    return OUT


def main() -> None:
    path = export_exercise_content()
    with OUT.open(encoding="utf-8") as fh:
        count = sum(1 for _ in csv.DictReader(fh))
    emerging = len(EMERGING_TECHNIQUE_IDS)
    print(f"Wrote {path} ({count} techniques, includes {emerging} emerging)")
    print(f"Progress template: {PROGRESS}")


if __name__ == "__main__":
    main()
