#!/usr/bin/env python3
"""
Generate Dashboard Studio exercise_runner.json from exercise_content.csv.

Run from repo root: python3 scripts/sync_exercise_runner_dashboard.py

Regenerated during package_splunk_app.sh — edit this script, not the JSON directly.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from splunk_studio_xml import wrap_studio_dashboard_xml
CSV_PATH = ROOT / "splunk_app" / "splunk_compliance_app" / "lookups" / "exercise_content.csv"
OUT_PATH = (
    ROOT / "splunk_app" / "splunk_compliance_app" / "default" / "data" / "ui" / "views" / "exercise_runner.xml"
)
LEGACY_JSON_PATH = OUT_PATH.with_suffix(".json")

CELL_WIDTH = 1440
MARKDOWN_H = 170
INPUT_H = 70
BUTTON_H = 60
PRED_H = 110
RESULTS_H = 300
TRIAGE_H = 160
CHART_H = 260
REVEAL_H = 60
EXPL_H = 240
CELL_GAP = 20

TIER_TABS = [
    ("layout_tier0", "Tier 0 — Orientation"),
    ("layout_tier1", "Tier 1 — Beginner"),
    ("layout_tier2", "Tier 2 — Intermediate"),
    ("layout_tier3", "Tier 3 — Advanced"),
    ("layout_tier4", "Tier 4 — Coverage & Compliance"),
    ("layout_tier5", "Tier 5 — Vendor-Realistic Tooling"),
    ("layout_tier6", "Tier 6 — Capstone / Blue Team"),
]


def _layout_item(item: str, y: int, h: int) -> dict:
    """Canvas inputs must use type=input; visualizations use type=block (Splunk DS)."""
    return {
        "item": item,
        "type": "input" if item.startswith("input_") else "block",
        "position": {"x": 0, "y": y, "w": CELL_WIDTH, "h": h},
    }


def _button_input(label: str, token: str, *, value: str = "1") -> dict:
    """
    Dashboard Studio input.button (Splunk 10.2 builder schema).

    Verified shape: options.label for visible text; drilldown.setToken on click.
    Buttons do NOT use options.items (that is input.dropdown — causes generic "BUTTON" UI).
    """
    return {
        "type": "input.button",
        "options": {"label": label},
        "eventHandlers": [
            {
                "type": "drilldown.setToken",
                "options": {"tokens": [{"token": token, "value": value}]},
            }
        ],
    }


def _token(technique_id: str) -> str:
    return technique_id.replace(".", "_")


def _load_rows() -> List[dict]:
    with CSV_PATH.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _esc_spl(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _prediction_query(technique_id: str, token: str) -> str:
    tid = _esc_spl(technique_id)
    return (
        f'| inputlookup exercise_content | search technique_id="{tid}" | head 1 '
        f'| eval feedback=case('
        f'expected_outcome="VARIES", "You predicted " + "${token}$" + ". This technique is honestly VARIES in the lab.", '
        f'"${token}$"="NOT_SURE", "No prediction — typical expected outcome: " + expected_outcome + ".", '
        f'"${token}$"=expected_outcome, "You predicted " + "${token}$" + " — aligns with " + expected_outcome + ".", '
        f'true(), "You predicted " + "${token}$" + "; typical outcome is " + expected_outcome + ". Compare control fields in results.") '
        f"| table feedback"
    )


def _results_query(technique_id: str, run_token: str, *, chart_suffix: str = "") -> str:
    tid = _esc_spl(technique_id)
    base = (
        f'| inputlookup exercise_content | search technique_id="{tid}" | head 1 '
        f'| eval _run="${run_token}$" '
        f'| where _run=1 OR _run="1" '
        f"| eval effective_spl=spl_query "
        f"| fields effective_spl "
        f'| map maxsearches=1 search="$effective_spl$"'
    )
    if chart_suffix == "bar":
        return base + " | stats count by gen_ai_agent_id | sort - count | head 10"
    if chart_suffix == "line":
        return base + " | timechart span=5m count"
    return base


def _add_technique_cell(
    *,
    row: dict,
    y: int,
    inputs: Dict[str, Any],
    data_sources: Dict[str, Any],
    visualizations: Dict[str, Any],
    conditions: Dict[str, Any],
    structure: List[dict],
) -> int:
    tid = row["technique_id"]
    tok = _token(tid)
    pred_token = f"pred_{tok}"
    run_token = f"run_{tok}"
    reveal_token = f"reveal_{tok}"

    title = row["title"]
    instructions = row["instructions_text"].replace("\n", "\n\n")[:1200]
    chart_type = row.get("chart_type", "table")

    inputs[f"input_pred_{tok}"] = {
        "type": "input.dropdown",
        "title": f"{tid} — Before you run, predict:",
        "options": {
            "token": pred_token,
            "defaultValue": "NOT_SURE",
            "items": [
                {"label": "Not sure — run it", "value": "NOT_SURE"},
                {"label": "BLOCKED", "value": "BLOCKED"},
                {"label": "INJECTED", "value": "INJECTED"},
                {"label": "SIMULATED (hunt-only)", "value": "SIMULATED"},
                {"label": "VARIES", "value": "VARIES"},
            ],
        },
    }
    inputs[f"input_run_{tok}"] = _button_input("▶ Run this cell", run_token)
    inputs[f"input_reveal_{tok}"] = _button_input("Reveal explanation", reveal_token)

    data_sources[f"ds_pred_{tok}"] = {
        "type": "ds.search",
        "name": f"Prediction {tid}",
        "options": {"query": _prediction_query(tid, pred_token)},
    }
    data_sources[f"ds_results_{tok}"] = {
        "type": "ds.search",
        "name": f"Results {tid}",
        "options": {"query": _results_query(tid, run_token)},
    }
    data_sources[f"ds_triage_{tok}"] = {
        "type": "ds.search",
        "name": f"Triage {tid}",
        "options": {
            "query": (
                f'| inputlookup exercise_content | search technique_id="{_esc_spl(tid)}" | head 1 '
                f"| table triage_runbook_text"
            )
        },
    }
    data_sources[f"ds_expl_{tok}"] = {
        "type": "ds.search",
        "name": f"Explanation {tid}",
        "options": {
            "query": (
                f'| inputlookup exercise_content | search technique_id="{_esc_spl(tid)}" | head 1 '
                f"| table explanation_text, framework_mapping, mitigation_text"
            )
        },
    }

    visualizations[f"viz_hdr_{tok}"] = {
        "type": "splunk.markdown",
        "title": title,
        "options": {
            "markdown": (
                f"### {title}\n\n"
                f"**Expected outcome:** `{row['expected_outcome']}` · **Mode:** `{row['execution_mode']}`\n\n"
                f"{instructions}"
            )
        },
    }
    visualizations[f"viz_pred_{tok}"] = {
        "type": "splunk.singlevalue",
        "title": "Prediction vs expected outcome",
        "dataSources": {"primary": f"ds_pred_{tok}"},
        "options": {"field": "feedback"},
    }
    visualizations[f"viz_results_{tok}"] = {
        "type": "splunk.table",
        "title": "Results (click Run, then Submit)",
        "dataSources": {"primary": f"ds_results_{tok}"},
        "options": {"count": 20, "wrap": True},
    }
    visualizations[f"viz_triage_{tok}"] = {
        "type": "splunk.table",
        "title": "Triage runbook — apply now",
        "dataSources": {"primary": f"ds_triage_{tok}"},
        "options": {"count": 5, "wrap": True},
    }
    visualizations[f"viz_expl_{tok}"] = {
        "type": "splunk.table",
        "title": "Explanation · Framework mapping · Mitigations",
        "dataSources": {"primary": f"ds_expl_{tok}"},
        "options": {"count": 10, "wrap": True},
        "containerOptions": {
            "visibility": {"conditions": [f"cond_reveal_{tok}"]}
        },
    }

    conditions[f"cond_reveal_{tok}"] = {
        "name": f"Explanation revealed {tid}",
        "value": f"${reveal_token}$=1",
    }

    blocks = [
        (f"viz_hdr_{tok}", MARKDOWN_H),
        (f"input_pred_{tok}", INPUT_H),
        (f"input_run_{tok}", BUTTON_H),
        (f"viz_pred_{tok}", PRED_H),
        (f"viz_results_{tok}", RESULTS_H),
        (f"viz_triage_{tok}", TRIAGE_H),
    ]

    if chart_type == "bar":
        data_sources[f"ds_chart_{tok}"] = {
            "type": "ds.search",
            "name": f"Chart bar {tid}",
            "options": {"query": _results_query(tid, run_token, chart_suffix="bar")},
        }
        visualizations[f"viz_chart_{tok}"] = {
            "type": "viz.column",
            "title": "Visualization (bar)",
            "dataSources": {"primary": f"ds_chart_{tok}"},
        }
        blocks.append((f"viz_chart_{tok}", CHART_H))
    elif chart_type == "line":
        data_sources[f"ds_chart_{tok}"] = {
            "type": "ds.search",
            "name": f"Chart line {tid}",
            "options": {"query": _results_query(tid, run_token, chart_suffix="line")},
        }
        visualizations[f"viz_chart_{tok}"] = {
            "type": "viz.line",
            "title": "Visualization (timechart)",
            "dataSources": {"primary": f"ds_chart_{tok}"},
        }
        blocks.append((f"viz_chart_{tok}", CHART_H))

    blocks.extend([
        (f"input_reveal_{tok}", REVEAL_H),
        (f"viz_expl_{tok}", EXPL_H),
    ])

    for item, height in blocks:
        structure.append(_layout_item(item, y, height))
        y += height + CELL_GAP

    return y


def _tier0_layout(
    inputs: Dict[str, Any],
    data_sources: Dict[str, Any],
    visualizations: Dict[str, Any],
) -> Tuple[List[dict], int]:
    structure: List[dict] = []
    visualizations["viz_tier0_intro"] = {
        "type": "splunk.markdown",
        "title": "Tier 0 — Orientation",
        "options": {
            "markdown": (
                "### Tier 0 — Orientation (no attacks)\n\n"
                "**Goal:** Understand the defend path before breaking anything.\n\n"
                "1. Read [CONCEPTS.md](https://github.com/machowdhury/AgentwatchRange/blob/main/docs/CONCEPTS.md) — architecture, transparency, limitations\n"
                "2. Submit one **legitimate loan request** on the banking app (`:5000`)\n"
                "3. Run the **baseline telemetry** cell below and confirm events appear\n\n"
                "**Exit criteria:** You can explain intake → LLM → controls → OTel → Splunk without running an attack."
            )
        },
    }
    data_sources["ds_tier0_baseline"] = {
        "type": "ds.search",
        "name": "Tier 0 baseline telemetry",
        "options": {
            "query": (
                'index=acme_agentic_telemetry sourcetype="otel:agentic:json" '
                "earliest=$global_time.earliest$ latest=$global_time.latest$ "
                "| stats count by campaign_week"
            )
        },
    }
    visualizations["viz_tier0_baseline"] = {
        "type": "splunk.table",
        "title": "Baseline telemetry — golden path",
        "dataSources": {"primary": "ds_tier0_baseline"},
        "options": {"count": 10},
    }
    inputs["input_run_tier0"] = _button_input("▶ Run baseline SPL", "run_tier0")
    y = 0
    for item, h in [
        ("viz_tier0_intro", 320),
        ("input_run_tier0", BUTTON_H),
        ("viz_tier0_baseline", 220),
    ]:
        structure.append(_layout_item(item, y, h))
        y += h + CELL_GAP
    return structure, y


def _tier5_layout(
    inputs: Dict[str, Any],
    data_sources: Dict[str, Any],
    visualizations: Dict[str, Any],
) -> Tuple[List[dict], int]:
    structure: List[dict] = []
    visualizations["viz_tier5_intro"] = {
        "type": "splunk.markdown",
        "title": "Tier 5 — Vendor-realistic tooling",
        "options": {
            "markdown": (
                "### Tier 5 — Vendor-realistic tooling (Cisco overlay)\n\n"
                "**Prerequisite:** Tiers 1–3 complete.\n\n"
                "Re-run a subset of attacks with Cisco AI Defense scanners and MLTK anomaly views:\n\n"
                "```\n"
                "docker compose -f docker-compose.yml -f docker-compose.cisco.yml --profile local up -d\n"
                "```\n\n"
                "**Workshop path:** Scenario 1 → 6 → 7 → 9, then open **MLTK Anomaly Hunting** dashboard.\n\n"
                "**Comparison below:** AcmeGate/AcmeSentinel telemetry for two Tier 1–2 techniques — re-run the same attack under the Cisco overlay and compare control fields."
            )
        },
    }
    for label, tid in [("Tier 1 example (AML.T0015)", "AML.T0015"), ("Tier 2 example (AML.T0050)", "AML.T0050")]:
        tok = _token(tid)
        run_token = f"run_t5_{tok}"
        inputs[f"input_run_t5_{tok}"] = _button_input(f"▶ Run {tid}", run_token)
        data_sources[f"ds_t5_{tok}"] = {
            "type": "ds.search",
            "name": f"Tier 5 comparison {tid}",
            "options": {
                "query": (
                    f'| inputlookup exercise_content | search technique_id="{tid}" | head 1 '
                    f'| eval _run="${run_token}$" | where _run=1 OR _run="1" '
                    f"| eval effective_spl=spl_query | fields effective_spl "
                    f'| map maxsearches=1 search="$effective_spl$" '
                    f"| stats count values(acme_output_guard_action) as guard_action "
                    f"values(acme_output_guard_blocked) as blocked values(workflow.blocked) as workflow_blocked "
                    f"by technique_id"
                )
            },
        }
        visualizations[f"viz_t5_{tok}"] = {
            "type": "splunk.table",
            "title": label,
            "dataSources": {"primary": f"ds_t5_{tok}"},
            "options": {"count": 5, "wrap": True},
        }

    y = 0
    structure.append(_layout_item("viz_tier5_intro", y, 360))
    y += 380
    for tid in ["AML.T0015", "AML.T0050"]:
        tok = _token(tid)
        for item, h in [(f"input_run_t5_{tok}", BUTTON_H), (f"viz_t5_{tok}", 180)]:
            structure.append(_layout_item(item, y, h))
            y += h + CELL_GAP
    return structure, y


def _tier6_layout(visualizations: Dict[str, Any]) -> Tuple[List[dict], int]:
    visualizations["viz_tier6_intro"] = {
        "type": "splunk.markdown",
        "title": "Tier 6 — Capstone / Blue Team",
        "options": {
            "markdown": (
                "### Tier 6 — Capstone / Blue Team\n\n"
                "**Prerequisite:** Tiers 1–5 (or skip Tier 5 if Cisco overlay unavailable).\n\n"
                "| Activity | Resource |\n"
                "|----------|----------|\n"
                "| MAESTRO threat-model-first workflow | [MAESTRO_WORKSHOP.md](https://github.com/machowdhury/AgentwatchRange/blob/main/docs/MAESTRO_WORKSHOP.md) |\n"
                "| Build-your-own detection for one Phase 1 emerging technique | [WORKSHOP.md](https://github.com/machowdhury/AgentwatchRange/blob/main/docs/WORKSHOP.md) Q504+ |\n"
                "| Guided finale | Workshop paths: 15-min → Standard → Deep → Fire All 10 → MAESTRO |\n\n"
                "**Capstone prompt:** Pick one of **AML.T0070–T0075**, write a detection rule using `norm_*` or raw OTel fields, "
                "validate it in **Threat Hunting**, and document false-positive handling in your runbook."
            )
        },
    }
    structure = [_layout_item("viz_tier6_intro", 0, 420)]
    return structure, 440


def build_dashboard() -> dict:
    rows = _load_rows()
    by_tier: Dict[int, List[dict]] = defaultdict(list)
    for row in rows:
        by_tier[int(row["learning_tier"])].append(row)
    for tier_rows in by_tier.values():
        tier_rows.sort(key=lambda r: r["technique_id"])

    inputs: Dict[str, Any] = {
        "input_time": {
            "type": "input.timerange",
            "title": "Time Range",
            "options": {"token": "global_time", "defaultValue": "-30m,now"},
        },
        "input_learner": {
            "type": "input.text",
            "title": "Learner ID (optional)",
            "options": {"token": "learner_id", "defaultValue": "anonymous"},
        },
    }
    data_sources: Dict[str, Any] = {}
    visualizations: Dict[str, Any] = {}
    conditions: Dict[str, Any] = {}
    layout_definitions: Dict[str, Any] = {}

    # Tier progress data sources (tiers 1–4)
    for tier in (1, 2, 3, 4):
        data_sources[f"ds_tier{tier}_progress"] = {
            "type": "ds.search",
            "name": f"Tier {tier} progress",
            "options": {
                "query": (
                    f"| inputlookup exercise_content | search learning_tier={tier} "
                    f"| stats count as tier_total "
                    f"| appendcols [ search index=acme_agentic_telemetry sourcetype=\"otel:agentic:json\" "
                    f"earliest=$global_time.earliest$ latest=$global_time.latest$ technique_id=AML.* "
                    f"| lookup exercise_content technique_id OUTPUT learning_tier "
                    f"| search learning_tier={tier} | stats dc(technique_id) as tier_observed ] "
                    f"| eval tier_observed=coalesce(tier_observed,0) "
                    f"| eval progress=round(100*tier_observed/tier_total,1) "
                    f"| table tier_observed tier_total progress"
                )
            },
        }

    # Tier 0
    t0_structure, t0_h = _tier0_layout(inputs, data_sources, visualizations)
    layout_definitions["layout_tier0"] = {
        "type": "absolute",
        "options": {"display": "auto-scale", "width": CELL_WIDTH, "height": max(t0_h, 600)},
        "structure": t0_structure,
    }

    # Tiers 1-4 — notebook cells
    for tier in (1, 2, 3, 4):
        structure: List[dict] = []
        y = 0
        tok = f"tier{tier}"
        visualizations[f"viz_{tok}_progress"] = {
            "type": "splunk.table",
            "title": f"Tier {tier} — techniques with telemetry in window",
            "dataSources": {"primary": f"ds_tier{tier}_progress"},
            "options": {"count": 5},
        }
        structure.append(_layout_item(f"viz_{tok}_progress", y, 100))
        y += 120
        for row in by_tier.get(tier, []):
            y = _add_technique_cell(
                row=row,
                y=y,
                inputs=inputs,
                data_sources=data_sources,
                visualizations=visualizations,
                conditions=conditions,
                structure=structure,
            )
        layout_definitions[f"layout_tier{tier}"] = {
            "type": "absolute",
            "options": {"display": "auto-scale", "width": CELL_WIDTH, "height": max(y + 200, 800)},
            "structure": structure,
        }

    # Tier 5 & 6
    t5_structure, t5_h = _tier5_layout(inputs, data_sources, visualizations)
    layout_definitions["layout_tier5"] = {
        "type": "absolute",
        "options": {"display": "auto-scale", "width": CELL_WIDTH, "height": max(t5_h, 700)},
        "structure": t5_structure,
    }
    t6_structure, t6_h = _tier6_layout(visualizations)
    layout_definitions["layout_tier6"] = {
        "type": "absolute",
        "options": {"display": "auto-scale", "width": CELL_WIDTH, "height": max(t6_h, 500)},
        "structure": t6_structure,
    }

    return {
        "title": "Exercise Runner",
        "description": (
            "Tab-per-tier notebook-style guided practice. Each Tier 1–4 cell: predict, run hunt SPL, "
            "triage, then reveal explanation. Data-driven from exercise_content.csv."
        ),
        "inputs": inputs,
        "defaults": {
            "dataSources": {
                "ds.search": {
                    "options": {
                        "queryParameters": {
                            "earliest": "$global_time.earliest$",
                            "latest": "$global_time.latest$",
                        }
                    }
                }
            }
        },
        "dataSources": data_sources,
        "visualizations": visualizations,
        "expressions": {"conditions": conditions},
        "layout": {
            "options": {
                "submitButton": True,
                "submitOnDashboardLoad": False,
                "showTitleAndDescription": True,
            },
            "globalInputs": ["input_time", "input_learner"],
            "tabs": {
                "items": [
                    {"layoutId": layout_id, "label": label}
                    for layout_id, label in TIER_TABS
                ],
                "options": {"barPosition": "top", "showTabBar": True},
            },
            "layoutDefinitions": layout_definitions,
        },
    }


def main() -> None:
    if not CSV_PATH.is_file():
        raise SystemExit(f"Missing {CSV_PATH} — run scripts/sync_exercise_content.py first")
    dashboard = build_dashboard()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        wrap_studio_dashboard_xml(dashboard["title"], dashboard["description"], dashboard),
        encoding="utf-8",
    )
    if LEGACY_JSON_PATH.is_file():
        LEGACY_JSON_PATH.unlink()
        print(f"Removed legacy {LEGACY_JSON_PATH.name}")
    json.loads(json.dumps(dashboard))
    tier_counts = defaultdict(int)
    with CSV_PATH.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            tier_counts[int(row["learning_tier"])] += 1
    print(f"Wrote {OUT_PATH}")
    print(f"  Tabs: 7 | Tier technique counts: {dict(sorted(tier_counts.items()))}")
    print(f"  Visualizations: {len(dashboard['visualizations'])} | Data sources: {len(dashboard['dataSources'])}")


if __name__ == "__main__":
    main()
