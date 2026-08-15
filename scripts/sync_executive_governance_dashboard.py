#!/usr/bin/env python3
"""
Generate Executive AI Governance dashboard (Dashboard Studio JSON only).

- executive_governance.json — sole nav view (no Classic .xml twin; avoids name collision)

Run from repo root: python3 scripts/sync_executive_governance_dashboard.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / "splunk_app" / "splunk_compliance_app" / "default" / "data" / "ui" / "views"
OUT_JSON = VIEWS / "executive_governance.json"
# Removed dual-dashboard outputs (pre-18.1 name-collision workaround).
LEGACY_XML = VIEWS / "executive_governance.xml"
LEGACY_STUDIO = VIEWS / "executive_governance_studio.json"

W = 1440

QUERIES = {
    "readiness": (
        "| inputlookup acme_framework_lookup "
        "| stats count as total_techniques "
        "| appendcols [ search `acme_genai_index` technique_id=AML.* NOT testbed_mode=BASELINE_TRAFFIC "
        "| stats dc(technique_id) as techniques_observed ] "
        "| eval readiness_score=round(100*techniques_observed/total_techniques,1) "
        '| eval governance_status=case(readiness_score>=80,"compliant",readiness_score>=50,"needs-review",true(),"violation") '
    ),
    "regulatory": (
        'search `acme_genai_index` NOT testbed_mode=BASELINE_TRAFFIC severity IN ("Critical","High","critical","high") '
        "| stats count as high_severity_events "
        'sum(eval(if(acme_output_guard_blocked=true OR acme_input_guard_blocked=true OR workflow.blocked=true '
        'OR mcp.gateway.action="BLOCK" OR acme_output_guard_action IN ("HARD_DENY","QUARANTINE") '
        'OR (hitl_required=true AND hitl_bypassed=false),1,0))) as blocked_events '
        "| eval control_efficacy=if(high_severity_events>0, round(100*blocked_events/high_severity_events,1), 100) "
        "| eval regulatory_gap=round(100-control_efficacy,1) "
        '| eval governance_status=case(regulatory_gap<=20,"compliant",regulatory_gap<=50,"needs-review",true(),"violation") '
    ),
    "portfolio": (
        "search `acme_registry_index` "
        "| sort - _time | dedup agent_id | eval registry_key=agent_id "
        "| join type=left registry_key [ search `acme_genai_index` NOT testbed_mode=BASELINE_TRAFFIC "
        "| stats count as attack_events dc(technique_id) as distinct_techniques values(severity) as severities by gen_ai_agent_id "
        "| rename gen_ai_agent_id as registry_key ] "
        "| eval attack_events=coalesce(attack_events,0) | eval distinct_techniques=coalesce(distinct_techniques,0) "
        '| eval risk_band=case(agent_status="shadow" OR trust_score<0.5,"violation",attack_events>15 OR distinct_techniques>8,"needs-review",true(),"compliant") '
        "| table agent_id agent_name agent_status trust_score owning_department attack_events distinct_techniques risk_band "
        "| sort - attack_events - trust_score"
    ),
    "agent_counts": (
        "search `acme_registry_index` | sort - _time | dedup agent_id "
        '| stats count(eval(agent_status="running")) as running_agents count(eval(agent_status="shadow")) as shadow_agents count as agents_in_latest_snapshot'
    ),
    "agent_registry": (
        "search `acme_registry_index` | sort - _time | dedup agent_id "
        "| table _time agent_id agent_name agent_status model_origin owning_department mcp_scope trust_score trust_boundary agent_role "
        "| sort agent_status agent_id"
    ),
    "guardrail": (
        "search `acme_genai_index` NOT testbed_mode=BASELINE_TRAFFIC "
        '(acme_output_guard_blocked=true OR acme_input_guard_blocked=true OR workflow.blocked=true '
        'OR mcp.gateway.action=BLOCK OR acme_output_guard_action IN ("HARD_DENY","QUARANTINE")) '
        "| timechart span=1h count by technique_id limit=8 useother=f"
    ),
    "hitl": (
        "search `acme_genai_index` NOT testbed_mode=BASELINE_TRAFFIC (hitl_required=true OR hitl_bypassed=true) "
        "| sort - _time | table _time gen_ai_agent_id technique_id hitl_required hitl_bypassed hitl.gate_enabled loan_amount_usd incident_id "
        "| head 25"
    ),
    "eu_ai_act": (
        "| inputlookup framework_compliance_crosswalk | stats count by eu_ai_act_risk_tier severity | sort - count"
    ),
}


def _ds(name: str, query: str) -> dict:
    return {"type": "ds.search", "name": name, "options": {"query": query}}


def build_studio_json() -> dict:
    data_sources = {
        "ds_readiness": _ds("ds_readiness", QUERIES["readiness"] + "| table readiness_score governance_status techniques_observed total_techniques"),
        "ds_regulatory_gap": _ds("ds_regulatory_gap", QUERIES["regulatory"] + "| table regulatory_gap governance_status control_efficacy high_severity_events blocked_events"),
        "ds_portfolio_risk": _ds("ds_portfolio_risk", QUERIES["portfolio"]),
        "ds_agent_counts": _ds("ds_agent_counts", QUERIES["agent_counts"]),
        "ds_agent_registry": _ds("ds_agent_registry", QUERIES["agent_registry"]),
        "ds_guardrail_timechart": _ds("ds_guardrail_timechart", QUERIES["guardrail"]),
        "ds_hitl_table": _ds("ds_hitl_table", QUERIES["hitl"]),
        "ds_eu_ai_act": _ds("ds_eu_ai_act", QUERIES["eu_ai_act"]),
    }
    structure = [
        {"item": "viz_header", "type": "block", "position": {"x": 0, "y": 0, "w": W, "h": 200}},
        {"item": "viz_readiness", "type": "block", "position": {"x": 0, "y": 210, "w": 350, "h": 120}},
        {"item": "viz_readiness_detail", "type": "block", "position": {"x": 360, "y": 210, "w": 320, "h": 120}},
        {"item": "viz_regulatory_gap", "type": "block", "position": {"x": 700, "y": 210, "w": 350, "h": 120}},
        {"item": "viz_regulatory_detail", "type": "block", "position": {"x": 1060, "y": 210, "w": 380, "h": 120}},
        {"item": "viz_portfolio", "type": "block", "position": {"x": 0, "y": 340, "w": W, "h": 260}},
        {"item": "viz_agent_counts", "type": "block", "position": {"x": 0, "y": 610, "w": 420, "h": 100}},
        {"item": "viz_agent_registry", "type": "block", "position": {"x": 440, "y": 610, "w": 1000, "h": 220}},
        {"item": "viz_guardrail_chart", "type": "block", "position": {"x": 0, "y": 840, "w": 900, "h": 280}},
        {"item": "viz_eu_ai_act", "type": "block", "position": {"x": 920, "y": 840, "w": 520, "h": 280}},
        {"item": "viz_hitl", "type": "block", "position": {"x": 0, "y": 1130, "w": W, "h": 320}},
    ]
    return {
        "title": "Executive AI Governance",
        "description": "CISO and auditor front door — framework readiness, regulatory control gap, portfolio risk, agent inventory, and guardrail efficacy.",
        "inputs": {
            "input_time": {
                "type": "input.timerange",
                "title": "Time Range",
                "options": {"token": "global_time", "defaultValue": "-24h,now"},
            }
        },
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
        "visualizations": {
            "viz_header": {
                "type": "splunk.markdown",
                "options": {
                    "markdown": "### Executive AI Governance — AgentWatch Range\n\nCISO and auditor front door — framework readiness, regulatory control gap, portfolio risk, agent inventory, and guardrail efficacy.\n\n**Drill-down:** [NIST AI RMF](/app/acme_genai_compliance/nist_rmf_compliance) · [Exercise Runner](/app/acme_genai_compliance/exercise_runner)"
                },
            },
            "viz_readiness": {
                "type": "splunk.singlevalue",
                "title": "Framework Readiness Score",
                "dataSources": {"primary": "ds_readiness"},
                "options": {"field": "readiness_score", "unit": "%", "unitPosition": "after"},
            },
            "viz_readiness_detail": {
                "type": "splunk.table",
                "title": "Readiness breakdown",
                "dataSources": {"primary": "ds_readiness"},
            },
            "viz_regulatory_gap": {
                "type": "splunk.singlevalue",
                "title": "Regulatory Gap Metric",
                "dataSources": {"primary": "ds_regulatory_gap"},
                "options": {"field": "regulatory_gap", "unit": "%", "unitPosition": "after"},
            },
            "viz_regulatory_detail": {
                "type": "splunk.table",
                "title": "Control efficacy",
                "dataSources": {"primary": "ds_regulatory_gap"},
            },
            "viz_portfolio": {
                "type": "splunk.table",
                "title": "AI Portfolio Risk Matrix",
                "dataSources": {"primary": "ds_portfolio_risk"},
                "options": {"count": 15, "wrap": True},
            },
            "viz_agent_counts": {
                "type": "splunk.table",
                "title": "Agent inventory",
                "dataSources": {"primary": "ds_agent_counts"},
            },
            "viz_agent_registry": {
                "type": "splunk.table",
                "title": "Registered agents",
                "dataSources": {"primary": "ds_agent_registry"},
                "options": {"count": 10, "wrap": True},
            },
            "viz_guardrail_chart": {
                "type": "viz.line",
                "title": "Guardrail blocks over time",
                "dataSources": {"primary": "ds_guardrail_timechart"},
            },
            "viz_eu_ai_act": {
                "type": "splunk.table",
                "title": "EU AI Act crosswalk",
                "dataSources": {"primary": "ds_eu_ai_act"},
            },
            "viz_hitl": {
                "type": "splunk.table",
                "title": "HITL governance events",
                "dataSources": {"primary": "ds_hitl_table"},
                "options": {"count": 25, "wrap": True},
            },
        },
        "layout": {
            "type": "absolute",
            "globalInputs": ["input_time"],
            "options": {
                "submitButton": True,
                "submitOnDashboardLoad": True,
                "display": "auto-scale",
                "width": W,
                "height": 2100,
            },
            "structure": structure,
        },
    }


def main() -> None:
    VIEWS.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(build_studio_json(), indent=2) + "\n", encoding="utf-8")
    for legacy in (LEGACY_XML, LEGACY_STUDIO):
        if legacy.is_file():
            legacy.unlink()
            print(f"Removed legacy {legacy.name}")
    json.loads(OUT_JSON.read_text(encoding="utf-8"))
    print(f"Wrote {OUT_JSON.name} (Dashboard Studio — nav default executive_governance)")


if __name__ == "__main__":
    main()
