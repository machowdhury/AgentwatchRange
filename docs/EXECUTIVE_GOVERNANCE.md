# Executive AI Governance Dashboard

Dashboard Studio view: **Executive AI Governance** (`executive_governance.json`) — the default landing page on Splunk 10+ for CISO, risk, and audit audiences in the **AgentWatch Range — GenAI Compliance** Splunk app. A Classic Simple XML fallback lives at `executive_governance_classic.xml` in the nav.

## What it shows

| Section | Metric / panel | Data source |
|---------|----------------|-------------|
| **11.1 KPIs** | Framework Readiness Score | `acme_framework_lookup` × `otel:agentic:json` technique coverage |
| | Regulatory Gap Metric | High/Critical severity events vs control-block rate |
| | AI Portfolio Risk Matrix | `acme:agentic:registry:json` joined with attack counts per agent |
| **11.2 Inventory** | Running vs shadow counts | Latest deduped registry snapshot in time window |
| | Agent registry table | `acme:agentic:registry:json` |
| **11.3 Guardrails** | Block timechart by technique | `acme_control_block` signals over time |
| | HITL governance table | `hitl_required`, `hitl_bypassed`, gate status |
| **11.4** | Global time picker | Applies to all panels via `$global_time$` tokens |
| **11.5** | Color semantics | Macro `` `acme_governance_status_colors` `` — compliant / needs-review / violation |
| **11.6** | Cross-links | Markdown header links to NIST RMF, Technique Coverage, Threat Hunting, Cross-App Normalization, Exercise Runner |

## Filters and honesty

- **No `makeresults`** — all panels query real indexes and lookups.
- **Baseline exclusion:** attack-oriented panels use `NOT testbed_mode=BASELINE_TRAFFIC` so benign continuous traffic does not inflate risk scores.
- **Registry vs events:** inventory reflects periodic snapshots from `GET /api/v1/registry/snapshot` (Phase 10.3), not inferred from OTel alone.

## EU AI Act column

`framework_compliance_crosswalk.csv` includes `eu_ai_act_risk_tier` (High-Risk / Limited) for sim cross-app mappings. Enriched on sim events via `` `acme_sim_crosswalk_enrich` ``.

## Validation SPL

After a campaign week (not baseline-only):

```spl
`acme_genai_index` earliest=-24h latest=now NOT testbed_mode=BASELINE_TRAFFIC
| stats dc(technique_id) as techniques count as events
```

Registry sanity:

```spl
`acme_registry_index` earliest=-24h latest=now
| stats count dc(agent_id) as agents dc(eval(if(agent_status="shadow",agent_id,null))) as shadow
```

## Related

- [LEARNING_PATH.md](LEARNING_PATH.md) — Tier 4 coverage points here for executive summaries
- [CONCEPTS.md](CONCEPTS.md) — baseline traffic and registry architecture
- [EXERCISE_RUNNER.md](EXERCISE_RUNNER.md) — practitioner drill-down from executive view
