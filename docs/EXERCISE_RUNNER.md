# Exercise Runner — Guided Splunk Practice

**Dashboard:** GenAI Compliance Monitor → **Exercise Runner** (first nav item)

Phase 5 adds a Dashboard Studio view for single-technique guided practice across all **51** registry entries.

## Workflow

1. **Filter by tier** (1–3 for curriculum; 4 for coverage techniques).
2. **Select a technique** from the dropdown (populated from `exercise_content.csv`).
3. **Predict** BLOCKED / INJECTED / SIMULATED / Not sure — optional, does not block running SPL.
4. **Review instructions** and optional **custom SPL** override.
5. **Inspect results** table and conditional chart (bar or line when `chart_type` applies).
6. **Apply triage runbook** text alongside results (primary SOC takeaway).
7. **Reveal explanation** for framework mapping and mitigations (collapsed until button click).

## Data sources

| Lookup | Purpose |
|--------|---------|
| `exercise_content.csv` | Instructions, SPL, chart type, runbook, expected outcome |
| `exercise_progress.csv` | Optional learner progress template (best-effort; not required) |

Regenerate content after taxonomy changes:

```bash
python3 scripts/sync_exercise_content.py
python3 scripts/package_splunk_app.sh
```

## Expected outcomes

| Value | Meaning |
|-------|---------|
| `BLOCKED` | Runtime control telemetry expected (CodeGuard / DefenseClaw / workflow block) |
| `INJECTED` | Detect-only or successful injection path (e.g. Scenario 9 RAG) |
| `SIMULATED` | Hunt-only OTel — no live LLM block/inject semantics |
| `VARIES` | Honest label for non-deterministic small-model or config-dependent behavior |

Prediction comparison is **not graded** — it frames reasoning before seeing results.

## Limitations

- Requires **Dashboard Studio** (Splunk Enterprise 8.2+ / Splunk Cloud compatible builds).
- Progress indicator uses **telemetry observed in the time window**, not a persisted KV store.
- `map`-based SPL execution inherits lookup query limits; keep custom SPL edits bounded.
- Existing dashboards (Threat Hunting, Coverage Matrix, etc.) are unchanged — Tier 4+ workflows still use those views.
