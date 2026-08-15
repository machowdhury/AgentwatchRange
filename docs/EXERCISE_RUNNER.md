# Exercise Runner — Guided Splunk Practice

**Dashboard:** GenAI Compliance Monitor → **Exercise Runner** (second nav item)

Dashboard Studio view with **seven tier tabs** (Tier 0–6) and **notebook-style cells** for Tier 1–4 techniques. Content is generated from `exercise_content.csv` via `scripts/sync_exercise_runner_dashboard.py`.

## Workflow

### Tab-per-tier navigation

| Tab | Content |
|-----|---------|
| **Tier 0 — Orientation** | Onboarding walkthrough + runnable baseline telemetry golden-path SPL (no graded techniques) |
| **Tier 1 — Beginner** | 2 technique cells |
| **Tier 2 — Intermediate** | 3 technique cells |
| **Tier 3 — Advanced** | 19 technique cells |
| **Tier 4 — Coverage & Compliance** | 27 technique cells |
| **Tier 5 — Vendor Tooling** | Cisco overlay steps + comparison cells for Tier 1–2 examples |
| **Tier 6 — Capstone** | MAESTRO, build-your-own detection prompt, workshop finale links |

Open the tab matching your curriculum tier — no global tier dropdown.

### Notebook cell interaction (Tiers 1–4)

Each technique is a **scrollable cell** in its tier tab:

1. **Header** — technique ID, title, instructions (from `exercise_content.csv`).
2. **Predict** — choose BLOCKED / INJECTED / SIMULATED / VARIES / Not sure (per cell).
3. **▶ Run this cell** — sets the cell's run token; click dashboard **Submit** to execute SPL.
4. **Results** — table (and bar/line chart when `chart_type` applies) appears directly below that cell.
5. **Triage runbook** — shown alongside results (primary SOC takeaway).
6. **Reveal explanation** — expands framework mapping and mitigations for that cell only.

Tier 3 and Tier 4 tabs are long by design — scroll like a notebook.

## Data sources

| Lookup | Purpose |
|--------|---------|
| `exercise_content.csv` | Instructions, SPL, chart type, runbook, expected outcome |
| `exercise_progress.csv` | Optional learner progress template (best-effort; not required) |

Regenerate after taxonomy or exercise content changes:

```bash
python3 scripts/sync_exercise_content.py
python3 scripts/sync_exercise_runner_dashboard.py
python3 scripts/package_splunk_app.sh
```

## Expected outcomes

| Value | Meaning |
|-------|---------|
| `BLOCKED` | Runtime control telemetry expected (AcmeGate / AcmeSentinel / workflow block) |
| `INJECTED` | Detect-only or successful injection path (e.g. Scenario 9 RAG) |
| `SIMULATED` | Hunt-only OTel — no live LLM block/inject semantics |
| `VARIES` | Honest label for non-deterministic small-model or config-dependent behavior |

Prediction comparison is **not graded** — it frames reasoning before seeing results.

## Limitations

- Requires **Dashboard Studio** (Splunk Enterprise 8.2+ / Splunk Cloud compatible builds).
- Each cell requires **Run** then dashboard **Submit** (Dashboard Studio batch refresh model).
- Progress indicator uses **telemetry observed in the time window**, not a persisted KV store.
- `map`-based SPL execution inherits lookup query limits; keep hunt SPL bounded.
- Tier 5 comparison cells show Acme-side telemetry; Cisco overlay differences are documented in-tab, not auto-ingested.
- Existing dashboards (Threat Hunting, Coverage Matrix, etc.) are unchanged — bulk Tier 4 workflows still use those views.
