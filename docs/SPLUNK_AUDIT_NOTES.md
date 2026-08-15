# Splunk Compliance App — Phase 3 Audit Notes

Audit date: 2026-08-15  
Scope: `splunk_app/splunk_compliance_app/` (saved searches, macros, dashboards, lookups)

## Summary

Phase 3 hardened detection logic, unified block/detect semantics across dashboards, added emerging-threat saved searches (AML.T0070–T0075), and improved practitioner-facing SOC views (gaps panel, three-state coverage matrix, kill-chain ordering, NIST attestation).

**Golden path SPL unchanged** — README Step 6 still uses:

```spl
index=acme_agentic_telemetry sourcetype="otel:agentic:json" earliest=-15m
| stats count by campaign_week
```

All app searches use the `acme_genai_index` macro (no hardcoded HEC tokens or index names in SPL bodies).

---

## A. Detection logic (`savedsearches.conf`)

### Findings

| Issue | Severity | Resolution |
|-------|----------|------------|
| No saved searches for Phase 1 emerging LIVE/HYBRID scenarios (T0072–T0075, T0070–T0071) | High | Added Section 7 with six corroborated detections |
| Block detection limited to AcmeSentinel/AcmeGate/workflow only | Medium | New `acme_control_block` macro covers emerging fields |
| Some hunts omitted `incident_id` / `kill_chain.stage` in `table` output | Low | Emerging searches include all three correlation fields |

### New saved searches

- **AML.T0072** — Memory drift + trust score corroboration
- **AML.T0074** — HITL bypass when gate disabled + amount threshold
- **AML.T0073** — Privilege creep (granted vs used scope)
- **AML.T0075** — Message provenance / A2A integrity failure
- **AML.T0070** — MCP manifest poisoning (gateway block)
- **AML.T0071** — Skill supply chain (provenance + AIBOM)

All use `` `acme_genai_index` `` and explicit `dispatch.earliest_time` / `dispatch.latest_time`.

---

## B. Macros (`macros.conf`)

| Macro | Purpose |
|-------|---------|
| `acme_control_block` | Unified detect/block predicate for matrix, heatmap, gap panels |
| `acme_session_window` | `-15m` window aligned with README golden path |

Customers retarget data by editing `acme_genai_index` only.

---

## C. Dashboard fixes

### `compliance_overview.xml`

- Reordered KPI row: Critical → Active Blocks → Detection Gaps → Kill Chains → Total Events
- Added **Detection Gaps This Session** table (`NOT_ATTEMPTED` vs attempted-without-block)

### `technique_coverage_matrix.xml`

- Three states: `NOT_ATTEMPTED` / `ATTEMPTED_NOT_DETECTED` / `DETECTED`
- Catalog count reflects 51 techniques
- Block counts via join on `acme_control_block` (macro-safe)

### `mitre_atlas_heatmap.xml`

- Detected count uses expanded `acme_control_block`
- Heat score adds intensity from block/event ratio (0 = gap, 1+ = observed, 2+ = detected)

### `killchain_timeline.xml` / `actor_chain_narrative.xml`

- Stage ordering: `tonumber(stage_num)` then `_time`
- `convert ctime()` for consistent display timezone
- KC-F001 (Memory Drift Chain) added to actor narrative dropdown
- Forensics table includes `kill_chain.stage` and `campaign_week`

### `nist_rmf_compliance.xml`

- **Event-Driven Control Attestation** panel with `last_validated` from `control.status` telemetry + campaign-week fallback

### `mltk_anomaly_hunting.xml`

- MLTK install probe (`| rest /services/apps/local`)
- Graceful empty-state when `fit MLTKContainer` returns no results
- Token chart requires `total_tokens>0` before forecast

### `threat_hunting.xml`

- Defense efficacy chart includes emerging block fields

---

## D. Framework telemetry (supporting)

- `chain_engine.py`: default `campaign_week=0` on kill-chain events; single-technique emissions inherit `campaign_week` from executor when provided

---

## E. Known limitations

1. **MLTK / CTSM** — Forecast panel requires Splunk MLTK + Cisco Time Series Model; hunts using `cisco_tsm_anomaly_score` work without MLTK.
2. **HITL T0074** — When `HITL_GATE_ENABLED=false`, events appear as governance gaps (`ATTEMPTED_NOT_DETECTED`) until gate is enabled or a dedicated governance alert is tuned.
3. **Control attestation** — `control.status` events populate only after Workshop control-validation paths; otherwise panel shows `NOT_RUN` / campaign-week `OBSERVED`.
4. **Phase 6 rename (complete)** — AcmeGate/AcmeSentinel middleware and `acme_*_guard_*` telemetry fields; vendor-sim sourcetype `acme:agentic:vendorsim:json`; Cross-App Normalization dashboard.
5. **Official ATLAS catalog** — Lab ships 51 executable techniques; full MITRE ATLAS remains larger (gaps expected).

---

## F. Validation checklist

```bash
python3 scripts/sync_splunk_lookups.py
bash scripts/package_splunk_app.sh
```

After workshop run:

1. Golden path SPL returns `campaign_week` buckets
2. Compliance Overview → Detection Gaps shows techniques without blocks after LIVE runs
3. Technique Coverage Matrix → three-state colors populate
4. Fire KC-F001 → Kill-Chain Timeline stages sort by `stage_num`
5. Emerging searches return rows for T0072/T0074 when scenarios execute

---

## G. Files changed (Phase 3)

- `splunk_app/.../default/macros.conf`
- `splunk_app/.../default/savedsearches.conf`
- `splunk_app/.../default/data/ui/views/compliance_overview.xml`
- `splunk_app/.../default/data/ui/views/technique_coverage_matrix.xml`
- `splunk_app/.../default/data/ui/views/mitre_atlas_heatmap.xml`
- `splunk_app/.../default/data/ui/views/killchain_timeline.xml`
- `splunk_app/.../default/data/ui/views/actor_chain_narrative.xml`
- `splunk_app/.../default/data/ui/views/nist_rmf_compliance.xml`
- `splunk_app/.../default/data/ui/views/mltk_anomaly_hunting.xml`
- `splunk_app/.../default/data/ui/views/threat_hunting.xml`
- `apps/framework/chain_engine.py`
- `docs/SPLUNK_AUDIT_NOTES.md` (this file)
