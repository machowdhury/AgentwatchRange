# Splunk Cloud & Enterprise Compatibility

The **GenAI Compliance Monitor** (`acme_genai_compliance` v2.3+) is designed for **Splunk Enterprise** and **Splunk Cloud** using the same install package.

Official reference: [Vet apps for Splunk Cloud Platform](https://dev.splunk.com/enterprise/docs/releaseapps/cloudvetting/)

---

## Design choices for Cloud compatibility

| Requirement | How this app complies |
|-------------|----------------------|
| No custom binaries | **No `bin/` folder** — dashboards, macros, CSV lookups, SPL only |
| No `local/` in package | All config under `default/`; customers edit macros in UI |
| Index flexibility | `` `acme_genai_index` `` macro — no hardcoded customer index in dashboards |
| Field extraction | `props.conf` for `otel:agentic:json` on search heads (SHC-safe) |
| Lookups | CSV files in `lookups/` with `transforms.conf` definitions |
| Scheduled alerts | **Ship disabled** (`disabled=1`) — enable after macro/index setup |
| No KV store without collections | Unused KV transform removed |
| No MLTK dependency | Core dashboards work without Machine Learning Toolkit |
| No `_internal` access | All searches use customer index via macro |
| **Design / a11y** | Splunk UI severity palette; see `DESIGN_SYSTEM.md` |
| **MLTK / CTSM** | Optional `mltk_anomaly_hunting` dashboard + saved searches (requires MLTK + cisco-time-series-model) |

---

## Pre-upload validation

From the repository root:

```bash
chmod +x scripts/validate_splunk_app.sh scripts/package_splunk_app.sh
./scripts/validate_splunk_app.sh
./scripts/package_splunk_app.sh
```

Output: `dist/acme_genai_compliance-*.tar.gz` — use the **exact filename printed** at the end of `./scripts/package_splunk_app.sh`.

---

## Splunk Cloud install

1. **Upload** the `.tar.gz` via **Apps → Upload app** (admin may need private-app approval).
2. **Create index** `acme_agentic_telemetry` (or your name).
3. **Create HEC token** → sourcetype `otel:agentic:json` → your index.
4. **Edit macro** `acme_genai_index` if index/sourcetype differs.
5. Open **GenAI Compliance Monitor → Setup Guide** in the app.
6. Verify: `` index=YOUR_INDEX sourcetype="otel:agentic:json" | head 5 ``
7. **Enable saved searches** (optional): Settings → Searches, reports, and alerts → filter `GenAI Compliance` → enable after tuning.

**Local Docker Splunk:** Run `./scripts/splunk_local_bootstrap.sh` from the repo root instead of manual index/HEC steps 2–3.

---

## Splunk Enterprise install

```bash
$SPLUNK_HOME/bin/splunk install app dist/acme_genai_compliance-*.tar.gz -update 1
$SPLUNK_HOME/bin/splunk restart
```

Same index, HEC, and macro steps as Cloud.

---

## AppInspect (recommended before Splunk Cloud production)

Splunk Cloud private apps should pass **AppInspect** with the `cloud` tag:

```bash
# Requires Splunk AppInspect CLI from Splunk Developer tools
appinspect inspect dist/acme_genai_compliance-*.tar.gz --mode test --included-tags cloud
```

If you do not have AppInspect locally, upload to a Splunk Cloud **test stack** first and review **Manage Apps → App inspection**.

---

## What customers must configure (not bundled)

| Item | Why not auto-configured |
|------|-------------------------|
| Index | Customer-specific retention / RBAC |
| HEC token | Secret — created in Splunk UI |
| `` `acme_genai_index` `` macro | Points app at customer index |
| Scheduled detections | Disabled until data flows and macro is correct |

---

## Troubleshooting Cloud upload rejection

| Issue | Fix |
|-------|-----|
| Private app policy | Request admin approval on Splunk Cloud |
| AppInspect failure | Run `./scripts/validate_splunk_app.sh`; fix reported issues |
| Dashboards empty | Macro/index/HEC mismatch — see Setup Guide |
| Alerts never fire | Saved searches ship **disabled** — enable manually |

---

## Support

- [INSTALL.md](INSTALL.md) — full install for local Docker, Cloud, Enterprise
- [docs/USER_GUIDE.md](../docs/USER_GUIDE.md) — dashboard meanings and Workshop paths
- Repository: https://github.com/machowdhury/OrchestraACME
