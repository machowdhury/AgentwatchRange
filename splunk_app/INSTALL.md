# OrchestraACME Splunk App Installation Guide

**Before Splunk setup:** Complete stack prerequisites in **[docs/PREREQUISITES.md](../docs/PREREQUISITES.md)** (Docker, Ollama, HEC alignment).

This guide covers installing the **GenAI Compliance Monitor** app (`acme_genai_compliance`) in three deployment modes.

| Mode | Splunk Location | OrchestraACME Stack |
|------|-----------------|---------------------|
| **Local Lab** | Docker Splunk container | `docker compose --profile local up` |
| **Splunk Cloud** | Your Splunk Cloud stack | `docker compose -f docker-compose.yml -f docker-compose.external.yml up` |
| **Splunk Enterprise** | On-prem / VM Splunk | Same as Splunk Cloud (external mode) |

---

## 1. Build the Install Package

From the OrchestraACME repository root:

```bash
chmod +x scripts/validate_splunk_app.sh scripts/package_splunk_app.sh
./scripts/package_splunk_app.sh
```

This creates `dist/acme_genai_compliance-<VERSION>.tar.gz` — use the **exact filename printed** at the end of `./scripts/package_splunk_app.sh` (version is set in that script's `VERSION=` line).

The tarball uses the correct Splunk app folder name (`acme_genai_compliance`) required for Cloud and Enterprise installation.

---

## 2. Splunk Cloud Installation

### Prerequisites

- Splunk Cloud admin or app-install privileges
- Permission to create indexes and HEC tokens (or admin assistance)
- OrchestraACME OTel Collector configured to ship to Splunk Cloud HEC

### Step A — Install the App

1. Log in to your Splunk Cloud instance
2. Navigate to **Apps → Browse more apps → Upload app**
3. Upload the tarball from `dist/` (filename printed by `./scripts/package_splunk_app.sh`)
4. If prompted, request **private app approval** from your Splunk Cloud administrator

> **Alternative (admin CLI on SHC):**
> ```bash
> splunk install app dist/acme_genai_compliance-*.tar.gz -update 1 -auth admin:<password>
> ```

### Step B — Create Index

1. **Settings → Indexes → New Index**
2. Name: `acme_agentic_telemetry`
3. Save

### Step C — Create HEC Token

1. **Settings → Data Inputs → HTTP Event Collector → Global Settings** → Enable
2. **New Token**
   - Name: `orchestra-acme-otel`
   - Source type: `otel:agentic:json`
   - Index: `acme_agentic_telemetry`
3. Copy the token value

### Step D — Note Your HEC Endpoint

Splunk Cloud HEC URL format:

```
https://http-inputs-<YOUR_STACK>.splunkcloud.com/services/collector/event
```

Find the exact URL in **Settings → Data Inputs → HTTP Event Collector**.

### Step E — Configure OrchestraACME (External Mode)

On your OrchestraACME Docker host, edit `.env`:

```bash
SPLUNK_MODE=external
SPLUNK_HEC_ENDPOINT=https://http-inputs-YOUR_STACK.splunkcloud.com/services/collector/event
SPLUNK_HEC_TOKEN=<your-splunk-cloud-hec-token>
SPLUNK_HEC_INDEX=acme_agentic_telemetry
SPLUNK_HEC_SOURCETYPE=otel:agentic:json
SPLUNK_HEC_TLS_SKIP_VERIFY=false
```

Start without the local Splunk container:

```bash
docker compose -f docker-compose.yml -f docker-compose.external.yml up --build -d
```

### Step F — Verify & Open Dashboards

Run in Splunk Cloud Search:

```spl
index=acme_agentic_telemetry sourcetype="otel:agentic:json" | head 20
```

Open the in-app setup guide:

**GenAI Compliance Monitor → Setup Guide**

---

## 3. Splunk Enterprise (External) Installation

Follow the same steps as Splunk Cloud (Section 2), replacing the HEC endpoint with your Enterprise host:

```bash
SPLUNK_HEC_ENDPOINT=https://<your-splunk-host>:8088/services/collector/event
```

Install the app via UI or CLI:

```bash
$SPLUNK_HOME/bin/splunk install app dist/acme_genai_compliance-*.tar.gz -update 1
$SPLUNK_HOME/bin/splunk restart
```

---

## 4. Local Docker Splunk Installation

When using the bundled Splunk container:

```bash
# Recommended — compliance app + MLTK from splunk_app/
chmod +x scripts/package_splunk_app.sh scripts/splunk_install_apps.sh
./scripts/package_splunk_app.sh
./scripts/splunk_install_apps.sh
```

Then enable HEC and create the index:

```bash
chmod +x scripts/splunk_local_bootstrap.sh
./scripts/splunk_local_bootstrap.sh
docker compose restart otel_collector   # if OTel started before HEC
```

**Legacy alias:** `./scripts/splunk_install_app.sh` calls the same combined installer.

This avoids `splunk install app` tarball extraction issues (`bundle_tmp` errors) common when the CLI was previously run as root.

### MLTK (Machine Learning Toolkit)

Required for **MLTK Anomaly Hunting** and CTSM token forecasting panels.

**Local lab (bundled tarball):**

Place `splunk-ai-toolkit_600.tgz` under `splunk_app/` (included in this repo when provided). `splunk_install_apps.sh` extracts it to `Splunk_ML_Toolkit` in the container.

**Splunk Cloud / Enterprise:** Install MLTK from Splunkbase, or upload the same tarball if your admin allows sideloading.

---

Or manually:

```bash
./scripts/package_splunk_app.sh
TARBALL="$(cat dist/.last_package)"
tar -xzf "$TARBALL" -C /tmp
docker exec -u root acme_splunk rm -rf /opt/splunk/etc/apps/acme_genai_compliance
docker cp /tmp/acme_genai_compliance acme_splunk:/opt/splunk/etc/apps/acme_genai_compliance
docker exec -u root acme_splunk chown -R splunk:splunk /opt/splunk/etc/apps/acme_genai_compliance
docker compose exec -u splunk splunk /opt/splunk/bin/splunk restart
```

Legacy tarball install (only if `bundle_tmp` permissions are correct):

```bash
./scripts/package_splunk_app.sh
TARBALL="$(cat dist/.last_package)"
docker cp "$TARBALL" acme_splunk:/tmp/
docker compose exec -u splunk splunk /opt/splunk/bin/splunk install app \
  "/tmp/$(basename "$TARBALL")" -update 1 -auth admin:ACMEPassword2026!
docker compose exec -u splunk splunk /opt/splunk/bin/splunk restart
```

Or copy the source directory:

```bash
docker cp splunk_app/splunk_compliance_app acme_splunk:/opt/splunk/etc/apps/acme_genai_compliance
docker compose exec -u root splunk bash -c "chown -R splunk:splunk /opt/splunk/etc/apps/acme_genai_compliance"
docker compose exec -u splunk splunk /opt/splunk/bin/splunk restart
```

Enable HEC and create index:

```bash
./scripts/splunk_local_bootstrap.sh
```

Or configure manually in Splunk Web as documented in the main `README.md`.

---

## 5. Custom Index / Sourcetype

If your environment uses different names, edit the app macro (no code changes required):

**Settings → Advanced Search → Search macros → `acme_genai_index`**

Default:

```spl
index=acme_agentic_telemetry sourcetype="otel:agentic:json"
```

All dashboards and saved searches inherit this macro automatically.

---

## 6. Optional: Legacy Cisco AI Defense App

For `cisco:aidefense:json` sourcetype (legacy OrchestraACME telemetry), install separately:

```
splunk_app/App-Agentic-Compliance/
```

Package manually:

```bash
tar -czf dist/app-agentic-compliance-1.0.0.tar.gz -C splunk_app/App-Agentic-Compliance .
```

---

## 7. Splunk Cloud vetting & Enterprise compatibility

See **[splunk_app/CLOUD_VETTING.md](CLOUD_VETTING.md)** for the full checklist aligned with [Splunk Cloud app vetting](https://dev.splunk.com/enterprise/docs/releaseapps/cloudvetting/).

```bash
./scripts/validate_splunk_app.sh   # pre-upload checks
./scripts/package_splunk_app.sh    # build dist/acme_genai_compliance-*.tar.gz
```

**Key points:**
- Same `.tar.gz` installs on **Splunk Cloud** and **Splunk Enterprise**
- No `bin/` scripts — SPL dashboards and CSV lookups only
- Scheduled detection searches ship **disabled**; enable after macro + HEC are configured
- MLTK recommended for **MLTK Anomaly Hunting** / CTSM panels — install via `splunk_install_apps.sh`
- Colors follow the [Splunk UI Design System](https://splunkui.splunk.com/DesignSystem/Accessibility/Color) — see [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md)
- Optional Cisco + MLTK: [docs/CISCO_INTEGRATION.md](../docs/CISCO_INTEGRATION.md)

---

## 8. Troubleshooting

| Issue | Resolution |
|-------|------------|
| App upload rejected on Splunk Cloud | Request private app install from Splunk support/admin |
| No data in dashboards | Verify `acme_genai_index` macro matches your index/sourcetype |
| HEC 403 errors | Token index/sourcetype permissions; verify token is active |
| Bootstrap Permission denied on `/opt/splunk` | Re-run after `git pull` — bootstrap uses REST API, not `splunk` CLI as root |
| App install `bundle_tmp` / Permission denied | Prior root `splunk` CLI | `./scripts/splunk_install_apps.sh` (repairs ownership + copies to `etc/apps`) |
| MLTK panels empty | MLTK not installed | Run `./scripts/splunk_install_apps.sh` or install MLTK from Splunkbase |

---

## Support

- Repository: https://github.com/machowdhury/OrchestraACME
- In-app guide: **GenAI Compliance Monitor → Setup Guide**
- Cloud vetting: [splunk_app/CLOUD_VETTING.md](CLOUD_VETTING.md)
