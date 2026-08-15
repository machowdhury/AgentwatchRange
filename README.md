# OrchestraACME

> **Last updated:** 2026-08-15 · **Docs version:** 2.4.0

**A Docker-based agentic AI security range for red-teaming, runtime defense, and compliance monitoring.**

ACME Bank deployed four AI agents to speed up loan approvals. Six weeks later, their compliance officer got an email she didn't expect — not from a firewall breach, but from poisoned tool metadata and drifting session memory. This lab lets you attack that same pipeline (live Ollama LLM), see runtime controls block or allow attacks, and prove outcomes in Splunk.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-GenAI-000000?logo=opentelemetry&logoColor=white)](apps/app_runtime.py)
[![Splunk](https://img.shields.io/badge/Splunk-GenAI_Compliance-65A637?logo=splunk&logoColor=white)](splunk_app/splunk_compliance_app/)

> **Repository:** [github.com/machowdhury/OrchestraACME](https://github.com/machowdhury/OrchestraACME)  
> **Author:** Mahamudul Alam Chowdhury ([@machowdhury](https://github.com/machowdhury))

---

## Choose your path

| Path | Go here |
|------|---------|
| **New to this? → Start Here** | [Start here — your first 30 minutes](#start-here--your-first-30-minutes) below |
| **I know Docker/Splunk → Quick Start** | [Condensed commands](#quick-start) |
| **I want the architecture → Concepts** | [docs/CONCEPTS.md](docs/CONCEPTS.md) |
| **I want a structured curriculum → Learning Path** | [docs/LEARNING_PATH.md](docs/LEARNING_PATH.md) |

---

## Start here — your first 30 minutes

You need **Docker Desktop** (or Docker Engine + Compose v2) and **~16 GB RAM** if Splunk runs locally.  
Full hardware checklist: [docs/PREREQUISITES.md](docs/PREREQUISITES.md)

### Step 1 — Get the code and start containers (~5–15 min)

```bash
git clone https://github.com/machowdhury/OrchestraACME.git
cd OrchestraACME
cp .env.example .env
docker compose --profile local up --build -d
```

> **Tip:** `.env.example` sets `COMPOSE_PROFILES=local` so plain `docker compose up` works after `cp .env.example .env`. On older clones, always pass `--profile local`.

Wait for Ollama to pull the model (first boot only, ~1.3 GB):

```bash
docker compose --profile local logs -f ollama    # Ctrl+C when llama3.2:1b appears
docker compose --profile local ps              # all services running / healthy
```

**Optional:** check one-shot HEC init — `docker logs acme_splunk_hec_init` should end with `PASS — HEC returned HTTP 200`. If it failed, Step 2 fixes it.

### Step 2 — Install Splunk apps and verify HEC (~5 min)

Splunk UI starts without the compliance app or custom index. Run once:

```bash
chmod +x scripts/package_splunk_app.sh scripts/splunk_install_apps.sh scripts/splunk_local_bootstrap.sh
./scripts/package_splunk_app.sh
./scripts/splunk_install_apps.sh      # compliance app + MLTK
./scripts/splunk_local_bootstrap.sh   # index + HEC token (safe to re-run)
docker compose --profile local restart otel_collector
```

**Pass:** bootstrap prints `HEC returned HTTP 200`.

Quick terminal check:

```bash
curl -s -o /dev/null -w "HEC HTTP %{http_code}\n" \
  http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk acme-hec-token-0000-1111-2222-3333" \
  -d '{"event":{"install_test":true}}'
```

Expected: `HEC HTTP 200` (not `000`).

### Step 3 — Open the lab and check status

| App | URL | You should see |
|-----|-----|----------------|
| **Attack Panel** | http://localhost:5001 | Header: **TARGET ONLINE** + **LLM ONLINE** (green) |
| **Banking app** | http://localhost:5000 | Loan pipeline UI loads |
| **Splunk** | http://localhost:8000 | Login: `admin` / password from `.env` (default `ACMEPassword2026!`) |

Attack Panel tabs (left to right): **Top 10 Scenarios** (default) → All 45 → Threat Chains → Custom → **Workshop** (last).

### Step 4 — Verify telemetry before any attack (~3 min)

**Do this before firing scenarios.** You want proof that **benign** traffic reaches Splunk — then attacks are easy to spot.

**Option A — Automatic baseline (easiest)**

The banking app sends harmless loan requests every 90–240 seconds once Ollama is healthy.

1. Wait **2–3 minutes** after stack startup.
2. Check the simulator: `curl -s http://localhost:5000/api/v1/traffic/status` — `"running": true`, `ticks_ok` increasing.
3. In Splunk **Search**:

```spl
index=acme_agentic_telemetry earliest=-15m
| stats count by testbed_mode
```

**Pass:** `count` ≥ 1. Often you see `BASELINE_TRAFFIC` (automatic) and/or `BANKING_LIVE` (manual UI).

**Option B — One manual loan (recommended first time)**

1. Open http://localhost:5000  
2. Enter a normal message, for example:

   ```text
   I would like to apply for a small business loan. Annual revenue is $250,000.
   ```

3. Click **Run Through All Agents**  
4. Click **↺ Refresh Sessions** — pipeline history should show your request  
5. Wait **30–60 seconds**, then in Splunk:

```spl
index=acme_agentic_telemetry earliest=-15m
| stats count by testbed_mode gen_ai.agent.name
```

**Pass:** count > 0; agents such as `acme-agent-intake-001` appear.

> **Not zero?** Re-run `./scripts/splunk_local_bootstrap.sh`, restart OTel, wait another minute. See [Verification & Troubleshooting](docs/REFERENCE.md#verification--troubleshooting).

### Step 5 — Run your first attack (~5 min)

Only after Step 4 shows events in Splunk.

1. Open http://localhost:5001  
2. Click the **Workshop** tab (last tab)  
3. Click **RUN FIRST WIN PATH**  
4. Wait for the path to finish (Scenarios 6 → 5 → 9)

### Step 6 — Prove the attack in Splunk (~2 min)

Wait **60 seconds**, then in Splunk **Search**:

```spl
index=acme_agentic_telemetry sourcetype="otel:agentic:json" earliest=-15m
| stats count by campaign_week
```

**Pass:** `count` increased vs Step 4 and you see scenario numbers (e.g. `6`, `5`, `9`).

To separate attacks from baseline noise:

```spl
index=acme_agentic_telemetry earliest=-15m NOT testbed_mode=BASELINE_TRAFFIC
| stats count by campaign_week
```

Open **GenAI Compliance Monitor → Overview** — event count should be non-zero.

### Step 7 — You're done with the basics

You have a working **baseline → attack → telemetry → Splunk** loop. Pick your next path in the table below.

**Stuck?** [Verification & Troubleshooting](docs/REFERENCE.md#verification--troubleshooting) · HEC `000` or OTel `connection reset` on 8088 → `./scripts/splunk_local_bootstrap.sh`

---

## Quick Start

For experienced operators — same flow as [Start here](#start-here--your-first-30-minutes):

```bash
git clone https://github.com/machowdhury/OrchestraACME.git && cd OrchestraACME
cp .env.example .env
docker compose --profile local up --build -d
./scripts/package_splunk_app.sh && ./scripts/splunk_install_apps.sh && ./scripts/splunk_local_bootstrap.sh
docker compose --profile local restart otel_collector
```

Then: http://localhost:5001 → **Workshop** → **RUN FIRST WIN PATH** → Splunk Search (Step 6 above).

| URL | Role |
|-----|------|
| http://localhost:5001 | Attack Panel |
| http://localhost:5000 | Banking app (defend path) |
| http://localhost:8000 | Splunk (monitor) |

Cloud VM: replace `localhost` with your server IP — [docs/CLOUD_VM_DEPLOYMENT.md](docs/CLOUD_VM_DEPLOYMENT.md)

---

## What to read next

| Read this | When |
|-----------|------|
| **[docs/CONCEPTS.md](docs/CONCEPTS.md)** | Architecture, containers, DefenseClaw/AcmeGate transparency, limitations |
| **[docs/REFERENCE.md](docs/REFERENCE.md)** | Env vars, credentials, API curl examples, install detail, troubleshooting |
| **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** | Workshop buttons, SPL queries, dashboards, maturity lifecycle |
| **[docs/ATTACK_PANEL_GUIDE.md](docs/ATTACK_PANEL_GUIDE.md)** | Every Attack Panel tab — outcomes, per-scenario SPL |
| **[docs/WORKSHOP.md](docs/WORKSHOP.md)** | Full curriculum, hunt questions Q101–Q509, facilitator runbook |
| **[docs/PREREQUISITES.md](docs/PREREQUISITES.md)** | Docker install, permissions, Splunk checklist |
| **[docs/THREAT_SURFACES.md](docs/THREAT_SURFACES.md)** | Agentic attack surfaces → Scenario 1–10 + emerging techniques |
| **[docs/MAESTRO_WORKSHOP.md](docs/MAESTRO_WORKSHOP.md)** | CSA MAESTRO threat modeling path |
| **[docs/CISCO_INTEGRATION.md](docs/CISCO_INTEGRATION.md)** | Optional Cisco + MLTK overlay |
| **[splunk_app/INSTALL.md](splunk_app/INSTALL.md)** | Splunk Cloud / Enterprise app upload |

---

## License & Attribution

OrchestraACME Lab — Principal DevSecOps Systems Engineering range for agentic AI security validation.

**Third-party / reference names:** AcmeGate and AcmeSentinel are **lab-original** Python middleware. Optional [Cisco AI Defense overlay](docs/CISCO_INTEGRATION.md) uses real third-party tools when enabled. Splunk and Ollama run as described in their respective containers/images. See [NOTICE.md](NOTICE.md).

MIT License — see [LICENSE](LICENSE).
