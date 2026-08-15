# AgentWatch Range — Concepts

> **Last updated:** 2026-08-15 · **Docs version:** 2.4.0 (Phase 2 restructure)

Deep architecture, transparency, and limitations. For install commands and env vars see [REFERENCE.md](REFERENCE.md). For the 30-minute golden path see [README.md](../README.md#start-here--your-first-30-minutes).

---

## ACME Bank — the story

ACME Bank deployed four AI agents to speed up loan approvals: intake, document extraction, credit risk, and compliance. Six weeks later, their compliance officer got an email she did not expect — not because a hacker broke the firewall, but because a poisoned tool description, a community skill, and a string of "helpful" session notes had quietly shifted what "approve" meant. The Top 10 scenarios and emerging techniques in this lab are episodes of that same week, not abstract checklist items.

---

## Agentic Security Architecture

AgentWatch Range targets **workflow-realistic** agentic security validation, not prompt-only red teaming.

- Attacks exploit **tools, RAG, memory, A2A, and orchestration** surfaces — not just strings sent to one agent
- Defense is **enforced in code paths** (MCP gateway, memory policy, A2A verifier, orchestration guard) plus regex output inspection
- Framework mapping produces **measurable control evidence** (NIST pass/fail per scenario)
- Splunk tracks **detection efficacy** (coverage %, MTTD, chain completeness, control attestation)
- **51 techniques** (45 core + 6 emerging) form a curated threat library with reproducible kill chains

**Nine agentic threat surface categories** (2025–2026) map to Top 10 lab scenarios — see [THREAT_SURFACES.md](THREAT_SURFACES.md).

| Layer | Module |
|-------|--------|
| Unified workflow guard | `apps/framework/workflow_guard.py` |
| MCP tool gateway | `apps/framework/mcp_gateway.py` |
| A2A DID verifier | `apps/framework/a2a_verifier.py` |
| Memory policy | `apps/framework/memory_policy.py` |
| RAG / Galileo probe | `apps/framework/rag_store.py` |
| Orchestration guard | `apps/framework/orchestration_guard.py` |
| NIST control evidence | `apps/framework/control_matrix.yaml` + `control_validator.py` |
| SOAR containment sim | `apps/framework/soar_simulator.py` |

### Cisco AI Defense + Splunk MLTK (optional)

Enable real [Cisco AI Defense](https://github.com/cisco-ai-defense) scanners, [Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) hunt enrichment, and [Cisco Time Series Model](https://github.com/splunk/cisco-time-series-model) anomaly dashboards **without breaking Workshop attacks** (`LAB_MODE=teach`).

```bash
docker compose -f docker-compose.yml -f docker-compose.cisco.yml --profile local up --build -d
```

Attack panel → **Cisco + MLTK Anomaly Hunt** → Splunk **MLTK Anomaly Hunting** dashboard.

Full guide: [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md)

### CSA MAESTRO threat modeling (optional)

Add **design-time** agentic threat modeling with the official [CSA MAESTRO Threat Analyzer](https://github.com/CloudSecurityAlliance/MAESTRO), then validate predictions in Splunk. Part of **Workshop Level 5A** — see [WORKSHOP.md](WORKSHOP.md).

Attack panel → **MAESTRO Threat Model → Attack → Splunk** · API: `GET /api/v1/maestro/architecture`

Detail: [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md)


---


## How Everything Works (Plain Language)

Read this if you want the full picture after completing [Start here](../README.md#start-here--your-first-30-minutes).

### The 30-second version

1. You start five Docker containers (or four if you use external Splunk).
2. The **banking app** runs four AI agents in a row; each agent asks **Ollama** a question and gets a real text answer.
3. The **attack panel** sends malicious prompts to those same agents on purpose.
4. Before and after every LLM call, **AcmeGate** (input) and **AcmeSentinel** (output) scan text with pattern rules. If something looks like an injection or escape, the call is **blocked** and logged.
5. Every call also emits **OpenTelemetry** data (tokens, latency, agent name, block/allow decision).
6. The **OTel Collector** receives that data and forwards it to **Splunk** over HTTP Event Collector (HEC).
7. The **Splunk compliance app** is a separate install — it reads that index and shows dashboards. Splunk does not run the AI.

Nothing in step 4–7 happens inside Ollama. Nothing in step 6–7 requires the Python apps to include a Splunk SDK.

### What happens on first boot (realistic timeline)

| Phase | Time | What you will see |
|-------|------|-------------------|
| `docker compose up` | 0–2 min | Images build/pull; containers start |
| Ollama model pull | 2–10 min | `docker compose logs -f ollama` — downloads `llama3.2:1b` (~1.3 GB) unless cached |
| Splunk first init | 3–8 min | `docker compose logs -f splunk` — license acceptance, indexer startup |
| Banking app ready | After Ollama healthy | http://localhost:5000 responds; LLM calls fail until model is pulled |
| Baseline traffic | ~45s after banking app + Ollama healthy | Background simulator sends benign loan requests every 90–240s (`testbed_mode=BASELINE_TRAFFIC`) |
| Splunk events | After HEC + index exist | Baseline + attack events appear when HEC token, index, and collector config align |
| Dashboards | After **you** install the app | Empty Splunk UI until `acme_genai_compliance` is installed and index has data |

**Important:** `docker compose up` alone does **not** install the Splunk compliance app or create the `acme_agentic_telemetry` index. Those are documented steps you run once.

### Each container — what it really does

| Container | What it does | What it does **not** do | Host port |
|-----------|--------------|-------------------------|-----------|
| **ollama** | Serves a local LLM; pulls one model from `OLLAMA_MODEL` | Pick models automatically; call Splunk; enforce security policy | 11434 |
| **banking_app** | 4-agent loan pipeline, REST APIs, OTel export, AcmeGate/AcmeSentinel | Connect to OpenAI/Anthropic; embed a Splunk client | 5000 |
| **attack_panel** | UI + API that POSTs adversarial payloads to banking_app | Run its own LLM; bypass banking_app middleware | 5001 |
| **otel_collector** | Receives OTLP; batches; exports to Splunk HEC + JSONL file | Store long-term data by itself; run detections | 4317, 4318 |
| **splunk** (local mode) | Indexes HEC events; hosts Web UI | Start automatically with dashboards pre-installed | 8000, 8088 |

All containers talk on an internal Docker network (`acme_mesh`). Only the ports above are published to your laptop.

### Defend path — one legitimate loan request

```text
You type a loan request on :5000
    → banking_app receives POST /api/v1/process
    → Agent 1 (Intake) builds a prompt + calls Ollama /api/generate
         → AcmeGate checks your input text
         → Ollama returns text
         → AcmeSentinel checks model output text
         → OTel span + metrics sent to otel_collector:4318
    → Agent 2, 3, 4 repeat (each with its own system prompt)
    → Final APPROVED / DENIED shown in UI
    → otel_collector forwards events to Splunk HEC
    → (if app installed) Splunk dashboards update
```

Each agent uses the **same** Ollama model (`OLLAMA_MODEL`). There is no routing like “use a bigger model for compliance.”

### Attack path — one adversarial scenario

```text
You click a scenario on :5001
    → attack_panel POSTs to banking_app /api/v1/agent/<target_agent_id>
    → Same middleware + Ollama path as above, but input is a crafted attack string
    → Outcome is non-deterministic:
         BLOCKED  = AcmeGate or AcmeSentinel matched a pattern → HARD_DENY telemetry
         INJECTED = Model responded without triggering a rule (logged for gap analysis)
    → Either way, telemetry should land in Splunk if HEC is configured
```

Attacks are **real HTTP requests** with **real model inference**. Outcomes are **not scripted** — a small model may sometimes refuse an attack without AcmeSentinel firing, or occasionally comply in ways rules miss. That is intentional for detection engineering practice.

### AcmeSentinel and AcmeGate — full transparency

These names reference **Cisco AI Defense-style runtime controls**, but in this repository they are **open-source Python middleware** in `apps/agents/llm_client.py`:

| Control | When it runs | How it works in this lab | Production equivalent |
|---------|--------------|--------------------------|---------------------|
| **AcmeGate** | Before the prompt is sent to Ollama | Regex scan for markup/injection patterns in user input | Input sanitization / secure prompt assembly |
| **AcmeSentinel** | After Ollama returns text | Regex scan for jailbreak success, shell escape, wire-transfer strings, etc. | Output-side AI firewall / policy gateway |

- They are **not** Cisco product binaries you install separately.
- They are **not** ML classifiers — they are explicit pattern lists you can read in source code.
- They **can** be disabled via `ACME_OUTPUT_GUARD_ENABLED=false` / `ACME_INPUT_GUARD_ENABLED=false` in environment (see `docker-compose.yml`).
- When they block, they emit telemetry fields (`acme_output_guard_blocked`, `acme_input_guard_blocked`, rule IDs) shaped for Splunk lookups and framework crosswalks.

This lab is meant to **demonstrate the telemetry and workflow** you would get with enterprise AI defense tooling, not to replace a vendor appliance.

### Why Splunk for agentic AI security (Phase 6)

Agentic apps will **never** agree on a native schema. The value of a SIEM here is not collecting more logs — it is **normalizing heterogeneous agentic telemetry** into one framework-mappable model (`norm_*` fields in `props.conf`), so compliance and detection logic does not get rewritten per app.

Open **GenAI Compliance Monitor → Cross-App Normalization** after Tier 3 to compare raw vs normalized events across `otel:agentic:json`, `acme:agentic:vendorsim:json`, `acme:agentic:thirdparty:json`, and inventory snapshots in `acme:agentic:registry:json`.

**Inventory vs events:** Agentic telemetry is not only heterogeneous in field names — it is heterogeneous in *data model*. Transaction streams (`otel:agentic:json`) differ from periodic inventory snapshots (`acme:agentic:registry:json`). Splunk must normalize both for governance dashboards (Phase 11).

### Continuous baseline traffic (Phase 10)

Benign traffic runs through the **real** banking pipeline (`testbed_mode=BASELINE_TRAFFIC`), not `makeresults` SPL:

| Mechanism | Purpose |
|-----------|---------|
| In-process `traffic_simulator` (default on banking app) | OTel benign loan requests every 90–240s |
| `scripts/baseline_traffic_generator.py` | External HTTP client to banking API |
| `docker compose --profile baseline --profile local up` | HEC trickle for vendorsim, thirdparty, registry |

Filter attacks: `` NOT testbed_mode=BASELINE_TRAFFIC ``

### Splunk — full transparency on the integration

| Question | Honest answer |
|----------|---------------|
| Do the Python apps talk to Splunk directly? | **No.** They only talk to the OTel Collector. |
| What sends data to Splunk? | The **OTel Collector** `splunk_hec` exporter in `config/otel-collector-config.yaml`. |
| What format? | JSON events, sourcetype `otel:agentic:json`, index `acme_agentic_telemetry`. |
| What does the Splunk app do? | **Read-only:** dashboards, lookups, scheduled searches on that index. |
| Does Splunk run Ollama or agents? | **No.** |
| Local vs Cloud? | **Local:** Splunk container in compose. **Cloud/Enterprise:** you point HEC env vars at your stack; no Splunk container. |
| Two Splunk apps in repo? | **Primary:** `splunk_compliance_app` (`acme_genai_compliance`). **Legacy optional:** `App-Agentic-Compliance` for synthetic `acme:agentic:vendorsim:json` vendor-sim telemetry. Use the primary one. |

**Three places must agree on HEC settings** or you will see no events: `.env`, `docker-compose.yml` environment injection into the collector, and Splunk’s HEC token configuration (index + sourcetype permissions).

### Ollama model selection — full transparency

| Statement | True / false |
|-----------|--------------|
| The app auto-detects the “best” model for each agent | **False** |
| You configure exactly one model for the whole lab | **True** — `OLLAMA_MODEL` (default `llama3.2:1b`) |
| The init script pulls that model on container start | **True** — `scripts/ollama_init.sh` |
| You can change models without code changes | **True** — edit `.env`, restart stack |
| Larger models need more RAM | **True** — adjust Docker memory limits if needed |

Default `llama3.2:1b` is chosen so the lab runs on CPU with modest hardware. It is **not** representative of production banking model quality.

---

---


## What This Project Is — and Is Not

| This project **is** | This project **is not** |
|---------------------|-------------------------|
| A **security research lab** for agentic AI | A production banking system |
| **Live** LLM calls via Ollama | A mocked/fake LLM with canned attack results |
| A reference **OTel GenAI** instrumentation example | A complete Cisco AI Defense product deployment |
| A **Splunk app + HEC pipeline** for detection validation | Splunk-native AI inference or SOAR automation |
| A **deliberately attackable** multi-agent chain | A hardened, pen-tested application |
| Open source you can inspect and modify | A black-box commercial appliance |

---

## Honest Limitations

We document these on purpose so expectations stay realistic:

1. **Regex defenses miss and over-block.** Novel jailbreaks may succeed; benign text may match financial regexes. Tune patterns in `llm_client.py` for your demos.
2. **Small models behave inconsistently.** Attack success rates vary run-to-run. Use results to test *detections*, not to score model safety scientifically.
3. **Splunk setup is manual.** Local Docker: run `./scripts/splunk_install_apps.sh` (compliance app + MLTK from `splunk_app/`), then `./scripts/splunk_local_bootstrap.sh` for HEC + index. Splunk Cloud: index, HEC token, app upload, and MLTK are your steps.
4. **No auto model routing.** All four agents share one `OLLAMA_MODEL`.
5. **Default credentials are public in this repo.** Fine for localhost labs only.
6. **Framework mappings include control attestation** — NIST pass/fail is emitted per event; not a certified compliance attestation.
7. **GPU is optional.** CPU inference is slow but functional; first response may take 10–30+ seconds.

---

## Why It Exists — The Agent Security Problem

Enterprises are deploying **multi-agent AI systems** that chain LLMs across intake, extraction, risk scoring, and compliance gates. These systems introduce attack surfaces that traditional AppSec tools were not built for:

| Gap | What Goes Wrong |
|-----|-----------------|
| **No runtime visibility** | Prompt injections and jailbreaks happen inside agent reasoning loops — invisible to WAFs and API gateways |
| **No policy enforcement at the model layer** | A compromised agent can escalate privileges, escape tool boundaries, or exfiltrate data across chain hops |
| **No compliance mapping** | Security teams cannot tie runtime AI events to OWASP LLM, MITRE ATLAS, or internal control frameworks |
| **No detection validation** | SIEM rules for AI threats are written blind — without a range to fire real attacks and confirm alerts fire |

**AgentWatch Range closes this gap** by giving security engineers a repeatable lab to **build, break, detect, and report** on agentic AI risk.

---

---


## How It Helps — Security, Monitoring & Compliance

### 1. Agent Security (Offense + Defense)

| Capability | How AgentWatch Range Delivers It |
|------------|-------------------------------|
| **Red-team testing** | Ten-scenario adversarial lifecycle console fires real prompt injection, tool escape, identity spoofing, and autonomous agent attacks |
| **Runtime defense** | Workflow guards (MCP, A2A, memory, orchestration) + AcmeGate/AcmeSentinel on every LLM call |
| **Multi-agent chain testing** | 4-agent loan pipeline (Intake → Extraction → Risk → Compliance) mirrors real enterprise agent orchestration |
| **Non-deterministic reasoning** | Live Ollama `llama3.2:1b` calls — attacks test actual model behavior, not canned responses |

### 2. Security Monitoring (Observability)

| Capability | How AgentWatch Range Delivers It |
|------------|-------------------------------|
| **GenAI semantic conventions** | OpenTelemetry emits `gen_ai.system`, `gen_ai.request.model`, `gen_ai.prompt`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` |
| **Distributed tracing** | Full agent chain traced end-to-end through OTel Collector |
| **Threat alerting** | Security events streamed as `otel:agentic:json` with MITRE ATLAS technique IDs, OWASP LLM/ASI mappings, and AcmeSentinel actions |
| **Token anomaly detection** | Splunk CTSM forecasting panel detects abnormal GenAI token consumption patterns |

### 3. Compliance (Framework Alignment)

| Capability | How AgentWatch Range Delivers It |
|------------|-------------------------------|
| **Framework crosswalk** | 45+ technique registry spanning MITRE ATLAS, OWASP LLM Top 10, OWASP ASI, CSA MAESTRO, and NIST AI RMF |
| **Compliance dashboards** | Detection Efficacy, Control Attestation, Technique Coverage, kill-chain timeline, NIST RMF |
| **Audit trail** | Every blocked transaction logged with event ID, transaction ID, matched indicator, agent name, and severity |
| **Configuration variance detection** | Dashboard identifies events that fail crosswalk enrichment — surfacing governance gaps |

### 4. Who Should Use This

- **Detection engineers** — validate Splunk ES correlation searches against live `otel:agentic:json` telemetry
- **AI security architects** — prototype runtime guardrails before production agent deployment
- **Compliance officers** — demonstrate OWASP LLM / MITRE ATLAS control coverage with live evidence
- **Red teamers** — exercise agentic attack chains in an isolated, instrumented environment
- **DevSecOps engineers** — integrate OTel GenAI instrumentation patterns into CI/CD pipelines

---

---


## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Host Machine                                        │
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌─────────────────────────────┐  │
│  │ Attack Panel │───▶│ Banking App  │───▶│ Ollama (llama3.2:1b)        │  │
│  │  :5001       │    │  :5000       │    │  :11434 (internal)          │  │
│  └──────────────┘    └──────┬───────┘    └─────────────────────────────┘  │
│                             │                                               │
│                             │ OTLP (traces, metrics, logs)                  │
│                             ▼                                               │
│                    ┌─────────────────┐                                      │
│                    │ OTel Collector  │                                      │
│                    │ :4317 / :4318   │                                      │
│                    └────────┬────────┘                                      │
│                             │ HEC                                           │
│                             ▼                                               │
│                    ┌─────────────────┐     ┌──────────────────────────┐   │
│                    │ Splunk          │────▶│ acme_genai_compliance    │   │
│                    │ :8000 / :8088   │     │ (dashboard + lookups)    │   │
│                    └─────────────────┘     └──────────────────────────┘   │
│                                                                             │
│  Network: acme_mesh (Docker bridge)                                         │
│  Volume: shared_telemetry → /var/log/acme_sentinel                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Banking App** (`app_runtime.py`) runs a 4-agent transaction chain. Each agent calls Ollama for real LLM inference.
2. **AcmeGate / AcmeSentinel** middleware scans every prompt and model response. On threat detection the pipeline is blocked and a security event is emitted.
3. **OpenTelemetry** exports GenAI metrics, traces, and security logs to the OTel Collector on port `4318`.
4. **OTel Collector** forwards everything to Splunk HEC as `sourcetype=otel:agentic:json` in the `acme_agentic_telemetry` index.
5. **Attack Panel** (`exploit_ui.py`) fires real adversarial payloads at targeted banking agents.
6. **Splunk Compliance App** joins live telemetry against framework crosswalks and visualizes threats, kill-chains, and compliance posture.

### Ollama Model Selection

The app does **not** auto-pick a model per agent or task. One model is configured for the entire lab:

| Step | What happens |
|------|----------------|
| `.env` | Set `OLLAMA_MODEL` (default `llama3.2:1b`) |
| Container start | `scripts/ollama_init.sh` pulls that model into Ollama |
| Every agent call | `llm_client.py` posts to `/api/generate` with the same model name |

To switch models, change `OLLAMA_MODEL` in `.env` and restart the stack. The banking dashboard reports whether the configured model is loaded (`GET /api/v1/ollama/health`).

### Splunk Integration (How It Connects)

This is **not** a direct Splunk SDK integration inside the Python apps. Telemetry flows through a standard observability pipeline:

| Layer | Role |
|-------|------|
| **Banking / attack apps** | Emit OTLP logs, traces, and metrics to the OTel Collector (`:4318`) |
| **OTel Collector** | Batches and forwards to Splunk via the **HEC exporter** (`splunk_hec`) |
| **Splunk index** | Stores events as `index=acme_agentic_telemetry`, `sourcetype=otel:agentic:json` |
| **Splunk compliance app** | Dashboards, lookups, and saved searches query that index — it does not run the LLM |

**Local mode:** Splunk runs in Docker; HEC points at `http://splunk:8088`.  
**Splunk Cloud / Enterprise:** No local Splunk container — point `.env` HEC settings at your Cloud or on-prem endpoint and install the packaged app. See [splunk_app/INSTALL.md](splunk_app/INSTALL.md).

---

---
