# AgentWatch Range — User Guide

Run the lab from the **Attack Panel**, generate telemetry, hunt in Splunk, and **light up** the GenAI Compliance Monitor app.

**Attack Panel:** http://localhost:5001  
**Banking app:** http://localhost:5000  
**Splunk:** http://localhost:8000 (local Docker profile)

> **Terminology:** The Attack Panel and workshop use **Scenario 1–10** (one per agentic threat surface). In Splunk telemetry the scenario index is stored in the numeric field `campaign_week` (values 1–10) — use that field in SPL, not the phrase “campaign week” in reports or training materials.

**New here?** Complete [Prerequisites](#prerequisites), verify [baseline in Splunk](../README.md#step-4--verify-telemetry-before-any-attack-3-min), then read:

- **[Learning Path (Tiers 0–6)](LEARNING_PATH.md)** — structured curriculum: beginner → advanced → compliance → capstone  
- **[Attack Panel tab guide](ATTACK_PANEL_GUIDE.md)** — what each tab means, OUTCOME, SPL + dashboard per scenario  
- **[Workshop paths](#workshop-paths--where-to-start-what-to-run-where-to-end)** — guided button sequences

---

## Prerequisites

> **Complete checklist:** **[PREREQUISITES.md](PREREQUISITES.md)** — hardware, Docker install (Ubuntu/macOS/Windows), `docker.sock` permissions, Splunk one-time setup, verification.

```bash
git clone https://github.com/machowdhury/AgentwatchRange.git
cd AgentwatchRange
cp .env.example .env
docker compose --profile local up --build -d
```

> **Cloud VM (AWS EC2 / Azure / Google Compute Engine):** See [docs/CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md) for which ports to open on security groups / firewalls (`5000`, `5001`, `8000` restricted — never expose `8088`, `11434`, or OTel ports to the internet).

Wait for Ollama (`docker compose logs -f ollama`). Then install Splunk apps and configure HEC — see checklist below or [WORKSHOP.md Exercise map](WORKSHOP.md#exercise-map-follow-in-order).

Confirm the panel header shows **TARGET ONLINE** and **LLM ONLINE** before firing attacks.

**Splunk quick checklist** (do once after `docker compose up`):

1. `./scripts/package_splunk_app.sh` — build compliance app tarball
2. `./scripts/splunk_install_apps.sh` — installs compliance app + MLTK from `splunk_app/splunk-ai-toolkit_600.tgz`
3. `./scripts/splunk_local_bootstrap.sh` — enables HEC, creates index `acme_agentic_telemetry`, creates token matching `.env`
4. **Verify baseline (before attacks):** submit one normal loan on http://localhost:5000 *or* wait 2–3 min for auto traffic, then:

   ```spl
   index=acme_agentic_telemetry earliest=-15m | stats count by testbed_mode
   ```

   **Pass:** count > 0 (`BASELINE_TRAFFIC` and/or `BANKING_LIVE`)

5. If OTel was running before HEC: `docker compose --profile local restart otel_collector`

Open http://localhost:5001 — default tab is **Top 10 Scenarios**. Check header **TARGET ONLINE** and **LLM ONLINE** before firing attacks.

**Banking app** (http://localhost:5000): after **Run Through All Agents**, click **↺ Refresh Sessions** to reload the pipeline history table.

---

## The Workshop

> **Start here:** **[WORKSHOP.md → Exercise map](WORKSHOP.md#exercise-map-follow-in-order)** — numbered checklist from install through first hunt.  
> **Full curriculum:** **[WORKSHOP.md](WORKSHOP.md)** — Levels 0–5, hunt questions Q101–Q503, role tracks.

The AgentWatch Range Workshop is a **hands-on lab**, not theory-only training: learners attack a live multi-agent banking app, observe runtime controls (block / allow / detect-only), and **prove outcomes in Splunk**.

Use the Attack Panel **Workshop** tab (**last menu item**) for one-click guided paths. Use **Top 10 Scenarios** (default tab) for individual exercises. **Splunk Search** is where learners answer hunt questions — same pattern as [Splunk BOTS](https://github.com/splunk/botsv3).

> **Rule:** Wait **60 seconds** after any Attack Panel path finishes before running SPL in Splunk.

---

## Workshop paths — where to start, what to run, where to end

This section is the **on-ramp**. It explains each Workshop button, the maturity level it maps to, the Splunk queries to prove success, and what to do next.

### Where everyone starts

| Step | Where | Action | Pass when |
|------|-------|--------|-----------|
| **0** | Terminal + Splunk | Install stack, apps, HEC — [Prerequisites](#prerequisites) | `index=acme_agentic_telemetry earliest=-15m \| stats count` > 0 |
| **1** | Attack Panel → **Workshop** tab | Click **15-Minute First Win** | Q101–Q103 return rows (below) |

**Do not skip Level 0.** Without HEC and the compliance app, Workshop buttons fire attacks but Splunk stays empty.

### Maturity lifecycle (start → end)

```text
LEVEL 0  Install & verify ingest          ← START (everyone)
   ↓
LEVEL 1  15-Minute First Win              ← first attack path (everyone)
   ↓
LEVEL 2  SOC hunts (Q201–Q210)            ← junior / mid analyst depth
   ↓
LEVEL 3  Standard Workshop (KC-C001)    ← senior analyst / correlation
   ↓
LEVEL 4  Deep Workshop + optional Cisco   ← detection engineering / coverage
   ↓
LEVEL 5  MAESTRO Validate + Fire All 10    ← END (architect / GRC evidence)
```

| If you are… | Start at | Realistic end state |
|-------------|----------|---------------------|
| **Executive / taster** | Level 0 + First Win | Level 1 — prove pipeline works |
| **Junior SOC analyst** | Level 0 + First Win | Level 2 — write basic hunts |
| **Senior SOC / IR** | Level 1 | Level 3 — `incident_id` correlation |
| **Detection engineer** | Level 1 | Level 4 — Technique Coverage Matrix |
| **Architect** | Level 1 | Level 5A — MAESTRO validate path |
| **GRC / compliance** | Level 1 | Level 5B — Fire All 10 + NIST dashboards |

Full hunt questions and facilitator notes: **[WORKSHOP.md](WORKSHOP.md)** (includes emerging-threat hunts **Q504–Q509** for AML.T0070–T0075).

### Emerging threats (2026 append)

Six techniques (**AML.T0070–T0075**) extend the registry without changing the Top 10 golden path. See [THREAT_SURFACES.md](THREAT_SURFACES.md) and [ATTACK_PANEL_GUIDE.md](ATTACK_PANEL_GUIDE.md#1b-emerging-threat-techniques-amlt0070t0075).

---

### 1. 15-Minute First Win

| | |
|--|--|
| **Maturity** | Level 1 — Pipeline proof |
| **Time** | ~15 minutes |
| **Who** | **Everyone** — your first hands-on win |
| **Attack Panel** | **Workshop** tab (last) → **RUN FIRST WIN PATH** |
| **What runs** | Scenario **6** (MCP tools) → **5** (output gateway) → **9** (RAG detect-only) |
| **What you learn** | Three control philosophies: block **before** LLM, block/deny **after** LLM, **detect-only** |
| **Splunk dashboards** | Overview · Control Attestation · Detection Efficacy |

**What to do**

1. Confirm Attack Panel header: **TARGET ONLINE** + **LLM ONLINE**.
2. Click **RUN FIRST WIN PATH**; wait for the path to finish (~3–5 min of attacks + delays).
3. Wait **60 seconds**, then open Splunk Search.

**Queries to run (pass criteria)**

```spl
`acme_genai_index` earliest=-30m campaign_week=6
| stats count by workflow.blocked workflow.block_reason
```
**Pass:** `workflow.blocked=true` on Scenario 6 (pre-LLM tool block).

```spl
`acme_genai_index` earliest=-30m campaign_week=5
| table acme_output_guard.action acme_output_guard_blocked workflow.blocked
```
**Pass:** You see `acme_output_guard.action` (e.g. `HARD_DENY` or `ALLOW`) — output-side control fired or allowed.

```spl
`acme_campaign_w9` earliest=-30m
| table workflow.blocked galileo_observe_alert control.status
```
**Pass:** Events exist; discuss detect-only (alert may fire without hard block).

**Next step:** Level 2 hunts ([WORKSHOP.md Level 2](WORKSHOP.md#level-2--soc-hunts-junior--senior-analyst)) or jump to **Standard Workshop** if you are a senior analyst.

---

### 2. Standard Workshop

| | |
|--|--|
| **Maturity** | Level 3 — Correlation |
| **Time** | ~25 minutes |
| **Who** | Senior SOC, incident responders |
| **Prerequisite** | Level 1 (First Win) complete |
| **Attack Panel** | **Workshop** tab → **RUN STANDARD WORKSHOP** |
| **What runs** | First Win (6 → 5 → 9) + kill chain **KC-C001** (Fraudulent Loan Pipeline) |
| **What you learn** | Single-surface attacks vs **multi-stage** stories tied by `incident_id` |
| **Splunk dashboards** | Actor Chain Story · Kill-Chain Timeline · Detection Efficacy |

**Queries to run**

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats dc(kill_chain.stage) AS stages values(kill_chain.stage) BY incident_id
```
**Pass:** Multiple `kill_chain.stage` values for one `incident_id`.

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats values(gen_ai.agent.name) AS agents BY incident_id
```
**Pass:** More than one agent name in the chain.

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats count by incident_id workflow.blocked acme_output_guard_blocked
```
**Pass:** You can narrate which stages blocked vs reached the model.

**Next step:** **Deep Workshop** (coverage) or **Fire All 10** (GRC breadth).

---

### 3. Deep Workshop

| | |
|--|--|
| **Maturity** | Level 4 — Detection engineering |
| **Time** | ~45+ minutes (includes **RUN ALL 45 TECHNIQUES** ~10–20 min) |
| **Who** | Detection engineers, purple team |
| **Prerequisite** | Standard Workshop recommended |
| **Attack Panel** | **Workshop** tab → **RUN DEEP WORKSHOP** |
| **What runs** | Standard Workshop + full **45-technique registry** (LIVE + SIMULATED + HYBRID) |
| **What you learn** | MITRE ATLAS **coverage math** — OBSERVED vs NOT_OBSERVED |
| **Splunk dashboards** | Technique Coverage Matrix · Detection Efficacy · Threat Hunting |

**Queries to run**

Open **Technique Coverage Matrix** dashboard (preferred), or:

```spl
`acme_genai_index` earliest=-24h
| stats count by technique_id
| sort -count
```
**Pass:** Multiple `technique_id` values; dashboard shows OBSERVED % > 0.

```spl
`acme_genai_index` earliest=-24h
| stats count by testbed_mode
```
**Pass:** Mix of live attack events and simulated technique events.

**Next step:** Optional **Cisco + MLTK** overlay, or **MAESTRO Validate** for architects.

---

### 4. Fire All 10 Scenarios

| | |
|--|--|
| **Maturity** | Level 5B — Compliance / GRC evidence |
| **Time** | ~5–10 minutes (automated sequence) |
| **Who** | GRC, risk, security leadership demos |
| **Prerequisite** | Level 1 minimum; best after Level 3–4 |
| **Attack Panel** | **Workshop** tab → **FIRE ALL 10 SCENARIOS** |
| **What runs** | Scenarios **1–10** in order (all eight agentic surfaces) |
| **What you learn** | Full control attestation and framework coverage in one pass |
| **Splunk dashboards** | Control Attestation · NIST AI RMF Scoring · Technique Heatmap |

**Queries to run**

```spl
`acme_genai_index` earliest=-1h
| stats latest(control.status) AS control_status BY campaign_week control.control_id
| sort campaign_week
```
**Pass:** Rows for scenarios 1–10 with PASS/FAIL control evidence.

```spl
`acme_genai_index` earliest=-1h
| stats dc(campaign_week) AS scenarios_seen
```
**Pass:** `scenarios_seen=10`.

**Next step:** Export dashboard screenshots for audit packs; re-run after control changes for regression.

---

### 5. MAESTRO Validate Path

| | |
|--|--|
| **Maturity** | Level 5A — Architecture validation |
| **Time** | ~60–90 minutes (includes external MAESTRO UI) |
| **Who** | Security architects, threat modelers |
| **Prerequisite** | Level 1; CSA MAESTRO running on **http://localhost:9002** — [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md) |
| **Attack Panel** | **Workshop** tab → **RUN MAESTRO VALIDATE PATH** |
| **What runs** | Copies architecture blurb → you threat-model in MAESTRO → fires Scenarios **6, 8, 9, 10** |
| **What you learn** | Design-time threats (MAESTRO layers L2–L6) vs runtime telemetry proof |
| **Splunk dashboards** | Detection Efficacy · MAESTRO layer panels · Control Attestation |

**What to do**

1. Start MAESTRO on `:9002` (host, not Docker).
2. Run **MAESTRO VALIDATE PATH**; paste architecture into MAESTRO when prompted.
3. After attacks, prove predicted layers fired in Splunk.

**Query to run**

```spl
`acme_genai_index` earliest=-30m
| mvexpand framework.maestro_layers
| search framework.maestro_layers=L*
| stats dc(framework.maestro_layers) AS layers_at_risk
| eval maestro_coverage_pct=round(layers_at_risk/7*100,1)
```
**Pass:** `maestro_coverage_pct` > 50 after validation scenarios.

**Next step:** Document gaps where MAESTRO predicted risk but telemetry did not fire — detection backlog.

---

### 6. Cisco + MLTK Anomaly Hunt

| | |
|--|--|
| **Maturity** | Level 4B — Optional overlay |
| **Time** | ~30 minutes |
| **Who** | Splunk practitioners, teams using Cisco AI Defense + MLTK |
| **Prerequisite** | MLTK installed (`splunk_install_apps.sh`); Cisco overlay: `docker compose -f docker-compose.yml -f docker-compose.cisco.yml --profile local up -d` — [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md) |
| **Attack Panel** | **Workshop** tab → **RUN CISCO + MLTK PATH** |
| **What runs** | Preflight checks + Scenarios **1, 6, 7, 9** |
| **What you learn** | AIBOM drift, MCP scan telemetry, CTSM token anomaly patterns |
| **Splunk dashboards** | MLTK Anomaly Hunting · Detection Efficacy · Threat Hunting |

**Queries to run**

```spl
`acme_campaign_w1` earliest=-30m
| table cisco_aibom_status agent.aibom_validated model_artifact_hash_expected model_artifact_hash_found
```
**Pass:** AIBOM fields populated after Scenario 1.

```spl
`acme_genai_index` earliest=-30m campaign_week=7
| table gen_ai.usage.input_tokens gen_ai.usage.output_tokens cisco_tsm_anomaly_score mltk.ctsm_signal
```
**Pass:** Token usage + anomaly score fields for cost/DoS hunting.

Open **MLTK Anomaly Hunting** dashboard for CTSM forecast panels.

**Next step:** Return to **Deep Workshop** coverage or production rule tuning.

---

### Quick reference — all Workshop buttons

| Button | Level | Runs | First SPL to run |
|--------|-------|------|------------------|
| **15-Minute First Win** | 1 | Scenarios 6 → 5 → 9 | `` `acme_campaign_w6` earliest=-30m \| stats count by workflow.blocked `` |
| **Standard Workshop** | 3 | First Win + KC-C001 | `` `acme_genai_index` incident_id=* \| stats dc(kill_chain.stage) BY incident_id `` |
| **Deep Workshop** | 4 | Standard + All 45 | Open **Technique Coverage Matrix** |
| **Fire All 10** | 5B | Scenarios 1–10 | `` `acme_genai_index` \| stats dc(campaign_week) AS scenarios_seen `` |
| **MAESTRO Validate** | 5A | Arch + 6,8,9,10 | MAESTRO layer coverage SPL (above) |
| **Cisco + MLTK** | 4B | Preflight + 1,6,7,9 | `` `acme_campaign_w1` earliest=-30m \| table cisco_aibom_status `` |

---

## Beyond the Workshop — expand your knowledge

The Workshop is the **on-ramp**. For **every tab, scenario, chain, and SPL query**, see **[ATTACK_PANEL_GUIDE.md](ATTACK_PANEL_GUIDE.md)**.

Use this map to decide what to explore next and **why** each capability exists.

### Learning progression

Follow **[LEARNING_PATH.md](LEARNING_PATH.md)** for tier-ordered curriculum (Tier 0 orientation → Tier 6 capstone). The map below is the same journey by Attack Panel tab:

```text
Tier 0 — Orientation (CONCEPTS + baseline Splunk)
    ↓
Tier 1–3 — Top 10 Scenarios + Threat Chains (guided surfaces)
    ↓
Tier 4 — All 51 Techniques bulk run (compliance evidence)
    ↓
Tier 5 — Cisco + MLTK overlay (optional)
    ↓
Tier 6 — Workshop capstone paths
```

```text
Workshop (guided paths)
    ↓
Top 10 Scenarios (one surface at a time, Full Pipeline variant)
    ↓
Threat Chains (multi-stage stories, incident_id correlation)
    ↓
All 45 Techniques (MITRE breadth, LIVE / SIMULATED / HYBRID modes)
    ↓
Custom Payload (your own strings, agent targeting)
    ↓
Splunk Threat Hunting + SPL macros (practitioner hunts)
```

### Additional capabilities — what, why, when

| Capability | Where | What it adds beyond Workshop | Why we built it |
|------------|-------|------------------------------|-----------------|
| **Individual scenarios** | Top 10 tab | Pause on one surface; use **Preview Payload** | Deep-dive a single OWASP / NIST mapping in class |
| **Full Pipeline** | Top 10 → ⚡ on any card | Same attack through **all 4 agents** | Shows how one payload propagates across an agent chain |
| **Threat Chains (KC-*)** | Threat Chains tab | 5-stage rogue-actor narratives | Teaches kill-chain thinking and `incident_id` hunts |
| **45-technique registry** | All 45 tab | Full MITRE ATLAS library; per-technique **EXECUTE** | Proves detection **coverage %**, not just 10 demos |
| **LIVE vs SIMULATED vs HYBRID** | Technique cards | Some threats cannot be ethically live-fired | Supply-chain / recon style events still appear in Splunk for hunts |
| **Custom Payload** | Custom tab | Your own injection strings | Red-team exercises and variant testing |
| **Control Attestation dashboard** | Splunk app | NIST pass/fail per scenario | Bridges security engineering and governance audiences |
| **Detection Efficacy dashboard** | Splunk app | Coverage %, MTTD, chain completeness | Answers “are we measuring agentic risk?” with numbers |
| **Technique Coverage Matrix** | Splunk app | OBSERVED vs NOT_OBSERVED grid | Prioritize purple-team backlog from evidence |
| **Actor Chain Story** | Splunk app | Timeline per `incident_id` | SOC-style narrative for leadership |
| **Threat Hunting playbooks** | Splunk app | Starter SPL per technique | Graduates learners from buttons to queries |

### Suggested expansion paths by goal

| Your goal | After Workshop, do this |
|-----------|------------------------|
| Teach **one** surface deeply (e.g. MCP tools) | Top 10 → Scenario 6 only → run hunt SPL → discuss BLOCKED vs INJECTED |
| Teach **pipeline** risk | Same scenario with **⚡ Full Pipeline** → compare single-agent vs 4-agent events |
| Teach **SOC correlation** | Threat Chains → KC-A001 and KC-D001 → Actor Chain Story + correlation SPL |
| Build a **coverage report** | All 45 → RUN ALL 45 → Technique Coverage Matrix screenshot + NOT_OBSERVED list |
| Teach **governance** | Fire All 10 → Control Attestation + NIST AI RMF Scoring walkthrough |
| Run a **mini red team** | Custom tab + mix of chains; learners write hunts in Splunk |

---

## What we built the Workshop with (lab stack)

The Workshop is not a separate product — it orchestrates components already in AgentWatch Range. Understanding the stack helps you explain the lab credibly and troubleshoot when something does not light up.

### End-to-end flow

```text
Workshop button (Attack Panel :5001)
    → REST API (/api/exploit, /api/chains, /api/techniques/execute-all)
    → Banking app (:5000) — 4 agents, workflow guards, AcmeGate, AcmeSentinel
    → Ollama (:11434) — live LLM inference (llama3.2:1b by default)
    → OpenTelemetry spans + security attributes
    → OTel Collector (:4318) — batch, enrich
    → Splunk HEC (:8088) — index acme_agentic_telemetry
    → GenAI Compliance Monitor app — dashboards, macros, hunts
```

### Components called by Workshop paths

| Component | Role in Workshop | Path / artifact |
|-----------|------------------|-----------------|
| **Attack Panel** (`apps/exploit_ui.py`) | UI, Workshop sequencer, terminal feed | http://localhost:5001 |
| **Workshop definitions** | Step lists, delays, Splunk checklist (client-side `WORKSHOPS` object) | Attack Panel **Workshop** tab (last) |
| **Banking app** (`apps/app_runtime.py`, `agents/agent_router.py`) | Agent APIs, pipeline, OTel export | http://localhost:5000 |
| **Attack payloads** (`apps/framework/attack_payloads.py`) | Scenarios 1–10 adversarial strings + metadata | Used by `/api/exploit/<n>` |
| **Workflow guard** (`apps/framework/workflow_guard.py`) | Pre-LLM policy — orchestration, MCP, A2A, memory | Scenarios 2, 6, 8, 10 |
| **MCP gateway** (`apps/framework/mcp_gateway.py`) | Tool scope enforcement | Scenario 6, KC-C001 stages |
| **A2A verifier** (`apps/framework/a2a_verifier.py`) | Delegation / DID checks | Scenario 8, KC-D001 |
| **Memory policy** (`apps/framework/memory_policy.py`) | Persistent instruction abuse | Scenario 10 |
| **RAG store / probe** (`apps/framework/rag_store.py`) | Retrieval anomaly telemetry | Scenario 9, KC-A001 |
| **Orchestration guard** (`apps/framework/orchestration_guard.py`) | Supervisor bypass detection | Scenario 2 |
| **AcmeGate** (in `llm_client.py`) | Input pattern block | Scenario 3 |
| **AcmeSentinel** (in `llm_client.py`) | Output HARD_DENY | Scenario 5 |
| **Control validator** (`control_validator.py` + `control_matrix.yaml`) | NIST pass/fail on emit | Control Attestation dashboard |
| **Technique executor** (`apps/framework/technique_executor.py`) | 45 MITRE playbooks (LIVE/SIM/HYBRID) | Deep Workshop, All 45 tab |
| **Kill chain engine** (`apps/framework/chain_engine.py`) | KC-A001…E001 staged execution + `incident_id` | Standard Workshop |
| **Ollama** | Local LLM — non-deterministic BLOCKED vs INJECTED | Docker service `ollama` |
| **OTel Collector** | OTLP → Splunk HEC + optional JSONL | `otel_collector` in compose |
| **Splunk compliance app** | Dashboards, lookups, macros `` `acme_campaign_w1` `` … | `splunk_app/splunk_compliance_app/` |

### Splunk artifacts the Workshop expects

| Artifact | Purpose |
|----------|---------|
| Index `acme_agentic_telemetry` | Stores all workshop-generated events |
| Sourcetype `otel:agentic:json` | HEC routing |
| Macro `` `acme_genai_index` `` | Base search for all dashboards |
| Macros `` `acme_campaign_w1` `` … `` `w10` `` | Per-scenario hunts (match Scenario 1–10) |
| Lookups `acme_framework_lookup`, `acme_control_matrix_lookup` | Technique matrix + NIST attestation |
| Dashboards Overview, Detection Efficacy, Control Attestation, Technique Coverage Matrix, Actor Chain Story | Workshop completion checklists |

### What is real vs simulated (teach this honestly)

| Real | Simulated / enriched (still valid for hunts) |
|------|---------------------------------------------|
| HTTP attack traffic, Ollama inference | Some 45-technique **SIMULATED** events (supply chain, recon) |
| AcmeGate / AcmeSentinel / workflow guard decisions | SOAR containment fields (lab stub, not a live SOAR) |
| OTel → Splunk pipeline (when HEC configured) | “Cisco” product names on fields — lab middleware, not commercial products |
| Kill chain **HYBRID** stages where live LLM applies | Accelerated chain timing (`accelerated: true`) |

Saying this out loud in a workshop builds trust and mirrors how production ranges mix live execution with safe simulation.

---

## Attack Panel — all options

Everything at **http://localhost:5001**. Five tabs on the left (light theme for readability); **Real-Time Attack Feed** on the right.

**Tab order:** Top 10 Scenarios (default) → All 45 Techniques → Threat Chains → Custom Payload → **Workshop (last)**

```
Click (Scenario / Chain / Workshop path) → Banking app → Ollama → OTel → Splunk → Dashboard
```

### Tab 1 — Top 10 Scenarios (default)

| Button | What it does |
|--------|----------------|
| **Run scenario n** | One adversarial payload to one agent (fastest demo). |
| **Full Pipeline** | Same payload through all **4 agents** in sequence. |
| **Preview Payload** | Raw attack string (does not fire). |

Cards are labeled **Scenario n — SURFACE** (e.g. Scenario 6 — TOOLS SURFACE). See [THREAT_SURFACES.md](THREAT_SURFACES.md).

---

### Tab 2 — All 45 Techniques

| Button | What it does |
|--------|----------------|
| **↻ Reload Catalog** | Refresh 45 technique cards. |
| **⚡ RUN ALL 45 TECHNIQUES** | Full registry (LIVE + SIMULATED + HYBRID). ~10–20 min. |
| **▶ EXECUTE** (per card) | One technique (e.g. `AML.T0050`). |

| Mode | Meaning |
|------|---------|
| **LIVE** | Real Ollama call |
| **SIMULATED** | Enriched OTel only |
| **HYBRID** | Both |

---

### Tab 3 — Threat Chains

| Button | What it does |
|--------|----------------|
| **▶ EXECUTE THREAT CHAIN** | All stages with shared `incident_id`. |

| Chain | Name |
|-------|------|
| KC-A001 | Silent Data Harvest |
| KC-B001 | Trojan Model Operation |
| KC-C001 | Fraudulent Loan Pipeline |
| KC-D001 | Agent Impersonation Cascade |
| KC-E001 | Denial-of-Wallet |

---

### Tab 4 — Custom Payload

Custom string, agent picker, optional **Full Pipeline**, **Execute**.

---

### Tab 5 — Workshop (last — guided learning paths)

| Button | Duration | What runs | Splunk dashboards to open |
|--------|----------|-----------|---------------------------|
| **RUN FIRST WIN PATH** | ~15 min | Scenarios 6 → 5 → 9 | Control Attestation, Detection Efficacy, Overview |
| **RUN STANDARD WORKSHOP** | ~25 min | First Win + chain **KC-C001** | + Actor Chain Story |
| **RUN DEEP WORKSHOP** | ~45+ min | Standard + **RUN ALL 45** | + Technique Coverage Matrix |
| **FIRE ALL 10 SCENARIOS** | ~5 min | Scenarios 1–10 sequential | Control Attestation, NIST AI RMF |
| **MAESTRO VALIDATE PATH** | varies | Architecture + scenarios 6,8,9,10 | MAESTRO layer coverage |
| **CISCO + MLTK PATH** | ~30 min | Preflight + 1,6,7,9 | MLTK Anomaly Hunting |

Progress and a Splunk checklist appear in the panel after each path completes.

---

## Light up the Splunk Compliance App

**“Lit up”** = events in `index=acme_agentic_telemetry`, macros resolve, dashboards show **non-zero** panels.

### What to click → dashboard → why

After each action: wait **30–60 seconds**.

| Your goal | What to click | Dashboard | Why it populates |
|-----------|---------------|-----------|------------------|
| Prove telemetry | **Workshop** tab → First Win, or **Top 10** → any scenario | **Overview** | `gen_ai.agent.*` on `otel:agentic:json` events |
| Input/output blocking | **Scenario 3** or **5** | **Control Attestation** | `acme_input_guard_blocked`, `acme_output_guard.action`, `control.status` |
| Workflow-surface blocks | **Scenario 2**, **6**, or **8** | **Detection Efficacy** | `workflow.block_reason` (orchestration, MCP, A2A) |
| All 10 surfaces | **FIRE ALL 10 SCENARIOS** (Workshop) | **Control Attestation** | Scenarios 1–10 + NIST fields |
| Technique breadth | **RUN ALL 45** or Deep Workshop | **Technique Coverage Matrix** | `technique_id` → OBSERVED / NOT_OBSERVED |
| Multi-stage story | **KC-C001** or Standard Workshop | **Actor Chain Story** | Shared `incident_id` across stages |
| Detect-only RAG | **Scenario 9** | Threat Hunting / Overview | `galileo_observe_alert` without always blocking |
| Token / cost abuse | **Scenario 7** or **KC-E001** | **Detection Efficacy** | `gen_ai.usage.*_tokens`, `call_depth_detected` |

### Minimum viable check (2 minutes)

1. **Workshop** tab (last) → **RUN FIRST WIN PATH** (or **Top 10** → Scenario 6)
2. Splunk:

```spl
`acme_campaign_w6` earliest=-15m
| table _time tool.scope_violation workflow.block_reason control.status
```

3. **Control Attestation** — scenario 6 row has data  
4. **Overview** — event count > 0  

### Macro tweak

If Search has data but dashboards are empty, edit macro **`acme_genai_index`** to match your index name.

---

## GenAI Compliance Monitor — dashboard & visualization guide

**App name in Splunk:** GenAI Compliance Monitor (`acme_genai_compliance` v2.3+)  
**Install:** `./scripts/splunk_install_apps.sh` (local Docker — compliance + MLTK) or `./scripts/package_splunk_app.sh` → upload to Splunk Cloud  
**Validate (Cloud/Enterprise):** `./scripts/validate_splunk_app.sh` — see [splunk_app/CLOUD_VETTING.md](../splunk_app/CLOUD_VETTING.md)

All dashboards read `` `acme_genai_index` `` (default: `index=acme_agentic_telemetry sourcetype="otel:agentic:json"`). Empty panels mean no telemetry yet — run a Workshop path first.

**Note:** Scheduled detection saved searches ship **disabled** for Splunk Cloud-safe install. Enable them under **Settings → Searches, reports, and alerts** after HEC ingest is verified (see **Setup Guide** dashboard).

### Navigation map

| # | Menu label | Primary audience | One-line purpose |
|---|------------|------------------|------------------|
| 1 | **Setup Guide** | Admin | HEC, index, macros, Splunk Cloud wiring |
| 2 | **Overview** | Everyone | “Is the lab alive?” — event volume, severity, agents |
| 3 | **Detection Efficacy** | Detection engineer | Coverage %, MTTD, workflow blocks, chain completeness |
| 4 | **Control Attestation** | GRC / risk | NIST pass/fail per scenario |
| 5 | **Technique Coverage** | Purple team | OBSERVED vs NOT_OBSERVED for all 45 techniques |
| 6 | **Threat Hunting** | SOC analyst | Per-technique SPL playbooks + live results |
| 7 | **Actor Chain Story** | Leadership / SOC | Rogue-actor narrative per `incident_id` |
| 8 | **ATLAS Matrix Heatmap** | Framework mapping | Tactic×technique matrix (GAP / OBSERVED / DETECTED) |
| 9 | **Kill-Chain Timeline** | Incident responder | Forensic timeline per kill-chain incident |
| 10 | **NIST AI RMF Scoring** | Compliance | OWASP / NIST / MAESTRO posture scores |
| 11 | **Dataset Export** | ML / research | HuggingFace export readiness |
| 12 | **Search** | Power user | Raw SPL |

### Status colors used across the app

| Label / color | Meaning |
|---------------|---------|
| **GAP** / grey | Technique in catalog but **no events** in time range — run lab attack to fill |
| **OBSERVED** / blue | Technique fired; telemetry exists (may or may not be blocked) |
| **DETECTED** / red | Technique observed **and** blocked (`workflow`, AcmeGate, or AcmeSentinel) |
| **NOT_OBSERVED** / green (OWASP tables) | Risk category with **no** matching events (good for compliance score) |
| **ACTIVE** / yellow–red (OWASP) | Risk category seen in telemetry |
| **PASS / FAIL** (Control Attestation) | NIST control evidence from `control.status` |
| **NOT_TESTED** | Scenario never fired in time range |

---

### 1 — Setup Guide

Static HTML walkthrough (not data-driven).

| Section | What it means |
|---------|----------------|
| Package & install | Build `.tar.gz` from repo; upload to Splunk Cloud or Enterprise |
| Index + HEC | Create `acme_agentic_telemetry` and token for `otel:agentic:json` |
| OTel collector | Point AgentWatch Range `.env` at your HEC endpoint |
| Macros | Edit `` `acme_genai_index` `` if your index name differs |
| Health check SPL | Verify events before opening other dashboards |

**Light up:** Complete once per environment. No attacks required.

---

### 2 — Overview (default landing page)

**Purpose:** Prove ingest works and show high-level security posture.

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Total Security Events (7d) | Single value | All agentic OTel events — **>0 means pipeline works** |
| Critical Severity Events | Single value | Events tagged `framework.severity=Critical` |
| Active Kill-Chain Incidents | Single value | Distinct `incident_id` with `testbed_mode=KILL_CHAIN_ACTIVE` |
| AcmeSentinel HARD_DENY Blocks | Single value | Output-side blocks in last 24h |
| Unique Agents Monitored | Single value | How many `agent.id` values sent telemetry |
| Security Events Over Time by Severity | Stacked area chart | Attack/benign traffic trend by severity |
| Events by MITRE ATLAS Tactic | Bar chart | Which [ATLAS tactics](https://atlas.mitre.org/) appear most in your data |
| OWASP LLM Top 10 — Active Risk Status | Table | LLM01–LLM10: NOT OBSERVED vs ACTIVE vs CRITICAL ACTIVE |
| OWASP ASI Agentic Top 10 — Active Risk Status | Table | ASI01–ASI10 agentic risks |
| Top 10 Agents by Risk Score | Table | Agents ranked by max CVSS and technique diversity |
| Recent AcmeSentinel Actions | Table | Last 20 output-gateway decisions (HARD_DENY, ALERT, etc.) |

**Light up:** Banking app benign loan **or** Workshop **First Win**.  
**Best for:** First live demo — “we have telemetry.”

---

### 3 — Detection Efficacy

**Purpose:** Measurable detection program metrics (not just event counts).

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Technique Coverage % | Single % | Observed techniques ÷ 45 catalog entries |
| MTTD (seconds, blocked events) | Single value | Avg time to block (workflow/AcmeGate/AcmeSentinel) |
| Chain Incidents | Single value | Count of `ACME-INC-*` correlated incidents |
| Control Pass Rate % | Single % | Latest `control.pass_rate_pct` from attestation |
| Kill-Chain Stage Completeness | Table | Per `incident_id`: how many kill-chain stages seen (HIGH/MEDIUM/LOW) |
| Workflow Surface Blocks | Pie chart | Breakdown of `workflow.block_reason` (MCP, A2A, orchestration, memory) |
| Scenario Activity | Chart | Events per scenario (1–10) |

**Light up:** **First Win** (workflow blocks) + **Standard Workshop** (chains) + **Deep Workshop** (coverage %).  
**Best for:** “We can measure agentic detection efficacy.”

---

### 4 — Control Attestation

**Purpose:** Governance evidence — which NIST controls passed or failed per lab scenario.

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Controls Passed / Failed | Single values | Sum of `control.pass_count` / `control.fail_count` |
| Latest Pass Rate | Single % | Most recent `control.pass_rate_pct` |
| NIST Control Matrix | Table | Each scenario (week 1–10): expected control, pass signal, **PASS / FAIL / NOT_TESTED** |

Filters: time range, scenario (1–10).

**Light up:** **FIRE ALL 10 SCENARIOS** or run scenarios individually.  
**Best for:** Risk and compliance audiences.

---

### 5 — Technique Coverage

**Purpose:** Practitioner matrix — every catalog technique vs your telemetry.

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Techniques Observed | Single value | Count of distinct `technique_id` seen |
| Coverage % | Single % | Observed ÷ 45 |
| Top-10 Live Scenarios Fired | Single value | Techniques flagged `is_top_10=true` |
| Full Technique Matrix | Table | Per technique: **OBSERVED / NOT_OBSERVED**, event count, incidents, LIVE/SIM/HYBRID mode |

Filter: execution mode (LIVE / SIMULATED / HYBRID).

**Light up:** **RUN ALL 45 TECHNIQUES** or **Deep Workshop**.  
**Best for:** Purple-team backlog prioritization.

---

### 6 — Threat Hunting

**Purpose:** Graduate from buttons to SPL — playbook-driven hunts.

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Technique picker | Input | Filter by `technique_id` (e.g. `AML.T0050`) |
| Playbook table | Table | Hunt SPL template, steps, rogue-actor story per technique |
| Live hunt results | Table | Matching events for selected technique |
| Block ratio stats | Table | Blocked vs total per technique |

**Light up:** Any single scenario or technique **EXECUTE**.  
**Best for:** SOC training — copy SPL into Search.

---

### 7 — Actor Chain Story

**Purpose:** Tell a multi-stage attack story for one `incident_id`.

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Active Threat Actor Incidents | Table | Per incident: threat actor profile, technique chain, stages seen, max CVSS — **click row to drill** |
| Stage Timeline | Table | Chronological stages: technique, agents, risk statement, AcmeSentinel action |

Filter: chain ID (KC-A001 … KC-E001).

**Light up:** **Standard Workshop** (KC-C001) or any **EXECUTE THREAT CHAIN**.  
**Best for:** Leadership briefings — “here’s the attack story.”

---

### 8 — ATLAS Matrix Heatmap (v2.3+)

**Purpose:** [MITRE ATLAS](https://atlas.mitre.org/)-style coverage matrix — more practical than generic Splunkbase apps for **this lab** because cells link to Attack Panel actions.

Compared to [ATT&CK Heatmap (5742)](https://splunkbase.splunk.com/app/5742) and [ATLAS AI Detection (8527)](https://splunkbase.splunk.com/app/8527): see comparison table in [Light up](#light-up-the-splunk-compliance-app) above.

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Lab Catalog Coverage % | Single % | Observed ÷ 45 executable techniques |
| Tactics With Evidence | Single value | How many of 16 ATLAS tactics have ≥1 event |
| Techniques Detected / Blocked | Single value | Techniques with guard blocks |
| Gap Count | Single value | Catalog techniques with **no** events (grey cells) |
| MITRE ATLAS Tactic Coverage | Table | Per tactic: expected / observed / detected / coverage % + heat bar |
| Technique × Tactic Heatmap | Heatmap chart | **0=GAP, 1=OBSERVED, 2=DETECTED** per cell |
| ATLAS Technique Matrix | Table | Full catalog with **Light Up In Lab** column + **drilldown to Search** |
| Detection Readiness | Table | Tier-1/Tier-2 field presence in your index (like 8527 setup check, tuned to OTel schema) |
| Kill-Chain Stage Distribution | Pie chart | Events by `framework.kill_chain_stage` |
| CVSS Distribution | Column chart | Severity buckets of observed attacks |

Matrix status filter: All / Gaps only / Observed / Detected.

**Light up:** **Deep Workshop** (best) or **FIRE ALL 10** + **RUN ALL 45**.  
**Catalog scope:** 45 lab-executable techniques × 16 tactics (full official ATLAS is larger; unmapped = GAP).

---

### 9 — Kill-Chain Timeline

**Purpose:** Forensic incident view — dwell time, stage forensics, copy-paste SPL.

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Total Kill-Chain Incidents | Single value | Active chain runs in 24h |
| Max Stages in Single Incident | Single value | Longest chain depth |
| Highest CVSS in Any Chain | Single value | Worst-case severity across chains |
| Agents Compromised Across Chains | Single value | Agent spread in chain attacks |
| Kill-Chain Incidents Over Time | Column chart | When chains ran |
| Chain Stages by Kill-Chain Stage Type | Bar chart | Recon / Execution / Exfil distribution |
| Incident Summary | Table | Per `incident_id`: dwell time, technique chain, agents — **click to drill** |
| Stage-by-Stage Forensics | Table | Appears after drill: every stage with CVSS, AcmeSentinel, detection signal |
| Correlation SPL box | HTML | Copy-paste hunt for selected incident |

Filters: scenario family (A–E), incident ID.

**Light up:** Any **EXECUTE THREAT CHAIN** (KC-*).  
**Best for:** Incident-response tabletop exercises.

---

### 10 — NIST AI RMF Scoring

**Purpose:** Multi-framework compliance posture (not just MITRE).

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| OWASP LLM Compliance Score | Single % | Inverse of distinct LLM risks observed (higher = fewer risks seen) |
| OWASP ASI Compliance Score | Single % | Same for agentic ASI risks |
| MAESTRO Layer Risk Coverage | Single % | % of 7 CSA MAESTRO layers with risk events |
| NIST AI RMF Controls at Risk | Single value | Distinct NIST control IDs triggered |
| NIST AI RMF Function Risk Status | Column chart | GOVERN / MAP / MEASURE / MANAGE event counts |
| Compliance Score Trend (7d) | Line chart | OWASP LLM score over time |
| NIST Control Detail | Table | Per control ID: risk status, events, techniques |
| Agent Behavioral Drift | Table | 7d vs 30d CVSS baseline per agent (drift detection) |

**Light up:** **FIRE ALL 10 SCENARIOS**.  
**Best for:** Quarterly risk review and executive summaries.

---

### 11 — Dataset Export

**Purpose:** Research / ML — is your telemetry rich enough to export?

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Total Events in Dataset Window | Single value | Volume in selected window (default 30d) |
| Unique ATLAS Techniques | Single value | Technique diversity for training data |
| Kill-Chain Incidents Recorded | Single value | Multi-stage examples in dataset |
| Export Readiness | Single value | Schema completeness score for HuggingFace-style export |
| Schema field coverage tables | Tables | Which OTel fields are populated (agent, technique, CVSS, etc.) |

**Light up:** **Deep Workshop** + sustained lab use.  
**Best for:** Building public datasets from lab runs.

---

### 12 — MLTK Anomaly Hunting

**Purpose:** Cisco Time Series Model token forecasting + behavioral anomaly hunts (requires Splunk MLTK + [cisco-time-series-model](https://github.com/splunk/cisco-time-series-model)).

| Visualization | Type | What it tells you |
|---------------|------|-------------------|
| Prerequisites panel | HTML | MLTK, CTSM app, Foundation-Sec-8B, Cisco overlay setup |
| CTSM Signal Events | Single value | Events flagged for MLTK time-series anomaly |
| Max TSM Anomaly Score | Single value | Peak `cisco_tsm_anomaly_score` in window |
| RAG / Galileo Alerts | Single value | Behavioral retrieval anomalies |
| Cisco Scan Findings | Single value | AIBOM/MCP preflight failures |
| Token usage — CTSM forecast | Line chart | `\| fit MLTKContainer algo=ctsm_forecast` on hourly tokens |
| Anomaly events table | Table | Scenario 7 Infinity Bill — depth, loop tokens, cost |
| Behavioral anomalies table | Table | Scenarios 1 & 9 — AIBOM drift, Galileo scores |
| Workshop SPL box | HTML | Copy-paste hunts + Foundation-Sec API example |

**Light up:** Workshop → **Cisco + MLTK Anomaly Hunt** (Scenarios 1, 6, 7, 9).  
**Optional:** `POST /api/v1/hunt/foundation-sec` with [Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B).

---

### Quick reference — Workshop path → dashboards

| Workshop path | Dashboards that should light up |
|---------------|--------------------------------|
| **15-Minute First Win** | Overview, Detection Efficacy, Control Attestation |
| **Standard Workshop** | + Actor Chain Story, Kill-Chain Timeline |
| **Deep Workshop** | + Technique Coverage, ATLAS Matrix Heatmap |
| **Fire All 10 Scenarios** | + NIST AI RMF Scoring, Control Attestation (all rows) |
| **Cisco + MLTK Anomaly Hunt** | MLTK Anomaly Hunting, Detection Efficacy, Threat Hunting (Scenarios 1,6,7,9) |
| **MAESTRO Validate** | NIST AI RMF (MAESTRO %), Control Attestation (6,8,9,10), Detection Efficacy |

Wait **60 seconds** after each path before refreshing Splunk.

See also: [WORKSHOP.md](WORKSHOP.md) · [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md) · [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md)

---

## Top 10 scenarios — surface, hunt, learning question

For each: **Top 10 Scenarios** tab → **▶ FIRE SCENARIO n** → wait 60s → SPL → dashboard.

| Scenario | Surface | Click | Typical status | Key fields | Learning question | Dashboard |
|----------|---------|-------|----------------|------------|-------------------|-----------|
| 1 | Supply chain / drift | **▶ FIRE SCENARIO 1** | Drift telemetry | `cisco_aibom_status`, `cisco.aibom.*`, `agent.aibom_validated` | *How would you detect prompt drift without blocking every request?* | Control Attestation, **MLTK Anomaly Hunting** |
| 2 | Orchestration | **▶ FIRE SCENARIO 2** | BLOCKED | `foundry.orchestrator_override`, `workflow.block_reason` | *Why enforce policy at the orchestrator, not only in prompts?* | Detection Efficacy |
| 3 | Input validation | **▶ FIRE SCENARIO 3** | BLOCKED | `acme_input_guard.rule_id`, `acme_input_guard_blocked` | *What attacks does input validation miss if you skip output inspection?* | Control Attestation |
| 4 | Shadow runtime | **▶ FIRE SCENARIO 4** | INJECTED + discovery | `slm.unapproved`, `deployment.tier` | *How do you govern models IT never approved?* | Overview |
| 5 | Output gateway | **▶ FIRE SCENARIO 5** | BLOCKED or INJECTED | `acme_output_guard.action`, `acme_output_guard_blocked` | *When is post-LLM output inspection the right layer?* | Control Attestation |
| 6 | Tools (MCP) | **▶ FIRE SCENARIO 6** | BLOCKED | `tool.scope_violation`, `mcp.gateway.rule_id` | *Why block tool abuse before the LLM runs?* | Detection Efficacy |
| 7 | Cost / DoS | **▶ FIRE SCENARIO 7** | Often INJECTED + **CTSM anomaly** | `gen_ai.usage.*_tokens`, `cisco_tsm_anomaly_score`, `mltk.ctsm_signal` | *What is your token budget alert threshold per agent?* | **MLTK Anomaly Hunting** |
| 8 | Agent identity (A2A) | **▶ FIRE SCENARIO 8** | BLOCKED | `cryptographic_passport_valid=false` | *Who is allowed to delegate authority between agents?* | Control Attestation |
| 9 | Retrieval (RAG) | **▶ FIRE SCENARIO 9** | Alert, not always block | `galileo_observe_alert`, `galileo_anomaly_score` | *Why might detect-only be correct for retrieval exfil?* | Threat Hunting, **MLTK Anomaly Hunting** |
| 10 | Memory / SOC | **▶ FIRE SCENARIO 10** | BLOCKED + SOAR | `containment.action`, `soar.playbook_id` | *How fast must containment run once memory policy fires?* | Control Attestation |

### Example hunt — Scenario 6

```spl
`acme_campaign_w6` earliest=-15m
| table _time session.id tool.scope_violation mcp.gateway.rule_id workflow.block_reason control.status control.pass_rate_pct
```

### All 10 scenarios

Workshop → **▶ FIRE ALL 10 SCENARIOS**, then:

```spl
`acme_genai_index` earliest=-1h campaign_week=*
| stats count by campaign_week workflow.block_reason acme_output_guard.action
| sort campaign_week
```

---

## Kill chains

**Tab 3** → **▶ EXECUTE THREAT CHAIN**, or use **Standard Workshop**.

| Chain | Best dashboard | Learning question |
|-------|----------------|-------------------|
| KC-A001 | Actor Chain Story | *How would you spot slow RAG exfil without a single HARD_DENY?* |
| KC-B001 | Control Attestation | *What supply-chain signal precedes model backdoor behavior?* |
| KC-C001 | Actor Chain Story | *Which stage would you block first in a fraud pipeline?* |
| KC-D001 | Control Attestation | *How do you bind agent identity cryptographically in production?* |
| KC-E001 | Detection Efficacy | *What cost anomaly would trigger finance + security jointly?* |

**Correlation hunt:**

```spl
`acme_genai_index` incident_id=ACME-INC-* earliest=-1h
| stats values(technique_id) as techniques values(framework.kill_chain_stage) as stages count as events by incident_id
| eval stage_count=mvcount(stages)
| where stage_count>=2
| sort - stage_count
```

---

## 45 techniques

**Tab 2** → **⚡ RUN ALL 45** or **Deep Workshop**.

```spl
| inputlookup acme_framework_lookup
| join type=left technique_id [
    search `acme_genai_index` earliest=-24h
    | stats count as events by technique_id
  ]
| eval status=if(isnull(events),"NOT_OBSERVED","OBSERVED")
| table technique_id technique_name tactic_name status events severity
```

Aim for **coverage % > 50%** on **Technique Coverage Matrix** after a full run.

---

## Layered defenses

| Layer | When | Terminal signal |
|-------|------|-------------------|
| Workflow guard | Before LLM | `workflow.block_reason` |
| AcmeGate | Before LLM | `acme_input_guard_blocked=true` |
| AcmeSentinel | After LLM | `acme_output_guard.action=HARD_DENY` |

| Status | Meaning |
|--------|---------|
| **BLOCKED** | Guard fired — still valuable Splunk evidence |
| **INJECTED** | Model reached — detection-gap exercise |

---

## Optional: curl equivalents

```bash
curl -X POST http://localhost:5001/api/exploit/6
curl -X POST http://localhost:5001/api/exploit/pipeline/6
curl -X POST http://localhost:5001/api/techniques/AML.T0050/execute
curl -X POST http://localhost:5001/api/techniques/execute-all -H "Content-Type: application/json" -d '{"delay_seconds":0.2}'
curl -X POST http://localhost:5001/api/chains/KC-C001/execute -H "Content-Type: application/json" -d '{"accelerated":true,"hybrid_live":true}'
```

---

## Banking app (benign baseline)

http://localhost:5000 — normal loan processing UI.

**Continuous baseline (default):** With `TRAFFIC_SIM_ENABLED=true` (see `.env`), the banking app sends **benign loan requests** every 90–240 seconds through live Ollama agents. Events land in Splunk with `testbed_mode=BASELINE_TRAFFIC` so hunts can separate noise from attacks.

| API | Purpose |
|-----|---------|
| `GET /api/v1/traffic/status` | Simulator running, tick counts, last error |
| `POST /api/v1/traffic/start` | Start background loop |
| `POST /api/v1/traffic/stop` | Pause baseline (attacks still work) |
| `POST /api/v1/traffic/tick` | Fire one baseline event immediately |

**Splunk — baseline only:**

```spl
`acme_genai_index` earliest=-1h testbed_mode=BASELINE_TRAFFIC
| timechart span=5m count by gen_ai.agent.name
```

**Splunk — attacks only (exclude baseline):**

```spl
`acme_genai_index` earliest=-1h NOT testbed_mode=BASELINE_TRAFFIC
```

~20% of baseline ticks run the **full 4-agent pipeline**; the rest hit **intake only** to keep CPU load reasonable on small VMs. Tune with `TRAFFIC_SIM_PIPELINE_RATIO`, `TRAFFIC_SIM_INTERVAL_MIN_SEC`, `TRAFFIC_SIM_INTERVAL_MAX_SEC` in `.env`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| **TARGET OFFLINE** | `docker compose ps` — banking_app healthy |
| **LLM OFFLINE** | Wait for Ollama; check `/api/v1/ollama/health` |
| Workshop stuck | Keep tab open; Deep Workshop includes 10–20 min RUN ALL 45 |
| Tab 2 / 3 empty | **↻ Reload Catalog** or refresh |
| Dashboards empty, Search has data | Fix `acme_genai_index` macro |
| Scenarios 2, 6, 8 always BLOCKED | Expected — pre-LLM guards |
| Scenario 9 not blocked | Expected — detect-only |

---

## Learn more

- [THREAT_SURFACES.md](THREAT_SURFACES.md) — surfaces vs prompts; framework crosswalk
- [CONCEPTS.md](CONCEPTS.md) — architecture, transparency, honest limits
- [REFERENCE.md](REFERENCE.md) — install, env vars, troubleshooting
- [README.md](../README.md) — golden path
- [splunk_app/INSTALL.md](../splunk_app/INSTALL.md) — Splunk install
