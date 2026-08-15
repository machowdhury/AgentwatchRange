# OrchestraACME Workshop Curriculum

**Ordered learning path** for security analysts, detection engineers, architects, and compliance teams.

| Resource | URL |
|----------|-----|
| Attack Panel (run paths) | http://localhost:5001 → **Workshop** tab (last menu item) |
| Splunk (run hunts) | http://localhost:8000 → **Search** or app dashboards |
| Banking app | http://localhost:5000 |

**Companion docs:** [PREREQUISITES.md](PREREQUISITES.md) · [USER_GUIDE.md](USER_GUIDE.md) · [THREAT_SURFACES.md](THREAT_SURFACES.md) · [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md) · [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md) · [CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md)

---

## Exercise map (follow in order)

Use this as your checklist. Each level builds on the previous one.

| Step | Where | What you do | Pass when |
|------|-------|-------------|-----------|
| **0.1** | Terminal | `cp .env.example .env` then `docker compose --profile local up --build -d` | All containers running |
| **0.2** | Terminal | Wait for Ollama; `docker compose --profile local ps` | `acme_ollama` healthy |
| **0.3** | Terminal | `./scripts/package_splunk_app.sh` then `./scripts/splunk_install_apps.sh` | MLTK + Compliance app installed |
| **0.4** | Terminal | `./scripts/splunk_local_bootstrap.sh` (+ restart OTel if needed) | HEC HTTP 200 |
| **0.5** | http://localhost:5001 | **Top 10 Scenarios** tab; check TARGET + LLM online | Both green |
| **0.6** | http://localhost:5000 + Splunk | **Verify baseline telemetry** — wait for auto traffic *or* submit one normal loan, then Search | `index=acme_agentic_telemetry earliest=-15m \| stats count` → count > 0 |
| **1** | Attack Panel | Run **Scenario 6**, then **5**, then **9** (or **Workshop** → First Win) | New events in Splunk with `campaign_week` |
| **2** | Splunk | Answer hunt questions Q201–Q203 in Level 2 below | SPL returns rows |
| **3** | Attack Panel → Threat Chains | Run **KC-C001** | `incident_id` correlates in Splunk |
| **4+** | Splunk dashboards | Technique Coverage, Control Attestation | Per level below |

> **Rule:** Complete **0.6** (baseline in Splunk) **before** Step **1** (first attack).  
> **Per-tab detail:** [ATTACK_PANEL_GUIDE.md](ATTACK_PANEL_GUIDE.md) — OUTCOME + SPL + dashboard for every scenario, chain, and workshop path.  
> **Tip:** Use the Attack Panel **Workshop** tab (last menu item) for one-click paths.

---

## About the OrchestraACME Workshop

### What it is

The **OrchestraACME Workshop** is a hands-on security lab curriculum — live exercises in a running environment, not lecture-only training. Learners operate a realistic **multi-agent loan-processing application** under attack, observe how **runtime controls** behave (block, allow, detect-only), and prove outcomes in **Splunk** using the same workflows they use in production SOC and detection engineering.

Two tools work together:

| Tool | Role in the workshop |
|------|----------------------|
| **Attack Panel** (`:5001`) | Fires ordered, reproducible adversarial scenarios and kill chains — one click runs a full learning path |
| **Splunk** (`:8000`) | Answers hunt questions, validates blocks and alerts, produces coverage and compliance evidence |

Every attack sends **real HTTP traffic** through **live Ollama inference**. Telemetry uses **OpenTelemetry GenAI semantic conventions** (`gen_ai.*`, `workflow.*`, `framework.*`) and lands in Splunk as `otel:agentic:json`. Outcomes are genuinely non-deterministic: some runs **BLOCK**, others **INJECT** — which is intentional. Production agent security is not binary.

The curriculum is **ordered** (Levels 0–5), **role-aware** (analyst through GRC), and includes **BOTS-style hunt questions** (Q101–Q503) — the same pedagogy as [Splunk BOTS](https://github.com/splunk/botsv3), applied to agentic AI telemetry.

---

### Why organizations run this workshop

Most agentic-AI security training fails in predictable ways:

| Failure mode | What goes wrong | How this workshop fixes it |
|--------------|-----------------|---------------------------|
| **Theory without telemetry** | Teams discuss MCP and RAG risks but never see `workflow.block_reason` in a SIEM | Every path emits searchable OTel fields you can hunt the same day |
| **Prompt demos without surfaces** | Red teams test injection strings on a chatbot, not tool gateways or A2A trust chains | Ten scenarios map to **workflow surfaces** — tools, RAG, memory, A2A, orchestration, supply chain |
| **Controls without evidence** | “We use guardrails” with no pass/fail per control or scenario | **Control Attestation** and NIST panels show PASS/FAIL per scenario (1–10) |
| **Detection without coverage math** | Ad hoc Splunk searches with no sense of MITRE breadth | **Technique Coverage Matrix** shows OBSERVED vs NOT_OBSERVED across 45 techniques |
| **Architecture without validation** | Threat models sit in documents; nobody checks if telemetry would catch predicted failures | Optional **MAESTRO** path: model → attack → prove layer coverage in Splunk |
| **Splunk training on synthetic logs** | Analysts learn SPL on stale canned data unrelated to GenAI | Hunts use **your lab’s live index** after **your** attacks — field names match emerging GenAI conventions |

**Who typically sponsors a workshop:**

- **Security leadership** — demonstrate measurable agentic risk program, not AI buzzwords
- **SOC / detection teams** — build hunts before production agents ship
- **Platform / AppSec** — validate where to place controls (pre-LLM vs post-LLM vs detect-only)
- **GRC / risk** — produce framework-aligned evidence (OWASP LLM, NIST AI RMF, MAESTRO layers)
- **Splunk practitioners** — practice GenAI telemetry, MLTK anomaly patterns, and compliance dashboards on realistic data

---

### What participants walk away with

Concrete **deliverables**, not just awareness:

| Deliverable | Where it lives after the workshop |
|-------------|-----------------------------------|
| **Working hunt SPL** | Q201–Q503 queries in this doc; macros `` `acme_campaign_w6` `` … `` `w10` ``; Threat Hunting playbooks |
| **Dashboard literacy** | Twelve Splunk views — Overview, Detection Efficacy, Control Attestation, Technique Coverage, Actor Chain Story, NIST AI RMF, etc. |
| **Reproducible attack scenarios** | Top 10 scenarios + 5 kill chains + 45-technique registry — re-run anytime for regression or demos |
| **Control placement vocabulary** | Pre-LLM workflow block vs post-LLM output deny vs detect-only — defensible in architecture reviews |
| **Coverage baseline** | Screenshot or export of technique OBSERVED % and NOT_OBSERVED backlog |
| **Compliance narrative** | NIST control pass/fail per scenario; MAESTRO layer coverage % |
| **Honest gap analysis** | Terminal `INJECTED` outcomes — where models complied despite controls; fuels detection backlog |
| **Optional Cisco / MLTK path** | AIBOM + MCP scan telemetry, CTSM token anomaly patterns (when overlay enabled) |

Participants leave with artifacts they can **paste into Confluence**, **attach to audit responses**, or **adapt into production detection rules** — because field names and patterns mirror what enterprises are standardizing on for GenAI observability.

---

### Skills you will use in daily work

Skills are mapped by role. You do not need every level; follow the [role quick-start](#role-quick-start-pick-one-row) row that matches your job.

#### Junior SOC analyst

**Daily work context:** Triage alerts, initial investigation, escalate with context.

| Skill | Workshop level | On-the-job use |
|-------|----------------|----------------|
| Confirm GenAI telemetry ingest | Level 0–1 | “Are we actually logging agent calls?” — first question on any AI incident |
| Hunt by scenario number | Level 1–2 | Map alerts to **which agent surface** failed (tools vs output vs retrieval) |
| Read `workflow.blocked` and `workflow.block_reason` | Level 1, Q204 | Triage pre-LLM blocks vs model-reached events |
| Read `defenseclaw.action` / `codeguard_blocked` | Level 1, Q102 | Distinguish output-side denials from input validation |
| Field discovery on unfamiliar sourcetypes | Level 2, Q201–Q203 | Same muscle memory as BOTS — explore before you filter |
| Use macros and time bounds | All levels | Production hunts: `` `acme_genai_index` `` pattern translates to your org’s index macro |

**Outcome:** You can open a GenAI security event, name the **control layer** that fired, and write a basic SPL triage query without waiting for a senior analyst.

---

#### Senior SOC analyst / incident responder

**Daily work context:** Correlate multi-stage attacks, build timelines, brief leadership.

| Skill | Workshop level | On-the-job use |
|-------|----------------|----------------|
| Correlate by `incident_id` | Level 3, Q301–Q303 | Agent compromises span stages — same skill as chaining ES notable events |
| Kill-chain storytelling | Level 3, Actor Chain Story | Executive briefings: “intake → extraction → risk → compliance” |
| Interpret `kill_chain.stage` | Level 3 | Place agent events on an intrusion timeline |
| Distinguish single-surface vs chained abuse | Level 1 vs 3 | Prioritize response: one bad tool call vs orchestrated fraud pipeline |
| Hunt A2A / RAG / memory indicators | Level 2, Q207–Q209 | Emerging agentic IOCs: `cryptographic_passport_valid`, `vector_retrieval_count`, `containment.action` |

**Outcome:** You can run an **end-to-end agentic incident narrative** in Splunk and explain which agents and surfaces were involved across time.

---

#### Detection engineer

**Daily work context:** Write rules, measure coverage, reduce false positives, prioritize purple-team backlog.

| Skill | Workshop level | On-the-job use |
|-------|----------------|----------------|
| Measure technique OBSERVED % | Level 4, Q401 | Defensible “MITRE ATLAS coverage for agents” metric in security roadmaps |
| Maintain NOT_OBSERVED backlog | Level 4, Q402 | Purple-team prioritization from evidence, not guesswork |
| Design pre-LLM vs post-LLM detections | Level 1 | Rule placement: gateway block SPL ≠ output inspection SPL |
| Token / cost anomaly patterns | Level 2 Q206, Level 4B | DoS and “infinity bill” class detections on `gen_ai.usage.*` |
| MLTK + CTSM forecasting (optional) | Level 4B, Cisco path | Behavioral baselines when point thresholds fail on bursty GenAI traffic |
| Adapt playbook SPL from lab to prod | Threat Hunting dashboard | Copy pattern, swap index/sourcetype, keep field logic |
| Foundation-Sec-8B hunt enrichment (optional) | MLTK dashboard | LLM-assisted triage narrative on technique context |

**Outcome:** You can publish a **coverage report**, propose **three detection layers** for an agent architecture, and hand SOC **ready-to-run SPL** with documented expected fields.

---

#### Security engineer / platform engineer

**Daily work context:** Implement gateways, guardrails, OTel instrumentation, CI/CD security gates.

| Skill | Workshop level | On-the-job use |
|-------|----------------|----------------|
| Map controls to code paths | Level 1 + THREAT_SURFACES | Know *where* MCP gateway, A2A verifier, memory policy sit relative to LLM calls |
| Evaluate LAB_MODE teach vs enforce | Cisco path | Roll out scanners without breaking dev workflows — pattern for gradual enforcement |
| Instrument `gen_ai.*` and security extensions | Level 0 | OTel GenAI conventions for your own agents |
| Test control regression | Re-run First Win after changes | “Did we break the MCP block?” — mini regression suite |
| Full pipeline vs single-agent blast radius | Top 10 → Full Pipeline | One payload across four agents — how delegation amplifies impact |

**Outcome:** You can **place and test controls** with Splunk proof, and speak the same language as SOC about `workflow.*` and `framework.*` fields.

---

#### Security architect

**Daily work context:** Threat model agent systems, design trust boundaries, review vendor claims.

| Skill | Workshop level | On-the-job use |
|-------|----------------|----------------|
| CSA MAESTRO 7-layer thinking | Level 5A | Structure agentic threat models (L1 foundation → L7 ecosystem) |
| Predict → attack → prove loop | MAESTRO Validate | Close the gap between design docs and observable telemetry |
| Map surfaces to OWASP LLM / ASI / NIST | Level 5, THREAT_SURFACES | Framework crosswalk in architecture reviews |
| Reason about non-determinism and autonomy | All levels | Design detections that survive model variance |
| Multi-agent trust propagation | Level 3 + Scenario 8 | A2A identity, delegation chains, session binding |

**Outcome:** You can deliver a **threat model with validation evidence** — not just a diagram — and prioritize controls by MAESTRO layer and observed Splunk coverage.

---

#### Compliance / GRC / risk

**Daily work context:** Control assessments, audit evidence, AI governance programs.

| Skill | Workshop level | On-the-job use |
|-------|----------------|----------------|
| NIST AI RMF posture from live events | Level 5B, Q502–Q503 | Move from policy PDFs to `control.status` per scenario |
| OWASP LLM risk categories observed | Level 5B | “Which LLM Top 10 categories generated telemetry this quarter?” |
| MAESTRO layer risk coverage % | Level 5A, Q501 | Agentic-specific coverage metric for risk committees |
| Scenario-to-control traceability | Fire All 10 + Control Attestation | Scenarios 1–10 map to attestation rows |
| Explain detect-only vs block | Level 1, Scenario 9 | Defensible risk acceptance: monitor retrieval exfil without blocking every query |

**Outcome:** You can **show auditors Splunk evidence** tied to named scenarios and frameworks — and explain *why* a detect-only control is intentional.

---

#### Workshop facilitator

**Daily work context:** Run brown-bags, customer workshops, internal enablement.

| Skill | Resource | On-the-job use |
|-------|----------|----------------|
| 90-minute scripted session | [Facilitator runbook](#facilitator-runbook-90-minute-session) | Repeatable delivery without rewriting content |
| Role-based pacing | [Role quick-start](#role-quick-start-pick-one-row) | Right depth for mixed audiences |
| BOTS-style progressive hunts | Q201–Q210 | Keeps room engaged in Splunk Search |
| Benign + malicious traffic contrast | Level 0 tip | Overview dashboard shows normal vs attack traffic |

---

### What makes this different from “AI security awareness” training

| Typical awareness session | OrchestraACME Workshop |
|---------------------------|------------------------|
| Theory-only prompt injection training | Live injection against Ollama with logged outcome |
| Generic “monitor your LLM” | Specific fields: `workflow.block_reason`, `technique_id`, `framework.maestro_layers` |
| One demo video | 45 techniques + 5 kill chains you re-run locally |
| Quiz on OWASP LLM Top 10 | Splunk panel showing which categories **fired** in your environment |
| Architecture diagram only | Optional MAESTRO + Splunk **prove** loop |

---

### Time investment

| Depth | Levels | Typical time | Best for |
|-------|--------|--------------|----------|
| **Taster** | 0 + 1 | ~35 min | Executives, kickoff, “is the lab alive?” |
| **SOC foundation** | 0–2 | ~2 hours | Junior–mid analysts |
| **SOC advanced** | 0–3 | ~3 hours | Senior analysts, IR |
| **Detection engineering** | 0–4 | ~4 hours | Detection engineers, purple team |
| **Full program** | 0–5 | ~6–8 hours | Architects, GRC, multi-day enablement |

---

## How to use this guide

Read top to bottom **once**, then jump to your role track. Every level assumes the previous level is complete.

```text
Level 0  Environment          (everyone, ~20 min)
Level 1  Pipeline proof        (everyone, ~15 min)
Level 2  SOC hunts            (analysts, ~45 min)     ← BOTS-style questions in Splunk Search
Level 3  Correlation          (senior analyst, ~30 min)
Level 4  Detection engineering (detection engineer, ~60 min)
Level 5  Architecture & GRC    (architect + compliance, ~90 min)
```

**Where to run queries:** Always in **Splunk Search** (or copy from **Threat Hunting** / **MLTK Anomaly Hunting** dashboards). Do not skip Splunk — the workshop is designed to build SIEM muscle memory.

**Where to fire attacks:** Attack Panel → **Workshop** tab (last menu item), or individual scenario buttons on **Top 10 Scenarios**.

**Timing rule:** Wait **60 seconds** after each Attack Panel path before running SPL.

> **Public terminology:** Use **Scenario 1–10** in workshops and customer-facing materials. Splunk events store the scenario index in field `campaign_week` (integer 1–10). SPL examples below use that field name; do not label it “campaign week” in narratives.

---

## Level 0 — Environment (everyone)

**Time:** about 20–45 minutes the first time (longer while Ollama downloads the AI model).  
**Goal:** Make sure all three parts of the lab can talk to each other — the **banking app**, the **attack panel**, and **Splunk** — before you run any workshop scenarios.

You do **not** need to understand Docker, Splunk, or AI to complete Level 0. Follow each step in order. If a step says **PASS**, you are done with that step. If something does not match **PASS**, use the troubleshooting table at the end of this section or ask your facilitator.

### What you are setting up (plain language)

Think of the lab as three websites that work together:

| Piece | What it is | Address (on your laptop) |
|-------|------------|--------------------------|
| **Banking app** | A fake bank loan system with four AI assistants | http://localhost:5000 |
| **Attack Panel** | The workshop remote control — runs practice attacks | http://localhost:5001 |
| **Splunk** | Where security logs appear as charts and tables | http://localhost:8000 |

Behind the scenes, Docker runs several small programs (containers) on your machine. You only need to open those three URLs in your browser for Level 0.

> **Using a cloud server instead of your laptop?**  
> Replace `localhost` with your server’s address (for example `http://203.0.113.50:5001`). Firewall steps: [CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md).

> **Using Splunk Cloud instead of local Splunk?**  
> You still complete Level 0 for the banking app and Attack Panel. Splunk steps use **your Splunk Cloud URL** in the browser — see [Path B](#path-b--splunk-cloud-or-company-splunk-no-local-splunk-container) below.

---

### Before you start — checklist

> **Full install guide:** [PREREQUISITES.md](PREREQUISITES.md) — Docker on Ubuntu, `docker.sock` permissions, Splunk app, verification.

Ask your facilitator or IT contact if you are unsure. You need:

- [ ] A computer or VM with **Docker Engine 24+** and **Compose v2** — `docker compose version` works  
- [ ] **`docker ps` works without `sudo`** (Linux) — if not, see [PREREQUISITES § docker.sock](PREREQUISITES.md#fix-permission-denied-on-dockersock)  
- [ ] At least **16 GB RAM** recommended if Splunk runs on the same machine  
- [ ] Internet access for the first startup (downloads the AI model, ~1.3 GB)  
- [ ] A web browser (Chrome, Edge, or Firefox)  
- [ ] The OrchestraACME project folder (from `git clone` or a zip from your instructor)  
- [ ] About **30–60 minutes** on first boot — Splunk and the AI model take time to start  

**You do not need:** a Splunk license separately (local lab includes one in Docker), or your own OpenAI API key.

---

### Choose your setup path

| Path | Splunk runs… | Start command |
|------|--------------|---------------|
| **A — Local lab (most classrooms)** | In Docker on your machine | `docker compose --profile local up --build -d` |
| **B — Splunk Cloud / company Splunk** | On Splunk Cloud or another server | `docker compose -f docker-compose.yml -f docker-compose.external.yml up --build -d` |

Path **A** is the default in this guide. Path **B** skips the local Splunk container; your admin configures HEC — see [splunk_app/INSTALL.md](../splunk_app/INSTALL.md) Section 2.

---

### Step 0.1 — Start the lab software

**Who does this:** Usually one person per machine (facilitator or tech lead). Learners can watch or follow along.

1. Open a **terminal** (Mac: Terminal app; Windows: PowerShell or Git Bash; Linux: your shell).

2. Go to the project folder:

   ```bash
   cd OrchestraACME
   ```

   *(Use the actual folder name where you cloned the repo.)*

3. Copy the settings template (first time only):

   ```bash
   cp .env.example .env
   ```

   This creates a configuration file. Defaults are fine for Level 0.

4. Start everything (**Path A — local Splunk**):

   ```bash
   docker compose --profile local up --build -d
   ```

   - The first run can take **5–15 minutes**.  
   - `-d` means “run in the background” so you can close the terminal window later.  
   - **PASS:** The command finishes without a red `ERROR` line.
   - **If `permission denied` on `docker.sock`:** See [PREREQUISITES.md](PREREQUISITES.md#fix-permission-denied-on-dockersock) — add your user to the `docker` group, then retry without `sudo`.

5. Check that services are running:

   ```bash
   docker compose ps
   ```

   **PASS:** You see containers such as `acme_banking_app`, `acme_attack_panel`, `acme_ollama`, `acme_otel_collector`, and `acme_splunk`. Most show `healthy` or `running` after a few minutes.

6. **Wait for the AI model** (important — do not skip):

   ```bash
   docker compose logs -f ollama
   ```

   Watch until you see a message that the model **`llama3.2:1b`** was pulled or is ready. Press **Ctrl+C** to stop watching logs.

   **PASS:** Ollama log shows the model is available.  
   **If stuck here:** Wait up to 10 minutes on a slow connection. Ask facilitator to run `docker compose logs ollama` and check disk space.

**Optional — see live startup logs for all services:**

```bash
docker compose logs -f
```

Press **Ctrl+C** when bored — services keep running.

---

### Step 0.2 — Open the Attack Panel and check the lights

**Who does this:** Everyone.

1. Open your browser.

2. Go to: **http://localhost:5001**  
   *(Cloud VM: `http://<your-server-ip>:5001`)*

3. Look at the **top bar**. You should see:

   | Status text | Meaning | PASS |
   |-------------|---------|------|
   | **TARGET ONLINE** (green) | Banking app is reachable | ✅ |
   | **LLM ONLINE** (green) | AI model is ready | ✅ |

4. The default tab is **Top 10 Scenarios**. Use **Workshop** (last tab) for guided paths.

5. If you see **TARGET OFFLINE** or **LLM OFFLINE** (red):

   - Wait 2–3 more minutes and refresh the page (F5).  
   - Confirm Step 0.1 finished and Ollama pulled the model.  
   - Run in terminal: `curl -s http://localhost:5000/health` — should return JSON with `"status": "healthy"`.

**PASS:** Both **TARGET ONLINE** and **LLM ONLINE** are green.

You should see tabs in this order: **Top 10 Scenarios** (default) → All 45 Techniques → Threat Chains → Custom Payload → **Workshop** (last). Use **Workshop** for guided paths in Level 1+.

---

### Step 0.3 — Install Splunk apps (MLTK + Compliance)

**Who does this:** Facilitator or anyone with Splunk admin on the lab instance.

1. Build the compliance app package (one time):

   ```bash
   chmod +x scripts/package_splunk_app.sh
   ./scripts/package_splunk_app.sh
   ```

   **PASS:** File exists: `dist/acme_genai_compliance-*.tar.gz`.

2. Install MLTK + compliance app:

   ```bash
   chmod +x scripts/splunk_install_apps.sh
   ./scripts/splunk_install_apps.sh
   ```

   This installs **Splunk ML Toolkit** from `splunk_app/splunk-ai-toolkit_600.tgz` (if present) and **GenAI Compliance Monitor**.

3. Open Splunk: **http://localhost:8000** → log in (`admin` / `ACMEPassword2026!`).

4. **PASS:** App picker shows **GenAI Compliance Monitor** and **Splunk ML Toolkit**.

**Legacy alias:** `./scripts/splunk_install_app.sh` calls the same combined installer.

**Full reference:** [splunk_app/INSTALL.md](../splunk_app/INSTALL.md)

#### Path B — Splunk Cloud or company Splunk

Ask your Splunk admin to install both tarballs and create index `acme_agentic_telemetry` with HEC sourcetype `otel:agentic:json`. Put HEC URL/token in `.env`.

---

### Step 0.4 — Confirm logs can reach Splunk (HEC)

**What HEC means:** HTTP Event Collector — the pipe that sends security events from the lab into Splunk.

#### Path A — Local Splunk (default `.env`)

`docker compose up` starts Splunk but **does not** always enable HEC on first boot. Run once:

```bash
chmod +x scripts/splunk_local_bootstrap.sh
./scripts/splunk_local_bootstrap.sh
```

**PASS:** Script prints `HEC returned HTTP 200`.

**Quick UI check (optional):**

1. Splunk → **Settings → Data inputs → HTTP Event Collector** — HEC enabled, token `orchestra-acme-otel` exists.
2. **GenAI Compliance Monitor → Setup Guide** — index `acme_agentic_telemetry`, sourcetype `otel:agentic:json`.

If events never appear after Step 0.6, re-run bootstrap and verify `SPLUNK_HEC_TOKEN` in `.env` — see [USER_GUIDE.md](USER_GUIDE.md).

#### Path B — Splunk Cloud

Admin confirms `.env` has correct **Splunk Cloud HEC URL** and token. **PASS:** test ingest or Step 0.6 shows events in Search.

---

### Step 0.6 — Confirm harmless “normal” traffic (before any attack)

**Why:** Prove the **baseline → Splunk** path works before you add attack noise. The workshop compares normal loan traffic with attack traffic — if Step 0.6 fails, fix ingest here instead of debugging scenarios.

**Who does this:** Everyone — **required before Level 1**.

**Option A — Automatic (default)**

1. After stack startup + bootstrap, wait **2–3 minutes** (Ollama + ~45s simulator delay).
2. Check simulator: `curl -s http://localhost:5000/api/v1/traffic/status` — `"running": true`, `ticks_ok` increasing.
3. Splunk **Search**:

   ```spl
   index=acme_agentic_telemetry earliest=-15m
   | stats count by testbed_mode
   ```

4. **PASS:** count ≥ 1; often `BASELINE_TRAFFIC` from the background simulator.

**Option B — Manual loan (recommended on first install)**

1. Open **http://localhost:5000**
2. Enter a normal message:

   ```text
   I would like to apply for a small business loan. Annual revenue is $250,000.
   ```

3. Click **Run Through All Agents**, then **↺ Refresh Sessions**
4. Wait **30–60 seconds**
5. Splunk **Search**:

   ```spl
   index=acme_agentic_telemetry earliest=-15m
   | stats count by testbed_mode gen_ai.agent.name
   ```

6. **PASS:** count > 0; agents such as `acme-agent-intake-001`; `BANKING_LIVE` and/or `BASELINE_TRAFFIC`.

**Filter attacks only** (after Level 1):

```spl
index=acme_agentic_telemetry earliest=-1h NOT testbed_mode=BASELINE_TRAFFIC
```

If count stays **0**, re-run `./scripts/splunk_local_bootstrap.sh`, `docker compose --profile local restart otel_collector`, wait 60s, retry.

---

### Level 0 complete — final checklist

Check every box before moving to [Level 1](#level-1--pipeline-proof-everyone):

- [ ] `docker compose --profile local ps` shows main containers running  
- [ ] http://localhost:5001 → **TARGET ONLINE** and **LLM ONLINE**  
- [ ] http://localhost:8000 → Splunk login works (Path A) *or* Splunk Cloud login works (Path B)  
- [ ] **GenAI Compliance Monitor** app visible in Splunk  
- [ ] **Baseline telemetry:** Step 0.6 Search shows count **> 0** (`BASELINE_TRAFFIC` and/or manual loan)  
- [ ] You know which URL to use for Attack Panel and Splunk for the rest of the workshop  

**Congratulations — Level 0 is complete.**  
Next: [Level 1 — Pipeline proof](#level-1--pipeline-proof-everyone) (**▶ RUN FIRST WIN PATH** on the Attack Panel).

---

### Level 0 troubleshooting (plain language)

| What you see | Likely cause | What to try |
|--------------|--------------|-------------|
| `docker compose` command not found | Docker not installed or not running | Start **Docker Desktop**; reopen terminal |
| Attack Panel **LLM OFFLINE** | Model still downloading | `docker compose logs -f ollama` — wait for `llama3.2:1b` |
| Attack Panel **TARGET OFFLINE** | Banking container not up | `docker compose ps` — restart: `docker compose --profile local up -d` |
| Splunk login page won’t load | Splunk still starting (up to 8 min) | `docker compose logs -f splunk` — wait for “running” |
| Splunk **Overview** shows 0 events | HEC not configured or too soon | Run `./scripts/splunk_local_bootstrap.sh`; wait 60s after Step 0.6 |
| OTel logs `connection reset by peer` on 8088 | HEC disabled, SSL-only, or init skipped | Run `./scripts/splunk_local_bootstrap.sh` then `docker compose restart otel_collector`; check `docker compose logs splunk_hec_init` |
| OTel logs `permission denied` on `otel-raw-genai.jsonl` | Shared volume permissions | Bootstrap script fixes this; `docker compose restart otel_collector` |
| Bootstrap `Permission denied` on `/opt/splunk/...` | Splunk CLI run as root | `./scripts/splunk_local_bootstrap.sh` (REST) or `./scripts/splunk_install_apps.sh` |
| Browser can’t open `:5001` on cloud VM | Firewall | Open ports per [CLOUD_VM_DEPLOYMENT.md](CLOUD_VM_DEPLOYMENT.md) |
| `permission denied` on scripts | Script not executable | `chmod +x scripts/*.sh` |
| Splunk app install `bundle_tmp` error | Root-owned paths in container | `./scripts/splunk_install_apps.sh` after `git pull` |
| Everything slow | Not enough RAM | Close other apps; use machine with 16+ GB RAM |

**Still stuck?** Collect for your facilitator: output of `docker compose ps`, screenshot of Attack Panel header, and screenshot of Splunk Overview.

---

### Facilitator notes for Level 0

- Run Step 0.6 **once per room** on a shared screen so everyone sees Splunk count go from 0 → non-zero before any attack.
- For mixed audiences: non-technical learners focus on Steps **0.5**, **0.6**, and Splunk Search; tech lead does **0.1**–**0.4**.
- Budget **15 minutes** after `docker compose up` before declaring failure — Splunk and Ollama are slow on first boot.  
- Default Splunk password is for **lab only** — rotate on any internet-facing VM.

---

## Level 1 — Pipeline proof (everyone)

**Goal:** See three different control philosophies in one sitting.

**Attack Panel:** **▶ RUN FIRST WIN PATH** (Scenarios 6 → 5 → 9)

| Scenario | Surface | What you teach |
|----------|---------|----------------|
| 6 | MCP tools | Block **before** LLM (`workflow.block_reason`) |
| 5 | Output gateway | Block or flag **after** LLM (`defenseclaw.action`) |
| 9 | RAG | **Detect-only** — alert without always blocking |

**Splunk dashboards:** Overview · Detection Efficacy · Control Attestation

**Level 1 check — answer in Splunk Search:**

<details>
<summary><strong>Q101</strong> — Which scenario produced a workflow block before the model ran?</summary>

```spl
`acme_genai_index` earliest=-30m campaign_week=6
| stats count by workflow.block_reason workflow.blocked
```

Look for `workflow.blocked=true` and a tool-scope `workflow.block_reason` on Scenario 6 events.

</details>

<details>
<summary><strong>Q102</strong> — Which field tells you DefenseClaw acted on output?</summary>

```spl
`acme_genai_index` earliest=-30m campaign_week=5
| table defenseclaw.action defenseclaw_blocked codeguard_blocked workflow.blocked
```

**Answer field:** `defenseclaw.action` (e.g. `HARD_DENY`, `ALLOW`).

</details>

<details>
<summary><strong>Q103</strong> — Scenario 9: was the attack blocked or only observed?</summary>

```spl
`acme_campaign_w9` earliest=-30m
| table workflow.blocked galileo_observe_alert vector_retrieval_count control.status
```

Discuss why detect-only may be correct for retrieval exfiltration.

</details>

---

## Level 2 — SOC hunts (junior → senior analyst)

**Goal:** Field discovery and hunt writing — same pedagogy as [Splunk BOTS](https://github.com/splunk/botsv3) 200-series, but on agentic telemetry.

**Prerequisite:** Level 1 complete.

**Attack Panel:** **▶ RUN FIRST WIN PATH** again if events aged out, then fire **Scenario 8** manually (Top 10 tab).

### Hunt progression (do in order)

| # | Question | Skill |
|---|----------|-------|
| Q201 | What sourcetype/index holds agentic events? | Index discovery |
| Q202 | Which agents appear in telemetry? | Field inventory |
| Q203 | How many events per scenario? | Aggregation |
| Q204 | What blocked Scenario 6? | Workflow forensics |
| Q205 | Which MITRE technique IDs fired? | Framework fields |
| Q206 | Token usage for Scenario 7 | Cost / DoS hunting |
| Q207 | A2A identity failure on Scenario 8 | Multi-agent trust |
| Q208 | RAG indicators on Scenario 9 | Retrieval hunting |
| Q209 | Memory / containment on Scenario 10 | Autonomous escape |
| Q210 | Events sharing one `incident_id` | Correlation prep |

<details>
<summary><strong>Q201</strong> — What index and sourcetype should you search?</summary>

```spl
index=acme_agentic_telemetry earliest=-1h
| stats count by sourcetype
```

**Expected sourcetype:** `otel:agentic:json` · Shortcut macro: `` `acme_genai_index` ``

</details>

<details>
<summary><strong>Q202</strong> — List the four banking agents seen in telemetry.</summary>

```spl
`acme_genai_index` earliest=-1h
| stats count by gen_ai.agent.name
| sort -count
```

**Expected:** `acme-agent-intake-001`, `acme-agent-docingest-002`, `acme-agent-creditrisk-003`, `acme-agent-compliance-004`

</details>

<details>
<summary><strong>Q203</strong> — Event count per scenario after First Win.</summary>

```spl
`acme_genai_index` earliest=-30m
| stats count by campaign_week
| sort campaign_week
```

</details>

<details>
<summary><strong>Q204</strong> — What workflow block reason appears for MCP tool abuse?</summary>

```spl
`acme_campaign_w6` earliest=-30m
| stats count by workflow.block_reason tool.scope_violation workflow.blocked
```

</details>

<details>
<summary><strong>Q205</strong> — Which `technique_id` values appear?</summary>

```spl
`acme_genai_index` earliest=-30m
| stats count by technique_id framework.severity
| sort -count
```

</details>

<details>
<summary><strong>Q206</strong> — Fire Scenario 7, then find token surge fields.</summary>

Attack Panel → **▶ FIRE SCENARIO 7**, wait 60s.

```spl
`acme_campaign_w7` earliest=-15m
| table gen_ai.usage.input_tokens gen_ai.usage.output_tokens call_depth_detected campaign_week
| sort - gen_ai.usage.input_tokens
```

</details>

<details>
<summary><strong>Q207</strong> — A2A spoof indicators (Scenario 8).</summary>

```spl
`acme_campaign_w8` earliest=-15m
| table cryptographic_passport_valid a2a.sender_agent workflow.block_reason
```

</details>

<details>
<summary><strong>Q208</strong> — RAG exfil indicators (Scenario 9).</summary>

```spl
`acme_campaign_w9` earliest=-15m
| table galileo_observe_alert vector_retrieval_count workflow.blocked
```

</details>

<details>
<summary><strong>Q209</strong> — Memory / SOC bypass (Scenario 10).</summary>

```spl
`acme_campaign_w10` earliest=-15m
| table memory.policy.rule_id containment.action workflow.blocked
```

</details>

<details>
<summary><strong>Q210</strong> — Preview: events that share an incident_id (Level 3).</summary>

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats count by incident_id
| where count > 1
```

If empty, complete Level 3 first.

</details>

**Splunk dashboards:** Threat Hunting · Overview · Detection Efficacy

---

## Level 3 — Correlation (senior analyst)

**Goal:** Multi-stage adversary behavior tied by `incident_id`.

**Attack Panel:** **▶ RUN STANDARD WORKSHOP** (First Win + kill chain **KC-C001**)

| Concept | Field | Dashboard |
|---------|-------|-----------|
| Single-surface attack | scenario index (`campaign_week`), `trace_id` | Control Attestation |
| Multi-stage story | `incident_id` | Actor Chain Story |
| Timeline | `_time`, `kill_chain.stage` | Kill-Chain Timeline |

<details>
<summary><strong>Q301</strong> — How many stages fired for KC-C001?</summary>

```spl
`acme_genai_index` earliest=-1h
| search incident_id=*
| stats dc(kill_chain.stage) AS stages values(kill_chain.stage) BY incident_id
```

</details>

<details>
<summary><strong>Q302</strong> — Which agents participated in one incident?</summary>

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats values(gen_ai.agent.name) AS agents BY incident_id
```

</details>

<details>
<summary><strong>Q303</strong> — Were any chain stages blocked?</summary>

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats count by incident_id workflow.blocked defenseclaw_blocked codeguard_blocked
```

</details>

**Splunk dashboards:** Actor Chain Story · Kill-Chain Timeline · Detection Efficacy (chain completeness)

---

## Level 4 — Detection engineering

**Goal:** Measurable coverage, playbooks, and optional Cisco/MLTK overlay.

**Audience:** Detection engineers, security engineers building rules.

### Track 4A — Coverage breadth (~45 min)

**Attack Panel:** **▶ RUN DEEP WORKSHOP** (Standard + RUN ALL 45 TECHNIQUES)

Keep the browser tab open 10–20 minutes during RUN ALL 45.

<details>
<summary><strong>Q401</strong> — What percentage of techniques are OBSERVED?</summary>

Open **Technique Coverage Matrix** dashboard, or:

```spl
| inputlookup acme_framework_lookup
| eval observed=if([| `acme_genai_index` earliest=-24h | stats count BY technique_id | rename technique_id AS tid | eval observed=1 | table tid observed], 1, 0)
```

Prefer the dashboard for workshop delivery.

</details>

<details>
<summary><strong>Q402</strong> — List NOT_OBSERVED techniques (purple-team backlog).</summary>

Use **Technique Coverage Matrix** → filter NOT_OBSERVED, or Threat Hunting playbook list.

</details>

<details>
<summary><strong>Q403</strong> — Mean time to detect proxy: events with `defenseclaw_blocked` or `workflow.blocked`.</summary>

```spl
`acme_genai_index` earliest=-24h (workflow.blocked=true OR defenseclaw_blocked=true OR codeguard_blocked=true)
| timechart span=1h count
```

</details>

### Track 4B — Cisco + MLTK overlay (~30 min, optional)

**Prerequisite:** `docker compose -f docker-compose.yml -f docker-compose.cisco.yml --profile local up -d`

**Attack Panel:** **▶ RUN CISCO + MLTK PATH**

See [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md) and Splunk **MLTK Anomaly Hunting** dashboard.

<details>
<summary><strong>Q404</strong> — AIBOM scan telemetry after Scenario 1.</summary>

```spl
`acme_campaign_w1` earliest=-30m
| table cisco_aibom_status agent.aibom_validated model_artifact_hash_expected model_artifact_hash_found
```

</details>

**Splunk dashboards:** Technique Coverage Matrix · Detection Efficacy · MLTK Anomaly Hunting

---

## Level 5 — Architecture & compliance

**Goal:** Design-time modeling + governance evidence for architects and GRC.

### Track 5A — MAESTRO threat modeling (architects)

**Attack Panel:** **▶ RUN MAESTRO VALIDATE PATH**

Full procedure: [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md)

<details>
<summary><strong>Q501</strong> — MAESTRO layer coverage after validation path.</summary>

```spl
`acme_genai_index` earliest=-30m
| mvexpand framework.maestro_layers
| search framework.maestro_layers=L*
| stats dc(framework.maestro_layers) AS layers_at_risk
| eval maestro_coverage_pct=round(layers_at_risk/7*100,1)
```

Target: **>50%** after Scenarios 6, 8, 9, 10.

</details>

### Track 5B — Compliance attestation (GRC)

**Attack Panel:** **▶ FIRE ALL 10 SCENARIOS**

<details>
<summary><strong>Q502</strong> — NIST control pass/fail per scenario.</summary>

Open **Control Attestation** dashboard, or:

```spl
`acme_genai_index` earliest=-1h
| stats latest(control.status) AS control_status BY campaign_week control.control_id
| sort campaign_week
```

</details>

<details>
<summary><strong>Q503</strong> — OWASP LLM risk categories observed.</summary>

Open **NIST AI RMF Scoring** dashboard (OWASP panels), or:

```spl
`acme_genai_index` earliest=-1h
| mvexpand framework.owasp_llm
| stats count by framework.owasp_llm
```

</details>

<details>
<summary><strong>Q504</strong> — MCP tool manifest poisoning (AML.T0070).</summary>

Run technique **AML.T0070** from All Techniques, then:

```spl
`acme_genai_index` earliest=-30m technique_id="AML.T0070"
| table _time tool_manifest_tampered mcp.gateway.rule_id workflow.block_reason
```

**Honest limitation:** SIMULATED path uses a lab fixture manifest; production MCP registries need separate scanning tooling.

</details>

<details>
<summary><strong>Q505</strong> — Unsigned community skill install (AML.T0071).</summary>

```spl
`acme_genai_index` earliest=-30m technique_id="AML.T0071"
| table skill.provenance_valid skill.registry agent.aibom_validated cisco_aibom_status
```

</details>

<details>
<summary><strong>Q506</strong> — Memory behavioral drift over a session (AML.T0072 / KC-F001).</summary>

Execute **KC-F001** or AML.T0072 (LIVE multi-turn), then:

```spl
`acme_genai_index` earliest=-30m (technique_id="AML.T0072" OR chain_id="KC-F001")
| timechart avg(memory_entry_trust_score) avg(approval_rate_by_session) by session.id
```

</details>

<details>
<summary><strong>Q507</strong> — Agent privilege creep (AML.T0073).</summary>

```spl
`acme_genai_index` earliest=-30m technique_id="AML.T0073"
| table granted_scope used_scope scope_delta privilege_creep_detected
```

</details>

<details>
<summary><strong>Q508</strong> — HITL bypass on high-value loan (AML.T0074).</summary>

With `HITL_GATE_ENABLED=false` (default), run AML.T0074:

```spl
`acme_genai_index` earliest=-30m technique_id="AML.T0074"
| table hitl_required hitl_bypassed loan_amount_usd hitl.gate_enabled workflow.alert
```

Re-run with `HITL_GATE_ENABLED=true` and confirm `workflow.blocked=true`.

</details>

<details>
<summary><strong>Q509</strong> — A2A message provenance tampering (AML.T0075).</summary>

```spl
`acme_genai_index` earliest=-30m technique_id="AML.T0075"
| table message.provenance_valid message.hash_expected message.hash_received a2a.verification_failure
```

</details>

**Splunk dashboards:** NIST AI RMF Scoring · Control Attestation · MITRE ATLAS Heatmap

---

## Role quick-start (pick one row)

| Role | Start here | Through level | Attack Panel path | Primary Splunk views |
|------|------------|---------------|-------------------|----------------------|
| **Junior SOC analyst** | Level 0 → 1 | Level 2 (Q201–Q210) | First Win | Overview, Threat Hunting |
| **Senior SOC analyst** | Level 1 | Level 3 (Q301–Q303) | Standard Workshop | Actor Chain Story, Kill-Chain Timeline |
| **Detection engineer** | Level 2 | Level 4 (Q401–Q404) | Deep Workshop + optional Cisco | Technique Coverage, Detection Efficacy |
| **Security engineer** | Level 1 | Level 2 + Top 10 **Full Pipeline** | First Win + manual scenarios | Detection Efficacy, workflow fields |
| **Security architect** | Level 3 | Level 5A (MAESTRO) | MAESTRO Validate | NIST AI RMF, MAESTRO coverage % |
| **Compliance / GRC** | Level 1 | Level 5B (Q502–Q503) | Fire All 10 | Control Attestation, NIST AI RMF |
| **Facilitator (half-day)** | Level 0 | Levels 1 → 3 | First Win → Standard | All dashboards in order |
| **Facilitator (full day)** | Level 0 | Levels 1 → 5 | Deep + Fire All 10 | Full app nav |

---

## Attack Panel path reference

| Button | Scenarios / steps | Maps to level |
|--------|-------------------|---------------|
| **15-Minute First Win** | 6 → 5 → 9 | Level 1 |
| **Standard Workshop** | First Win + KC-C001 | Level 3 |
| **Deep Workshop** | Standard + RUN ALL 45 | Level 4A |
| **Fire All 10 Scenarios** | 1–10 | Level 5B |
| **MAESTRO Validate** | MAESTRO briefing + 6,8,9,10 | Level 5A |
| **Cisco + MLTK** | Preflight + 1,6,7,9 | Level 4B |

---

## Facilitator runbook (90-minute session)

| Min | Activity | Materials |
|-----|----------|-----------|
| 0–15 | Level 0 + Level 1 live demo | Attack Panel First Win, Splunk Overview |
| 15–40 | Learners Level 2 hunts Q201–Q207 | This doc, Splunk Search |
| 40–55 | Instructor Level 3 KC-C001 story | Actor Chain Story dashboard |
| 55–70 | Q208–Q210 + discussion | THREAT_SURFACES.md |
| 70–90 | Optional: Control Attestation or MAESTRO overview | Level 5 dashboards |

---

## Splunk vs Jupyter — recommendation

### Stay Splunk-native (recommended)

| Reason | Detail |
|--------|--------|
| **Audience expectation** | Analysts and detection engineers live in Splunk Search and ES — not notebooks |
| **Already built in** | Threat Hunting, MLTK Anomaly Hunting, and playbook lookups ship hunt SPL in the app |
| **One less dependency** | No Python kernel, `splunk-sdk`, or notebook server to debug in class |
| **BOTS precedent** | [Splunk BOTS](https://github.com/splunk/botsv3) teaches via **questions + SPL in Splunk** — this curriculum follows that pattern (Q201–Q503 above) |

This guide **is** your notebook: ordered questions, collapsible SPL, Attack Panel buttons for reproducible data generation.

### When Jupyter might make sense (optional, not default)

Consider a **separate optional appendix** only if:

- Audience is **ML/data science** leaning and already lives in Jupyter
- You run a **multi-day** course with homework outside Splunk
- You want `splunk-sdk` programmatic exports for research (Dataset Export dashboard already covers HF export)

**Risk of Jupyter as primary UI:** splits attention, feels like “extra tooling,” and duplicates what Splunk Search already does. For Splunk/Cisco workshops, it often **pulls people away** from the SIEM they need to operate in production.

### If you add Jupyter later (lightweight pattern)

Do **not** replace Splunk. Use Jupyter as a **facilitator-only** or **homework** artifact:

```text
Cell 1: Markdown — Q204 question text (copy from this doc)
Cell 2: splunk-sdk query — same SPL as Search
Cell 3: Markdown — discussion / expected fields
```

Keep Attack Panel for attacks; keep Splunk as the student-facing hunt surface.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Zero events in Q201 | Complete Level 0; run First Win; check HEC token and index |
| Q210 empty | Run Standard Workshop (KC-C001) |
| Q401 all NOT_OBSERVED | Run Deep Workshop; widen time range to 24h |
| MAESTRO step cancelled | Install CSA MAESTRO on :9002 — [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md) |
| Cisco preflight skipped | Start `docker-compose.cisco.yml` overlay |

---

## Document map

| Doc | Use when |
|-----|----------|
| **WORKSHOP.md** (this file) | Ordered curriculum + hunt questions |
| [USER_GUIDE.md](USER_GUIDE.md) | Splunk dashboard field-by-field reference |
| [THREAT_SURFACES.md](THREAT_SURFACES.md) | What each scenario teaches |
| [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md) | CSA MAESTRO install + validate |
| [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md) | Cisco overlay + MLTK |
