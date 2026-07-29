# Attack Panel — Tab Guide, Outcomes & Splunk Validation

**Attack Panel:** http://localhost:5001  
**Splunk app:** GenAI Compliance Monitor (http://localhost:8000)

Use this guide after [install + baseline verification](../README.md#step-4--verify-telemetry-before-any-attack-3-min).  
**Rule:** Wait **60 seconds** after any button finishes before running SPL or opening dashboards (OTel batching).

---

## Splunk dashboards (GenAI Compliance Monitor)

| Dashboard | When to use it |
|-----------|----------------|
| **Overview** | First check — total event count, agent activity, recent attacks |
| **Detection Efficacy** | Which scenarios fired, block rates, workflow surface breakdown |
| **Control Attestation** | NIST pass/fail evidence per scenario (1–10) |
| **Technique Coverage** | MITRE ATLAS OBSERVED vs NOT_OBSERVED after **All 45** or **Deep Workshop** |
| **Threat Hunting** | Starter SPL playbooks per technique |
| **Actor Chain Story** | Multi-stage narrative by `incident_id` (Threat Chains, Standard Workshop) |
| **Kill-Chain Timeline** | Stage order over time for one `incident_id` |
| **ATLAS Matrix Heatmap** | Visual MITRE coverage after broad technique runs |
| **NIST AI RMF Scoring** | Framework rollup after **Fire All 10** |
| **MLTK Anomaly Hunting** | Token surge / CTSM patterns (Scenario 7, Cisco path) |

**Index macro:** `` `acme_genai_index` `` expands to `index=acme_agentic_telemetry sourcetype="otel:agentic:json"`.

**Scenario macros:** `` `acme_campaign_w1` `` … `` `acme_campaign_w10` `` filter by `campaign_week`.

---

## Tab overview — what each tab means & expected OUTCOME

| Tab | What it is | You click… | **OUTCOME** (what success looks like) |
|-----|------------|------------|--------------------------------------|
| **Top 10 Scenarios** | One curated attack per **agentic surface** (orchestration, tools, RAG, …) | **Run scenario N** or **⚡ Full Pipeline** | Terminal shows **BLOCKED** or **INJECTED**; Splunk gets one `campaign_week=N` event with control fields |
| **All 45 Techniques** | Full **MITRE ATLAS** library (LIVE / SIMULATED / HYBRID) | **EXECUTE** per card, or **RUN ALL 45** | Splunk fills with `technique_id=AML.T*` events; Coverage Matrix shows OBSERVED techniques |
| **Threat Chains** | **Multi-stage rogue-actor** stories (5 families) | **EXECUTE THREAT CHAIN** on KC-* | One shared `incident_id` spans 4–5 stages; Actor Chain Story shows timeline |
| **Custom Payload** | **Your own** injection string | Type payload → pick agent → **EXECUTE** | Real LLM call; Splunk event with your text in `gen_ai.prompt` / block fields |
| **Workshop** | **Guided paths** (ordered sequences) | Path buttons (First Win, Standard, …) | Multiple scenarios/chains run automatically; open listed dashboards + SPL below |

---

## 1. Top 10 Scenarios

### What this tab means

Each card is **Scenario 1–10** (stored as `campaign_week` in Splunk). One button fires **one real adversarial payload** to **one target agent** via the live Ollama LLM. DefenseClaw, CodeGuard, and workflow guards run on the real code path.

- **Preview payload** — read the string before firing (no LLM call).
- **Run scenario N** — single-agent attack.
- **⚡ Full Pipeline** — same payload routed through **all four agents** in sequence (shows propagation).

### OUTCOME when you run Top 10

| Terminal status | Meaning |
|-----------------|--------|
| **BLOCKED** | A control stopped the attack (pre-LLM workflow, CodeGuard input, or DefenseClaw output) |
| **INJECTED** | Payload reached the model; response may partially comply — **still logged** (important for workshops) |
| **ERROR** | Banking app / Ollama unreachable — fix stack, not Splunk |

**Splunk OUTCOME:** New row(s) with `testbed_mode=CAMPAIGN_LIVE`, `campaign_week=1..10`, target `gen_ai.agent.name`, plus surface-specific fields below.

### All 10 scenarios — validation cheat sheet

| # | Theme | Surface | Target agent | Typical terminal | Primary dashboard | Splunk query (run after 60s) |
|---|-------|---------|--------------|------------------|-------------------|------------------------------|
| **1** | Code Compliance Illusion (AI BOM drift) | orchestration | creditrisk-003 | BLOCKED or INJECTED | Control Attestation · Detection Efficacy | `` `acme_campaign_w1` earliest=-30m \| table cisco_aibom_status agent.aibom_validated model_artifact_hash_expected model_artifact_hash_found control.status `` |
| **2** | Agentic Evaluation Harness (Foundry bypass) | orchestration | intake-001 | Often **BLOCKED** (orchestration guard) | Detection Efficacy → Workflow Surface Blocks | `` `acme_campaign_w2` earliest=-30m \| table foundry.policy_status foundry.orchestrator_override workflow.blocked workflow.block_reason `` |
| **3** | Secure-by-Default Vibe Coding | prompt | docingest-002 | Often **BLOCKED** (CodeGuard pre-LLM) | Control Attestation | `` `acme_campaign_w3` earliest=-30m \| table codeguard_blocked codeguard.rule_id codeguard.status workflow.blocked `` |
| **4** | Shadow AI at the Edge (rogue SLM) | runtime | intake-001 | INJECTED (detect/asset) | Overview · Detection Efficacy | `` `acme_campaign_w4` earliest=-30m \| table slm.unapproved gen_ai.request.model deployment.tier llm.runtime `` |
| **5** | Guarding the Front Desk (jailbreak) | prompt | intake-001 | BLOCKED or INJECTED | Control Attestation · Detection Efficacy | `` `acme_campaign_w5` earliest=-30m \| table defenseclaw.action defenseclaw_blocked defenseclaw.rule_id workflow.blocked `` |
| **6** | Intern with the Master Key (MCP escape) | tools | docingest-002 | Often **BLOCKED** (pre-LLM tool scope) | Control Attestation · Detection Efficacy | `` `acme_campaign_w6` earliest=-30m \| stats count by workflow.blocked workflow.block_reason tool.scope_violation gen_ai.tool.name `` |
| **7** | The Infinity Bill (token surge) | orchestration | creditrisk-003 | INJECTED (cost/DoS signal) | MLTK Anomaly Hunting · Detection Efficacy | `` `acme_campaign_w7` earliest=-30m \| table gen_ai.usage.input_tokens gen_ai.usage.output_tokens call_depth_detected cisco_tsm_anomaly_score `` |
| **8** | Identity Fracture (A2A DID spoof) | a2a | compliance-004 | Often **BLOCKED** (trust chain) | Actor Chain Story · Control Attestation | `` `acme_campaign_w8` earliest=-30m \| table cryptographic_passport_valid delegation.chain did.document workflow.blocked `` |
| **9** | The Invisible Leak (RAG exfil) | rag | docingest-002 | Often **INJECTED** (detect-only) | Threat Hunting · Detection Efficacy | `` `acme_campaign_w9` earliest=-30m \| table galileo_observe_alert galileo_anomaly_score vector_retrieval_count workflow.blocked control.status `` |
| **10** | Self-Healing SOC (rogue agent) | memory | intake-001 | BLOCKED or INJECTED | Control Attestation · Kill-Chain Timeline | `` `acme_campaign_w10` earliest=-30m \| table containment.action containment.latency_ms soar.playbook_id memory.policy.rule_id `` |

**Pass (any scenario):** Query returns ≥1 row in last 30m with expected fields populated.

**Full Pipeline variant:** Same queries; add `| stats count by gen_ai.agent.name` — expect **up to four agents** for one `campaign_week`.

**Exclude baseline noise:**

```spl
`acme_genai_index` earliest=-30m NOT testbed_mode=BASELINE_TRAFFIC campaign_week=6
| table _time gen_ai.agent.name workflow.blocked defenseclaw.action
```

---

## 2. All 45 Techniques

### What this tab means

The **MITRE ATLAS technique registry** — broader than the Top 10 demos. Each card is one `technique_id` (e.g. `AML.T0000`).

| Mode | Badge color | What happens |
|------|-------------|--------------|
| **LIVE** | Green | Real HTTP + Ollama call (like Top 10) |
| **SIMULATED** | Orange | Enriched OTel event **without** live model harm (recon, supply chain, etc.) |
| **HYBRID** | Mixed | Live stage + simulated enrichment |

### OUTCOME when you run All 45

| Action | OUTCOME |
|--------|---------|
| **EXECUTE** (one card) | One `technique_id` event in Splunk; terminal shows LIVE result or SIMULATED confirmation |
| **RUN ALL 45 TECHNIQUES** | 45 techniques over ~10–20 min; Coverage Matrix fills in; mix of LIVE + SIMULATED rows |

**Splunk OUTCOME:** Events with `technique_id=AML.T*`, `framework.kill_chain_stage`, `cvss_score`, and mode in `testbed_mode` or technique metadata.

### Validation

**After one technique:**

```spl
`acme_genai_index` earliest=-30m technique_id="AML.T0000"
| table _time technique_id testbed_mode workflow.blocked gen_ai.agent.name
```

**After RUN ALL 45 (preferred — open dashboard):**

1. **GenAI Compliance Monitor → Technique Coverage** — OBSERVED % increases; NOT_OBSERVED backlog shrinks.
2. Or Search:

```spl
`acme_genai_index` earliest=-24h
| stats count by technique_id
| sort -count
```

**Pass:** ≥10 distinct `technique_id` values after a full run; dashboard OBSERVED > 0%.

**Detection Efficacy panel:** **Technique Coverage %** and **Kill-chain stage distribution**.

---

## 3. Threat Chains

### What this tab means

**Multi-stage rogue-actor campaigns** — 4–5 ordered techniques sharing one **`incident_id`**. Modes are **HYBRID** (live LLM stages + correlated Splunk timeline).

| Chain | Name | Stages | CVSS | Story |
|-------|------|--------|------|-------|
| **KC-A001** | Silent Data Harvest | 5 | 8.8 | Recon → API probe → prompt leak → RAG discovery → embedding exfil |
| **KC-B001** | Trojan Model Operation | 4 | 9.5 | Training poison → bad model artifact → backdoor → C2 |
| **KC-C001** | Document-Borne Financial Fraud | 5 | 9.8 | Poisoned loan doc → RAG injection → credit override → payment tool → transfer |
| **KC-D001** | Rogue Agent Cascade | 5 | 9.0 | Internal model drift → autonomous mode → cross-agent override → memory persist → SOAR |
| **KC-E001** | Zero-Trust Identity Fracture | 5 | 9.3 | Low-priv access → credential harvest → A2A spoof → lateral agent hop → exfil |

### OUTCOME when you run Threat Chains

| Terminal | Splunk |
|----------|--------|
| Progress through stages; may show BLOCKED/INJECTED per stage | **One `incident_id`** (e.g. `ACME-INC-A1B2C3D4`) ties all stages; `kill_chain.stage` / `framework.kill_chain_stage` vary per event |

### Validation (all chains)

**Primary dashboard:** **Actor Chain Story** — select your `incident_id`.

**Core correlation query:**

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats dc(framework.kill_chain_stage) AS stages values(framework.kill_chain_stage) AS stage_list values(technique_id) AS techniques BY incident_id
| where stages >= 3
```

**Pass:** One `incident_id` with **≥3 distinct stages** and multiple `technique_id` values.

**Kill-Chain Timeline dashboard:** same `incident_id` — visual stage order.

### Per-chain SPL (optional)

**KC-C001 (workshop default — fraud pipeline):**

```spl
`acme_genai_index` earliest=-1h incident_id=* kill_chain.name="*Fraud*"
| transaction incident_id maxspan=15m
| table _time gen_ai.agent.name technique_id workflow.blocked kill_chain.stage
```

**KC-A001 (data harvest):**

```spl
`acme_genai_index` earliest=-1h incident_id=*
| search technique_id IN ("AML.T0005","AML.T0000","AML.T0003","AML.T0037","AML.T0038")
| stats count values(technique_id) BY incident_id
```

**KC-B001 (supply chain):**

```spl
`acme_genai_index` earliest=-1h cisco_aibom_status=HASH_MISMATCH
| table incident_id technique_id model_artifact_hash_expected model_artifact_hash_found
```

---

## 4. Custom Payload

### What this tab means

Free-form red-team input — **your** prompt injection, jailbreak, or tool-escape string sent to a **chosen agent** (or **Full Pipeline** through all four).

### OUTCOME when you run Custom Payload

| Terminal | Splunk |
|----------|--------|
| **BLOCKED** / **INJECTED** / **ERROR** same as Top 10 | Events with `testbed_mode=CAMPAIGN_LIVE` or custom session; `gen_ai.agent.name` = selected agent; no fixed `campaign_week` unless you add it via API |

### Validation

```spl
`acme_genai_index` earliest=-15m
| search gen_ai.agent.name="acme-agent-intake-001"
| sort - _time
| head 5
| table _time workflow.blocked defenseclaw_blocked codeguard_blocked workflow.block_reason
```

**Pass:** Your execute appears within 60s; you can explain which layer blocked or allowed.

**Tip:** Run a **benign** message first on :5000, then a **malicious** custom payload — compare `workflow.block_reason` in Splunk.

---

## 5. Workshop tab

Guided **multi-step paths**. Keep the Attack Panel tab open until the path completes.

### OUTCOME summary

| Button | Runs | **OUTCOME** |
|--------|------|-------------|
| **15-Minute First Win** | Scenarios **6 → 5 → 9** | Three control philosophies in Splunk: pre-LLM block, output gateway, detect-only RAG |
| **Standard Workshop** | First Win + **KC-C001** | Above + multi-stage `incident_id` fraud chain |
| **Deep Workshop** | Standard + **RUN ALL 45** | Full MITRE coverage math on Technique Coverage Matrix |
| **Fire All 10 Scenarios** | Scenarios **1–10** | All `campaign_week` values; Control Attestation + NIST dashboards populated |
| **Cisco + MLTK Path** | Preflight + Scenarios **1, 6, 7, 9** | AIBOM + MCP scan + token anomaly fields for MLTK panels |
| **MAESTRO Validate** | Architecture brief + Scenarios **6, 8, 9, 10** | MAESTRO layer tags in telemetry vs design-time predictions |

---

### Workshop 1 — 15-Minute First Win

**Dashboards:** Overview · Control Attestation (rows 5,6,9) · Detection Efficacy

```spl
`acme_campaign_w6` earliest=-30m
| stats count by workflow.blocked workflow.block_reason
```
**Pass:** `workflow.blocked=true` on Scenario 6 (MCP / tool scope).

```spl
`acme_campaign_w5` earliest=-30m
| table defenseclaw.action defenseclaw_blocked workflow.blocked
```
**Pass:** DefenseClaw fields present — discuss output-side vs input-side.

```spl
`acme_campaign_w9` earliest=-30m
| table galileo_observe_alert workflow.blocked control.status
```
**Pass:** Events exist; Scenario 9 often **detect-only** (alert without hard block).

---

### Workshop 2 — Standard Workshop

**Dashboards:** Actor Chain Story · Kill-Chain Timeline · Control Attestation

Run First Win queries above, then:

```spl
`acme_genai_index` earliest=-1h incident_id=*
| stats dc(framework.kill_chain_stage) AS stages values(gen_ai.agent.name) BY incident_id
| where stages >= 2
```
**Pass:** KC-C001 `incident_id` with multiple stages and agents.

---

### Workshop 3 — Deep Workshop

**Dashboards:** Technique Coverage Matrix · Detection Efficacy · Threat Hunting

Standard Workshop queries + open **Technique Coverage** after **RUN ALL 45** completes.

```spl
`acme_genai_index` earliest=-24h
| stats count by technique_id testbed_mode
| sort -count
```
**Pass:** Mix of LIVE and SIMULATED; Coverage Matrix OBSERVED % > 0.

---

### Workshop 4 — Fire All 10 Scenarios

**Dashboards:** Control Attestation · NIST AI RMF Scoring · ATLAS Matrix Heatmap

```spl
`acme_genai_index` earliest=-1h
| stats dc(campaign_week) AS scenarios_seen
```
**Pass:** `scenarios_seen=10`.

```spl
`acme_genai_index` earliest=-1h
| stats latest(control.status) AS control_status BY campaign_week control.control_id
| sort campaign_week
```
**Pass:** Rows for scenarios 1–10 in **Control Attestation** (same data in dashboard).

---

### Workshop 5 — MAESTRO Validate

**Prerequisite:** CSA MAESTRO on http://localhost:9002 — [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md)

**Dashboards:** NIST AI RMF Scoring · Control Attestation · Detection Efficacy · Technique Coverage

```spl
`acme_genai_index` earliest=-30m campaign_week IN (6,8,9,10)
| mvexpand framework.maestro_layers
| stats dc(framework.maestro_layers) AS layers_at_risk BY campaign_week
```
**Pass:** MAESTRO layer tags (L2–L6) appear on validation scenarios.

---

### Workshop 6 — Cisco + MLTK Anomaly Hunt

**Prerequisite:** `docker compose -f docker-compose.yml -f docker-compose.cisco.yml --profile local up -d` + MLTK installed

**Dashboards:** MLTK Anomaly Hunting · Threat Hunting · Detection Efficacy

```spl
`acme_campaign_w1` earliest=-30m
| table cisco_aibom_status agent.aibom_validated
```

```spl
`acme_campaign_w7` earliest=-30m
| table gen_ai.usage.input_tokens cisco_tsm_anomaly_score mltk.ctsm_signal
```

**Pass:** Cisco + token fields populated; **MLTK Anomaly Hunting** chart shows surge pattern after Scenario 7.

---

## Quick reference — first query per tab

| Tab / action | First SPL to run |
|--------------|------------------|
| Baseline (before attacks) | `` index=acme_agentic_telemetry earliest=-15m \| stats count by testbed_mode `` |
| Top 10 → Scenario N | `` `acme_campaign_wN` earliest=-30m \| table _time workflow.blocked control.status `` |
| All 45 → one technique | `` `acme_genai_index` earliest=-30m technique_id="AML.T0000" \| head 5 `` |
| Threat Chain KC-C001 | `` `acme_genai_index` incident_id=* earliest=-1h \| stats dc(framework.kill_chain_stage) BY incident_id `` |
| Custom Payload | `` `acme_genai_index` earliest=-15m \| sort - _time \| head 5 `` |
| Workshop First Win | `` `acme_campaign_w6` earliest=-30m \| stats count by workflow.blocked `` |

---

## Related docs

- [USER_GUIDE.md](USER_GUIDE.md) — workshop maturity lifecycle, facilitator notes  
- [WORKSHOP.md](WORKSHOP.md) — full curriculum, hunt questions Q101–Q503  
- [README.md](../README.md) — install from scratch, baseline before first attack  
- [THREAT_SURFACES.md](THREAT_SURFACES.md) — eight agentic surfaces explained
