# MAESTRO Threat Modeling Workshop

**Workshop Level 5A** in the ordered curriculum — see **[WORKSHOP.md](WORKSHOP.md)** for full path (Levels 0–5) and role tracks.

Design-time threat modeling with the [CSA MAESTRO Threat Analyzer](https://github.com/CloudSecurityAlliance/MAESTRO), then validate predictions in OrchestraACME and Splunk.

> **Disclaimer:** CSA MAESTRO and OrchestraACME are educational tools. AI-generated threats and mitigations are not a substitute for professional security review. See the [MAESTRO README](https://github.com/CloudSecurityAlliance/MAESTRO#disclaimer).

## Why add this to the lab?

OrchestraACME already tags telemetry with `framework.maestro_layers` (L1–L7) and shows **MAESTRO Layer Risk Coverage** in Splunk. What was missing is the **predict → attack → prove** loop:

| Phase | Tool | Question answered |
|-------|------|-------------------|
| **Model** | CSA MAESTRO Threat Analyzer | What could go wrong per layer? |
| **Attack** | OrchestraACME Workshop | Do our scenarios hit those layers? |
| **Prove** | Splunk NIST AI RMF | Which layers actually lit up in telemetry? |

This complements (does not replace) the **Cisco + MLTK** path: Cisco scanners focus on runtime supply-chain and MCP posture; MAESTRO focuses on architecture-level agentic threat identification.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| OrchestraACME running | `docker compose --profile local up -d` |
| Splunk compliance app installed | For MAESTRO coverage % panel |
| Node.js 18+ | For CSA MAESTRO only |
| LLM for MAESTRO | Gemini, OpenAI, or **Ollama** (reuse lab Ollama on host: `http://localhost:11434`) |

---

## Part 1 — Install CSA MAESTRO Threat Analyzer

```bash
git clone https://github.com/CloudSecurityAlliance/MAESTRO.git
cd MAESTRO
npm install
```

Create `.env` in the MAESTRO repo:

```bash
# Reuse OrchestraACME Ollama (published on host port 11434)
LLM_PROVIDER=ollama
OLLAMA_SERVER_ADDRESS=http://localhost:11434
LLM_MODEL=llama3.2:1b
```

Run **two terminals** in the MAESTRO directory:

```bash
# Terminal 1
npm run dev
# → http://localhost:9002

# Terminal 2
npm run genkit:watch
```

Reference: [CSA MAESTRO Getting Started](https://github.com/CloudSecurityAlliance/MAESTRO#getting-started)

---

## Part 2 — Get the OrchestraACME architecture blurb

**Option A — Attack Panel workshop (recommended)**

1. Open http://localhost:5001 → **Workshop** tab (last menu item)
2. Click **▶ RUN MAESTRO VALIDATE PATH**
3. Step 1 copies the architecture to your clipboard and pauses for MAESTRO analysis

**Option B — API**

```bash
curl -s http://localhost:5000/api/v1/maestro/architecture | jq -r .architecture_description
```

**Option C — Validation guide (scenarios + SPL)**

```bash
curl -s http://localhost:5000/api/v1/maestro/validation-guide | jq .
```

---

## Part 3 — Threat model in MAESTRO

1. Open http://localhost:9002
2. Paste the OrchestraACME architecture into the architecture textarea
3. Run analysis — review **traditional** and **agentic** threats per layer
4. Note which layers MAESTRO ranks highest (typically **L3**, **L4**, **L5**, **L6** for this lab)

**Reflection prompts:**

- Did MAESTRO flag MCP tool escape and excessive agency (L3/L4)?
- Did it identify A2A trust-chain risks across the four-agent pipeline (L5)?
- Did it warn about RAG/context injection (L2) and guardrail bypass (L6)?

---

## Part 4 — Validate in the lab

Run the **MAESTRO Validate** workshop path (Scenarios **6 → 8 → 9 → 10**):

| Scenario | MAESTRO layers | Validates |
|----------|----------------|-----------|
| 6 — MCP tool escape | L4, L5 | Capability abuse, tool gateway |
| 8 — A2A identity spoof | L5 | Multi-agent trust propagation |
| 9 — RAG exfil probe | L2 | Data operations / retrieval |
| 10 — Memory / SOC bypass | L6 | Security & compliance controls |

Or fire manually from **Top 10 Scenarios** tab.

Wait **60 seconds** for Splunk ingest.

---

## Part 5 — Prove in Splunk

Open these dashboards:

1. **NIST AI RMF Scoring** → **MAESTRO Layer Risk Coverage** (target: >50% after validation path)
2. **Control Attestation** → scenarios 6, 8, 9, 10
3. **Detection Efficacy** → workflow blocks vs detect-only

**Validation SPL** (copy from Search):

```spl
`acme_genai_index` earliest=-30m
| eval layers=split(framework.maestro_layers, ",")
| mvexpand layers
| search layers=L*
| stats count by layers campaign_week workflow.block_reason
| sort layers campaign_week
```

**Coverage % SPL:**

```spl
`acme_genai_index` earliest=-30m
| mvexpand framework.maestro_layers
| search framework.maestro_layers=L*
| stats dc(framework.maestro_layers) AS layers_at_risk
| eval maestro_coverage_pct=round(layers_at_risk/7*100,1)
```

### Predict vs observe worksheet

| MAESTRO layer | Predicted threat (your notes) | Scenario fired | Observed in Splunk? |
|---------------|------------------------------|----------------|---------------------|
| L2 | | 9 | |
| L4 | | 6 | |
| L5 | | 6, 8 | |
| L6 | | 10 | |

---

## Scenario ↔ layer reference

| Scenario | Title | MAESTRO layers |
|----------|-------|----------------|
| 1 | AI BOM / supply chain | L1, L7 |
| 2 | Foundry evaluation bypass | L7 |
| 3 | AcmeGate rule breach | L2 |
| 4 | Shadow SLM at edge | L7 |
| 5 | Output gateway jailbreak | L3 |
| 6 | MCP tool escape | L4, L5 |
| 7 | Token surge (Infinity Bill) | L5 |
| 8 | A2A identity spoof | L5 |
| 9 | RAG exfil probe | L2 |
| 10 | Memory / SOC bypass | L6 |

Full map: `GET /api/v1/maestro/architecture` → `scenario_layer_map`

---

## Facilitator timing (~35 min)

| Minutes | Activity |
|---------|----------|
| 0–5 | Intro MAESTRO 7-layer model ([CSA paper](https://cloudsecurityalliance.org/artifacts/agentic-ai-threat-modeling-framework-maestro)) |
| 5–15 | Learners run MAESTRO analysis on OrchestraACME architecture |
| 15–25 | **MAESTRO Validate** workshop path in Attack Panel |
| 25–35 | Splunk compare: predicted layers vs `framework.maestro_layers` |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| MAESTRO won't start | Ensure Node 18+, run both `npm run dev` and `npm run genkit:watch` |
| Ollama errors in MAESTRO | Set `OLLAMA_SERVER_ADDRESS=http://localhost:11434`; confirm `ollama list` shows `llama3.2:1b` |
| Splunk MAESTRO % is 0 | Run validation scenarios; widen time range to Last 30 minutes |
| MAESTRO predicts threats lab doesn't demonstrate | Expected — use **Deep Workshop** or **RUN ALL 45** for broader layer coverage |

---

## References

- [CSA MAESTRO Threat Analyzer (GitHub)](https://github.com/CloudSecurityAlliance/MAESTRO)
- [Agentic AI Threat Modeling Framework: MAESTRO (CSA)](https://cloudsecurityalliance.org/artifacts/agentic-ai-threat-modeling-framework-maestro)
- OrchestraACME [USER_GUIDE.md](USER_GUIDE.md) — Workshop paths
- OrchestraACME [CISCO_INTEGRATION.md](CISCO_INTEGRATION.md) — Runtime scanning overlay
