# Cisco AI Defense + Splunk MLTK Integration

AgentWatch Range integrates **optional** tooling from [Cisco AI Defense](https://github.com/cisco-ai-defense), [Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B), and [Splunk Cisco Time Series Model](https://github.com/splunk/cisco-time-series-model) without breaking Workshop attacks.

---

## Quick start (Splunk/Cisco employees)

```bash
cp .env.example .env

# Enable Cisco overlay (teach mode — scans log only, attacks unchanged)
docker compose -f docker-compose.yml -f docker-compose.cisco.yml --profile local up --build -d

# Attack panel → Workshop tab (last) → **Cisco + MLTK Anomaly Hunt**
```

On Splunk:

1. Install **Machine Learning Toolkit** (Splunkbase)
2. Install **cisco-time-series-model** from [github.com/splunk/cisco-time-series-model](https://github.com/splunk/cisco-time-series-model)
3. Install the compliance app tarball printed by `./scripts/package_splunk_app.sh` (upload from `dist/`)
4. Open **MLTK Anomaly Hunting** dashboard

---

## LAB_MODE — attacks keep working

| Mode | Behavior |
|------|----------|
| **`teach`** (default) | Cisco AIBOM + MCP Scanner run **log-only**. Lab middleware still blocks Scenarios 3/5/6/8 as before. Workshop paths stay reproducible. |
| **`enforce`** | Cisco scan `FAIL` can block workflow (advanced). Use only after Standard Workshop. |

```bash
LAB_MODE=teach          # default in docker-compose.cisco.yml
LAB_MODE=enforce        # stricter demos
```

Existing escape hatches still work:

```bash
ACME_OUTPUT_GUARD_ENABLED=false
ACME_INPUT_GUARD_ENABLED=false
```

---

## What integrates with what

| Tool | Repo | AgentWatch Range usage |
|------|------|-------------------|
| **AI BOM** | [cisco-ai-defense/aibom](https://github.com/cisco-ai-defense/aibom) | Scenario 1 telemetry + preflight scan |
| **MCP Scanner** | [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Scenario 6 preflight + `data/mcp/acme_banking_mcp.json` |
| **AcmeSentinel** (lab middleware) | N/A — lab-original | Python regex output gateway in `llm_client.py`; telemetry fields `acme_output_guard.*` |
| **DefenseClaw** (real OSS, optional Phase 7) | [cisco-ai-defense/defenseclaw](https://github.com/cisco-ai-defense/defenseclaw) | *Not embedded* — distinct from lab AcmeSentinel; optional future integration |
| **Foundation-Sec-8B** | [fdtn-ai/Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) | `POST /api/v1/hunt/foundation-sec` hunt enrichment via Ollama |
| **Cisco TSM** | [splunk/cisco-time-series-model](https://github.com/splunk/cisco-time-series-model) | Splunk `\| fit MLTKContainer algo=ctsm_forecast` on token time series |

---

## Three Cisco-adjacent things (do not confuse)

1. **Real commercial overlay** — `docker-compose.cisco.yml` (Cisco AI Defense platform, Foundation-Sec-8B, CTSM).
2. **Real open-source tools (optional Phase 7)** — DefenseClaw, MCP Scanner, Skill Scanner from [github.com/cisco-ai-defense](https://github.com/cisco-ai-defense).
3. **Lab simulated-telemetry dashboard** — `acme:agentic:sim:json` in `App-Agentic-Compliance` — fully synthetic, not real Cisco data.

**AcmeGate** and **AcmeSentinel** (this lab's regex middleware) are unrelated to all three. See [NOTICE.md](../NOTICE.md).

---

## Optional host install (real scanners)

```bash
chmod +x scripts/install_cisco_tools.sh
./scripts/install_cisco_tools.sh
```

Or: `pip install -r apps/requirements-cisco.txt`

Without CLIs, teach mode uses **local manifest + MCP policy** scans (still emits `cisco.aibom.*` / `cisco.mcp.*` fields).

---

## Foundation-Sec-8B on Ollama

1. Set in `.env`:

```bash
FOUNDATION_SEC_ENABLED=true
FOUNDATION_SEC_PULL=true
OLLAMA_SECURITY_MODEL=hf.co/fdtn-ai/Foundation-Sec-8B-GGUF:Q4_K_M
```

2. Rebuild Ollama container (large download).

3. Enrich a hunt:

```bash
curl -s -X POST http://localhost:5000/api/v1/hunt/foundation-sec \
  -H "Content-Type: application/json" \
  -d '{"technique_id":"AML.T0040","context":"call_depth=12 tokens_consumed_in_loop=48000"}'
```

---

## API endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/cisco/status` | Integration health |
| `POST /api/v1/cisco/scan/aibom` | AI BOM scan |
| `POST /api/v1/cisco/scan/mcp` | MCP config scan |
| `POST /api/v1/cisco/scan/preflight` | Both scans |
| `POST /api/v1/hunt/foundation-sec` | Foundation-Sec-8B analysis |

Attack panel proxy: `POST /api/cisco/preflight` → banking app.

---

## Splunk workshop hunts

See **GenAI Compliance Monitor → MLTK Anomaly Hunting** or `docs/USER_GUIDE.md`.

| Scenario | Anomaly type | Key fields |
|----------|--------------|------------|
| 1 | Supply chain / AIBOM | `cisco_aibom_status`, `cisco.aibom.*` |
| 6 | MCP tool surface | `cisco.mcp.*`, `mcp.gateway.*` |
| 7 | Token surge (CTSM) | `cisco_tsm_anomaly_score`, `mltk.ctsm_signal` |
| 9 | RAG behavioral | `galileo_observe_alert`, `galileo_anomaly_score` |

Saved searches (ship disabled): **MLTK: CTSM Token Surge**, **Behavioral RAG Anomaly**, **Cisco AIBOM Drift Hunt**.

---

## Blog alignment

Workshop paths that cover Cisco + MLTK demos are documented in [WORKSHOP.md](WORKSHOP.md) Level 4B.

Private author prompts remain in `docs/private/` (gitignored).
