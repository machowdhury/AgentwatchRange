# Third-Party Tools & Attribution

This lab integrates or references the following **real** third-party software. AgentWatch Range does **not** claim authorship of these tools.

| Component | Source | License | Usage in this repo |
|-----------|--------|---------|-------------------|
| Splunk Enterprise / Cloud | [splunk.com](https://www.splunk.com) | Commercial | Compliance dashboards, HEC ingestion |
| Ollama | [ollama.com](https://ollama.com) | MIT | Local LLM runtime |
| OpenTelemetry Collector | [opentelemetry.io](https://opentelemetry.io) | Apache-2.0 | Telemetry pipeline |
| Cisco AI Defense (optional overlay) | Cisco commercial platform | Commercial | `docker-compose.cisco.yml` — Foundation-Sec-8B, CTSM |
| Cisco AI Defense open-source tools (optional, Phase 7) | [github.com/cisco-ai-defense](https://github.com/cisco-ai-defense) | Apache-2.0 | Not embedded by default; future Tier 5 capstone |

## Lab-original components (not third-party)

| Component | Description |
|-----------|-------------|
| **AcmeGate** | Lab-original Python regex input middleware (`apps/agents/llm_client.py`) |
| **AcmeSentinel** | Lab-original Python regex output middleware (same module) |
| **Simulated vendor-style telemetry** | Fully synthetic `acme:agentic:sim:json` — not real Cisco AI Defense data |
| **Third-party sim telemetry** | Synthetic `acme:agentic:thirdparty:json` from `scripts/emit_thirdparty_telemetry.py` |

AcmeGate and AcmeSentinel are **not** affiliated with Cisco DefenseClaw or any vendor product. Field names were renamed in Phase 6 to avoid implying vendor authorship.

**AgentWatch Range** as a project name is not affiliated with, and makes no claim over, any similarly-named tool or framework elsewhere (for example observability or agent-monitoring products that use "agentwatch" in their name).
