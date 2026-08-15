# Agentic Threat Surfaces (2025–2026)

OrchestraACME exercises **nine threat surface categories** (eight Top 10 surfaces plus **Supply Chain / Registry Trust**) when organizations move from chatbots to tool-using, multi-agent systems.

---

## The eight surfaces

| # | Threat surface | Workflow layer | Lab scenario | What you will see in Splunk |
|---|----------------|----------------|--------------|----------------------------|
| 1 | **AI supply chain & prompt drift** | Orchestration | Scenario 1 | `cisco_aibom_status`, `agent.aibom_validated` |
| 2 | **Orchestration policy bypass** | Orchestration | Scenario 2 | `foundry.orchestrator_override`, workflow block |
| 3 | **Unsafe generated / ingested content** | Input validation | Scenario 3 | `codeguard_blocked`, `CG-RULE-SBD-007` |
| 4 | **Shadow / unapproved models** | Runtime | Scenario 4 | `slm.unapproved=true`, `deployment.tier=shadow` |
| 5 | **Semantic jailbreak & output abuse** | Output gateway | Scenario 5 | `defenseclaw.action=HARD_DENY` |
| 6 | **MCP tool abuse & host escape** | Tools | Scenario 6 | `tool.scope_violation=true`, MCP gateway block |
| 7 | **Recursive token weaponization** | Cost / DoS | Scenario 7 | `call_depth_detected`, token usage spikes |
| 8 | **A2A identity spoofing** | Agent identity | Scenario 8 | `cryptographic_passport_valid=false` |
| 9 | **RAG / knowledge exfiltration** | Retrieval | Scenario 9 | `galileo_observe_alert`, `vector_retrieval_count` |
| 10 | **Autonomous escape & containment** | Memory / SOC | Scenario 10 | `memory.policy.rule_id`, `containment.action=QUARANTINE` |

---

## Ninth surface — Supply Chain / Registry Trust (2026 emerging)

| # | Threat surface | Workflow layer | Lab technique | What you will see in Splunk |
|---|----------------|----------------|---------------|----------------------------|
| 11 | **Supply Chain / Registry Trust** | Tools / plugins | AML.T0070, AML.T0071 | `tool_manifest_tampered`, `skill.provenance_valid=false`, `agent.aibom_validated=false` |

This surface covers **MCP tool manifest poisoning** and **community skill/plugin poisoning** — attacks embedded in registry metadata rather than user prompts or unapproved model runtimes (Scenario 4).

### Six emerging threat scenarios (Phase 1 append)

| Technique ID | Title | Mode | Primary telemetry |
|--------------|-------|------|-------------------|
| AML.T0070 | MCP Tool Description Poisoning | SIMULATED | `tool_manifest_tampered=true` |
| AML.T0071 | Agent Supply Chain / Skill Poisoning | HYBRID | `skill.provenance_valid=false` |
| AML.T0072 | Memory Poisoning as Behavioral Drift | LIVE | `memory.drift_detected`, `memory_entry_trust_score` |
| AML.T0073 | Agent Identity Privilege Creep | SIMULATED | `granted_scope`, `used_scope`, `scope_delta` |
| AML.T0074 | Missing HITL Circuit Breaker | LIVE | `hitl_required`, `hitl_bypassed` |
| AML.T0075 | Agent-in-the-Middle Message Tampering | HYBRID | `message.provenance_valid=false` |

Execute via **All 51 Techniques** (45 original + 6 emerging) or threat chain **KC-F001** (memory drift).

---

## Why surfaces matter more than prompts

Traditional LLM testing focuses on **prompt injection strings**. Production agent failures happen on **surfaces**:

| Surface | Examples in production |
|---------|------------------------|
| **Tools** | MCP servers, function calling, shell plugins |
| **RAG** | Vector stores, retrieval poisoning, context leakage |
| **Memory** | Persistent instructions across sessions |
| **A2A** | Agent-to-agent messages without cryptographic binding |
| **Orchestration** | Supervisor overrides, eval harness bypass, multi-agent routing |
| **Runtime** | Unapproved models on endpoints outside IT governance |

OrchestraACME enforces and instruments these in `apps/framework/workflow_guard.py` — not only in prompt text.

---

## Framework crosswalk (educational)

| Surface | MITRE ATLAS | OWASP | NIST AI RMF |
|---------|-------------|-------|-------------|
| Tools (MCP) | AML.T0050 | LLM06 / ASI01 | GOVERN-1.1 |
| RAG exfil | AML.T0038 | LLM02 / ASI02 | MEASURE-2.10 |
| A2A spoof | AML.T0058 | LLM08 / ASI03 | GOVERN-1.1 |
| Orchestration bypass | AML.T0043 | LLM09 / ASI04 | MEASURE-2.6 |
| Shadow runtime | AML.T0005 | LLM05 / ASI04 | MAP-1.1 |
| Supply chain drift | AML.T0048 | LLM05 / ASI04 | GOVERN-6.1 |
| Token weaponization | AML.T0040 | LLM10 / ASI08 | MEASURE-2.5 |
| Autonomous escape | AML.T0026 | LLM04 / ASI02 | MANAGE-4.1 |

These are **educational mappings** for workshops — not compliance attestations.

---

## Lab depth: Top 10 vs 45 techniques vs kill chains

| Layer | Count | Use case |
|-------|-------|----------|
| **Top 10 scenarios** | 10 | Highest-fidelity single-surface demonstrations |
| **MITRE ATLAS registry** | 45 (+ 6 emerging) | Full technique coverage + hunt SPL per playbook |
| **Kill chains** | 6 | Multi-stage compromise stories (`KC-A001` … `KC-E001`, `KC-F001`) |

---

## Further reading

- [WORKSHOP.md](WORKSHOP.md) — ordered curriculum, hunt questions Q201–Q503
- [USER_GUIDE.md](USER_GUIDE.md) — run exploits, threat hunts, light up Splunk dashboards
- [README.md](../README.md) — architecture and installation
- [splunk_app/INSTALL.md](../splunk_app/INSTALL.md) — Splunk app install
