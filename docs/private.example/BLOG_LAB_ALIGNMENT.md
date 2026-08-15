# Blog ↔ Lab Alignment (10-Week Campaign) — INTERNAL

**Not for public workshop or customer materials.** Copy to `docs/private/BLOG_LAB_ALIGNMENT.md` on your machine.

Maps OrchestraACME Workshop scenarios to blog narrative tracks in `apps/framework/campaign_manifest.py`. Use when writing Splunk/Cisco blog posts or internal teaching from the lab.

| Week | Scenario | Blog track 1 (story) | Blog track 2 (Splunk demo) | Cisco / Splunk tech |
|------|----------|----------------------|----------------------------|---------------------|
| W1 | 1 — Code Compliance Illusion | Prompt drift vs code audits | AIBOM → Splunk lookup / drift hunt | [cisco-ai-defense/aibom](https://github.com/cisco-ai-defense/aibom) |
| W2 | 2 — Evaluation Harness | Structured eval roles | Foundry trace SPL | OTel `foundry.*` fields |
| W3 | 3 — Vibe Coding | IDE guardrails | AcmeGate input validation SPL | Lab AcmeGate + Cisco field names |
| W4 | 4 — Shadow SLM | Rogue edge models | SLM asset discovery dashboard | `slm.unapproved` telemetry |
| W5 | 5 — Front Desk | Semantic jailbreak | AcmeSentinel HARD_DENY correlation | Compatible with [DefenseClaw](https://github.com/cisco-ai-defense/defenseclaw) telemetry |
| W6 | 6 — MCP Tools | Tool privilege escape | MCP session / scope tracking | [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) |
| W7 | 7 — Infinity Bill | Recursive agent cost | **CTSM** `\| fit ctsm_forecast` token alert | [cisco-time-series-model](https://github.com/splunk/cisco-time-series-model) |
| W8 | 8 — Identity Fracture | A2A zero trust | DID verification ledger | [a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner) (optional) |
| W9 | 9 — Invisible Leak | RAG exfiltration | Behavioral anomaly hunts | Galileo-style `galileo_*` fields |
| W10 | 10 — Self-Healing SOC | Memory + rogue agent | SOAR 2s containment playbook | SOAR sim + Splunk ES |

## Workshop paths that cover blog demos

| Workshop path | Blog weeks best demonstrated |
|---------------|------------------------------|
| 15-Minute First Win | W5, W6, W9 |
| Standard Workshop | + kill chain (multi-stage narrative) |
| Deep Workshop | Full MITRE coverage matrix |
| Fire All 10 | All blog tracks (telemetry only) |
| **Cisco + MLTK Anomaly Hunt** | W1, W6, W7, W9 + Foundation-Sec-8B |

## Splunk dashboards per blog track 2

| Blog demo theme | Dashboard |
|-----------------|-----------|
| AIBOM / drift | Control Attestation, MLTK Anomaly Hunting |
| AcmeSentinel / output gateway | Control Attestation, Overview |
| MCP abuse | Detection Efficacy, MLTK Anomaly Hunting |
| CTSM token surge | **MLTK Anomaly Hunting** |
| RAG behavioral | Threat Hunting, MLTK Anomaly Hunting |
| Kill-chain / SOAR | Actor Chain Story, Kill-Chain Timeline |

## Foundation-Sec-8B in blogs

Position as **hunt copilot** (not autonomous blocker): analysts paste hunt rows into `POST /api/v1/hunt/foundation-sec` for MITRE-aligned triage bullets. Model card: [fdtn-ai/Foundation-Sec-8B](https://huggingface.co/fdtn-ai/Foundation-Sec-8B).
