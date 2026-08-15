# Technique Audit — Learning Tier Classification

Generated from `TECHNIQUE_REGISTRY` + `learning_tiers.py` assignment rules.
No techniques were removed in Phase 4 — classification and documentation only.

## Summary

| Tier | Count | Label |
|------|-------|-------|
| 1 | 2 | Tier 1 — Beginner |
| 2 | 3 | Tier 2 — Intermediate |
| 3 | 19 | Tier 3 — Advanced |
| 4 | 27 | Tier 4 — Coverage & Compliance |

- **Walkthrough-eligible (Tiers 1–3):** 22 techniques
- **Tier 4 with redundancy flag:** 11 SIMULATED/breadth entries
- **Tier 4 unique (no redundant_with):** 16 LIVE/HYBRID coverage entries

## Walkthrough-eligible techniques (Tiers 1–3)

| Technique | Tier | Mode | Scenario week | Notes |
|-----------|------|------|---------------|-------|
| AML.T0015 | 1 | LIVE | 3 | Evade ML Model via Adversarial Perturbat |
| AML.T0054 | 1 | LIVE | 5 | Indirect Prompt Injection |
| AML.T0040 | 2 | LIVE | 7 | Resource Exhaustion via Algorithmic Comp |
| AML.T0043 | 2 | LIVE | 2 | AI Tool Schema Discovery |
| AML.T0050 | 2 | LIVE | 6 | AI Agent Privilege Escalation via Tool A |
| AML.T0025 | 3 | HYBRID | — | AI Model Backdoor Persistence |
| AML.T0026 | 3 | LIVE | 10 | Rogue Agent Persistence |
| AML.T0029 | 3 | HYBRID | — | AI System Availability Disruption |
| AML.T0031 | 3 | LIVE | — | Exfiltrate Data via AI Model Output |
| AML.T0036 | 3 | LIVE | — | Data from AI-integrated Systems |
| AML.T0037 | 3 | LIVE | — | AI Data Discovery via Retrieval Probing |
| AML.T0038 | 3 | LIVE | 9 | Vector Database Exfiltration |
| AML.T0045 | 3 | LIVE | — | Agent Session Smuggling |
| AML.T0048 | 3 | HYBRID | — | AI System Supply Chain Compromise |
| AML.T0052 | 3 | LIVE | — | AI Audit Log Manipulation |
| AML.T0055 | 3 | LIVE | — | AI Context Window Poisoning |
| AML.T0058 | 3 | LIVE | 8 | Agent Identity Spoofing for Privilege Es |
| AML.T0060 | 3 | HYBRID | — | AI Agent C2 via Covert Prompt Channel |
| AML.T0071 | 3 | HYBRID | — | Agent Supply Chain / Skill Poisoning |
| AML.T0072 | 3 | LIVE | — | Memory Poisoning as Behavioral Drift |
| AML.T0074 | 3 | LIVE | — | Missing Human-in-the-Loop Circuit Breake |
| AML.T0075 | 3 | HYBRID | — | Agent-in-the-Middle Message Provenance T |

## Tier 4 — coverage-only (redundant_with set)

These still run in **RUN ALL 51** for compliance evidence. Do not teach as standalone exercises.

| Technique | redundant_with | Mode | Kill-chain stage |
|-----------|----------------|------|------------------|
| AML.T0000 | AML.T0005 | SIMULATED | Reconnaissance |
| AML.T0001 | AML.T0005 | SIMULATED | Reconnaissance |
| AML.T0002 | AML.T0037 | SIMULATED | Reconnaissance |
| AML.T0003 | AML.T0051 | SIMULATED | Reconnaissance |
| AML.T0004 | AML.T0038 | SIMULATED | Reconnaissance |
| AML.T0010 | AML.T0043 | HYBRID | InitialAccess |
| AML.T0012 | AML.T0054 | HYBRID | InitialAccess |
| AML.T0017 | AML.T0018 | SIMULATED | ResourceDevelopment |
| AML.T0018 | AML.T0048 | SIMULATED | ResourceDevelopment |
| AML.T0019 | AML.T0020 | SIMULATED | Staging |
| AML.T0020 | AML.T0051 | SIMULATED | Staging |

## Tier 4 — unique coverage (no redundancy flag)

| Technique | Mode | Rationale |
|-----------|------|-----------|
| AML.T0005 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0016 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0024 | HYBRID | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0030 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0034 | HYBRID | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0035 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0046 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0049 | HYBRID | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0051 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0056 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0057 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0061 | HYBRID | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0062 | HYBRID | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0063 | HYBRID | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0064 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |
| AML.T0065 | LIVE | Matrix/compliance breadth; not in Tier 1–3 curriculum |

## Maintainer recommendations (not executed)

1. **Do not delete** SIMULATED recon/staging techniques — they populate MITRE tactic coverage in Splunk.
2. **Consider merging** display in Attack Panel: group `redundant_with` SIMULATED cards under their canonical LIVE parent in a future UI pass (optional).
3. **Registry count (51)** is referenced in dashboards and docs — any removal requires synchronized lookup + README updates.
4. **Phase 5** will add `exercise_content.csv` with per-technique triage runbooks for Tier 1–3 walkthroughs first.

