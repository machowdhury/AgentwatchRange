# Learning Path — Difficulty Tiers (0–6)

Structured curriculum for OrchestraACME / AgentWatch Range. This is a **navigation layer** on top of existing tabs — nothing was removed, only ordered by progression.

**Start here if you are new:** complete [README golden path](../README.md#start-here--your-first-30-minutes) (Tier 0 exit criteria), then enter Tier 1.

---

## Tier 0 — Orientation (no attacks)

**Goal:** Understand the defend path before breaking anything.

| Step | Action |
|------|--------|
| 1 | Read [CONCEPTS.md](CONCEPTS.md) — architecture, transparency, limitations |
| 2 | Submit one legitimate loan request on `:5000` |
| 3 | Confirm baseline telemetry in Splunk: `index=acme_agentic_telemetry sourcetype="otel:agentic:json" earliest=-15m \| stats count by campaign_week` |

**Exit criteria:** You can explain intake → LLM → controls → OTel → Splunk without running an attack.

---

## Tier 1 — Beginner: single-surface, single-turn

**Teaches:** Input vs. output inspection (CodeGuard vs. DefenseClaw); what regex guardrails catch and miss.

| Scenario | Attack Panel | Tier badge |
|----------|--------------|------------|
| **3** — Secure-by-Default Vibe Coding | Top 10 → Scenario 3 | Tier 1 — Beginner |
| **5** — Guarding the Front Desk | Top 10 → Scenario 5 | Tier 1 — Beginner |

**Splunk proof:** `` `acme_campaign_w3` `` and `` `acme_campaign_w5` `` — compare `codeguard_blocked` vs `defenseclaw_action=HARD_DENY`.

**Recommended UI:** **GenAI Compliance Monitor → Exercise Runner** — select Tier 1 techniques after firing scenarios in the Attack Panel.

**Workshop shortcut:** [15-Minute First Win](WORKSHOP.md) includes Scenario 5 (and 6, 9 for contrast).

---

## Tier 2 — Intermediate: tools & orchestration

**Teaches:** Multi-step reasoning, orchestration bypass, token/cost abuse; `kill_chain.stage` correlation.

| Scenario | Surface |
|----------|---------|
| **2** — Foundry / orchestration bypass | orchestration |
| **6** — MCP tool scope escape | tools |
| **7** — Algorithmic DoS / token surge | orchestration |

**Splunk proof:** `` `acme_campaign_w6` earliest=-30m \| stats count by workflow.blocked `` (README golden path variant).

**Recommended UI:** **Exercise Runner** (Tier 2 filter) — predict BLOCKED before running hunt SPL for Scenario 6.

---

## Tier 3 — Advanced: identity, memory, RAG, multi-stage

**Teaches:** Cross-agent trust, behavioral/cumulative detection, kill-chain correlation.

| Activity | Where |
|----------|--------|
| Scenarios **8, 9, 10** | Top 10 tab |
| Threat chains **KC-A001 … KC-E001, KC-F001** | Threat Chains tab |
| Emerging **AML.T0070–T0075** | All 51 Techniques (individual EXECUTE) or Workshop Q504–Q509 |

**Splunk proof:** `incident_id=*` \| Actor Chain Story · Kill-Chain Timeline · emerging saved searches (Phase 3).

**Recommended UI:** **Exercise Runner** (Tier 3 filter) — work through emerging techniques AML.T0070–T0075 with triage runbooks before revealing explanations.

---

## Tier 4 — Coverage & Compliance (“All 51”)

**Purpose:** Bulk campaign to populate **Technique Coverage Matrix** and **Control Attestation** — NIST/OWASP/MITRE evidence generation, **not** 51 separate walkthroughs.

| Action | Outcome |
|--------|---------|
| Attack Panel → **All 51 Techniques** → **RUN ALL 51** | Matrix fills with NOT_ATTEMPTED / ATTEMPTED_NOT_DETECTED / DETECTED states |
| SIMULATED-only techniques | Hunt-only OTel; see [TECHNIQUE_AUDIT.md](TECHNIQUE_AUDIT.md) for redundancy map |

**Why this exists:** Compliance and purple-team backlog prioritization require breadth. Tier 4 techniques marked `redundant_with` in the registry teach the same concept as an earlier LIVE technique — run them for coverage, not for a second lesson.

---

## Tier 5 — Vendor-realistic tooling (Cisco overlay)

**Prerequisite:** Tiers 1–3 complete.

Re-run a subset of attacks with Cisco AI Defense scanners and MLTK anomaly views:

```bash
docker compose -f docker-compose.yml -f docker-compose.cisco.yml --profile local up -d
```

| Path | Scenarios |
|------|-----------|
| Workshop → **Cisco + MLTK Anomaly Hunt** | 1 → 6 → 7 → 9 |
| Splunk → **MLTK Anomaly Hunting** dashboard | CTSM + Galileo + AIBOM fields |

**Teaches:** Transparent lab controls vs. production ML-based detection on attacks you already understand.

---

## Tier 6 — Capstone / Blue team

**Prerequisite:** Tiers 1–5 (or skip Tier 5 if Cisco overlay unavailable).

| Activity | Doc |
|----------|-----|
| MAESTRO threat-model-first workflow | [MAESTRO_WORKSHOP.md](MAESTRO_WORKSHOP.md) |
| Build-your-own detection for one Phase 1 technique | [WORKSHOP.md](WORKSHOP.md) Q504+ |
| Guided finale | Workshop paths: 15-min → Standard → Deep → Fire All 10 → MAESTRO |

---

## Quick reference — scenario → tier

| Scenario week | Tier | Primary teaching focus |
|---------------|------|------------------------|
| 3, 5 | 1 | CodeGuard / DefenseClaw |
| 2, 6, 7 | 2 | Orchestration, MCP tools, DoS |
| 8, 9, 10 | 3 | A2A, RAG, rogue agent |
| 1, 4 | 4 (also Tier 5 Cisco) | Supply chain / shadow AI breadth |
| All 51 bulk run | 4 | Compliance matrix |
| Cisco overlay paths | 5 | Vendor ML scanners |
| Workshop finale | 6 | Capstone |

---

## Related docs

- [USER_GUIDE.md](USER_GUIDE.md) — full tab reference
- [ATTACK_PANEL_GUIDE.md](ATTACK_PANEL_GUIDE.md) — per-scenario SPL and outcomes
- [TECHNIQUE_AUDIT.md](TECHNIQUE_AUDIT.md) — tier assignment audit and redundancy recommendations
- [EXERCISE_RUNNER.md](EXERCISE_RUNNER.md) — Splunk guided exercise dashboard
- [WORKSHOP.md](WORKSHOP.md) — ordered workshop paths
