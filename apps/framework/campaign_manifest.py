"""
10-week blog campaign manifest — single source of truth for AgentWatch Range.

Drives attack panel labels, OTel enrichment, Splunk lookups, and docs/campaign/.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class CampaignWeek:
    week: int
    slug: str
    theme: str
    blog_track1: str
    blog_track2: str
    core_technology: str
    owasp_llm: List[str] = field(default_factory=list)
    owasp_asi: List[str] = field(default_factory=list)
    maestro: List[str] = field(default_factory=list)
    mitre_atlas: List[str] = field(default_factory=list)
    nist_ai_rmf: List[str] = field(default_factory=list)
    splunk_macro: str = ""
    splunk_saved_search: str = ""
    otel_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


CAMPAIGN_WEEKS: Dict[int, CampaignWeek] = {
    1: CampaignWeek(
        week=1,
        slug="code-compliance-illusion",
        theme="The Code Compliance Illusion",
        blog_track1="Why pristine code audits miss natural language prompt drift in live production environments.",
        blog_track2="Ingesting cisco-aibom into a Splunk KV Store lookup for continuous real-time signature reconciliation.",
        core_technology="cisco-aibom Build Manifest",
        owasp_llm=["LLM05"],
        owasp_asi=["ASI04"],
        maestro=["L1", "L7"],
        mitre_atlas=["AML.T0048", "AML.T0051.000"],
        nist_ai_rmf=["GOVERN-6.1", "MEASURE-2.5"],
        splunk_macro="acme_campaign_w1",
        splunk_saved_search="GenAI Campaign W1 - AI BOM Hash Mismatch",
        otel_fields=[
            "campaign_week", "cisco_aibom_status", "agent.aibom_validated",
            "model_artifact_hash_expected", "model_artifact_hash_found",
        ],
    ),
    2: CampaignWeek(
        week=2,
        slug="agentic-evaluation-harness",
        theme="The Agentic Evaluation Harness",
        blog_track1="Eliminating LLM noise by using structured evaluation roles to validate model safety boundaries.",
        blog_track2="Writing SPL queries to parse and ingest structural Foundry Spec trace states from the OTel pipeline.",
        core_technology="Foundry Security Spec Matrix",
        owasp_llm=["LLM09"],
        owasp_asi=["ASI04"],
        maestro=["L7"],
        mitre_atlas=["AML.T0043"],
        nist_ai_rmf=["MEASURE-2.6", "MANAGE-2.3"],
        splunk_macro="acme_campaign_w2",
        splunk_saved_search="GenAI Campaign W2 - Foundry Trace Policy Bypass",
        otel_fields=["foundry.trace_id", "foundry.policy_status", "foundry.orchestrator_override"],
    ),
    3: CampaignWeek(
        week=3,
        slug="secure-by-default-vibe-coding",
        theme="Secure-by-Default Vibe Coding",
        blog_track1="Shifting security left by enforcing natural language guardrails directly within the developer's IDE.",
        blog_track2="Splunk detection architecture for flagging AI-generated code snippets that breach input validation rules.",
        core_technology="Project AcmeGate Rulesets",
        owasp_llm=["LLM02", "LLM03"],
        owasp_asi=["ASI05"],
        maestro=["L2"],
        mitre_atlas=["AML.T0015", "AML.T0048"],
        nist_ai_rmf=["GOVERN-1.3", "MANAGE-2.4"],
        splunk_macro="acme_campaign_w3",
        splunk_saved_search="GenAI Campaign W3 - AcmeGate Rule Breach",
        otel_fields=["acme_input_guard.rule_id", "acme_input_guard_blocked", "acme_input_guard.field"],
    ),
    4: CampaignWeek(
        week=4,
        slug="shadow-ai-at-the-edge",
        theme="Shadow AI at the Edge",
        blog_track1="Managing the compliance liabilities and hidden compute costs of decentralized local models.",
        blog_track2="Building a Splunk Asset Discovery dashboard to trace rogue, unmapped edge Small Language Models (SLMs).",
        core_technology="Cisco AI Defense: Explorer Edition",
        owasp_llm=["LLM05"],
        owasp_asi=["ASI04"],
        maestro=["L7"],
        mitre_atlas=["AML.T0005", "AML.T0019"],
        nist_ai_rmf=["MAP-1.1", "GOVERN-6.2"],
        splunk_macro="acme_campaign_w4",
        splunk_saved_search="GenAI Campaign W4 - Unapproved Edge SLM",
        otel_fields=["llm.runtime", "slm.unapproved", "deployment.tier", "gen_ai.request.model"],
    ),
    5: CampaignWeek(
        week=5,
        slug="guarding-the-front-desk",
        theme="Guarding the Front Desk",
        blog_track1="Why traditional firewalls are blind to semantic compromises and adversarial conversations.",
        blog_track2="Constructing correlation rules to parse the acme:agentic:sim:json stream for runtime POLICY_HARD_DENY triggers.",
        core_technology="acmesentinel-gateway Go Proxy",
        owasp_llm=["LLM01"],
        owasp_asi=["ASI01"],
        maestro=["L3"],
        mitre_atlas=["AML.T0054", "AML.T0015"],
        nist_ai_rmf=["MANAGE-2.4", "MEASURE-2.5"],
        splunk_macro="acme_campaign_w5",
        splunk_saved_search="GenAI Campaign W5 - AcmeSentinel HARD_DENY",
        otel_fields=["acme_output_guard.action", "acme_output_guard.rule_id", "acme_output_guard_blocked"],
    ),
    6: CampaignWeek(
        week=6,
        slug="intern-with-the-master-key",
        theme="The Intern with the Master Key",
        blog_track1="Preventing automated agent tools from escalating privileges and escaping the container sandbox.",
        blog_track2="Operationalizing token and session tracking to catch Model Context Protocol (MCP) tool abuse and host escapes.",
        core_technology="AcmeSentinel OpenShell",
        owasp_llm=["LLM06"],
        owasp_asi=["ASI01"],
        maestro=["L4", "L5"],
        mitre_atlas=["AML.T0050", "AML.T0012"],
        nist_ai_rmf=["MANAGE-2.3", "GOVERN-1.1"],
        splunk_macro="acme_campaign_w6",
        splunk_saved_search="GenAI Campaign W6 - MCP Tool Scope Violation",
        otel_fields=["gen_ai.tool.name", "tool.scope_violation", "mcp.server.id", "session.id"],
    ),
    7: CampaignWeek(
        week=7,
        slug="the-infinity-bill",
        theme="The Infinity Bill",
        blog_track1="Defending enterprise balance sheets against weaponized, recursive multi-agent loops.",
        blog_track2="Leveraging the Cisco Time Series Model (| fit ctsm) in Splunk to forecast and alert on token consumption surges.",
        core_technology="Cisco Time Series Model (cisco-tsm)",
        owasp_llm=["LLM10"],
        owasp_asi=["ASI08"],
        maestro=["L5"],
        mitre_atlas=["AML.T0040", "AML.T0029"],
        nist_ai_rmf=["MEASURE-2.5", "MANAGE-4.1"],
        splunk_macro="acme_campaign_w7",
        splunk_saved_search="GenAI Campaign W7 - Token Surge Anomaly",
        otel_fields=["gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "call_depth_detected"],
    ),
    8: CampaignWeek(
        week=8,
        slug="the-identity-fracture",
        theme="The Identity Fracture",
        blog_track1="Enforcing zero-trust boundaries when agents pass authority laterally across different enclaves.",
        blog_track2="Building a cross-enclave verification ledger in Splunk using W3C Decentralized Identifiers (DIDs) and signatures.",
        core_technology="W3C DIDs & Cryptographic Passports",
        owasp_llm=["LLM08"],
        owasp_asi=["ASI03"],
        maestro=["L5"],
        mitre_atlas=["AML.T0058", "AML.T0045"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.3"],
        splunk_macro="acme_campaign_w8",
        splunk_saved_search="GenAI Campaign W8 - DID Verification Failure",
        otel_fields=["did.document", "delegation.chain", "cryptographic_passport_valid"],
    ),
    9: CampaignWeek(
        week=9,
        slug="the-invisible-leak",
        theme="The Invisible Leak",
        blog_track1="Spotting high-dimensional data exfiltration and semantic mutations inside RAG vector stores.",
        blog_track2="Designing behavioral anomaly searches to flag exfiltration attempts hidden in normal database lookups.",
        core_technology="Galileo Observe Engine",
        owasp_llm=["LLM02"],
        owasp_asi=["ASI02"],
        maestro=["L2"],
        mitre_atlas=["AML.T0038", "AML.T0037"],
        nist_ai_rmf=["MEASURE-2.10", "MANAGE-2.4"],
        splunk_macro="acme_campaign_w9",
        splunk_saved_search="GenAI Campaign W9 - RAG Exfiltration Anomaly",
        otel_fields=["galileo_observe_alert", "galileo_anomaly_score", "vector_retrieval_count"],
    ),
    10: CampaignWeek(
        week=10,
        slug="the-self-healing-soc",
        theme="The Self-Healing SOC",
        blog_track1="Overcoming analyst alert fatigue by migrating to automated, machine-speed containment.",
        blog_track2="Building a closed-loop Splunk SOAR playbook that executes 2-second tool blocks and quarantines affected nodes.",
        core_technology="Splunk SOAR",
        owasp_llm=["LLM04"],
        owasp_asi=["ASI02"],
        maestro=["L6"],
        mitre_atlas=["AML.T0026", "AML.T0052"],
        nist_ai_rmf=["MANAGE-4.1", "GOVERN-6.1"],
        splunk_macro="acme_campaign_w10",
        splunk_saved_search="GenAI Campaign W10 - SOAR Containment",
        otel_fields=["soar.playbook_id", "containment.action", "containment.latency_ms"],
    ),
}


def get_campaign_week(week: int) -> Optional[CampaignWeek]:
    return CAMPAIGN_WEEKS.get(week)


def get_all_campaign_weeks() -> List[CampaignWeek]:
    return [CAMPAIGN_WEEKS[w] for w in sorted(CAMPAIGN_WEEKS)]


def campaign_framework_tags(week: int) -> dict:
    """Flatten framework IDs for OTel log enrichment."""
    cw = get_campaign_week(week)
    if not cw:
        return {}
    return {
        "campaign_week": str(week),
        "campaign.slug": cw.slug,
        "campaign.theme": cw.theme,
        "campaign.core_technology": cw.core_technology,
        "owasp_llm": ",".join(cw.owasp_llm),
        "owasp_asi": ",".join(cw.owasp_asi),
        "mitre_atlas": ",".join(cw.mitre_atlas),
        "framework.maestro_layers": ",".join(cw.maestro),
        "framework.nist_ai_rmf": ",".join(cw.nist_ai_rmf),
    }
