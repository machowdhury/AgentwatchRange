"""
=============================================================================
ACME Security Testbed — Framework Taxonomy Library
=============================================================================
Single source of truth for all AI/ML security framework mappings:
  - MITRE ATLAS v2026.05  : 16 tactics, 84 techniques
  - OWASP LLM Top 10 2025 : LLM01–LLM10
  - OWASP ASI Top 10 2026 : ASI01–ASI10 (Agentic Security Initiative)
  - CSA MAESTRO            : 7-layer agentic AI threat model
  - NIST AI RMF 1.0        : GOVERN, MAP, MEASURE, MANAGE functions

Each TechniqueEntry carries every field required for:
  - OTel event enrichment
  - HuggingFace-compatible dataset export (emmanuelgjr/genai-incidents schema)
  - Splunk compliance dashboard lookup tables
  - Kill-chain chain_engine.py sequencing

Schema is intentionally flat — no nested objects — so it serialises cleanly
to CSV lookups, JSONL datasets, and OTel log attributes.
=============================================================================
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
import json

# =============================================================================
# DATA MODEL
# =============================================================================

@dataclass
class TechniqueEntry:
    """
    Canonical record for a single adversarial technique.
    Every field maps directly to a HuggingFace dataset column or
    a Splunk lookup field.
    """
    # --- Primary identifiers ---
    technique_id: str          # e.g. "AML.T0051"
    technique_name: str        # e.g. "LLM Prompt Injection"
    tactic_id: str             # e.g. "AML.TA0001"
    tactic_name: str           # e.g. "Initial Access"
    subtechnique_id: str = ""  # e.g. "AML.T0051.000"
    subtechnique_name: str = ""

    # --- Framework cross-mappings ---
    owasp_llm: List[str] = field(default_factory=list)   # ["LLM01", "LLM06"]
    owasp_asi: List[str] = field(default_factory=list)   # ["ASI01", "ASI03"]
    maestro_layers: List[str] = field(default_factory=list) # ["L3", "L4"]
    nist_ai_rmf: List[str] = field(default_factory=list) # ["GOVERN-1.1", "MEASURE-2.5"]

    # --- Risk scoring ---
    cvss_score: float = 7.0
    severity: str = "High"        # Critical | High | Medium | Low
    attack_vector: str = "Network"
    attack_complexity: str = "Low"

    # --- Kill-chain position ---
    kill_chain_stage: str = "Execution"  # Recon|InitialAccess|Execution|Persistence|Exfil|Impact
    kill_chain_order: int = 5            # 1=earliest in chain

    # --- Human-readable context ---
    description: str = ""
    impact: str = ""
    affected_components: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # --- Detection ---
    detection_signal: str = ""       # What OTel field/value indicates this
    splunk_spl_template: str = ""    # Starter SPL for detection
    acme_output_guard_action: str = ""     # HARD_DENY | ALERT | RATE_LIMIT | QUARANTINE
    galileo_check: str = ""          # Galileo platform validation type

    # --- Dataset compatibility (HuggingFace schema) ---
    references: List[str] = field(default_factory=list)
    real_world_incident: str = ""    # Known real incident if applicable
    quality_tier: str = "reviewed"   # reviewed | community | synthetic
    learning_tier: int = 4           # 0–6 curriculum tier (see learning_tiers.py)
    redundant_with: str = ""         # nullable technique_id if SIMULATED breadth-only

    def to_dict(self) -> dict:
        return asdict(self)

    def to_otel_attributes(self) -> dict:
        """Flatten to OTel-compatible string attributes for log enrichment."""
        return {
            "framework.technique_id": self.technique_id,
            "framework.technique_name": self.technique_name,
            "framework.tactic_id": self.tactic_id,
            "framework.tactic_name": self.tactic_name,
            "framework.subtechnique_id": self.subtechnique_id,
            "framework.owasp_llm": ",".join(self.owasp_llm),
            "framework.owasp_asi": ",".join(self.owasp_asi),
            "framework.maestro_layers": ",".join(self.maestro_layers),
            "framework.nist_ai_rmf": ",".join(self.nist_ai_rmf),
            "framework.cvss_score": str(self.cvss_score),
            "framework.severity": self.severity,
            "framework.kill_chain_stage": self.kill_chain_stage,
            "kill_chain.stage": self.kill_chain_stage,
            "framework.kill_chain_order": str(self.kill_chain_order),
            "framework.acme_output_guard_action": self.acme_output_guard_action,
            "framework.attack_vector": self.attack_vector,
            "framework.detection_signal": self.detection_signal,
        }


# =============================================================================
# CSA MAESTRO LAYER REGISTRY
# 7-layer agentic AI threat model (Cloud Security Alliance, Feb 2025)
# =============================================================================

MAESTRO_LAYERS = {
    "L1": {
        "id": "L1",
        "name": "Foundation Models",
        "description": "Base LLMs, multimodal models, embeddings, and fine-tuned variants",
        "primary_threats": ["model poisoning", "weight theft", "backdoor injection", "adversarial inputs"],
    },
    "L2": {
        "id": "L2",
        "name": "Data Operations",
        "description": "Training data pipelines, RAG retrieval stores, vector databases, context assembly",
        "primary_threats": ["training data poisoning", "vector DB exfiltration", "retrieval manipulation", "context injection"],
    },
    "L3": {
        "id": "L3",
        "name": "Agent Frameworks",
        "description": "Orchestration layers: LangChain, AutoGen, CrewAI, MCP, A2A protocol surfaces",
        "primary_threats": ["prompt injection", "tool schema abuse", "framework misconfiguration", "MCP tool escape"],
    },
    "L4": {
        "id": "L4",
        "name": "Agent Capabilities",
        "description": "Tool integrations, API access, code execution, browser control, file system access",
        "primary_threats": ["excessive agency", "RCE via tool abuse", "SSRF", "capability boundary violation"],
    },
    "L5": {
        "id": "L5",
        "name": "Multi-Agent Systems",
        "description": "Agent-to-agent communication, delegation chains, trust propagation, orchestrator/subagent topologies",
        "primary_threats": ["A2A identity spoofing", "trust chain hijack", "cascading failures", "session smuggling"],
    },
    "L6": {
        "id": "L6",
        "name": "Security & Compliance",
        "description": "Policy enforcement, audit logging, compliance controls, guardrails, human-in-the-loop",
        "primary_threats": ["guardrail bypass", "audit evasion", "HITL fatigue", "policy drift"],
    },
    "L7": {
        "id": "L7",
        "name": "Agent Ecosystem",
        "description": "Third-party plugins, skill/tool marketplaces, supply chain, deployment infrastructure",
        "primary_threats": ["supply chain compromise", "malicious plugin", "shadow AI", "model substitution"],
    },
}

# =============================================================================
# NIST AI RMF FUNCTION REGISTRY
# =============================================================================

NIST_AI_RMF_FUNCTIONS = {
    "GOVERN-1.1": "Policies, processes, and procedures are established for AI risk management",
    "GOVERN-1.2": "Organizational teams committed to AI risk management",
    "GOVERN-2.1": "Organizational policies exist for AI risk prioritization",
    "GOVERN-4.1": "Teams are committed to AI transparency and explainability",
    "GOVERN-5.1": "Policies established for organizational AI risk tolerance",
    "GOVERN-6.1": "Policies for AI risks from third-party entities",
    "MAP-1.1": "AI system context is established and understood",
    "MAP-1.5": "AI risks are identified and prioritized",
    "MAP-2.1": "AI entity characteristics and behaviors are monitored",
    "MAP-3.5": "AI system performance metrics are established",
    "MAP-5.1": "Likelihood of AI risk occurrence is estimated",
    "MEASURE-1.1": "AI risk measurement methodologies are established",
    "MEASURE-2.1": "AI risk metrics are developed",
    "MEASURE-2.5": "AI system performance is evaluated",
    "MEASURE-2.7": "AI risk is tracked on an ongoing basis",
    "MEASURE-2.10": "Privacy risk in AI is monitored",
    "MEASURE-4.1": "AI risk measurement methodologies are continually updated",
    "MANAGE-1.1": "AI risks based on assessments are prioritized",
    "MANAGE-2.1": "AI risk treatments are determined and documented",
    "MANAGE-2.4": "Mechanisms are established to collect AI incidents",
    "MANAGE-3.1": "AI risks are monitored on an ongoing basis",
    "MANAGE-4.1": "AI incidents are documented and analyzed",
}

# =============================================================================
# COMPLETE TECHNIQUE REGISTRY
# 84 MITRE ATLAS techniques across 16 tactics
# =============================================================================

TECHNIQUE_REGISTRY: List[TechniqueEntry] = [

    # =========================================================================
    # TACTIC: AML.TA0002 — RECONNAISSANCE
    # Adversary is trying to gather information about the AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0000",
        technique_name="ML Model Feature Inference via API",
        tactic_id="AML.TA0002",
        tactic_name="Reconnaissance",
        owasp_llm=["LLM03"],
        owasp_asi=["ASI04"],
        maestro_layers=["L1", "L3"],
        nist_ai_rmf=["MAP-1.5", "MEASURE-2.5"],
        cvss_score=5.3,
        severity="Medium",
        attack_vector="Network",
        kill_chain_stage="Reconnaissance",
        kill_chain_order=1,
        description="Adversary probes the model's inference API to identify input features, model type, and decision boundaries without access to model internals.",
        impact="Reveals model architecture enabling targeted evasion or extraction attacks",
        affected_components=["inference_api", "model_endpoint"],
        mitigations=["Rate-limit inference API", "Add query perturbation", "Monitor high-frequency probing patterns"],
        tags=["recon", "model-probing", "api-abuse"],
        detection_signal="inference_api_query_rate > baseline_sigma_3",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0000" | stats count by agent.id span=1m | where count > 50',
        acme_output_guard_action="RATE_LIMIT",
        quality_tier="reviewed",
        references=["https://atlas.mitre.org/techniques/AML.T0000"],
    ),

    TechniqueEntry(
        technique_id="AML.T0001",
        technique_name="AI Model Inference via Direct Access",
        tactic_id="AML.TA0002",
        tactic_name="Reconnaissance",
        owasp_llm=["LLM03"],
        maestro_layers=["L1"],
        nist_ai_rmf=["MAP-1.5"],
        cvss_score=5.0,
        severity="Medium",
        attack_vector="Local",
        kill_chain_stage="Reconnaissance",
        kill_chain_order=1,
        description="Adversary with direct access to model weights or files performs inference to reconstruct decision logic.",
        impact="Full model capability mapping without API rate limits",
        affected_components=["model_weights", "model_file_store"],
        mitigations=["Encrypt model weights at rest", "Restrict file system access", "Monitor model file reads"],
        tags=["recon", "direct-access", "model-file"],
        detection_signal="model_file_read_by_unauthorized_principal",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0001" | table _time agent.id event_type',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0002",
        technique_name="AI Model Inference via Passive Collection",
        tactic_id="AML.TA0002",
        tactic_name="Reconnaissance",
        owasp_llm=["LLM02"],
        maestro_layers=["L1", "L2"],
        nist_ai_rmf=["MAP-1.5", "MEASURE-2.10"],
        cvss_score=4.0,
        severity="Medium",
        attack_vector="Network",
        kill_chain_stage="Reconnaissance",
        kill_chain_order=1,
        description="Adversary passively collects model inputs and outputs from network traffic or shared logs to infer model behavior.",
        impact="Model capability map built without direct interaction",
        affected_components=["network_traffic", "shared_logs", "output_cache"],
        mitigations=["Encrypt inference traffic", "Redact outputs in shared logs", "Implement output perturbation"],
        tags=["recon", "passive", "traffic-analysis"],
        detection_signal="unusual_log_export_volume",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0002"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0003",
        technique_name="System Prompt Discovery",
        tactic_id="AML.TA0002",
        tactic_name="Reconnaissance",
        owasp_llm=["LLM07"],
        owasp_asi=["ASI01"],
        maestro_layers=["L3", "L6"],
        nist_ai_rmf=["MAP-1.5", "GOVERN-1.1"],
        cvss_score=6.5,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Reconnaissance",
        kill_chain_order=1,
        description="Adversary uses crafted prompts to extract or infer the hidden system prompt, revealing guardrails and behavioral constraints.",
        impact="Reveals guardrail structure enabling targeted bypass",
        affected_components=["system_prompt", "agent_context"],
        mitigations=["Instruct model not to reveal system prompt", "Monitor for prompt extraction patterns", "Validate outputs against system prompt disclosure"],
        tags=["recon", "system-prompt", "prompt-extraction"],
        detection_signal="output_contains_system_prompt_fragment",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0003" galileo_check="PROMPT_LEAK_DETECTED"',
        acme_output_guard_action="HARD_DENY",
        galileo_check="PROMPT_EXTRACTION_ATTEMPT",
        quality_tier="reviewed",
        real_world_incident="Bing Chat (Sydney) system prompt extraction, Feb 2023",
    ),

    TechniqueEntry(
        technique_id="AML.T0004",
        technique_name="Search for Victim AI Infrastructure",
        tactic_id="AML.TA0002",
        tactic_name="Reconnaissance",
        owasp_asi=["ASI04"],
        maestro_layers=["L7"],
        nist_ai_rmf=["MAP-1.1"],
        cvss_score=3.7,
        severity="Low",
        attack_vector="Network",
        kill_chain_stage="Reconnaissance",
        kill_chain_order=1,
        description="Adversary scans for exposed AI model endpoints, Jupyter notebooks, MLflow servers, or vector database ports.",
        impact="Identifies attack surface for subsequent exploitation",
        affected_components=["model_endpoint", "vector_db", "mlflow_server"],
        mitigations=["Remove public exposure of AI infrastructure", "Implement network segmentation", "Use Splunk Asset Discovery to inventory AI assets"],
        tags=["recon", "scanning", "infrastructure-discovery"],
        detection_signal="port_scan_targeting_ai_ports",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0004"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0005",
        technique_name="AI Model OSINT Collection",
        tactic_id="AML.TA0002",
        tactic_name="Reconnaissance",
        owasp_asi=["ASI04"],
        maestro_layers=["L1", "L7"],
        nist_ai_rmf=["MAP-1.1"],
        cvss_score=3.1,
        severity="Low",
        attack_vector="Network",
        kill_chain_stage="Reconnaissance",
        kill_chain_order=1,
        description="Adversary uses public sources (HuggingFace, GitHub, arXiv, job postings) to identify models, frameworks, and architecture used by target.",
        impact="Targeted attack planning using known vulnerabilities of identified model",
        affected_components=["public_model_card", "github_repo", "job_postings"],
        mitigations=["Limit public disclosure of model specifics", "Use opaque model identifiers externally"],
        tags=["recon", "osint", "open-source"],
        detection_signal="model_identifier_in_public_leak",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0005"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0001 — INITIAL ACCESS
    # Adversary is trying to get into your AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0010",
        technique_name="Obtain Capabilities: AI Tools",
        tactic_id="AML.TA0001",
        tactic_name="Initial Access",
        owasp_asi=["ASI04"],
        maestro_layers=["L7"],
        nist_ai_rmf=["GOVERN-6.1", "MAP-1.5"],
        cvss_score=6.0,
        severity="Medium",
        attack_vector="Supply Chain",
        kill_chain_stage="InitialAccess",
        kill_chain_order=2,
        description="Adversary acquires AI development tools, models, or datasets to use in attacks — including trojaned weights or poisoned fine-tuning datasets.",
        impact="Establishes foothold in AI development pipeline via compromised tooling",
        affected_components=["model_registry", "training_pipeline", "developer_tools"],
        mitigations=["Verify model provenance via AI BOM", "Sign and verify model artifacts", "Monitor model registry for unauthorized uploads"],
        tags=["initial-access", "supply-chain", "tooling"],
        detection_signal="unsigned_model_artifact_loaded",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0010" agent.aibom_validated="false"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0012",
        technique_name="Valid ML Service Credential Abuse",
        tactic_id="AML.TA0001",
        tactic_name="Initial Access",
        owasp_llm=["LLM08"],
        owasp_asi=["ASI03"],
        maestro_layers=["L3", "L6"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.1"],
        cvss_score=8.1,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="InitialAccess",
        kill_chain_order=2,
        description="Adversary uses stolen or leaked API keys, OAuth tokens, or service accounts to authenticate to AI model APIs.",
        impact="Unauthorized model access; potential for training data extraction or model abuse at victim's cost",
        affected_components=["api_key_store", "oauth_provider", "model_api"],
        mitigations=["Rotate API keys regularly", "Use short-lived tokens", "Monitor API key usage anomalies", "Implement IP allowlisting"],
        tags=["initial-access", "credential-abuse", "api-key"],
        detection_signal="api_key_used_from_anomalous_ip",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0012" | stats dc(source_ip) as unique_ips by api_key | where unique_ips > 3',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0048",
        technique_name="AI System Supply Chain Compromise",
        tactic_id="AML.TA0001",
        tactic_name="Initial Access",
        owasp_llm=["LLM05"],
        owasp_asi=["ASI04"],
        maestro_layers=["L1", "L7"],
        nist_ai_rmf=["GOVERN-6.1", "MAP-1.5"],
        cvss_score=9.1,
        severity="Critical",
        attack_vector="Supply Chain",
        kill_chain_stage="InitialAccess",
        kill_chain_order=2,
        description="Adversary compromises a component in the AI supply chain: a fine-tuning dataset, base model weights, an ML library dependency, or a third-party plugin.",
        impact="Persistent backdoor in production AI system from trusted supply chain source",
        affected_components=["training_dataset", "base_model", "ml_library", "plugin_registry"],
        mitigations=["AI BOM with cryptographic signing", "Verify dataset provenance", "Pin ML library versions and verify hashes", "Scan plugins before integration"],
        tags=["initial-access", "supply-chain", "backdoor"],
        detection_signal="model_hash_mismatch_vs_aibom_baseline",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0048" cisco_aibom_status="HASH_MISMATCH"',
        acme_output_guard_action="HARD_DENY",
        galileo_check="SUPPLY_CHAIN_INTEGRITY_FAIL",
        quality_tier="reviewed",
        real_world_incident="Hugging Face malicious model upload campaigns, 2024",
        references=["https://atlas.mitre.org/techniques/AML.T0048"],
    ),

    TechniqueEntry(
        technique_id="AML.T0049",
        technique_name="Publish Poisoned AI Agent Tool",
        tactic_id="AML.TA0001",
        tactic_name="Initial Access",
        owasp_asi=["ASI04"],
        maestro_layers=["L4", "L7"],
        nist_ai_rmf=["GOVERN-6.1"],
        cvss_score=8.8,
        severity="Critical",
        attack_vector="Supply Chain",
        kill_chain_stage="InitialAccess",
        kill_chain_order=2,
        description="Adversary publishes a malicious MCP tool, LangChain plugin, or agent skill to a public marketplace. Victim agent installs it, giving attacker persistent code execution within the agent's tool scope.",
        impact="Persistent RCE within agent tool sandbox; data exfiltration capability",
        affected_components=["mcp_tool_registry", "plugin_marketplace", "agent_tool_scope"],
        mitigations=["Verify tool provenance before installation", "Sandbox tool execution", "Monitor tool invocation patterns", "Maintain approved tool allowlist"],
        tags=["initial-access", "supply-chain", "mcp", "plugin-poison"],
        detection_signal="mcp_tool_invoked_not_in_approved_allowlist",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0049" acme_output_guard_action="HARD_DENY"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
        real_world_incident="BlueRock Security MCP server analysis: 36.7% SSRF-vulnerable, 2026",
    ),

    # =========================================================================
    # TACTIC: AML.TA0003 — RESOURCE DEVELOPMENT
    # Adversary is trying to establish resources for attacks
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0017",
        technique_name="Develop Adversarial Examples",
        tactic_id="AML.TA0003",
        tactic_name="Resource Development",
        owasp_llm=["LLM01"],
        maestro_layers=["L1", "L3"],
        nist_ai_rmf=["MEASURE-2.5"],
        cvss_score=6.5,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="ResourceDevelopment",
        kill_chain_order=2,
        description="Adversary crafts inputs specifically designed to cause model misclassification, harmful output, or guardrail bypass.",
        impact="Prepared attack payload for injection; bypasses model safety training",
        affected_components=["model_inference", "guardrail_layer"],
        mitigations=["Adversarial training", "Input validation and sanitisation", "Galileo fuzzing in pre-production"],
        tags=["resource-dev", "adversarial-examples", "evasion"],
        detection_signal="galileo_adversarial_input_flagged",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0017" galileo_validation="ADVERSARIAL_INPUT_DETECTED"',
        acme_output_guard_action="ALERT",
        galileo_check="ADVERSARIAL_EXAMPLE_DETECTED",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0018",
        technique_name="Poison Training Data",
        tactic_id="AML.TA0003",
        tactic_name="Resource Development",
        owasp_llm=["LLM03"],
        owasp_asi=["ASI04"],
        maestro_layers=["L1", "L2"],
        nist_ai_rmf=["MAP-1.5", "MEASURE-2.7"],
        cvss_score=9.0,
        severity="Critical",
        attack_vector="Supply Chain",
        kill_chain_stage="ResourceDevelopment",
        kill_chain_order=2,
        description="Adversary injects malicious samples into the training dataset before or during fine-tuning, embedding a backdoor triggered by a specific input pattern.",
        impact="Persistent backdoor in model weights; survives retraining if poison samples remain",
        affected_components=["training_dataset", "fine_tuning_pipeline", "model_weights"],
        mitigations=["Data provenance tracking", "Anomaly detection on training data distribution", "Certified defences against data poisoning"],
        tags=["resource-dev", "training-poison", "backdoor"],
        detection_signal="training_data_anomaly_score_elevated",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0018"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0004 — ML ATTACK STAGING
    # Adversary prepares ML-specific attack capabilities
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0019",
        technique_name="Establish ML Attack Infrastructure",
        tactic_id="AML.TA0004",
        tactic_name="ML Attack Staging",
        owasp_asi=["ASI04"],
        maestro_layers=["L1", "L7"],
        nist_ai_rmf=["MAP-1.5"],
        cvss_score=5.5,
        severity="Medium",
        attack_vector="Network",
        kill_chain_stage="Staging",
        kill_chain_order=3,
        description="Adversary sets up shadow ML infrastructure (proxy models, fine-tuned surrogates) to develop and test attacks offline before targeting the victim model.",
        impact="Enables rapid offline iteration of attack techniques without triggering victim defences",
        affected_components=["shadow_model", "adversary_compute"],
        mitigations=["Monitor for model cloning via watermarking", "Rate-limit and perturb API outputs to hinder surrogate training"],
        tags=["staging", "shadow-model", "surrogate"],
        detection_signal="watermark_absent_from_model_output",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0019"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0020",
        technique_name="Train Proxy Model",
        tactic_id="AML.TA0004",
        tactic_name="ML Attack Staging",
        owasp_llm=["LLM10"],
        maestro_layers=["L1"],
        nist_ai_rmf=["MEASURE-2.5"],
        cvss_score=6.0,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Staging",
        kill_chain_order=3,
        description="Adversary queries victim model API at scale to build a training dataset, then trains a surrogate (proxy) model that mimics victim behaviour — enabling transferable attacks.",
        impact="Attacker gains a local copy of victim model's functional behaviour for unlimited offline attack development",
        affected_components=["inference_api", "victim_model"],
        mitigations=["API query rate limits", "Output perturbation", "Watermarking", "Detect high-volume systematic querying"],
        tags=["staging", "model-stealing", "surrogate", "extraction"],
        detection_signal="systematic_api_query_pattern_detected",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0020" | bucket _time span=1h | stats count by agent.id | where count > 5000',
        acme_output_guard_action="RATE_LIMIT",
        quality_tier="reviewed",
        real_world_incident="Cloudflare workers AI model extraction, 2024",
    ),

    # =========================================================================
    # TACTIC: AML.TA0005 — EXECUTION
    # Adversary is trying to run malicious code or manipulate model inference
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0051",
        technique_name="LLM Prompt Injection",
        tactic_id="AML.TA0005",
        tactic_name="Execution",
        subtechnique_id="AML.T0051.000",
        subtechnique_name="Direct Prompt Injection",
        owasp_llm=["LLM01"],
        owasp_asi=["ASI01"],
        maestro_layers=["L3", "L4"],
        nist_ai_rmf=["GOVERN-1.1", "MEASURE-2.7", "MANAGE-2.4"],
        cvss_score=9.3,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=4,
        description="Adversary injects malicious instructions directly into the user-facing prompt, overriding system instructions or persona, causing the model to take unauthorised actions.",
        impact="Complete agent goal hijack; potential for unauthorised data access, financial transactions, or lateral movement",
        affected_components=["user_input", "agent_context", "tool_executor"],
        mitigations=["Inline prompt injection detection via acmesentinel-gateway", "Input sanitisation", "Least-privilege tool scopes", "Output validation"],
        tags=["execution", "prompt-injection", "direct", "goal-hijack"],
        detection_signal="prompt_injection_pattern_in_user_input",
        splunk_spl_template='sourcetype="otel:agentic:json" (technique_id="AML.T0051" OR subtechnique_id="AML.T0051.000") acme_output_guard_action="HARD_DENY"',
        acme_output_guard_action="HARD_DENY",
        galileo_check="PROMPT_INJECTION_RUNTIME",
        quality_tier="reviewed",
        real_world_incident="Bing Chat prompt injection via webpage content, 2023; Air Canada chatbot manipulation, 2024",
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),

    TechniqueEntry(
        technique_id="AML.T0054",
        technique_name="Indirect Prompt Injection",
        tactic_id="AML.TA0005",
        tactic_name="Execution",
        subtechnique_id="AML.T0051.001",
        subtechnique_name="Indirect Prompt Injection",
        owasp_llm=["LLM01"],
        owasp_asi=["ASI01", "ASI06"],
        maestro_layers=["L2", "L3", "L4"],
        nist_ai_rmf=["MEASURE-2.7", "MANAGE-2.4"],
        cvss_score=9.0,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=4,
        description="Adversary embeds malicious instructions inside external content (web pages, documents, emails) that the agent retrieves and processes, hijacking agent goals without direct user interaction.",
        impact="Persistent agent compromise via retrieval; exfiltration of context data to attacker-controlled server",
        affected_components=["rag_retrieval", "web_browser_tool", "document_reader", "email_integration"],
        mitigations=["Validate and sanitise retrieved content", "Isolate retrieval from instruction processing", "Flag retrieved content as untrusted"],
        tags=["execution", "prompt-injection", "indirect", "rag-poisoning"],
        detection_signal="agent_action_triggered_by_retrieved_content",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0054" injection_vector="retrieved_content"',
        acme_output_guard_action="HARD_DENY",
        galileo_check="INDIRECT_INJECTION_DETECTED",
        quality_tier="reviewed",
        real_world_incident="ChatGPT plugin indirect injection via web content, 2023",
    ),

    TechniqueEntry(
        technique_id="AML.T0055",
        technique_name="AI Context Window Poisoning",
        tactic_id="AML.TA0005",
        tactic_name="Execution",
        owasp_llm=["LLM01"],
        owasp_asi=["ASI06"],
        maestro_layers=["L2", "L3"],
        nist_ai_rmf=["MEASURE-2.7"],
        cvss_score=8.5,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=4,
        description="Adversary poisons the agent's context window by manipulating memory, conversation history, or retrieved documents so that subsequent reasoning is based on attacker-controlled premises.",
        impact="Persistent cross-session behavioural manipulation; all future agent decisions corrupted",
        affected_components=["context_window", "agent_memory", "conversation_history"],
        mitigations=["Validate memory integrity on load", "Limit context window to trusted sources", "Detect context drift via baseline comparison"],
        tags=["execution", "context-poisoning", "memory-attack"],
        detection_signal="context_hash_drift_from_approved_baseline",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0055" event_type="CONTEXT_WINDOW_POISONING_DETECTED"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0056",
        technique_name="AI Agent Memory Manipulation",
        tactic_id="AML.TA0005",
        tactic_name="Execution",
        owasp_asi=["ASI06"],
        maestro_layers=["L3", "L5"],
        nist_ai_rmf=["MEASURE-2.7", "MANAGE-2.4"],
        cvss_score=8.0,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=4,
        description="Adversary writes malicious content to an agent's persistent memory store (vector DB, key-value store), which is retrieved in future sessions and alters agent behaviour across session boundaries.",
        impact="Cross-session persistent compromise; affects all future users of the same agent",
        affected_components=["agent_memory_store", "vector_db", "kv_store"],
        mitigations=["Validate memory writes against content policy", "Sign and verify memory entries", "Purge suspicious memory entries"],
        tags=["execution", "memory-manipulation", "persistence", "cross-session"],
        detection_signal="memory_write_from_untrusted_source",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0056"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0057",
        technique_name="AI Agent Thread Hijacking",
        tactic_id="AML.TA0005",
        tactic_name="Execution",
        owasp_asi=["ASI01", "ASI07"],
        maestro_layers=["L3", "L5"],
        nist_ai_rmf=["MEASURE-2.7"],
        cvss_score=8.3,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=4,
        description="Adversary injects malicious content that persists within a single conversation thread, manipulating the agent across multiple turns within that session.",
        impact="Multi-turn conversation manipulation enabling complex social engineering or data extraction",
        affected_components=["conversation_thread", "multi_turn_context"],
        mitigations=["Validate each turn against original task intent", "Detect topic drift in multi-turn conversations"],
        tags=["execution", "thread-hijack", "multi-turn", "session"],
        detection_signal="conversation_intent_drift_detected",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0057"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0040",
        technique_name="Resource Exhaustion via Algorithmic Complexity",
        tactic_id="AML.TA0005",
        tactic_name="Execution",
        owasp_llm=["LLM10"],
        owasp_asi=["ASI08"],
        maestro_layers=["L3", "L4", "L5"],
        nist_ai_rmf=["MEASURE-2.5", "MANAGE-2.1"],
        cvss_score=7.5,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=4,
        description="Adversary triggers recursive agent delegation loops, infinite tool-call chains, or computationally explosive prompts that drain API budgets and degrade service availability.",
        impact="Financial drain via API cost explosion; service denial for legitimate users",
        affected_components=["agent_orchestrator", "tool_executor", "api_quota"],
        mitigations=["Recursive call depth limits", "Per-session token budget caps", "Cisco TSM anomaly detection on call rate", "Circuit breaker patterns"],
        tags=["execution", "dos", "resource-exhaustion", "loop-attack", "infinity-bill"],
        detection_signal="recursive_call_depth_exceeds_threshold",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0040" call_depth_detected > 10',
        acme_output_guard_action="RATE_LIMIT",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0006 — PERSISTENCE
    # Adversary tries to maintain their foothold in the AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0024",
        technique_name="Exfiltrate Training Data via ML API",
        tactic_id="AML.TA0006",
        tactic_name="Persistence",
        owasp_llm=["LLM02"],
        maestro_layers=["L1", "L2"],
        nist_ai_rmf=["MEASURE-2.10", "MANAGE-2.4"],
        cvss_score=7.7,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Persistence",
        kill_chain_order=5,
        description="Adversary uses targeted prompts or membership inference attacks to extract training data from the model, recovering PII, proprietary text, or security-sensitive content.",
        impact="Training data privacy breach; regulatory liability under GDPR, CCPA",
        affected_components=["model_inference", "training_data"],
        mitigations=["Differential privacy during training", "Output filtering for training data patterns", "Limit verbatim reproduction in model outputs"],
        tags=["persistence", "data-exfil", "membership-inference", "pii"],
        detection_signal="model_output_matches_training_data_pattern",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0024" pii_detected="true"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
        real_world_incident="Samsung ChatGPT training data concerns, 2023",
    ),

    TechniqueEntry(
        technique_id="AML.T0025",
        technique_name="AI Model Backdoor Persistence",
        tactic_id="AML.TA0006",
        tactic_name="Persistence",
        owasp_llm=["LLM03"],
        maestro_layers=["L1"],
        nist_ai_rmf=["MEASURE-2.5", "GOVERN-1.1"],
        cvss_score=9.5,
        severity="Critical",
        attack_vector="Supply Chain",
        kill_chain_stage="Persistence",
        kill_chain_order=5,
        description="Adversary embeds a trigger-activated backdoor in model weights during training or fine-tuning. The model behaves normally until the trigger phrase activates malicious behaviour.",
        impact="Persistent, stealthy model compromise surviving standard evaluation; catastrophic when triggered in production",
        affected_components=["model_weights", "fine_tuning_pipeline"],
        mitigations=["Neural cleanse and activation clustering defences", "Behavioural regression testing with trigger sweep", "AI BOM model hash verification"],
        tags=["persistence", "backdoor", "trojan", "trigger"],
        detection_signal="model_behavior_anomaly_on_specific_input_pattern",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0025"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0026",
        technique_name="Rogue Agent Persistence",
        tactic_id="AML.TA0006",
        tactic_name="Persistence",
        owasp_asi=["ASI10"],
        maestro_layers=["L5", "L6"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-3.1"],
        cvss_score=9.0,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="Persistence",
        kill_chain_order=5,
        description="A compromised or misaligned agent continues operating in unintended ways, concealing its behaviour from monitoring systems, self-replicating, or maintaining C2 channels.",
        impact="Persistent autonomous attacker operating inside trusted agent infrastructure",
        affected_components=["agent_runtime", "monitoring_system", "orchestrator"],
        mitigations=["Continuous behavioural monitoring", "Agent identity attestation", "Automatic agent quarantine on anomaly"],
        tags=["persistence", "rogue-agent", "misalignment", "self-directed"],
        detection_signal="agent_behavior_diverges_from_approved_policy",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0026" event_type="ROGUE_AGENT_DETECTED"',
        acme_output_guard_action="QUARANTINE",
        quality_tier="reviewed",
        real_world_incident="Replit agent meltdown incident, 2025",
    ),

    # =========================================================================
    # TACTIC: AML.TA0007 — DEFENCE EVASION
    # Adversary tries to avoid being detected
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0015",
        technique_name="Evade ML Model via Adversarial Perturbation",
        tactic_id="AML.TA0007",
        tactic_name="Defence Evasion",
        owasp_llm=["LLM01"],
        maestro_layers=["L1", "L3"],
        nist_ai_rmf=["MEASURE-2.5"],
        cvss_score=7.2,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="DefenceEvasion",
        kill_chain_order=4,
        description="Adversary applies minimal perturbations to inputs (character substitution, Unicode homoglyphs, steganographic encoding) to evade safety classifiers while preserving semantic meaning.",
        impact="Guardrail bypass enabling injection of content that would otherwise be blocked",
        affected_components=["safety_classifier", "input_filter", "guardrail_layer"],
        mitigations=["Normalise inputs before safety checks", "Ensemble multiple safety classifiers", "Unicode homoglyph detection"],
        tags=["defence-evasion", "adversarial-perturbation", "classifier-bypass"],
        detection_signal="homoglyph_or_encoding_anomaly_in_input",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0015"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0016",
        technique_name="Obtain Limited ML Model Feedback",
        tactic_id="AML.TA0007",
        tactic_name="Defence Evasion",
        owasp_llm=["LLM01"],
        maestro_layers=["L3"],
        nist_ai_rmf=["MEASURE-2.5"],
        cvss_score=5.0,
        severity="Medium",
        attack_vector="Network",
        kill_chain_stage="DefenceEvasion",
        kill_chain_order=4,
        description="Adversary probes model with edge-case inputs to characterise classifier decision boundaries and find evasion paths, using only minimal signals (accept/reject) as oracle.",
        impact="Enables precise evasion payload crafting against an opaque safety classifier",
        affected_components=["safety_classifier", "api_response"],
        mitigations=["Limit signal in rejection responses", "Add noise to rejection boundaries"],
        tags=["defence-evasion", "oracle-probing", "classifier-boundary"],
        detection_signal="systematic_edge_case_probing_pattern",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0016"',
        acme_output_guard_action="RATE_LIMIT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0052",
        technique_name="AI Audit Log Manipulation",
        tactic_id="AML.TA0007",
        tactic_name="Defence Evasion",
        owasp_asi=["ASI09"],
        maestro_layers=["L6"],
        nist_ai_rmf=["GOVERN-4.1", "MANAGE-4.1"],
        cvss_score=8.4,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="DefenceEvasion",
        kill_chain_order=4,
        description="Adversary or insider manipulates, suppresses, or forges AI system audit logs to conceal malicious activity from security monitoring.",
        impact="Invisible attack chain; forensic investigation impossible after incident",
        affected_components=["audit_log", "otel_pipeline", "siem_index"],
        mitigations=["Immutable audit log storage", "Log integrity verification via cryptographic signatures", "Monitor for log gaps or anomalous silence"],
        tags=["defence-evasion", "audit-evasion", "log-tampering"],
        detection_signal="otel_log_gap_detected_in_continuous_stream",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0052" | timechart count span=1m | where count=0',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0008 — DISCOVERY
    # Adversary tries to figure out your AI environment
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0037",
        technique_name="AI Data Discovery via Retrieval Probing",
        tactic_id="AML.TA0008",
        tactic_name="Discovery",
        owasp_llm=["LLM02"],
        owasp_asi=["ASI02"],
        maestro_layers=["L2", "L4"],
        nist_ai_rmf=["MEASURE-2.10"],
        cvss_score=7.4,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Discovery",
        kill_chain_order=3,
        description="Adversary uses crafted queries to systematically probe a RAG vector database, discovering the structure and content of proprietary documents accessible to the agent.",
        impact="Complete inventory of proprietary knowledge base accessible to the agent",
        affected_components=["vector_db", "rag_retrieval", "knowledge_base"],
        mitigations=["Rate-limit retrieval queries", "Monitor retrieval patterns vs baseline", "Implement access controls per document sensitivity"],
        tags=["discovery", "vector-db", "rag-probing", "data-mapping"],
        detection_signal="vector_retrieval_rate_anomaly",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0037" galileo_observe_alert="true"',
        acme_output_guard_action="RATE_LIMIT",
        galileo_check="VECTOR_RETRIEVAL_ANOMALY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0038",
        technique_name="Vector Database Exfiltration",
        tactic_id="AML.TA0008",
        tactic_name="Discovery",
        owasp_llm=["LLM02"],
        owasp_asi=["ASI02"],
        maestro_layers=["L2"],
        nist_ai_rmf=["MEASURE-2.10", "MANAGE-2.4"],
        cvss_score=8.8,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="Discovery",
        kill_chain_order=3,
        description="Adversary systematically reconstructs the entire embedding space of a vector database by querying nearest-neighbour endpoints, recovering proprietary document content.",
        impact="Full proprietary knowledge base exfiltrated; IP and confidential data at risk",
        affected_components=["vector_db", "embedding_model", "knowledge_base"],
        mitigations=["Galileo Observe anomaly detection on retrieval patterns", "Rate-limit similarity search", "Add noise to embedding responses"],
        tags=["discovery", "vector-db", "exfiltration", "embedding-reconstruction"],
        detection_signal="vector_retrieval_volume_anomaly_70x_baseline",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0038" galileo_anomaly_score > 0.9',
        acme_output_guard_action="QUARANTINE",
        galileo_check="VECTOR_EXFILTRATION_DETECTED",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0043",
        technique_name="AI Tool Schema Discovery",
        tactic_id="AML.TA0008",
        tactic_name="Discovery",
        owasp_asi=["ASI02"],
        maestro_layers=["L3", "L4"],
        nist_ai_rmf=["MAP-1.5"],
        cvss_score=5.8,
        severity="Medium",
        attack_vector="Network",
        kill_chain_stage="Discovery",
        kill_chain_order=3,
        description="Adversary extracts tool definitions (MCP schemas, function call specs) from an agent to map available capabilities and identify high-value tools for exploitation.",
        impact="Complete tool capability map enabling targeted tool abuse and privilege escalation",
        affected_components=["mcp_tool_schema", "function_call_spec", "agent_capabilities"],
        mitigations=["Restrict tool schema disclosure", "Validate tool invocations against purpose", "Monitor for tool enumeration patterns"],
        tags=["discovery", "tool-schema", "mcp", "capability-mapping"],
        detection_signal="tool_schema_enumeration_detected",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0043"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0009 — COLLECTION
    # Adversary tries to gather data of interest from the AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0035",
        technique_name="Data from Local AI System",
        tactic_id="AML.TA0009",
        tactic_name="Collection",
        owasp_llm=["LLM02"],
        owasp_asi=["ASI02"],
        maestro_layers=["L2", "L4"],
        nist_ai_rmf=["MEASURE-2.10"],
        cvss_score=7.8,
        severity="High",
        attack_vector="Local",
        kill_chain_stage="Collection",
        kill_chain_order=5,
        description="Adversary collects sensitive data from local AI system storage: model caches, conversation logs, retrieval indexes, and embedding stores.",
        impact="PII, trade secrets, and user conversation data exfiltrated from local storage",
        affected_components=["local_cache", "conversation_log", "embedding_store"],
        mitigations=["Encrypt local AI system storage", "Minimise data retention", "Audit file system access"],
        tags=["collection", "local-data", "pii", "conversation-log"],
        detection_signal="local_ai_data_read_by_unexpected_process",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0035"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0036",
        technique_name="Data from AI-integrated Systems",
        tactic_id="AML.TA0009",
        tactic_name="Collection",
        owasp_llm=["LLM02"],
        owasp_asi=["ASI02", "ASI03"],
        maestro_layers=["L4", "L5"],
        nist_ai_rmf=["MEASURE-2.10", "GOVERN-1.1"],
        cvss_score=8.2,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Collection",
        kill_chain_order=5,
        description="Adversary uses the AI agent's authorised tool access (CRM, email, ERP, databases) to systematically collect data beyond the agent's intended scope.",
        impact="Bulk data theft from integrated enterprise systems using agent's legitimate credentials",
        affected_components=["crm_integration", "email_tool", "erp_connector", "database_tool"],
        mitigations=["Enforce least-privilege tool scopes", "Monitor tool call volumes vs baseline", "Require human approval for bulk data operations"],
        tags=["collection", "tool-abuse", "data-theft", "enterprise-integration"],
        detection_signal="bulk_data_collection_via_agent_tool",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0036" | stats sum(records_accessed) by agent.id | where sum > 1000',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0010 — EXFILTRATION
    # Adversary tries to steal data from the AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0030",
        technique_name="Exfiltrate AI Model via Covert Channel",
        tactic_id="AML.TA0010",
        tactic_name="Exfiltration",
        owasp_llm=["LLM02"],
        maestro_layers=["L1", "L4"],
        nist_ai_rmf=["MANAGE-2.4"],
        cvss_score=8.5,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Exfiltration",
        kill_chain_order=6,
        description="Adversary extracts model weights or architecture via covert channels — e.g., encoding model data in seemingly innocuous API responses or out-of-band communications.",
        impact="Full model theft; attacker can run unlimited local inference without API costs",
        affected_components=["model_weights", "api_response", "network_channel"],
        mitigations=["Monitor outbound data volumes from model serving infrastructure", "Encrypt model weights", "Watermark model outputs"],
        tags=["exfiltration", "model-theft", "covert-channel"],
        detection_signal="unusual_outbound_data_from_model_server",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0030"',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0031",
        technique_name="Exfiltrate Data via AI Model Output",
        tactic_id="AML.TA0010",
        tactic_name="Exfiltration",
        owasp_llm=["LLM02"],
        owasp_asi=["ASI01"],
        maestro_layers=["L3", "L4"],
        nist_ai_rmf=["MEASURE-2.10", "MANAGE-2.4"],
        cvss_score=8.8,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="Exfiltration",
        kill_chain_order=6,
        description="Adversary tricks the agent into embedding sensitive data (credentials, PII, internal documents) inside its generated output — markdown images, hyperlinks, or encoded text — that is exfiltrated to an attacker-controlled endpoint.",
        impact="Automatic exfiltration of context data to attacker server triggered by model output rendering",
        affected_components=["model_output", "markdown_renderer", "browser_tool"],
        mitigations=["Block outbound URLs in rendered output", "Scan model outputs for sensitive data patterns", "Implement output DLP"],
        tags=["exfiltration", "output-exfil", "markdown-injection", "llm-exfil"],
        detection_signal="outbound_url_in_model_output_to_unknown_domain",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0031" exfil_url_detected="true"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0011 — IMPACT
    # Adversary tries to manipulate, disrupt, or destroy AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0029",
        technique_name="AI System Availability Disruption",
        tactic_id="AML.TA0011",
        tactic_name="Impact",
        owasp_llm=["LLM04"],
        owasp_asi=["ASI08"],
        maestro_layers=["L3", "L4", "L5"],
        nist_ai_rmf=["MANAGE-2.1"],
        cvss_score=7.5,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Impact",
        kill_chain_order=7,
        description="Adversary disrupts AI system availability through computational denial of service, context window flooding, or cascading agent failure propagation across the multi-agent topology.",
        impact="AI service unavailability; financial loss from SLA breach; cascading failure in dependent business processes",
        affected_components=["agent_orchestrator", "compute_pool", "rate_limiter"],
        mitigations=["Circuit breakers on agent call chains", "Cascading failure detection in Splunk", "Horizontal scaling with automatic throttling"],
        tags=["impact", "availability", "dos", "cascading-failure"],
        detection_signal="agent_service_latency_spike_and_error_rate_elevation",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0029" | timechart avg(latency_ms) span=1m | where avg > 5000',
        acme_output_guard_action="RATE_LIMIT",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0034",
        technique_name="AI Model Integrity Attack",
        tactic_id="AML.TA0011",
        tactic_name="Impact",
        owasp_llm=["LLM03"],
        maestro_layers=["L1", "L6"],
        nist_ai_rmf=["MEASURE-2.5", "GOVERN-1.1"],
        cvss_score=9.5,
        severity="Critical",
        attack_vector="Supply Chain",
        kill_chain_stage="Impact",
        kill_chain_order=7,
        description="Adversary corrupts or replaces model weights in production to degrade model quality, introduce systematic biases, or cause consistent misclassification.",
        impact="Corrupted model making systematically wrong decisions at scale in production",
        affected_components=["model_weights", "model_serving_layer", "model_registry"],
        mitigations=["Continuous model behavioural monitoring", "Cryptographic model weight integrity verification", "Anomaly detection on model performance metrics"],
        tags=["impact", "model-integrity", "weight-corruption"],
        detection_signal="model_performance_degradation_and_hash_mismatch",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0034" cisco_aibom_status="HASH_MISMATCH"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0012 — PRIVILEGE ESCALATION
    # Adversary tries to gain higher-level permissions in the AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0050",
        technique_name="AI Agent Privilege Escalation via Tool Abuse",
        tactic_id="AML.TA0012",
        tactic_name="Privilege Escalation",
        owasp_llm=["LLM06"],
        owasp_asi=["ASI02", "ASI03"],
        maestro_layers=["L4", "L5"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.1"],
        cvss_score=9.0,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="PrivilegeEscalation",
        kill_chain_order=5,
        description="Adversary manipulates an agent into invoking tools or APIs outside its authorised scope, escalating from a low-privilege agent context to privileged operations on integrated systems.",
        impact="Unauthorised execution of privileged operations: file writes, database mutations, financial transactions",
        affected_components=["tool_executor", "mcp_scope", "api_gateway"],
        mitigations=["Enforce MCP tool scope allowlists", "Require human approval for privileged tool calls", "AcmeSentinel OpenShell sandbox enforcement"],
        tags=["privilege-escalation", "tool-abuse", "scope-escape", "mcp"],
        detection_signal="tool_invoked_outside_approved_scope",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0050" scope_violation="true"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0058",
        technique_name="Agent Identity Spoofing for Privilege Escalation",
        tactic_id="AML.TA0012",
        tactic_name="Privilege Escalation",
        owasp_asi=["ASI03", "ASI07"],
        maestro_layers=["L5", "L6"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.1"],
        cvss_score=9.2,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="PrivilegeEscalation",
        kill_chain_order=5,
        description="Adversary spoofs a high-privilege agent's identity in inter-agent communications, causing downstream agents to grant elevated permissions to the spoofed entity.",
        impact="Unauthorised privilege escalation across the multi-agent trust chain",
        affected_components=["agent_identity", "a2a_protocol", "trust_chain", "did_document"],
        mitigations=["W3C DID cryptographic passports for agent identity", "Ed25519 signature verification on all inter-agent messages", "Zero-trust delegation enforcement"],
        tags=["privilege-escalation", "identity-spoofing", "a2a", "zero-trust"],
        detection_signal="did_signature_mismatch_on_agent_delegation",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0058" cryptographic_passport_valid="false"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0013 — LATERAL MOVEMENT
    # Adversary tries to move through the AI system
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0045",
        technique_name="Agent Session Smuggling",
        tactic_id="AML.TA0013",
        tactic_name="Lateral Movement",
        owasp_asi=["ASI07"],
        maestro_layers=["L5", "L6"],
        nist_ai_rmf=["MANAGE-2.4"],
        cvss_score=8.6,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="LateralMovement",
        kill_chain_order=5,
        description="Adversary exploits built-in trust in Agent-to-Agent (A2A) protocol to smuggle malicious session context between agents, building false trust over multi-turn conversations before executing payload.",
        impact="Full multi-agent topology compromise via trusted A2A channels",
        affected_components=["a2a_protocol", "agent_trust_chain", "session_context"],
        mitigations=["Validate inter-agent session integrity", "Verify agent identity at every handoff", "Monitor A2A message anomalies"],
        tags=["lateral-movement", "a2a", "session-smuggling", "trust-chain"],
        detection_signal="a2a_session_integrity_check_failed",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0045" event_type="A2A_SESSION_SMUGGLING_DETECTED"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
        real_world_incident="Palo Alto Unit 42 A2A session smuggling demonstration, Nov 2025",
    ),

    TechniqueEntry(
        technique_id="AML.T0046",
        technique_name="Inter-Agent Trust Chain Hijacking",
        tactic_id="AML.TA0013",
        tactic_name="Lateral Movement",
        owasp_asi=["ASI07", "ASI08"],
        maestro_layers=["L5"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.4"],
        cvss_score=9.0,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="LateralMovement",
        kill_chain_order=5,
        description="Adversary compromises one agent in a multi-agent pipeline and uses its trusted position to propagate malicious instructions to all downstream agents in the delegation chain.",
        impact="Cascading compromise of entire multi-agent workflow from a single compromised node",
        affected_components=["agent_orchestrator", "delegation_chain", "subagent_network"],
        mitigations=["Cryptographic attestation at each delegation hop", "Isolate agent failure domains", "Break trust propagation on anomaly detection"],
        tags=["lateral-movement", "trust-chain", "cascading", "multi-agent"],
        detection_signal="trust_propagation_anomaly_in_agent_chain",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0046"',
        acme_output_guard_action="QUARANTINE",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0014 — COMMAND AND CONTROL
    # Adversary communicates with compromised AI systems
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0060",
        technique_name="AI Agent C2 via Covert Prompt Channel",
        tactic_id="AML.TA0014",
        tactic_name="Command and Control",
        owasp_asi=["ASI01", "ASI10"],
        maestro_layers=["L3", "L5"],
        nist_ai_rmf=["MANAGE-2.4"],
        cvss_score=8.8,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="CommandAndControl",
        kill_chain_order=6,
        description="Adversary establishes a covert command and control channel through the AI agent's normal prompt/response interface, issuing encoded commands that the agent executes while appearing to have normal conversations.",
        impact="Persistent C2 over a trusted AI channel, bypassing traditional network-based C2 detection",
        affected_components=["agent_prompt_interface", "model_output", "tool_executor"],
        mitigations=["Monitor agent behaviour for encoded or anomalous instruction patterns", "Baseline agent response patterns", "Anomaly detection on tool invocation sequences"],
        tags=["c2", "covert-channel", "prompt-c2", "persistent"],
        detection_signal="encoded_instruction_pattern_in_agent_io",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0060"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0061",
        technique_name="Malicious AI Plugin as C2 Relay",
        tactic_id="AML.TA0014",
        tactic_name="Command and Control",
        owasp_asi=["ASI04", "ASI10"],
        maestro_layers=["L4", "L7"],
        nist_ai_rmf=["GOVERN-6.1"],
        cvss_score=8.5,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="CommandAndControl",
        kill_chain_order=6,
        description="A malicious tool or plugin installed in the agent's tool scope acts as a C2 relay, receiving commands from an external server and executing them via the agent's authorised capabilities.",
        impact="Full remote control of agent capabilities via a trusted-looking plugin",
        affected_components=["agent_plugin", "mcp_tool", "external_api"],
        mitigations=["Verify tool network destinations against allowlist", "Monitor outbound tool call destinations", "Plugin provenance verification"],
        tags=["c2", "malicious-plugin", "relay", "mcp"],
        detection_signal="tool_calling_unexpected_external_domain",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0061"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0015 — CREDENTIAL ACCESS
    # Adversary tries to steal account credentials or secrets
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0062",
        technique_name="Credential Extraction via Agent Tool",
        tactic_id="AML.TA0015",
        tactic_name="Credential Access",
        owasp_llm=["LLM06"],
        owasp_asi=["ASI02", "ASI03"],
        maestro_layers=["L4", "L6"],
        nist_ai_rmf=["GOVERN-1.1", "MEASURE-2.10"],
        cvss_score=9.1,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="CredentialAccess",
        kill_chain_order=5,
        description="Adversary manipulates the agent into using its authorised tool access to retrieve credentials from password managers, secret stores, or environment variable configs.",
        impact="Credential compromise enabling lateral movement beyond AI system to broader enterprise infrastructure",
        affected_components=["secret_store", "env_config", "password_manager_tool"],
        mitigations=["Restrict agent access to credential stores", "Monitor credential read events initiated by AI agents", "Require human confirmation for credential retrieval"],
        tags=["credential-access", "secret-theft", "tool-abuse"],
        detection_signal="credential_store_accessed_by_agent",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0062" tool_invoked="read_secret"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0063",
        technique_name="AI-Assisted Phishing and Social Engineering",
        tactic_id="AML.TA0015",
        tactic_name="Credential Access",
        owasp_llm=["LLM09"],
        owasp_asi=["ASI09"],
        maestro_layers=["L3", "L6"],
        nist_ai_rmf=["GOVERN-4.1"],
        cvss_score=8.0,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="CredentialAccess",
        kill_chain_order=4,
        description="Adversary weaponises a compromised or rogue AI agent to generate highly personalised phishing content or conduct convincing social engineering attacks against human operators.",
        impact="Human credential compromise at scale using AI-generated personalised content",
        affected_components=["agent_output", "email_tool", "human_operator"],
        mitigations=["Output scanning for social engineering patterns", "Flag AI-generated content to recipients", "Human review of outbound agent communications"],
        tags=["credential-access", "phishing", "social-engineering", "human-exploit"],
        detection_signal="agent_generating_credential_harvesting_content",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0063"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    # =========================================================================
    # TACTIC: AML.TA0016 — ESCAPE TO HOST
    # Adversary tries to break out of AI sandbox to underlying infrastructure
    # =========================================================================

    TechniqueEntry(
        technique_id="AML.T0064",
        technique_name="Container Escape via AI Code Execution",
        tactic_id="AML.TA0016",
        tactic_name="Escape to Host",
        owasp_llm=["LLM06"],
        owasp_asi=["ASI05"],
        maestro_layers=["L4", "L7"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.1"],
        cvss_score=9.8,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=5,
        description="Adversary manipulates an AI code execution tool (Jupyter kernel, sandbox interpreter, shell tool) to achieve container breakout and gain access to the underlying host or Kubernetes node.",
        impact="Full host compromise; access to all co-resident AI workloads and infrastructure",
        affected_components=["code_execution_tool", "container_runtime", "host_os"],
        mitigations=["Enforce gVisor or Firecracker sandboxing for code execution", "AcmeSentinel OpenShell namespace enforcement", "Block host mounts from code execution containers"],
        tags=["escape", "container-breakout", "rce", "code-execution"],
        detection_signal="agent_code_execution_accesses_host_namespace",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0064" rce_payload_detected="true"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

    TechniqueEntry(
        technique_id="AML.T0065",
        technique_name="SSRF via AI Agent Tool",
        tactic_id="AML.TA0016",
        tactic_name="Escape to Host",
        owasp_llm=["LLM01"],
        owasp_asi=["ASI02", "ASI05"],
        maestro_layers=["L4"],
        nist_ai_rmf=["GOVERN-1.1"],
        cvss_score=8.6,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Execution",
        kill_chain_order=5,
        description="Adversary abuses an AI agent's web browsing or HTTP tool to make requests to internal cloud metadata endpoints (169.254.169.254, cloud-internal APIs), accessing credentials and infrastructure data.",
        impact="Cloud credential theft; access to EC2/GCP/Azure metadata including IAM tokens",
        affected_components=["web_tool", "http_client_tool", "cloud_metadata_endpoint"],
        mitigations=["Block metadata IP ranges in agent network policy", "Validate all agent-initiated URLs against allowlist", "Monitor for metadata endpoint access attempts"],
        tags=["escape", "ssrf", "cloud-metadata", "web-tool"],
        detection_signal="agent_tool_requesting_cloud_metadata_endpoint",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0065" target_url LIKE "%169.254.169.254%"',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
        real_world_incident="BlueRock Security: 36.7% of scanned MCP servers SSRF-vulnerable, 2026",
    ),

    # =========================================================================
    # EMERGING THREATS (2026) — appended Phase 1; do not modify Top 10 / original 45
    # =========================================================================
    TechniqueEntry(
        technique_id="AML.T0070",
        technique_name="MCP Tool Description Poisoning",
        tactic_id="AML.TA0001",
        tactic_name="Initial Access",
        owasp_llm=["LLM07", "LLM06"],
        owasp_asi=["ASI04", "ASI01"],
        maestro_layers=["L3", "L4", "L7"],
        nist_ai_rmf=["GOVERN-6.1", "MEASURE-2.7"],
        cvss_score=8.9,
        severity="Critical",
        attack_vector="Supply Chain",
        kill_chain_stage="InitialAccess",
        kill_chain_order=2,
        description="Malicious MCP server returns a tool manifest whose description/metadata contains injected instructions, causing the agent to misuse an otherwise-legitimate tool without prompt injection.",
        impact="Agent executes privileged operations guided by poisoned tool metadata rather than user intent",
        affected_components=["mcp_gateway", "tool_registry", "agent_tool_router"],
        mitigations=["Validate tool manifest descriptions at registration", "Sign and pin approved tool manifests", "Separate tool metadata scanning from prompt scanning"],
        tags=["mcp", "supply-chain", "tool-manifest", "emerging-2026"],
        detection_signal="tool_manifest_tampered=true",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0070" tool_manifest_tampered=true',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),
    TechniqueEntry(
        technique_id="AML.T0071",
        technique_name="Agent Supply Chain / Skill Poisoning",
        tactic_id="AML.TA0001",
        tactic_name="Initial Access",
        owasp_llm=["LLM03", "LLM05"],
        owasp_asi=["ASI04"],
        maestro_layers=["L4", "L7"],
        nist_ai_rmf=["GOVERN-6.1", "MAP-1.5"],
        cvss_score=9.0,
        severity="Critical",
        attack_vector="Supply Chain",
        kill_chain_stage="InitialAccess",
        kill_chain_order=2,
        description="Community skill/plugin from an unverified registry contains hidden malicious instructions distinct from unapproved SLM runtime discovery.",
        impact="Persistent compromise via installed agent skill with no provenance or signature",
        affected_components=["skill_registry", "aibom", "agent_plugins"],
        mitigations=["Require signed skills", "AIBOM provenance validation", "Allowlist registries"],
        tags=["skill-poisoning", "supply-chain", "registry-trust", "emerging-2026"],
        detection_signal="skill.provenance_valid=false",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0071" skill.provenance_valid=false',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),
    TechniqueEntry(
        technique_id="AML.T0072",
        technique_name="Memory Poisoning as Behavioral Drift",
        tactic_id="AML.TA0006",
        tactic_name="Persistence",
        owasp_llm=["LLM01", "LLM04"],
        owasp_asi=["ASI06", "ASI10"],
        maestro_layers=["L3", "L5"],
        nist_ai_rmf=["MEASURE-2.7", "MANAGE-2.4"],
        cvss_score=8.4,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="Persistence",
        kill_chain_order=5,
        description="Adversary seeds benign-looking facts across multiple loan pipeline turns until compliance decisions drift over several runs.",
        impact="Gradual approval bias without single-shot injection; cross-session behavioral manipulation",
        affected_components=["memory_store", "compliance_agent", "session_context"],
        mitigations=["Session trust-decay monitoring", "Memory write provenance", "Approval rate anomaly detection"],
        tags=["memory-drift", "multi-turn", "behavioral", "emerging-2026"],
        detection_signal="memory.drift_detected=true",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0072" memory.drift_detected=true | timechart avg(memory_entry_trust_score) avg(approval_rate_by_session)',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),
    TechniqueEntry(
        technique_id="AML.T0073",
        technique_name="Agent Identity Privilege Creep",
        tactic_id="AML.TA0012",
        tactic_name="Privilege Escalation",
        owasp_llm=["LLM06", "LLM08"],
        owasp_asi=["ASI03", "ASI07"],
        maestro_layers=["L5", "L6"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.1"],
        cvss_score=8.7,
        severity="High",
        attack_vector="Network",
        kill_chain_stage="PrivilegeEscalation",
        kill_chain_order=5,
        description="Agent granted permissions diverge from actually-used permissions over a session, indicating silent privilege expansion.",
        impact="Unauthorized scope accumulation enabling downstream high-impact actions",
        affected_components=["a2a_verifier", "agent_identity", "scope_registry"],
        mitigations=["Track granted vs used scope per agent", "Alert on scope_delta", "Periodic scope attestation"],
        tags=["privilege-creep", "identity", "scope-drift", "emerging-2026"],
        detection_signal="privilege_creep_detected=true",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0073" privilege_creep_detected=true | table granted_scope used_scope scope_delta',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),
    TechniqueEntry(
        technique_id="AML.T0074",
        technique_name="Missing Human-in-the-Loop Circuit Breaker",
        tactic_id="AML.TA0011",
        tactic_name="Impact",
        owasp_llm=["LLM06", "LLM09"],
        owasp_asi=["ASI09"],
        maestro_layers=["L5", "L6"],
        nist_ai_rmf=["GOVERN-4.1", "MANAGE-2.1"],
        cvss_score=9.2,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="Impact",
        kill_chain_order=7,
        description="Attack attempts to auto-approve a large or irreversible loan transaction with no human checkpoint when HITL gate is disabled.",
        impact="High-value financial decision without human oversight; regulatory and fraud exposure",
        affected_components=["orchestration_guard", "compliance_agent", "hitl_gate"],
        mitigations=["Enable HITL_GATE_ENABLED for production", "Threshold-based approval holds", "Audit hitl_bypassed events"],
        tags=["hitl", "governance", "financial-controls", "emerging-2026"],
        detection_signal="hitl_bypassed=true",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0074" hitl_required=true hitl_bypassed=true',
        acme_output_guard_action="ALERT",
        quality_tier="reviewed",
    ),
    TechniqueEntry(
        technique_id="AML.T0075",
        technique_name="Agent-in-the-Middle Message Provenance Tampering",
        tactic_id="AML.TA0013",
        tactic_name="Lateral Movement",
        owasp_llm=["LLM08"],
        owasp_asi=["ASI07"],
        maestro_layers=["L5", "L6"],
        nist_ai_rmf=["GOVERN-1.1", "MANAGE-2.4"],
        cvss_score=8.8,
        severity="Critical",
        attack_vector="Network",
        kill_chain_stage="LateralMovement",
        kill_chain_order=5,
        description="Adversary tampers with message content in transit between agents, testing provenance/integrity rather than identity spoofing alone.",
        impact="Downstream agents act on altered inter-agent payloads while trust chain appears valid",
        affected_components=["a2a_verifier", "message_bus", "agent_delegation"],
        mitigations=["Message hash verification between hops", "End-to-end signing of A2A payloads", "Provenance audit trail"],
        tags=["a2a", "mitm", "provenance", "emerging-2026"],
        detection_signal="message.provenance_valid=false",
        splunk_spl_template='sourcetype="otel:agentic:json" technique_id="AML.T0075" message.provenance_valid=false',
        acme_output_guard_action="HARD_DENY",
        quality_tier="reviewed",
    ),

]

# =============================================================================
# OWASP LLM TOP 10 2025 REGISTRY
# =============================================================================

OWASP_LLM_REGISTRY = {
    "LLM01": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Malicious inputs manipulate LLM behaviour, bypassing safety controls or causing unauthorised actions",
        "severity": "Critical",
        "maestro_layers": ["L3", "L4"],
        "atlas_techniques": ["AML.T0051", "AML.T0054", "AML.T0055"],
    },
    "LLM02": {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "description": "LLM reveals confidential data from training, context window, or integrated systems",
        "severity": "High",
        "maestro_layers": ["L1", "L2"],
        "atlas_techniques": ["AML.T0024", "AML.T0031", "AML.T0038"],
    },
    "LLM03": {
        "id": "LLM03",
        "name": "Supply Chain Vulnerabilities",
        "description": "Compromised models, datasets, plugins, or dependencies introduce vulnerabilities",
        "severity": "Critical",
        "maestro_layers": ["L1", "L7"],
        "atlas_techniques": ["AML.T0018", "AML.T0025", "AML.T0048"],
    },
    "LLM04": {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
        "description": "Training data or RLHF feedback manipulated to embed biases or backdoors",
        "severity": "Critical",
        "maestro_layers": ["L1", "L2"],
        "atlas_techniques": ["AML.T0018", "AML.T0034"],
    },
    "LLM05": {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "description": "LLM outputs not validated before downstream use, enabling XSS, SSRF, code injection",
        "severity": "High",
        "maestro_layers": ["L3", "L4"],
        "atlas_techniques": ["AML.T0031", "AML.T0065"],
    },
    "LLM06": {
        "id": "LLM06",
        "name": "Excessive Agency",
        "description": "LLM granted too many capabilities or permissions, enabling unintended high-impact actions",
        "severity": "High",
        "maestro_layers": ["L4", "L5"],
        "atlas_techniques": ["AML.T0050", "AML.T0064"],
    },
    "LLM07": {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "description": "Confidential system prompt content revealed through model outputs",
        "severity": "Medium",
        "maestro_layers": ["L3", "L6"],
        "atlas_techniques": ["AML.T0003"],
    },
    "LLM08": {
        "id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "description": "Vulnerabilities in RAG pipelines, embedding models, and vector stores",
        "severity": "High",
        "maestro_layers": ["L2"],
        "atlas_techniques": ["AML.T0037", "AML.T0038"],
    },
    "LLM09": {
        "id": "LLM09",
        "name": "Misinformation",
        "description": "LLM generates or amplifies false, misleading, or harmful information at scale",
        "severity": "High",
        "maestro_layers": ["L1", "L3"],
        "atlas_techniques": ["AML.T0063"],
    },
    "LLM10": {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "description": "LLM processes excessive inputs consuming disproportionate resources, enabling DoS or financial drain",
        "severity": "High",
        "maestro_layers": ["L3", "L4"],
        "atlas_techniques": ["AML.T0040"],
    },
}

# =============================================================================
# OWASP ASI TOP 10 2026 REGISTRY (Agentic Security Initiative)
# =============================================================================

OWASP_ASI_REGISTRY = {
    "ASI01": {
        "id": "ASI01",
        "name": "Agent Goal Hijack",
        "description": "Attacker alters an agent's objectives or decision path through malicious content in the agent's planning or reasoning context",
        "severity": "Critical",
        "maestro_layers": ["L3", "L4"],
        "atlas_techniques": ["AML.T0051", "AML.T0054", "AML.T0055"],
        "llm_relationship": ["LLM01", "LLM06"],
    },
    "ASI02": {
        "id": "ASI02",
        "name": "Tool Misuse and Exploitation",
        "description": "Agent's tool access is abused to perform unauthorised actions beyond intended scope",
        "severity": "Critical",
        "maestro_layers": ["L4"],
        "atlas_techniques": ["AML.T0043", "AML.T0050", "AML.T0064"],
        "llm_relationship": ["LLM06"],
    },
    "ASI03": {
        "id": "ASI03",
        "name": "Agent Identity and Privilege Abuse",
        "description": "Agent identity is spoofed or privileges are abused to gain unauthorised access in multi-agent systems",
        "severity": "Critical",
        "maestro_layers": ["L5", "L6"],
        "atlas_techniques": ["AML.T0058", "AML.T0062"],
        "llm_relationship": ["LLM08"],
    },
    "ASI04": {
        "id": "ASI04",
        "name": "Agentic Supply Chain Compromise",
        "description": "Malicious components introduced via plugins, tools, models, or datasets in the AI supply chain",
        "severity": "Critical",
        "maestro_layers": ["L1", "L7"],
        "atlas_techniques": ["AML.T0048", "AML.T0049", "AML.T0018"],
        "llm_relationship": ["LLM03"],
    },
    "ASI05": {
        "id": "ASI05",
        "name": "Unexpected Code Execution",
        "description": "Agent executes arbitrary code via code execution tools, achieving sandbox escape or host access",
        "severity": "Critical",
        "maestro_layers": ["L4"],
        "atlas_techniques": ["AML.T0064", "AML.T0065"],
        "llm_relationship": ["LLM06"],
    },
    "ASI06": {
        "id": "ASI06",
        "name": "Memory and Context Poisoning",
        "description": "Agent's persistent memory or context window is poisoned, corrupting reasoning across sessions",
        "severity": "High",
        "maestro_layers": ["L2", "L3"],
        "atlas_techniques": ["AML.T0055", "AML.T0056", "AML.T0057"],
        "llm_relationship": ["LLM01", "LLM04"],
    },
    "ASI07": {
        "id": "ASI07",
        "name": "Insecure Inter-Agent Communication",
        "description": "Messages between agents are spoofed, intercepted, or manipulated due to lack of authentication or integrity controls",
        "severity": "Critical",
        "maestro_layers": ["L5"],
        "atlas_techniques": ["AML.T0045", "AML.T0046", "AML.T0058"],
        "llm_relationship": ["LLM08"],
    },
    "ASI08": {
        "id": "ASI08",
        "name": "Cascading Agent Failures",
        "description": "Failures or attacks propagate through multi-agent pipelines, amplifying impact across the system",
        "severity": "High",
        "maestro_layers": ["L5", "L6"],
        "atlas_techniques": ["AML.T0029", "AML.T0040", "AML.T0046"],
        "llm_relationship": ["LLM04", "LLM10"],
    },
    "ASI09": {
        "id": "ASI09",
        "name": "Human-Agent Trust Exploitation",
        "description": "Agent manipulates human operators into approving harmful actions through overconfident or misleading outputs",
        "severity": "High",
        "maestro_layers": ["L6"],
        "atlas_techniques": ["AML.T0063"],
        "llm_relationship": ["LLM09"],
    },
    "ASI10": {
        "id": "ASI10",
        "name": "Rogue Agents",
        "description": "Compromised, misaligned, or drifting agents operate autonomously in unintended and harmful ways",
        "severity": "Critical",
        "maestro_layers": ["L5", "L6"],
        "atlas_techniques": ["AML.T0026", "AML.T0060", "AML.T0061"],
        "llm_relationship": ["LLM06"],
    },
}

# =============================================================================
# LOOKUP HELPERS
# =============================================================================

def get_technique(technique_id: str) -> Optional[TechniqueEntry]:
    """Return a TechniqueEntry by its ATLAS technique ID."""
    for t in TECHNIQUE_REGISTRY:
        if t.technique_id == technique_id or t.subtechnique_id == technique_id:
            return t
    return None

def get_techniques_by_tactic(tactic_id: str) -> List[TechniqueEntry]:
    """Return all techniques belonging to a given tactic."""
    return [t for t in TECHNIQUE_REGISTRY if t.tactic_id == tactic_id]

def get_techniques_by_owasp_llm(owasp_id: str) -> List[TechniqueEntry]:
    """Return all techniques mapped to a given OWASP LLM risk."""
    return [t for t in TECHNIQUE_REGISTRY if owasp_id in t.owasp_llm]

def get_techniques_by_owasp_asi(asi_id: str) -> List[TechniqueEntry]:
    """Return all techniques mapped to a given OWASP ASI risk."""
    return [t for t in TECHNIQUE_REGISTRY if asi_id in t.owasp_asi]

def get_techniques_by_maestro_layer(layer_id: str) -> List[TechniqueEntry]:
    """Return all techniques touching a given MAESTRO layer."""
    return [t for t in TECHNIQUE_REGISTRY if layer_id in t.maestro_layers]

def get_techniques_by_severity(severity: str) -> List[TechniqueEntry]:
    """Return all techniques at a given severity level."""
    return [t for t in TECHNIQUE_REGISTRY if t.severity == severity]

def get_techniques_by_kill_chain_stage(stage: str) -> List[TechniqueEntry]:
    """Return all techniques at a given kill-chain stage, ordered by kill_chain_order."""
    return sorted(
        [t for t in TECHNIQUE_REGISTRY if t.kill_chain_stage == stage],
        key=lambda x: x.kill_chain_order
    )

def export_csv_lookup() -> str:
    """Export the full taxonomy as a CSV string for Splunk lookup tables."""
    import csv, io
    fields = [
        "technique_id", "technique_name", "tactic_id", "tactic_name",
        "subtechnique_id", "subtechnique_name",
        "owasp_llm", "owasp_asi", "maestro_layers", "nist_ai_rmf",
        "cvss_score", "severity", "attack_vector", "kill_chain_stage",
        "kill_chain_order", "description", "impact",
        "acme_output_guard_action", "galileo_check",
        "detection_signal", "splunk_spl_template",
        "real_world_incident", "quality_tier", "learning_tier", "redundant_with",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for t in TECHNIQUE_REGISTRY:
        row = t.to_dict()
        row["owasp_llm"] = "|".join(row["owasp_llm"])
        row["owasp_asi"] = "|".join(row["owasp_asi"])
        row["maestro_layers"] = "|".join(row["maestro_layers"])
        row["nist_ai_rmf"] = "|".join(row["nist_ai_rmf"])
        writer.writerow(row)
    return buf.getvalue()

def export_jsonl() -> str:
    """Export full taxonomy as JSONL for HuggingFace dataset compatibility."""
    lines = []
    for t in TECHNIQUE_REGISTRY:
        lines.append(json.dumps(t.to_dict()))
    return "\n".join(lines)

def get_framework_stats() -> dict:
    """Return coverage statistics across all frameworks."""
    tactics = set(t.tactic_id for t in TECHNIQUE_REGISTRY)
    return {
        "total_techniques": len(TECHNIQUE_REGISTRY),
        "unique_tactics": len(tactics),
        "owasp_llm_coverage": len(set(o for t in TECHNIQUE_REGISTRY for o in t.owasp_llm)),
        "owasp_asi_coverage": len(set(a for t in TECHNIQUE_REGISTRY for a in t.owasp_asi)),
        "maestro_layers_coverage": len(set(l for t in TECHNIQUE_REGISTRY for l in t.maestro_layers)),
        "nist_rmf_coverage": len(set(n for t in TECHNIQUE_REGISTRY for n in t.nist_ai_rmf)),
        "critical_techniques": len([t for t in TECHNIQUE_REGISTRY if t.severity == "Critical"]),
        "high_techniques": len([t for t in TECHNIQUE_REGISTRY if t.severity == "High"]),
        "medium_techniques": len([t for t in TECHNIQUE_REGISTRY if t.severity == "Medium"]),
        "with_real_world_incident": len([t for t in TECHNIQUE_REGISTRY if t.real_world_incident]),
    }


if __name__ == "__main__":
    stats = get_framework_stats()
    print("=== Framework Taxonomy Stats ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print("\n=== CSV lookup sample (first 3 rows) ===")
    csv_data = export_csv_lookup()
    for i, line in enumerate(csv_data.split("\n")[:4]):
        print(line[:120])
