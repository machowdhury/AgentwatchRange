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

Technique and framework registry data live in YAML under ``data/``:
  - ``technique_registry.yaml``
  - ``framework_registries.yaml``

Each TechniqueEntry carries every field required for:
  - OTel event enrichment
  - HuggingFace-compatible dataset export (emmanuelgjr/genai-incidents schema)
  - Splunk compliance dashboard lookup tables
  - Kill-chain chain_engine.py sequencing

Schema is intentionally flat — no nested objects — so it serialises cleanly
to CSV lookups, JSONL datasets, and OTel log attributes.
=============================================================================
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import json

import yaml

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
    maestro_layers: List[str] = field(default_factory=list)  # ["L3", "L4"]
    nist_ai_rmf: List[str] = field(default_factory=list)  # ["GOVERN-1.1", "MEASURE-2.5"]

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
# YAML LOADER
# =============================================================================

_DATA_DIR_CANDIDATES = (
    Path(__file__).resolve().parent / "data",
    Path("/app/framework/data"),
)


def _data_dir() -> Path:
    for candidate in _DATA_DIR_CANDIDATES:
        if candidate.is_dir():
            return candidate
    return _DATA_DIR_CANDIDATES[0]


def _load_yaml_file(name: str) -> dict:
    path = _data_dir() / name
    if not path.exists():
        raise FileNotFoundError(f"Taxonomy data file not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _technique_from_dict(raw: dict) -> TechniqueEntry:
    return TechniqueEntry(**raw)


def _load_technique_registry() -> List[TechniqueEntry]:
    data = _load_yaml_file("technique_registry.yaml")
    return [_technique_from_dict(entry) for entry in data.get("techniques", [])]


def _load_framework_registries() -> dict:
    return _load_yaml_file("framework_registries.yaml")


# =============================================================================
# REGISTRIES (loaded from YAML)
# =============================================================================

_framework_data = _load_framework_registries()

MAESTRO_LAYERS: Dict[str, dict] = _framework_data.get("maestro_layers", {})
NIST_AI_RMF_FUNCTIONS: Dict[str, dict] = _framework_data.get("nist_ai_rmf_functions", {})
OWASP_LLM_REGISTRY: Dict[str, dict] = _framework_data.get("owasp_llm_registry", {})
OWASP_ASI_REGISTRY: Dict[str, dict] = _framework_data.get("owasp_asi_registry", {})
TECHNIQUE_REGISTRY: List[TechniqueEntry] = _load_technique_registry()

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
        key=lambda x: x.kill_chain_order,
    )


def export_csv_lookup() -> str:
    """Export the full taxonomy as a CSV string for Splunk lookup tables."""
    import csv
    import io

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
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
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
    for line in csv_data.split("\n")[:4]:
        print(line[:120])
