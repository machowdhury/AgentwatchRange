"""
=============================================================================
ACME Security Testbed — Dataset Exporter
=============================================================================
Exports OTel telemetry events from Splunk into HuggingFace-compatible JSONL
datasets matching the schema of emmanuelgjr/genai-incidents.

Supports two export modes:
  1. LIVE MODE: Query Splunk HEC/API for real ingested events, transform them
     to HuggingFace schema, and write JSONL
  2. SYNTHETIC MODE: Generate a complete synthetic dataset from the taxonomy
     library (useful for seeding before any Splunk data exists)

Output schema matches:
  id, title, description, date, severity, attack_vector,
  category, corpus, source_ids, year, added, updated,
  affected, impact, mitre_atlas (list), mitre_atlas_tactics (list),
  owasp_llm (list), owasp_asi (list), owasp_dsgai (list),
  maestro_layers (list), nist_ai_rmf (list),
  mitigations (list), references (list), tags (list),
  cvss_score, quality_tier, aiid_id, cve_ids (list)
=============================================================================
"""

import os
import sys
import json
import uuid
import time
import logging
import datetime
import argparse
import csv
from typing import List, Dict, Optional
from pathlib import Path

# Allow running from the apps/ directory
sys.path.insert(0, str(Path(__file__).parent))

from framework.taxonomy import (
    TECHNIQUE_REGISTRY,
    OWASP_LLM_REGISTRY,
    OWASP_ASI_REGISTRY,
    MAESTRO_LAYERS,
    TechniqueEntry,
    get_technique,
    export_csv_lookup,
)
from framework.chain_engine import KILL_CHAINS, KILL_CHAIN_MAP

logger = logging.getLogger("acme.dataset_exporter")


def _splunk_tls_verify() -> bool:
    """When SPLUNK_HEC_TLS_SKIP_VERIFY is true, disable TLS verification (local self-signed Splunk)."""
    skip = os.environ.get("SPLUNK_HEC_TLS_SKIP_VERIFY", "true").lower()
    return skip not in ("true", "1", "yes")

# =============================================================================
# HuggingFace DATASET SCHEMA
# Matches emmanuelgjr/genai-incidents exactly
# =============================================================================

def technique_to_hf_record(
    technique: TechniqueEntry,
    incident_id: Optional[str] = None,
    chain_id: Optional[str] = None,
    stage_name: Optional[str] = None,
    extra_fields: Optional[dict] = None,
) -> dict:
    """
    Transform a TechniqueEntry into a HuggingFace-compatible incident record.
    Fills every field in the emmanuelgjr/genai-incidents schema.
    """
    now = datetime.datetime.utcnow()
    date_str = now.strftime("%Y-%m-%d")
    year = now.year

    # Build MAESTRO layer objects matching the HF schema structure
    maestro_layer_objects = []
    for layer_id in technique.maestro_layers:
        layer_info = MAESTRO_LAYERS.get(layer_id, {})
        maestro_layer_objects.append({
            "label": layer_info.get("name", layer_id),
            "layer": layer_id,
            "notes": layer_info.get("description", ""),
            "role": "impact",
        })

    # Build OWASP LLM references
    owasp_llm_list = technique.owasp_llm

    # Build OWASP ASI references
    owasp_asi_list = technique.owasp_asi

    # Build NIST AI RMF references
    nist_rmf_list = technique.nist_ai_rmf

    # Build MITRE ATLAS technique list
    atlas_techniques = [technique.technique_id]
    if technique.subtechnique_id:
        atlas_techniques.append(technique.subtechnique_id)

    # Build MITRE ATLAS tactics list
    atlas_tactics = [technique.tactic_id]

    # Determine category
    category = "agentic-ai" if technique.owasp_asi else "real-world"

    # Build affected string
    affected = ", ".join(technique.affected_components[:3]) if technique.affected_components else "AI agent system"

    # Build mitigations list
    mitigations = technique.mitigations

    # Build references list
    references = []
    for ref in technique.references:
        references.append({"title": ref, "type": "technical", "url": ref})
    if technique.real_world_incident:
        references.append({
            "title": technique.real_world_incident,
            "type": "incident",
            "url": f"https://atlas.mitre.org/studies/#{technique.technique_id.lower()}"
        })

    # Build tags list
    tags = list(technique.tags)
    tags.extend(owasp_llm_list)
    tags.extend(owasp_asi_list)
    tags.extend(technique.maestro_layers)
    if chain_id:
        tags.append(chain_id)

    record_id = incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}"

    record = {
        "id": record_id,
        "title": stage_name or technique.technique_name,
        "description": technique.description,
        "date": date_str,
        "year": year,
        "added": f"{now.isoformat()}Z",
        "updated": f"{now.isoformat()}Z",
        "severity": technique.severity,
        "attack_vector": technique.attack_vector,
        "category": category,
        "corpus": "security",
        "source_ids": [record_id],
        "affected": affected,
        "impact": technique.impact,
        "mitre_atlas": atlas_techniques,
        "mitre_atlas_tactics": atlas_tactics,
        "owasp_llm": owasp_llm_list,
        "owasp_asi": owasp_asi_list,
        "owasp_dsgai": [],  # Future: map to OWASP DSGAI when published
        "maestro_layers": maestro_layer_objects,
        "nist_ai_rmf": nist_rmf_list,
        "mitigations": mitigations,
        "references": references,
        "tags": tags,
        "cvss_score": technique.cvss_score,
        "quality_tier": technique.quality_tier,
        "aiid_id": None,
        "cve_ids": [],
        # Extended ACME-specific fields (backward-compatible additions)
        "acme_technique_id": technique.technique_id,
        "acme_tactic_id": technique.tactic_id,
        "acme_tactic_name": technique.tactic_name,
        "acme_kill_chain_stage": technique.kill_chain_stage,
        "acme_kill_chain_order": technique.kill_chain_order,
        "acme_acme_output_guard_action": technique.acme_output_guard_action,
        "acme_galileo_check": technique.galileo_check,
        "acme_detection_signal": technique.detection_signal,
        "acme_splunk_spl_template": technique.splunk_spl_template,
        "acme_chain_id": chain_id or "",
        "acme_real_world_incident": technique.real_world_incident,
        **(extra_fields or {}),
    }
    return record


def chain_to_hf_records(kill_chain) -> List[dict]:
    """Convert a full KillChain scenario into a list of HF records (one per stage)."""
    records = []
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    for stage_num, stage in enumerate(kill_chain.stages, 1):
        technique = get_technique(stage.technique_id)
        if not technique:
            continue
        record = technique_to_hf_record(
            technique=technique,
            incident_id=f"{incident_id}-S{stage_num:02d}",
            chain_id=kill_chain.chain_id,
            stage_name=f"[{kill_chain.name}] Stage {stage_num}: {stage.stage_name}",
            extra_fields={
                "acme_chain_name": kill_chain.name,
                "acme_chain_scenario_family": kill_chain.scenario_family,
                "acme_chain_stage_num": stage_num,
                "acme_chain_total_stages": len(kill_chain.stages),
                "acme_chain_threat_actor": kill_chain.threat_actor_profile,
                "acme_chain_total_cvss": kill_chain.total_cvss_score,
                **stage.custom_fields,
            }
        )
        records.append(record)
    return records


# =============================================================================
# EXPORT FUNCTIONS
# =============================================================================

def export_synthetic_dataset(output_path: str = "/var/log/acme_sentinel/acme_synthetic_dataset.jsonl") -> dict:
    """
    Generate a complete synthetic dataset from the taxonomy without requiring
    Splunk connectivity. Useful for seeding, testing, and sharing.
    """
    records = []

    # 1. One record per taxonomy technique
    for technique in TECHNIQUE_REGISTRY:
        record = technique_to_hf_record(technique)
        records.append(record)

    # 2. Multi-record sets from each kill chain (chain-context enrichment)
    for chain in KILL_CHAINS:
        chain_records = chain_to_hf_records(chain)
        records.extend(chain_records)

    # Write JSONL
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")

    stats = {
        "total_records": len(records),
        "technique_records": len(TECHNIQUE_REGISTRY),
        "chain_stage_records": len(records) - len(TECHNIQUE_REGISTRY),
        "unique_techniques": len(set(r["acme_technique_id"] for r in records)),
        "unique_chains": len(set(r["acme_chain_id"] for r in records if r["acme_chain_id"])),
        "severity_breakdown": {
            s: len([r for r in records if r["severity"] == s])
            for s in ["Critical", "High", "Medium", "Low"]
        },
        "output_path": output_path,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }

    logger.info(f"[Exporter] Synthetic dataset written: {len(records)} records → {output_path}")
    return stats


def export_splunk_lookup_csv(output_path: str = "/var/log/acme_sentinel/acme_framework_lookup.csv") -> dict:
    """
    Export the framework taxonomy as a Splunk-ready CSV lookup table.
    This file should be placed in the Splunk compliance app's lookups/ directory.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    csv_content = export_csv_lookup()
    with open(output_path, "w") as f:
        f.write(csv_content)

    row_count = len(csv_content.strip().split("\n")) - 1  # minus header
    logger.info(f"[Exporter] Splunk lookup CSV written: {row_count} techniques → {output_path}")
    return {"rows": row_count, "output_path": output_path}


def export_splunk_events_to_jsonl(
    splunk_host: str,
    splunk_port: int,
    splunk_username: str,
    splunk_password: str,
    output_path: str = "/var/log/acme_sentinel/acme_splunk_export.jsonl",
    earliest: str = "-7d",
    latest: str = "now",
    max_results: int = 10000,
) -> dict:
    """
    Query Splunk REST API for ingested OTel events and export as HF-compatible JSONL.
    Requires Splunk REST API access (port 8089 by default).
    """
    try:
        import urllib3
        urllib3.disable_warnings()
        import requests as req
    except ImportError:
        return {"error": "requests library not available"}

    search_query = (
        f'search index=acme_agentic_telemetry sourcetype="otel:agentic:json" '
        f'earliest={earliest} latest={latest} '
        f'| table _time incident_id chain_id framework.technique_id framework.technique_name '
        f'framework.tactic_id framework.severity framework.cvss_score '
        f'framework.kill_chain_stage framework.owasp_llm framework.owasp_asi '
        f'framework.maestro_layers framework.nist_ai_rmf '
        f'acme_output_guard_action detection_signal agent.id event_type '
        f'| head {max_results}'
    )

    try:
        # Submit search job
        search_url = f"https://{splunk_host}:{splunk_port}/services/search/jobs"
        r = req.post(
            search_url,
            auth=(splunk_username, splunk_password),
            data={"search": search_query, "output_mode": "json", "exec_mode": "normal"},
            verify=_splunk_tls_verify(),
            timeout=30,
        )
        if r.status_code != 201:
            return {"error": f"Search job creation failed: {r.status_code} {r.text[:200]}"}

        sid = r.json()["sid"]
        logger.info(f"[Exporter] Splunk search job created: sid={sid}")

        # Poll for completion
        status_url = f"{search_url}/{sid}"
        for _ in range(60):
            status = req.get(
                status_url,
                auth=(splunk_username, splunk_password),
                params={"output_mode": "json"},
                verify=_splunk_tls_verify(),
                timeout=10,
            ).json()
            if status["entry"][0]["content"]["dispatchState"] in ("DONE", "FAILED"):
                break
            time.sleep(2)

        # Fetch results
        results_url = f"{status_url}/results"
        results = req.get(
            results_url,
            auth=(splunk_username, splunk_password),
            params={"output_mode": "json", "count": max_results},
            verify=_splunk_tls_verify(),
            timeout=30,
        ).json()

        records = []
        for row in results.get("results", []):
            technique_id = row.get("framework.technique_id", "")
            technique = get_technique(technique_id)
            if technique:
                record = technique_to_hf_record(
                    technique=technique,
                    incident_id=row.get("incident_id"),
                    chain_id=row.get("chain_id"),
                    extra_fields={
                        "splunk_time": row.get("_time", ""),
                        "splunk_agent_id": row.get("agent.id", ""),
                        "splunk_event_type": row.get("event_type", ""),
                        "splunk_acme_output_guard_action": row.get("acme_output_guard_action", ""),
                    }
                )
                records.append(record)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")

        return {
            "records_exported": len(records),
            "output_path": output_path,
            "splunk_query": search_query,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        }

    except Exception as e:
        return {"error": str(e)}


def export_dataset_card(output_path: str = "/var/log/acme_sentinel/DATASET_CARD.md") -> str:
    """
    Generate a HuggingFace-style dataset card for the exported dataset.
    """
    stats = {
        "total_techniques": len(TECHNIQUE_REGISTRY),
        "kill_chains": len(KILL_CHAINS),
        "total_kill_chain_stages": sum(len(kc.stages) for kc in KILL_CHAINS),
        "owasp_llm": 10,
        "owasp_asi": 10,
        "maestro_layers": 7,
        "nist_rmf_controls": 12,
    }

    card = f"""---
license: cc-by-4.0
task_categories:
  - text-classification
  - text-retrieval
language:
  - en
tags:
  - security
  - cybersecurity
  - ai-safety
  - ai-security
  - llm
  - agentic-ai
  - mitre-atlas
  - owasp
  - csa-maestro
  - nist-ai-rmf
  - splunk
  - opentelemetry
size_categories:
  - 1K<n<10K
---

# ACME Banking GenAI & Agentic AI Security Incident Dataset

Generated by the ACME Security Testbed — a fully reproducible multi-agent
AI security simulation environment that emits authentic OpenTelemetry telemetry
into Splunk for compliance validation.

## Dataset Statistics

| Metric | Value |
|--------|-------|
| MITRE ATLAS Techniques | {stats['total_techniques']} |
| Kill-Chain Scenarios | {stats['kill_chains']} |
| Kill-Chain Stages | {stats['total_kill_chain_stages']} |
| OWASP LLM Top 10 Coverage | {stats['owasp_llm']}/10 |
| OWASP ASI Top 10 Coverage | {stats['owasp_asi']}/10 |
| CSA MAESTRO Layers | {stats['maestro_layers']}/7 |
| NIST AI RMF Controls | {stats['nist_rmf_controls']} |

## Schema

Compatible with `emmanuelgjr/genai-incidents` schema v2026.05.

```python
from datasets import load_dataset
ds = load_dataset("json", data_files="acme_synthetic_dataset.jsonl")
```

## Framework Coverage

- **MITRE ATLAS v2026.05**: 16 tactics, {stats['total_techniques']} techniques
- **OWASP LLM Top 10 2025**: LLM01–LLM10 complete
- **OWASP ASI Top 10 2026**: ASI01–ASI10 complete (Agentic Security Initiative)
- **CSA MAESTRO**: All 7 layers (L1 Foundation Models → L7 Agent Ecosystem)
- **NIST AI RMF 1.0**: GOVERN, MAP, MEASURE, MANAGE functions

## Kill-Chain Scenarios

| ID | Name | Stages | CVSS |
|----|------|--------|------|
""" + "\n".join(
        f"| {kc.chain_id} | {kc.name} | {len(kc.stages)} | {kc.total_cvss_score} |"
        for kc in KILL_CHAINS
    ) + f"""

## License

CC-BY-4.0

## Generated

{datetime.datetime.utcnow().strftime("%Y-%m-%d")} by ACME Security Testbed v2.0.0
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(card)
    return card


# =============================================================================
# FLASK ROUTES (mounted by app_runtime.py)
# =============================================================================

def register_export_routes(app, base_output_dir: str = "/var/log/acme_sentinel"):
    """Register dataset export API routes on an existing Flask app."""
    from flask import jsonify, request

    @app.route("/api/v1/dataset/export/synthetic", methods=["POST"])
    def export_synthetic():
        output_path = os.path.join(base_output_dir, "acme_synthetic_dataset.jsonl")
        stats = export_synthetic_dataset(output_path)
        return jsonify({"status": "exported", **stats})

    @app.route("/api/v1/dataset/export/lookup-csv", methods=["POST"])
    def export_lookup():
        output_path = os.path.join(base_output_dir, "acme_framework_lookup.csv")
        result = export_splunk_lookup_csv(output_path)
        return jsonify({"status": "exported", **result})

    @app.route("/api/v1/dataset/export/dataset-card", methods=["POST"])
    def export_card():
        output_path = os.path.join(base_output_dir, "DATASET_CARD.md")
        card = export_dataset_card(output_path)
        return jsonify({"status": "exported", "output_path": output_path, "preview": card[:500]})

    @app.route("/api/v1/dataset/stats", methods=["GET"])
    def dataset_stats():
        from framework.taxonomy import get_framework_stats
        return jsonify({
            "taxonomy_stats": get_framework_stats(),
            "kill_chains": [
                {
                    "chain_id": kc.chain_id,
                    "name": kc.name,
                    "scenario_family": kc.scenario_family,
                    "stages": len(kc.stages),
                    "total_cvss_score": kc.total_cvss_score,
                }
                for kc in KILL_CHAINS
            ],
            "owasp_llm_count": 10,
            "owasp_asi_count": 10,
            "maestro_layers_count": 7,
        })

    @app.route("/api/v1/dataset/schema", methods=["GET"])
    def dataset_schema():
        """Return the HuggingFace dataset schema as JSON."""
        sample = technique_to_hf_record(TECHNIQUE_REGISTRY[0])
        return jsonify({
            "schema_version": "2026.05",
            "compatible_with": "emmanuelgjr/genai-incidents",
            "field_count": len(sample.keys()),
            "fields": list(sample.keys()),
            "sample_record": sample,
        })


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="ACME Dataset Exporter")
    parser.add_argument("--mode", choices=["synthetic", "lookup", "card", "all"], default="all")
    parser.add_argument("--output-dir", default="/var/log/acme_sentinel")
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    if args.mode in ("synthetic", "all"):
        print("\n=== Exporting Synthetic Dataset ===")
        stats = export_synthetic_dataset(os.path.join(output_dir, "acme_synthetic_dataset.jsonl"))
        for k, v in stats.items():
            print(f"  {k}: {v}")

    if args.mode in ("lookup", "all"):
        print("\n=== Exporting Splunk Lookup CSV ===")
        result = export_splunk_lookup_csv(os.path.join(output_dir, "acme_framework_lookup.csv"))
        print(f"  Rows: {result['rows']} → {result['output_path']}")

    if args.mode in ("card", "all"):
        print("\n=== Exporting Dataset Card ===")
        card = export_dataset_card(os.path.join(output_dir, "DATASET_CARD.md"))
        print(card[:400])
