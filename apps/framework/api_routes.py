"""
Framework and kill-chain API route registration for OrchestraACME banking fabric.
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from typing import Any

import requests
from flask import Flask, jsonify, request

logger = logging.getLogger(__name__)

from framework.chain_engine import KILL_CHAINS, KILL_CHAIN_MAP, create_engine
from framework.taxonomy import (
    TECHNIQUE_REGISTRY,
    get_framework_stats,
    get_technique,
    get_techniques_by_maestro_layer,
    get_techniques_by_owasp_asi,
    get_techniques_by_owasp_llm,
    get_techniques_by_severity,
)

_chain_results: dict[str, dict[str, Any]] = {}
_results_lock = threading.Lock()


def _technique_to_dict(entry) -> dict[str, Any]:
    data = entry.to_dict()
    return data


def _filter_techniques() -> list:
    severity = request.args.get("severity")
    owasp = request.args.get("owasp")
    owasp_asi = request.args.get("owasp_asi")
    maestro = request.args.get("maestro")

    if severity:
        return get_techniques_by_severity(severity)
    if owasp:
        return get_techniques_by_owasp_llm(owasp)
    if owasp_asi:
        return get_techniques_by_owasp_asi(owasp_asi)
    if maestro:
        return get_techniques_by_maestro_layer(maestro)
    return list(TECHNIQUE_REGISTRY)


def register_framework_routes(app: Flask) -> None:
    @app.route("/api/v1/framework/techniques", methods=["GET"])
    def framework_techniques():
        techniques = _filter_techniques()
        return jsonify({
            "count": len(techniques),
            "techniques": [_technique_to_dict(t) for t in techniques],
        })

    @app.route("/api/v1/framework/technique/<technique_id>", methods=["GET"])
    def framework_technique_detail(technique_id: str):
        technique = get_technique(technique_id)
        if not technique:
            return jsonify({"error": f"Unknown technique: {technique_id}"}), 404
        return jsonify(_technique_to_dict(technique))

    @app.route("/api/v1/framework/emit/<technique_id>", methods=["POST"])
    def framework_emit_technique(technique_id: str):
        from framework.technique_executor import create_executor
        if not get_technique(technique_id):
            return jsonify({"error": f"Unknown technique: {technique_id}"}), 404
        try:
            result = create_executor().execute_technique(technique_id, force_mode="SIMULATED")
            return jsonify(result), 200
        except Exception as exc:
            logger.exception("framework_emit_technique failed for %s", technique_id)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/v1/framework/playbooks", methods=["GET"])
    def framework_playbooks():
        from framework.technique_playbooks import get_coverage_matrix
        return jsonify(get_coverage_matrix())

    @app.route("/api/v1/framework/playbook/<technique_id>", methods=["GET"])
    def framework_playbook_detail(technique_id: str):
        from framework.technique_playbooks import get_playbook
        playbook = get_playbook(technique_id)
        if not playbook:
            return jsonify({"error": f"Unknown technique: {technique_id}"}), 404
        return jsonify(playbook.to_dict())

    @app.route("/api/v1/framework/technique/<technique_id>/execute", methods=["POST"])
    def framework_execute_technique(technique_id: str):
        from framework.technique_executor import create_executor
        if not get_technique(technique_id):
            return jsonify({"error": f"Unknown technique: {technique_id}"}), 404
        body = request.get_json(silent=True) or {}
        try:
            result = create_executor().execute_technique(
                technique_id,
                incident_id=body.get("incident_id"),
                force_mode=body.get("force_mode"),
            )
            return jsonify(result)
        except Exception as exc:
            logger.exception("framework_execute_technique failed for %s", technique_id)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/v1/framework/execute-all", methods=["POST"])
    def framework_execute_all():
        from framework.technique_executor import create_executor
        body = request.get_json(silent=True) or {}
        delay = float(body.get("delay_seconds", 0.3))
        try:
            result = create_executor().execute_all(delay_seconds=delay)
            return jsonify(result)
        except Exception as exc:
            logger.exception("framework_execute_all failed")
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/v1/framework/stats", methods=["GET"])
    def framework_stats():
        return jsonify(get_framework_stats())


def register_chain_routes(app: Flask) -> None:
    otel_endpoint = os.environ.get("OTEL_COLLECTOR_HTTP", "http://otel_collector:4318")
    engine = create_engine(otel_endpoint)

    @app.route("/api/v1/chains", methods=["GET"])
    def list_chains():
        return jsonify({
            "chains": [
                {
                    "chain_id": chain.chain_id,
                    "name": chain.name,
                    "scenario_family": chain.scenario_family,
                    "total_cvss_score": chain.total_cvss_score,
                    "stages": len(chain.stages),
                    "threat_actor_profile": chain.threat_actor_profile,
                }
                for chain in KILL_CHAINS
            ]
        })

    @app.route("/api/v1/chains/<chain_id>/execute", methods=["POST"])
    def execute_chain(chain_id: str):
        if chain_id not in KILL_CHAIN_MAP:
            return jsonify({
                "error": f"Unknown chain_id: {chain_id}",
                "available": list(KILL_CHAIN_MAP.keys()),
            }), 404

        accelerated = bool((request.get_json(silent=True) or {}).get("accelerated", True))
        hybrid_live = bool((request.get_json(silent=True) or {}).get("hybrid_live", False))
        try:
            if hybrid_live:
                from framework.technique_executor import create_executor
                report = create_executor().execute_chain(chain_id, accelerated=accelerated, hybrid_live=True)
            else:
                report = engine.execute_chain(
                    chain_id,
                    accelerated=accelerated,
                    enrich_playbooks=True,
                )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404
        except requests.RequestException as exc:
            return jsonify({"error": f"Chain execution failed: {exc}"}), 502
        except Exception as exc:
            logger.exception("execute_chain failed for %s", chain_id)
            return jsonify({"error": str(exc)}), 500

        with _results_lock:
            _chain_results[report["incident_id"]] = report

        return jsonify(report)

    @app.route("/api/v1/chains/results/<incident_id>", methods=["GET"])
    def chain_results(incident_id: str):
        with _results_lock:
            report = _chain_results.get(incident_id)
        if not report:
            return jsonify({"error": f"No results for incident_id: {incident_id}"}), 404
        return jsonify(report)
