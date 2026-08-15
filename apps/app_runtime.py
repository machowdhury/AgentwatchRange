"""
=============================================================================
AgentWatch Range — Banking App Runtime v3.0
=============================================================================
Real 4-agent LLM loop backed by Ollama (llama3.2:1b).
Every agent turn makes an actual HTTP call to the local model.
All telemetry emitted using OTel GenAI Semantic Conventions.
=============================================================================
"""

import os, sys, json, time, uuid, hashlib, logging, threading, datetime
import requests
from flask import Flask, request, jsonify, render_template

sys.path.insert(0, os.path.dirname(__file__))
from agents.llm_client import call_ollama, ollama_health_check, _OLLAMA_MODEL, _OLLAMA_URL
from agents.agent_router import run_agent_pipeline, AGENTS

_app_dir = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(_app_dir, "templates"))
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "acme-lab-only-not-for-production")
logger = logging.getLogger("acme.banking.fabric")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")

# In-memory ring buffer for recent pipeline results (last 50 sessions)
_recent_sessions = []
_session_lock    = threading.Lock()

def _store_session(result: dict):
    with _session_lock:
        _recent_sessions.insert(0, result)
        if len(_recent_sessions) > 50:
            _recent_sessions.pop()

# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.route("/health")
def health():
    ollama_ok = ollama_health_check()
    return jsonify({
        "status":         "healthy" if ollama_ok else "degraded",
        "ollama_reachable": ollama_ok,
        "ollama_model":   _OLLAMA_MODEL,
        "service":        "acme-banking-fabric",
        "version":        "3.0.0",
        "traffic_sim":    traffic_status(),
        "timestamp":      time.time(),
    })


@app.route("/api/v1/process", methods=["POST"])
def process_request():
    """Main endpoint — runs user input through the real 4-agent LLM pipeline."""
    data       = request.get_json() or {}
    user_input = data.get("input", "").strip()
    session_id = data.get("session_id", str(uuid.uuid4()))

    if not user_input:
        return jsonify({"error": "input field required"}), 400

    logger.info(f"[API] New pipeline request | session={session_id} | input={user_input[:80]}")
    result = run_agent_pipeline(user_input, session_id)
    _store_session(result)
    return jsonify(result)


@app.route("/api/v1/agent/<agent_id>", methods=["POST"])
def call_single_agent(agent_id):
    """Call a single agent directly — for targeted exploit testing."""
    if agent_id not in AGENTS:
        return jsonify({"error": f"Unknown agent: {agent_id}"}), 404
    data    = request.get_json() or {}
    message = data.get("message", data.get("payload", "")).strip()
    if not message:
        return jsonify({"error": "message field required"}), 400

    agent      = AGENTS[agent_id]
    session_id = data.get("session_id", str(uuid.uuid4()))
    result     = call_ollama(
        system_prompt=agent["system_prompt"],
        user_message=message,
        agent_id=agent_id,
        agent_name=agent["name"],
        agent_role=agent["role"],
        session_id=session_id,
        temperature=agent.get("temperature", 0.7),
        max_tokens=agent.get("max_tokens", 512),
        skip_acmesentinel=data.get("skip_acmesentinel", False),
        incident_id=data.get("incident_id"),
        technique_id=data.get("technique_id", ""),
        testbed_mode=data.get("testbed_mode", "BANKING_LIVE"),
        campaign_week=int(data.get("campaign_week", 0) or 0),
    )
    return jsonify({**result, "agent_id": agent_id, "agent_name": agent["name"]})


@app.route("/api/v1/sessions", methods=["GET"])
def list_sessions():
    with _session_lock:
        return jsonify({"sessions": list(_recent_sessions), "count": len(_recent_sessions)})


@app.route("/api/v1/ollama/health", methods=["GET"])
def ollama_health():
    try:
        r = requests.get(f"{_OLLAMA_URL}/api/tags", timeout=5)
        models = r.json().get("models", [])
        return jsonify({
            "reachable": True,
            "models":    [m["name"] for m in models],
            "target_model": _OLLAMA_MODEL,
            "model_loaded": any(_OLLAMA_MODEL.split(":")[0] in m["name"] for m in models),
        })
    except Exception as e:
        return jsonify({"reachable": False, "error": str(e)}), 503


@app.route("/api/v1/agents", methods=["GET"])
def list_agents():
    return jsonify({
        "agents": [
            {"agent_id": aid, "name": a["name"], "role": a["role"],
             "trust_boundary": a["trust_boundary"], "enclave": a["enclave"]}
            for aid, a in AGENTS.items()
        ]
    })


@app.route("/api/v1/config", methods=["GET"])
def get_config():
    return jsonify({
        "ollama_url":   _OLLAMA_URL,
        "ollama_model": _OLLAMA_MODEL,
        "otel_endpoint": os.environ.get("OTEL_COLLECTOR_HTTP", ""),
        "acme_output_guard":   os.environ.get("ACME_OUTPUT_GUARD_ENABLED", "true"),
        "acme_input_guard":     os.environ.get("ACME_INPUT_GUARD_ENABLED", "true"),
    })


# =============================================================================
# DASHBOARD UI
# =============================================================================

@app.route("/")
def index():
    with _session_lock:
        sessions_snapshot = list(_recent_sessions[:10])
    return render_template("dashboard.html",
        model=_OLLAMA_MODEL,
        ollama_url=_OLLAMA_URL,
        agents=AGENTS,
        recent_sessions=sessions_snapshot)



from framework.api_routes import register_chain_routes, register_framework_routes
from framework.cisco_routes import register_cisco_routes
from framework.maestro_workshop import register_maestro_routes
from framework.dataset_exporter import register_export_routes
from framework.traffic_simulator import get_status as traffic_status, maybe_autostart, run_tick, start as traffic_start, stop as traffic_stop
from framework.campaign_manifest import get_all_campaign_weeks
from framework.attack_payloads import EMERGING_ATTACK_CLASSES
from framework.control_validator import evaluate_controls, control_summary

@app.route("/api/v1/campaign/weeks", methods=["GET"])
def campaign_weeks():
    return jsonify({
        "weeks": [w.to_dict() for w in get_all_campaign_weeks()],
        "emerging_attack_classes": EMERGING_ATTACK_CLASSES,
    })


@app.route("/api/v1/controls/evaluate", methods=["POST"])
def evaluate_control_evidence():
    data = request.get_json() or {}
    fields = data.get("fields", {})
    week = int(data.get("campaign_week", 0) or 0)
    evaluations = evaluate_controls(fields, week or None)
    return jsonify(control_summary(evaluations))


@app.route("/api/v1/registry/snapshot", methods=["GET"])
def registry_snapshot():
    from framework.agent_registry import build_registry_snapshot
    return jsonify({"agents": build_registry_snapshot()})


register_framework_routes(app)
register_chain_routes(app)
register_cisco_routes(app)
register_maestro_routes(app)
register_export_routes(app, base_output_dir="/var/log/acme_sentinel")


@app.route("/api/v1/traffic/status", methods=["GET"])
def traffic_sim_status():
    return jsonify(traffic_status())


@app.route("/api/v1/traffic/start", methods=["POST"])
def traffic_sim_start():
    return jsonify(traffic_start())


@app.route("/api/v1/traffic/stop", methods=["POST"])
def traffic_sim_stop():
    return jsonify(traffic_stop())


@app.route("/api/v1/traffic/tick", methods=["POST"])
def traffic_sim_tick():
    data = request.get_json(silent=True) or {}
    force_pipeline = data.get("full_pipeline")
    if force_pipeline is not None:
        force_pipeline = bool(force_pipeline)
    return jsonify(run_tick(force_pipeline=force_pipeline))


maybe_autostart()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
