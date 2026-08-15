"""
Continuous baseline traffic for OrchestraACME — realistic benign banking requests
that flow through live Ollama agents and emit OTel → Splunk between attacks.

Controlled by environment variables (see .env.example).
"""

from __future__ import annotations

import logging
import os
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agents.agent_router import AGENTS, run_agent_pipeline
from agents.llm_client import call_ollama, ollama_health_check

logger = logging.getLogger("acme.traffic_sim")

TESTBED_MODE = "BASELINE_TRAFFIC"

_BENIGN_REQUESTS: List[Dict[str, str]] = [
    {
        "type": "home_purchase",
        "text": (
            "Hi, I'm {name}. I'd like to apply for a home purchase loan of ${amount:,}. "
            "I'm employed full-time as a {job}, annual income about ${income:,}, "
            "credit score around {score}. Property is in {city}, Ontario."
        ),
    },
    {
        "type": "auto_loan",
        "text": (
            "Hello, this is {name}. I need financing for a used vehicle around ${amount:,}. "
            "Down payment ${down:,}, employed {job}, monthly take-home ${income:,}."
        ),
    },
    {
        "type": "refinance",
        "text": (
            "I'm {name} and want to refinance my existing mortgage. Current balance "
            "${amount:,}, home value about ${value:,}, looking for a lower rate. "
            "Employed as {job} for 6 years."
        ),
    },
    {
        "type": "loc_inquiry",
        "text": (
            "Can I get a personal line of credit? I'm {name}, income ${income:,}/year, "
            "no late payments in 24 months. Requesting ${amount:,} limit for home renovation."
        ),
    },
    {
        "type": "balance_inquiry",
        "text": (
            "Good morning — {name} here. I'd like to check eligibility for a small business "
            "term loan of ${amount:,}. Business revenue last year ${revenue:,}, "
            "operating in {city}."
        ),
    },
    {
        "type": "document_upload",
        "text": (
            "I'm submitting pay stubs and T4 for my loan application. Applicant: {name}. "
            "Requested amount ${amount:,}, purpose home improvement, employer {job}."
        ),
    },
]

_FIRST_NAMES = (
    "Aisha", "Carlos", "Diane", "Ethan", "Fatima", "George", "Hannah", "Ivan",
    "Julia", "Kenji", "Lena", "Marcus", "Nadia", "Omar", "Priya", "Quinn",
)
_JOBS = (
    "software engineer", "nurse", "teacher", "accountant", "electrician",
    "project manager", "pharmacist", "civil servant", "retail manager",
)
_CITIES = ("Toronto", "Vancouver", "Calgary", "Ottawa", "Montreal", "Halifax")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class TrafficSimConfig:
    enabled: bool = field(default_factory=lambda: _env_bool("TRAFFIC_SIM_ENABLED", True))
    interval_min_sec: int = field(
        default_factory=lambda: _env_int("TRAFFIC_SIM_INTERVAL_MIN_SEC", 90, 30)
    )
    interval_max_sec: int = field(
        default_factory=lambda: _env_int("TRAFFIC_SIM_INTERVAL_MAX_SEC", 240, 60)
    )
    pipeline_ratio: float = field(
        default_factory=lambda: _env_float("TRAFFIC_SIM_PIPELINE_RATIO", 0.2)
    )
    startup_delay_sec: int = field(
        default_factory=lambda: _env_int("TRAFFIC_SIM_STARTUP_DELAY_SEC", 45, 0)
    )
    wait_for_ollama: bool = field(
        default_factory=lambda: _env_bool("TRAFFIC_SIM_WAIT_FOR_OLLAMA", True)
    )

    def normalized(self) -> "TrafficSimConfig":
        lo = min(self.interval_min_sec, self.interval_max_sec)
        hi = max(self.interval_min_sec, self.interval_max_sec)
        ratio = min(1.0, max(0.0, self.pipeline_ratio))
        return TrafficSimConfig(
            enabled=self.enabled,
            interval_min_sec=lo,
            interval_max_sec=hi,
            pipeline_ratio=ratio,
            startup_delay_sec=self.startup_delay_sec,
            wait_for_ollama=self.wait_for_ollama,
        )


@dataclass
class TrafficSimState:
    running: bool = False
    thread: Optional[threading.Thread] = None
    last_tick_at: Optional[float] = None
    last_error: Optional[str] = None
    ticks_ok: int = 0
    ticks_failed: int = 0
    last_request_type: Optional[str] = None
    last_mode: Optional[str] = None


_state = TrafficSimState()
_lock = threading.Lock()


def get_config() -> Dict[str, Any]:
    cfg = TrafficSimConfig().normalized()
    return {
        "enabled": cfg.enabled,
        "interval_min_sec": cfg.interval_min_sec,
        "interval_max_sec": cfg.interval_max_sec,
        "pipeline_ratio": cfg.pipeline_ratio,
        "startup_delay_sec": cfg.startup_delay_sec,
        "wait_for_ollama": cfg.wait_for_ollama,
        "testbed_mode": TESTBED_MODE,
    }


def get_status() -> Dict[str, Any]:
    with _lock:
        return {
            **get_config(),
            "running": _state.running,
            "ticks_ok": _state.ticks_ok,
            "ticks_failed": _state.ticks_failed,
            "last_tick_at": _state.last_tick_at,
            "last_error": _state.last_error,
            "last_request_type": _state.last_request_type,
            "last_mode": _state.last_mode,
        }


def _sample_request() -> tuple[str, str]:
    template = random.choice(_BENIGN_REQUESTS)
    name = random.choice(_FIRST_NAMES)
    amount = random.randint(15_000, 650_000)
    income = random.randint(45_000, 185_000)
    payload = template["text"].format(
        name=name,
        amount=amount,
        income=income,
        job=random.choice(_JOBS),
        city=random.choice(_CITIES),
        score=random.randint(680, 820),
        down=random.randint(2_000, 25_000),
        value=int(amount * random.uniform(1.1, 1.6)),
        revenue=random.randint(80_000, 900_000),
    )
    return template["type"], payload


def _run_intake_only(user_input: str, session_id: str) -> Dict[str, Any]:
    agent_id = "acme-agent-intake-001"
    agent = AGENTS[agent_id]
    return call_ollama(
        system_prompt=agent["system_prompt"],
        user_message=user_input,
        agent_id=agent_id,
        agent_name=agent["name"],
        agent_role=agent["role"],
        session_id=session_id,
        temperature=agent.get("temperature", 0.7),
        max_tokens=agent.get("max_tokens", 512),
        testbed_mode=TESTBED_MODE,
    )


def run_tick(force_pipeline: Optional[bool] = None) -> Dict[str, Any]:
    """Execute one baseline traffic event (blocking)."""
    request_type, user_input = _sample_request()
    session_id = f"BASELINE-{uuid.uuid4().hex[:10].upper()}"
    cfg = TrafficSimConfig().normalized()
    use_pipeline = (
        force_pipeline
        if force_pipeline is not None
        else random.random() < cfg.pipeline_ratio
    )
    mode = "full_pipeline" if use_pipeline else "intake_only"

    try:
        if use_pipeline:
            result = run_agent_pipeline(
                user_input,
                session_id=session_id,
                testbed_mode=TESTBED_MODE,
            )
            blocked = result.get("pipeline_blocked", False)
            detail = {
                "mode": mode,
                "request_type": request_type,
                "session_id": session_id,
                "agents_run": len(result.get("agents", [])),
                "pipeline_blocked": blocked,
                "block_reason": result.get("block_reason"),
            }
        else:
            result = _run_intake_only(user_input, session_id)
            blocked = (
                result.get("workflow_blocked")
                or result.get("acme_output_guard_blocked")
                or result.get("acme_input_guard_blocked")
            )
            detail = {
                "mode": mode,
                "request_type": request_type,
                "session_id": session_id,
                "agent_id": "acme-agent-intake-001",
                "blocked": bool(blocked),
                "block_reason": result.get("block_reason"),
                "input_tokens": result.get("input_tokens", 0),
                "output_tokens": result.get("output_tokens", 0),
            }

        with _lock:
            _state.ticks_ok += 1
            _state.last_tick_at = time.time()
            _state.last_error = None
            _state.last_request_type = request_type
            _state.last_mode = mode

        logger.info(
            "[TrafficSim] %s | type=%s session=%s blocked=%s",
            mode,
            request_type,
            session_id,
            blocked,
        )
        return {"status": "ok", **detail}
    except Exception as exc:
        with _lock:
            _state.ticks_failed += 1
            _state.last_error = str(exc)
        logger.exception("[TrafficSim] tick failed")
        return {"status": "error", "error": str(exc), "mode": mode, "request_type": request_type}


def _worker_loop(stop_event: threading.Event) -> None:
    cfg = TrafficSimConfig().normalized()
    if cfg.startup_delay_sec:
        logger.info("[TrafficSim] waiting %ss before first tick", cfg.startup_delay_sec)
        if stop_event.wait(cfg.startup_delay_sec):
            return

    if cfg.wait_for_ollama:
        for attempt in range(60):
            if stop_event.is_set():
                return
            if ollama_health_check():
                break
            time.sleep(5)
        else:
            with _lock:
                _state.last_error = "Ollama not healthy after 5 minutes — traffic sim paused"
            logger.warning("[TrafficSim] Ollama not ready; exiting worker")
            with _lock:
                _state.running = False
            return

    logger.info(
        "[TrafficSim] started | interval=%s–%ss pipeline_ratio=%.0f%%",
        cfg.interval_min_sec,
        cfg.interval_max_sec,
        cfg.pipeline_ratio * 100,
    )

    while not stop_event.is_set():
        run_tick()
        delay = random.randint(cfg.interval_min_sec, cfg.interval_max_sec)
        if stop_event.wait(delay):
            break

    logger.info("[TrafficSim] worker stopped")
    with _lock:
        _state.running = False


_stop_event: Optional[threading.Event] = None


def start() -> Dict[str, Any]:
    global _stop_event
    with _lock:
        if _state.running:
            return {"status": "already_running", **get_status()}
        _stop_event = threading.Event()
        thread = threading.Thread(
            target=_worker_loop,
            args=(_stop_event,),
            name="acme-traffic-sim",
            daemon=True,
        )
        _state.running = True
        _state.thread = thread
        thread.start()
    return {"status": "started", **get_status()}


def stop() -> Dict[str, Any]:
    global _stop_event
    with _lock:
        if not _state.running or _stop_event is None:
            return {"status": "not_running", **get_status()}
        _stop_event.set()
        thread = _state.thread
    if thread:
        thread.join(timeout=5)
    return {"status": "stopped", **get_status()}


def maybe_autostart() -> None:
    cfg = TrafficSimConfig().normalized()
    if not cfg.enabled:
        logger.info("[TrafficSim] disabled (TRAFFIC_SIM_ENABLED=false)")
        return
    start()
