"""
Periodic benign HEC events for heterogeneous sourcetypes (Phase 10.2–10.3).
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
import urllib.request
from typing import Any, Dict, Optional

from framework.agent_registry import build_registry_snapshot

logger = logging.getLogger("acme.baseline_hec")

VENDORSIM_AGENTS = ("Customer Intake", "Document Extraction", "Credit Risk", "Compliance Verification")
THIRDPARTY_AGENTS = ("tp-agent-loan-001", "tp-agent-risk-002", "tp-agent-doc-003")


def _hec_config() -> Dict[str, str]:
    return {
        "endpoint": os.environ.get(
            "SPLUNK_HEC_ENDPOINT",
            "http://splunk:8088/services/collector/event",
        ),
        "token": os.environ.get("SPLUNK_HEC_TOKEN", "acme-hec-token-0000-1111-2222-3333"),
        "index_primary": os.environ.get("SPLUNK_HEC_INDEX", "acme_agentic_telemetry"),
        "index_vendorsim": os.environ.get("SPLUNK_VENDORSIM_INDEX", "security"),
    }


def send_hec(event: dict, sourcetype: str, index: str, source: str) -> None:
    cfg = _hec_config()
    payload = json.dumps({
        "time": int(time.time()),
        "host": "baseline-hec-emitter",
        "index": index,
        "sourcetype": sourcetype,
        "source": source,
        "event": event,
    }).encode("utf-8")
    req = urllib.request.Request(
        cfg["endpoint"],
        data=payload,
        headers={
            "Authorization": f"Splunk {cfg['token']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError(f"HEC HTTP {resp.status}")


def emit_benign_vendorsim() -> None:
    cfg = _hec_config()
    agent = random.choice(VENDORSIM_AGENTS)
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "agent_name": agent,
        "objective": "TA0040",
        "technique": "T0000",
        "subtechnique": "T0000.000",
        "finding_type": "BASELINE_HEALTHCHECK",
        "policy_action": "ALLOW",
        "threat_category": "benign",
        "gen_ai.usage.input_tokens": random.randint(50, 180),
        "gen_ai.usage.output_tokens": random.randint(30, 120),
        "testbed_mode": "BASELINE_TRAFFIC",
    }
    send_hec(event, "acme:agentic:vendorsim:json", cfg["index_vendorsim"], "baseline_hec/vendorsim")


def emit_benign_thirdparty() -> None:
    cfg = _hec_config()
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "agent_id": random.choice(THIRDPARTY_AGENTS),
        "threat_label": "BENIGN",
        "token_count_in": random.randint(60, 200),
        "token_count_out": random.randint(40, 150),
        "policy_result": "ALLOW",
        "severity": "low",
        "source_system": "acme_thirdparty_baseline",
        "testbed_mode": "BASELINE_TRAFFIC",
    }
    send_hec(event, "acme:agentic:thirdparty:json", cfg["index_primary"], "baseline_hec/thirdparty")


def emit_registry_snapshot() -> None:
    cfg = _hec_config()
    for row in build_registry_snapshot():
        send_hec(row, "acme:agentic:registry:json", cfg["index_primary"], "baseline_hec/registry")


def emit_all() -> Dict[str, Any]:
    emit_benign_vendorsim()
    emit_benign_thirdparty()
    emit_registry_snapshot()
    return {"status": "ok", "emitted": ["vendorsim", "thirdparty", "registry"]}


def run_loop(
    interval_min_sec: int = 120,
    interval_max_sec: int = 300,
    registry_every_n: int = 5,
) -> None:
    tick = 0
    lo, hi = min(interval_min_sec, interval_max_sec), max(interval_min_sec, interval_max_sec)
    logger.info("[BaselineHEC] loop started | interval=%s–%ss", lo, hi)
    while True:
        try:
            emit_benign_vendorsim()
            emit_benign_thirdparty()
            tick += 1
            if tick % registry_every_n == 0:
                emit_registry_snapshot()
        except Exception as exc:
            logger.warning("[BaselineHEC] tick failed: %s", exc)
        time.sleep(random.randint(lo, hi))
