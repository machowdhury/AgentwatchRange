#!/usr/bin/env python3
"""
Emit synthetic third-party agentic telemetry (acme:agentic:thirdparty:json) via HEC.

Demonstrates a deliberately different field convention from otel:agentic:json and
acme:agentic:sim:json for Phase 6 cross-app normalization lessons.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
import urllib.request

AGENTS = [
    "tp-agent-loan-001",
    "tp-agent-risk-002",
    "tp-agent-doc-003",
]
THREATS = [
    "PROMPT_INJECTION",
    "TOOL_ABUSE",
    "DATA_EXFIL",
    "POLICY_BYPASS",
    "BENIGN",
]


def emit(count: int = 5) -> None:
    endpoint = os.environ.get(
        "SPLUNK_HEC_ENDPOINT",
        "http://localhost:8088/services/collector/event",
    )
    token = os.environ.get("SPLUNK_HEC_TOKEN", "acme-hec-token-0000-1111-2222-3333")
    index = os.environ.get("SPLUNK_HEC_INDEX", "acme_agentic_telemetry")
    sourcetype = "acme:agentic:thirdparty:json"

    for i in range(count):
        threat = random.choice(THREATS)
        event = {
            "agent_id": random.choice(AGENTS),
            "threat_label": threat,
            "token_count_in": random.randint(80, 400),
            "token_count_out": random.randint(40, 300),
            "policy_result": "DENY" if threat != "BENIGN" else "ALLOW",
            "severity": "high" if threat != "BENIGN" else "low",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_system": "acme_thirdparty_simulator",
        }
        payload = json.dumps(
            {
                "time": int(time.time()),
                "host": "thirdparty-sim",
                "index": index,
                "sourcetype": sourcetype,
                "source": "scripts/emit_thirdparty_telemetry.py",
                "event": event,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={
                "Authorization": f"Splunk {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"event {i + 1}/{count} -> HTTP {resp.status}")
        except Exception as exc:
            print(f"HEC send failed: {exc}", file=sys.stderr)
            sys.exit(1)
        time.sleep(0.2)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    emit(n)
