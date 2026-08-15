#!/usr/bin/env python3
"""
Standalone benign traffic generator (Phase 10.1).

Posts real loan requests to the banking app API so events flow through
llm_client → AcmeGate/AcmeSentinel → OTel → Splunk (testbed_mode=BASELINE_TRAFFIC).

Use when TRAFFIC_SIM_ENABLED=false on banking_app but you still want ambient noise,
or to run baseline from a separate container/process.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

BANKING_URL = os.environ.get("BANKING_APP_URL", "http://localhost:5000").rstrip("/")

_REQUESTS = [
    "Hi, I'm {name}. I'd like a home loan of ${amount:,}. Income ${income:,}/year, credit ~{score}.",
    "Hello — {name} here. Auto loan request ${amount:,}, employed as {job} in {city}.",
    "Refinance inquiry: balance ${amount:,}, property value ${value:,}. Applicant {name}.",
    "Eligibility check for a ${amount:,} LOC for renovations. {name}, income ${income:,}.",
]

_NAMES = ("Aisha", "Carlos", "Diane", "Ethan", "Julia", "Marcus", "Priya")
_JOBS = ("engineer", "nurse", "teacher", "accountant")
_CITIES = ("Toronto", "Vancouver", "Calgary", "Ottawa")


def _sample() -> str:
    tpl = random.choice(_REQUESTS)
    return tpl.format(
        name=random.choice(_NAMES),
        amount=random.randint(20_000, 500_000),
        income=random.randint(50_000, 160_000),
        score=random.randint(680, 810),
        job=random.choice(_JOBS),
        city=random.choice(_CITIES),
        value=random.randint(300_000, 900_000),
    )


def post_process(text: str, full_pipeline: bool = False) -> dict:
    if full_pipeline:
        url = f"{BANKING_URL}/api/v1/process"
        body = {"input": text}
    else:
        url = f"{BANKING_URL}/api/v1/traffic/tick"
        body = {"full_pipeline": full_pipeline}
        if not full_pipeline:
            # traffic/tick generates its own request; optional override unused
            pass
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data if full_pipeline else b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_healthy(timeout_sec: int = 300) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"{BANKING_URL}/health")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("ollama_reachable"):
                    return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(5)
    print("Banking app / Ollama not healthy in time", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benign baseline traffic generator")
    parser.add_argument("--once", action="store_true", help="Single tick then exit")
    parser.add_argument("--interval-min", type=int, default=int(os.environ.get("BASELINE_INTERVAL_MIN_SEC", "90")))
    parser.add_argument("--interval-max", type=int, default=int(os.environ.get("BASELINE_INTERVAL_MAX_SEC", "240")))
    parser.add_argument("--pipeline-ratio", type=float, default=float(os.environ.get("BASELINE_PIPELINE_RATIO", "0.2")))
    parser.add_argument("--no-wait", action="store_true")
    args = parser.parse_args()

    if not args.no_wait:
        wait_healthy()

    lo, hi = min(args.interval_min, args.interval_max), max(args.interval_min, args.interval_max)

    def tick() -> None:
        use_pipeline = random.random() < args.pipeline_ratio
        try:
            if use_pipeline:
                result = post_process(_sample(), full_pipeline=True)
                print(f"pipeline ok blocked={result.get('pipeline_blocked')}")
            else:
                result = post_process("", full_pipeline=False)
                print(f"tick ok mode={result.get('mode')} blocked={result.get('blocked', result.get('pipeline_blocked'))}")
        except Exception as exc:
            print(f"tick failed: {exc}", file=sys.stderr)

    tick()
    if args.once:
        return

    while True:
        time.sleep(random.randint(lo, hi))
        tick()


if __name__ == "__main__":
    main()
