#!/usr/bin/env python3
"""Run Phase 10.2–10.3 baseline HEC loop (sim + thirdparty + registry)."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from framework.baseline_hec_emitter import emit_all, run_loop  # noqa: E402


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        print(emit_all())
        return
    run_loop(
        interval_min_sec=int(os.environ.get("BASELINE_HEC_INTERVAL_MIN_SEC", "120")),
        interval_max_sec=int(os.environ.get("BASELINE_HEC_INTERVAL_MAX_SEC", "300")),
        registry_every_n=int(os.environ.get("BASELINE_REGISTRY_EVERY_N", "5")),
    )


if __name__ == "__main__":
    main()
