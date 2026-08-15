#!/usr/bin/env python3
"""One-shot Phase 8 project rename: OrchestraACME → AgentWatch Range (not ACME Bank / acme:*)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "dist", "node_modules", "__pycache__", ".cursor", "agent-transcripts"}
SKIP_FILES = {"phase8_bulk_rename.py", "phase6_bulk_rename.py"}

TEXT_EXT = {
    ".py", ".md", ".yml", ".yaml", ".conf", ".xml", ".json", ".csv", ".sh",
    ".example", ".html", ".txt",
}

# Longest / most specific first. Do NOT touch orchestrator/orchestration tokens.
REPLACEMENTS = [
    ("orchestra_acme_aidefense_hec", "agentwatch_vendorsim_hec"),
    ("orchestra-acme-otel", "agentwatch-otel"),
    ("OrchestraACME DevSecOps", "AgentWatch Range DevSecOps"),
    ("OrchestraACME / AgentWatch Range", "AgentWatch Range"),
    ("OrchestraACME", "AgentWatch Range"),
]


def should_process(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if path.suffix and path.suffix not in TEXT_EXT and path.name not in {
        "Dockerfile.banking", "Dockerfile.attack", "LICENSE", "NOTICE.md",
    }:
        return False
    parts = set(path.parts)
    if parts & SKIP_DIRS:
        return False
    return True


def main() -> None:
    changed = 0
    for path in ROOT.rglob("*"):
        if not path.is_file() or not should_process(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        original = text
        for old, new in REPLACEMENTS:
            text = text.replace(old, new)
        if text != original:
            path.write_text(text, encoding="utf-8")
            changed += 1
            print(f"updated: {path.relative_to(ROOT)}")
    print(f"\nPhase 8 rename complete — {changed} files updated.")


if __name__ == "__main__":
    main()
