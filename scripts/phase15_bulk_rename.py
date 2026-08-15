#!/usr/bin/env python3
"""One-shot Phase 15 string replacements (legacy telemetry id → sim)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPLACEMENTS_FILE = Path(__file__).resolve().parent / "phase15_replacements.txt"
SKIP_DIRS = {".git", "dist", "node_modules", "__pycache__", ".cursor", "agent-transcripts"}
SKIP_FILES = {
    "phase15_bulk_rename.py",
    "phase15_replacements.txt",
    "phase8_bulk_rename.py",
    "phase6_bulk_rename.py",
}
TEXT_EXT = {
    ".py", ".md", ".yml", ".yaml", ".conf", ".xml", ".json", ".csv", ".sh",
    ".example", ".html", ".txt",
}


def _load_replacements() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for line in REPLACEMENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        old, new = line.split("|||", 1)
        pairs.append((old, new))
    return pairs


def should_process(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if path.suffix and path.suffix not in TEXT_EXT and path.name not in {
        "Dockerfile.banking", "Dockerfile.attack", "LICENSE", "NOTICE.md",
    }:
        return False
    if "agent-tools" in path.parts or "agent-transcripts" in path.parts:
        return False
    parts = set(path.parts)
    if parts & SKIP_DIRS:
        return False
    return True


def main() -> None:
    replacements = _load_replacements()
    changed = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if not should_process(path):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            original = text
            for old, new in replacements:
                text = text.replace(old, new)
            if text != original:
                path.write_text(text, encoding="utf-8")
                changed += 1
                print(f"updated: {path.relative_to(ROOT)}")
    print(f"\nPhase 15 rename complete — {changed} files updated.")


if __name__ == "__main__":
    main()
