#!/usr/bin/env python3
"""One-shot Phase 6.1 string replacements (CodeGuard/DefenseClaw → AcmeGate/AcmeSentinel)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "dist", "node_modules", "__pycache__", ".cursor"}
SKIP_FILES = {"phase6_bulk_rename.py", "109393c2-24fd-42f7-a81c-06dd758fe538.txt"}
TEXT_EXT = {
    ".py", ".md", ".yml", ".yaml", ".conf", ".xml", ".json", ".csv", ".sh",
    ".example", ".html", ".txt", ".yaml",
}

# Order matters: longest / most specific first.
REPLACEMENTS = [
    ("defenseclaw.action", "acme_output_guard.action"),
    ("defenseclaw.rule_id", "acme_output_guard.rule_id"),
    ("defenseclaw.pattern", "acme_output_guard.pattern"),
    ("defenseclaw.matched_text", "acme_output_guard.matched_text"),
    ("defenseclaw.agent_id", "acme_output_guard.agent_id"),
    ("framework.defenseclaw_action", "framework.acme_output_guard_action"),
    ("defenseclaw_rule_id", "acme_output_guard_rule_id"),
    ("defenseclaw_action", "acme_output_guard_action"),
    ("defenseclaw_blocked", "acme_output_guard_blocked"),
    ("defenseclaw-gateway", "acmesentinel-gateway"),
    ("defenseclaw_inspect_output", "acmesentinel_inspect_output"),
    ("DEFENSECLAW_DENY_PATTERNS", "ACMESENTINEL_DENY_PATTERNS"),
    ("DEFENSECLAW_COMPILED", "ACMESENTINEL_COMPILED"),
    ("DEFENSECLAW_HARD_DENY", "ACME_OUTPUT_GUARD_HARD_DENY"),
    ("DEFENSECLAW_ENABLED", "ACME_OUTPUT_GUARD_ENABLED"),
    ("DefenseClawViolation", "AcmeSentinelViolation"),
    ("skip_defenseclaw", "skip_acmesentinel"),
    ("codeguard.rule_id", "acme_input_guard.rule_id"),
    ("codeguard.rule_name", "acme_input_guard.rule_name"),
    ("codeguard.field", "acme_input_guard.field"),
    ("codeguard.pattern", "acme_input_guard.pattern"),
    ("codeguard.status", "acme_input_guard.status"),
    ("codeguard_validate_input", "acmegate_validate_input"),
    ("CODEGUARD_FORBIDDEN_INPUT_PATTERNS", "ACMEGATE_FORBIDDEN_INPUT_PATTERNS"),
    ("CODEGUARD_COMPILED", "ACMEGATE_COMPILED"),
    ("CODEGUARD_RULE_BREACH", "ACME_INPUT_GUARD_RULE_BREACH"),
    ("CODEGUARD_ENABLED", "ACME_INPUT_GUARD_ENABLED"),
    ("CodeGuardViolation", "AcmeGateViolation"),
    ("codeguard_blocked", "acme_input_guard_blocked"),
    ("/var/log/defenseclaw", "/var/log/acme_sentinel"),
    ("acme_defenseclaw_action", "acme_output_guard_action"),
    ("splunk_defenseclaw_action", "splunk_acme_output_guard_action"),
    ("CTRL-W3-CODEGUARD", "CTRL-W3-ACMEGATE"),
    ("CTRL-W5-DEFENSECLAW", "CTRL-W5-ACMESENTINEL"),
    ("CODEGUARD_SBD_VIOLATION", "ACMEGATE_SBD_VIOLATION"),
    # Display names (after field renames)
    ("[DEFENSECLAW HARD_DENY]", "[ACMESENTINEL HARD_DENY]"),
    ("[CODEGUARD BLOCKED]", "[ACMEGATE BLOCKED]"),
    ("DefenseClaw HARD_DENY", "AcmeSentinel HARD_DENY"),
    ("DefenseClaw detects", "AcmeSentinel detects"),
    ("CodeGuard detects", "AcmeGate detects"),
    ("Cisco DefenseClaw Gateway", "AcmeSentinel output gateway"),
    ("Project CodeGuard input validation", "AcmeGate input validation"),
    ("DEFENSECLAW GATEWAY", "ACMESENTINEL GATEWAY"),
    ("CodeGuard:", "AcmeGate:"),
    ("DefenseClaw:", "AcmeSentinel:"),
    ("| CodeGuard", "| AcmeGate"),
    ("| DefenseClaw", "| AcmeSentinel"),
    ("**CodeGuard**", "**AcmeGate**"),
    ("**DefenseClaw**", "**AcmeSentinel**"),
    ("CodeGuard Breach", "AcmeGate Breach"),
    ("CodeGuard pre-LLM", "AcmeGate pre-LLM"),
    ("DefenseClaw pre-LLM", "AcmeSentinel pre-LLM"),
    ('"defenseclaw"', '"acme_output_guard"'),
    ('"codeguard"', '"acme_input_guard"'),
    ("defenseclaw ", "acme_output_guard "),
    ("codeguard ", "acme_input_guard "),
    ("DefenseClaw ", "AcmeSentinel "),
    ("CodeGuard ", "AcmeGate "),
]


def should_process(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if path.suffix and path.suffix not in TEXT_EXT and path.name not in (".env.example",):
        return False
    if "agent-tools" in path.parts or "agent-transcripts" in path.parts:
        return False
    return True


def main() -> None:
    changed = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if not should_process(path):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, IsADirectoryError):
                continue
            original = text
            for old, new in REPLACEMENTS:
                text = text.replace(old, new)
            if text != original:
                path.write_text(text, encoding="utf-8")
                changed += 1
                print(f"updated {path.relative_to(ROOT)}")
    print(f"Done — {changed} files updated")


if __name__ == "__main__":
    main()
