#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

git config core.hooksPath scripts/git-hooks
chmod +x scripts/git-hooks/prepare-commit-msg

echo "Git hooks enabled: core.hooksPath=scripts/git-hooks"
echo "Commit-msg hook will strip unwanted co-author trailers."
