#!/usr/bin/env bash
# =============================================================================
# AgentWatch Range — Restore .env from .env.example if missing
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  echo "[restore-env] .env already exists — not overwriting."
  echo "  To reset: mv .env .env.bak && $0"
  exit 0
fi

if [[ ! -f .env.example ]]; then
  echo "[restore-env] ERROR: .env.example not found" >&2
  exit 1
fi

cp .env.example .env
echo "[restore-env] Created .env from .env.example"
echo ""
echo "  Splunk Web default login:"
echo "    username: admin"
echo "    password: ACMEPassword2026!  (unless you changed SPLUNK_PASSWORD before)"
echo ""
echo "  If login still fails, run: ./scripts/splunk_reset_admin_password.sh"
