#!/usr/bin/env bash
# =============================================================================
# AgentWatch Range — Reset local Docker Splunk admin password to match .env
# Use when .env was lost or you cannot log in to Splunk Web.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "[reset-password] .env missing — creating from .env.example..."
  ./scripts/restore_env.sh
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-ACMEPassword2026!}"
SPLUNK_CONTAINER="${SPLUNK_CONTAINER:-acme_splunk}"

echo "[reset-password] Waiting for Splunk (${SPLUNK_CONTAINER})..."
for i in $(seq 1 60); do
  if docker exec "$SPLUNK_CONTAINER" curl -sf "http://localhost:8000/en-US/account/login" >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "[reset-password] ERROR: Splunk Web not responding. Check: docker compose logs splunk" >&2
    exit 1
  fi
  sleep 5
done

echo "[reset-password] Setting admin password to value from .env (SPLUNK_PASSWORD)..."
if docker exec -u splunk "$SPLUNK_CONTAINER" /opt/splunk/bin/splunk cmd splunkd rest \
    --noauth POST /services/authentication/users/admin \
    -d "password=${SPLUNK_PASSWORD}" 2>/dev/null; then
  echo "[reset-password] Done."
else
  echo "[reset-password] REST reset failed — trying splunk edit user..."
  # May work if you still know the old password; otherwise recreate container
  if docker exec -u splunk "$SPLUNK_CONTAINER" /opt/splunk/bin/splunk edit user admin \
      -password "$SPLUNK_PASSWORD" -auth "admin:${SPLUNK_PASSWORD}" 2>/dev/null; then
    echo "[reset-password] Done."
  else
    echo "[reset-password] ERROR: could not reset password automatically."
    echo ""
    echo "  Nuclear option (keeps other containers; recreates Splunk only):"
    echo "    docker compose --profile local stop splunk"
    echo "    docker rm -f acme_splunk"
    echo "    docker compose --profile local up -d splunk"
    echo "    # wait 5 min — password will be SPLUNK_PASSWORD from .env"
    echo "    ./scripts/splunk_local_bootstrap.sh"
    echo "    ./scripts/splunk_install_app.sh"
    exit 1
  fi
fi

echo ""
echo "[reset-password] Login at http://localhost:8000"
echo "  username: admin"
echo "  password: ${SPLUNK_PASSWORD}"
