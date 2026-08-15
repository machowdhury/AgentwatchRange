#!/usr/bin/env bash
# =============================================================================
# AgentWatch Range — Install Splunk MLTK + GenAI Compliance app (local Docker)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-ACMEPassword2026!}"
SPLUNK_CONTAINER="${SPLUNK_CONTAINER:-acme_splunk}"
COMPLIANCE_APP_ID="${SPLUNK_APP_ID:-acme_genai_compliance}"
MLTK_APP_ID="${SPLUNK_MLTK_APP_ID:-Splunk_ML_Toolkit}"
MLTK_TARBALL="${SPLUNK_MLTK_TARBALL:-splunk_app/splunk-ai-toolkit_600.tgz}"
SPLUNK_BIN="/opt/splunk/bin/splunk"
AUTH="admin:${SPLUNK_PASSWORD}"
APPS_ROOT="/opt/splunk/etc/apps"

install_tarball_app() {
  local tarball="$1"
  local app_id="$2"
  local label="$3"

  if [[ ! -f "$tarball" ]]; then
    echo "[install] SKIP ${label}: tarball not found (${tarball})"
    return 0
  fi

  local staging
  staging="$(mktemp -d)"
  echo "[install] Extracting ${label} from $(basename "$tarball")..."
  tar -xzf "$tarball" -C "$staging"
  if [[ ! -d "${staging}/${app_id}" ]]; then
    echo "[install] ERROR: expected folder '${app_id}/' inside ${tarball}" >&2
    rm -rf "$staging"
    exit 1
  fi

  local dest="${APPS_ROOT}/${app_id}"
  echo "[install] Deploying ${label} to ${dest}..."
  docker exec -u root "$SPLUNK_CONTAINER" rm -rf "${dest}"
  docker cp "${staging}/${app_id}" "${SPLUNK_CONTAINER}:${dest}"
  docker exec -u root "$SPLUNK_CONTAINER" chown -R splunk:splunk "${dest}"
  rm -rf "$staging"
  echo "[install] ${label} deployed."
}

echo "[install] Waiting for Splunk (${SPLUNK_CONTAINER})..."
for i in $(seq 1 60); do
  if docker exec "$SPLUNK_CONTAINER" curl -sfk -u "$AUTH" \
      "https://127.0.0.1:8089/services/server/info" >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "[install] ERROR: Splunk not ready. Check: docker compose logs splunk" >&2
    exit 1
  fi
  sleep 5
done

echo "[install] Repairing Splunk filesystem ownership..."
docker exec -u root "$SPLUNK_CONTAINER" bash -c "
  mkdir -p /opt/splunk/var/run/splunk/bundle_tmp
  mkdir -p /opt/splunk/var/log/splunk /opt/splunk/var/log/introspection
  mkdir -p /opt/splunk/var/log/watchdog /opt/splunk/var/log/client_events
  chown -R splunk:splunk /opt/splunk/etc /opt/splunk/var
"

# 1) MLTK (required for MLTK Anomaly Hunting dashboard)
install_tarball_app "$MLTK_TARBALL" "$MLTK_APP_ID" "Splunk ML Toolkit"

# 2) AgentWatch Range compliance app
COMPLIANCE_TARBALL="${1:-}"
if [[ -z "$COMPLIANCE_TARBALL" ]]; then
  echo "[install] Packaging GenAI Compliance app..."
  ./scripts/package_splunk_app.sh
  if [[ -f dist/.last_package ]]; then
    COMPLIANCE_TARBALL="$(cat dist/.last_package)"
  else
    COMPLIANCE_TARBALL="$(ls -1 dist/acme_genai_compliance-*.tar.gz 2>/dev/null | sort -V | tail -1)"
  fi
fi
echo "[install] Using compliance package: ${COMPLIANCE_TARBALL}"
if [[ ! -f "$COMPLIANCE_TARBALL" ]]; then
  echo "[install] ERROR: compliance tarball not found: ${COMPLIANCE_TARBALL}" >&2
  exit 1
fi
install_tarball_app "$COMPLIANCE_TARBALL" "$COMPLIANCE_APP_ID" "GenAI Compliance Monitor"

echo "[install] Verifying deployed compliance app..."
docker exec "$SPLUNK_CONTAINER" bash -c "
  set -e
  APP='${APPS_ROOT}/${COMPLIANCE_APP_ID}'
  VER=\$(grep -E '^version' \"\${APP}/default/app.conf\" | head -1 | tr -d ' ')
  echo \"  app.conf: \${VER}\"
  if [[ -f \"\${APP}/default/data/ui/views/executive_governance.xml\" ]]; then
    echo '  executive_governance.xml: present'
  else
    echo '  WARNING: executive_governance.xml missing' >&2
  fi
  if grep -q 'layout_tier0' \"\${APP}/default/data/ui/views/exercise_runner.json\" 2>/dev/null; then
    echo '  exercise_runner.json: tabbed (Phase 17.2+)'
  else
    echo '  WARNING: exercise_runner.json looks like pre-17.2 (no tier tabs)' >&2
  fi
"

echo "[install] Restarting Splunk..."
docker exec -u splunk "$SPLUNK_CONTAINER" "$SPLUNK_BIN" restart

echo ""
echo "[install] Done."
echo "  Splunk Web: http://localhost:8000"
echo "  Apps: Splunk ML Toolkit + GenAI Compliance Monitor"
echo "  Login: admin / (password from .env SPLUNK_PASSWORD)"
