#!/usr/bin/env bash
# =============================================================================
# OrchestraACME — One-time local Splunk bootstrap (Docker Pattern A)
# Creates index + HEC token to match .env, fixes shared telemetry volume perms.
# Uses Splunk REST API (curl) — avoids splunk CLI permission issues as root.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Load .env if present
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-ACMEPassword2026!}"
SPLUNK_CONTAINER="${SPLUNK_CONTAINER:-acme_splunk}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-acme-hec-token-0000-1111-2222-3333}"
HEC_INDEX="${SPLUNK_HEC_INDEX:-acme_agentic_telemetry}"
HEC_SOURCETYPE="${SPLUNK_HEC_SOURCETYPE:-otel:agentic:json}"
HEC_INPUT_NAME="${SPLUNK_HEC_INPUT_NAME:-orchestra-acme-otel}"
AUTH="admin:${SPLUNK_PASSWORD}"
MGMT_URL="https://127.0.0.1:8089"

splunk_curl() {
  local method="$1"
  local path="$2"
  shift 2
  docker exec "$SPLUNK_CONTAINER" curl -sk -u "$AUTH" -X "$method" \
    "${MGMT_URL}${path}" "$@"
}

splunk_http_code() {
  local method="$1"
  local path="$2"
  shift 2
  splunk_curl "$method" "$path" -o /dev/null -w "%{http_code}" "$@"
}

echo "[bootstrap] Waiting for Splunk container (${SPLUNK_CONTAINER})..."
for i in $(seq 1 60); do
  code="$(splunk_http_code GET "/services/server/info" 2>/dev/null || echo "000")"
  if [[ "$code" == "200" ]]; then
    echo "[bootstrap] Splunk management API is up."
    break
  fi
  if [[ "$code" == "401" ]]; then
    echo "[bootstrap] ERROR: Splunk returned HTTP 401 — SPLUNK_PASSWORD in .env does not match this Splunk volume."
    echo "[bootstrap] Fix: ./scripts/splunk_reset_admin_password.sh  OR  docker compose down -v (wipes Splunk data)"
    exit 1
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "[bootstrap] ERROR: Splunk not ready after 5 minutes. Check: docker compose logs splunk"
    exit 1
  fi
  sleep 5
done

echo "[bootstrap] Ensuring shared telemetry volume is writable..."
docker exec -u root "$SPLUNK_CONTAINER" sh -c \
  'mkdir -p /var/log/defenseclaw && chmod 1777 /var/log/defenseclaw' || true

echo "[bootstrap] Enabling HTTP Event Collector (global)..."
hec_global_code="$(splunk_http_code POST "/services/data/inputs/http/http/enable" 2>/dev/null || echo "000")"
if [[ "$hec_global_code" == "200" || "$hec_global_code" == "201" ]]; then
  echo "[bootstrap] HEC enabled."
else
  echo "[bootstrap] HEC enable returned HTTP ${hec_global_code} (may already be enabled)."
fi

echo "[bootstrap] Disabling HEC SSL (OTel uses plain HTTP)..."
ssl_code="$(splunk_http_code POST "/services/data/inputs/http/http" -d "enableSSL=0" 2>/dev/null || echo "000")"
if [[ "$ssl_code" == "200" || "$ssl_code" == "201" ]]; then
  echo "[bootstrap] HEC SSL disabled — restarting splunkd to apply..."
  restart_code="$(splunk_http_code POST "/services/admin/server/control/restart_splunkd" 2>/dev/null || echo "000")"
  if [[ "$restart_code" == "200" || "$restart_code" == "201" ]]; then
    sleep 20
    for j in $(seq 1 60); do
      code="$(splunk_http_code GET "/services/server/info" 2>/dev/null || echo "000")"
      if [[ "$code" == "200" ]]; then
        echo "[bootstrap] Splunk management API is back after restart."
        splunk_http_code POST "/services/data/inputs/http/http/enable" >/dev/null 2>&1 || true
        sleep 5
        break
      fi
      if [[ "$j" -eq 60 ]]; then
        echo "[bootstrap] ERROR: Splunk did not come back after restart."
        exit 1
      fi
      sleep 5
    done
  else
    echo "[bootstrap] WARN: splunkd restart returned HTTP ${restart_code}; continuing."
  fi
else
  echo "[bootstrap] enableSSL=0 returned HTTP ${ssl_code} (may already be set)."
fi

echo "[bootstrap] Creating index '${HEC_INDEX}' (if missing)..."
index_code="$(splunk_http_code GET "/services/data/indexes/${HEC_INDEX}" 2>/dev/null || echo "404")"
if [[ "$index_code" == "200" ]]; then
  echo "[bootstrap] Index already exists."
else
  create_code="$(splunk_http_code POST "/services/data/indexes" \
    -d "name=${HEC_INDEX}" -d "datatype=event" 2>/dev/null || echo "000")"
  if [[ "$create_code" == "200" || "$create_code" == "201" ]]; then
    echo "[bootstrap] Index created."
  else
    echo "[bootstrap] ERROR: failed to create index (HTTP ${create_code})"
    splunk_curl POST "/services/data/indexes" -d "name=${HEC_INDEX}" -d "datatype=event" || true
    exit 1
  fi
fi

echo "[bootstrap] Configuring HEC token (input: ${HEC_INPUT_NAME})..."
# Remove stale input with same name so re-runs are idempotent
delete_code="$(splunk_http_code DELETE "/services/data/inputs/http/${HEC_INPUT_NAME}" 2>/dev/null || echo "404")"
if [[ "$delete_code" == "200" ]]; then
  echo "[bootstrap] Removed previous HEC input '${HEC_INPUT_NAME}'."
fi

token_code="$(splunk_http_code POST "/services/data/inputs/http" \
  -d "name=${HEC_INPUT_NAME}" \
  -d "token=${HEC_TOKEN}" \
  -d "index=${HEC_INDEX}" \
  -d "sourcetype=${HEC_SOURCETYPE}" \
  -d "disabled=0" 2>/dev/null || echo "000")"
if [[ "$token_code" == "200" || "$token_code" == "201" ]]; then
  echo "[bootstrap] HEC token configured."
else
  echo "[bootstrap] WARN: HEC token create returned HTTP ${token_code}"
  echo "[bootstrap] Checking for existing token from SPLUNK_HEC_TOKEN env..."
  splunk_curl GET "/services/data/inputs/http" | grep -q "${HEC_TOKEN}" && \
    echo "[bootstrap] Found existing token in Splunk — verify index is ${HEC_INDEX}" || \
    { echo "[bootstrap] ERROR: no matching HEC token"; exit 1; }
fi

echo "[bootstrap] Restarting OTel collector to flush HEC retry queue..."
docker compose restart otel_collector >/dev/null 2>&1 || true

echo ""
echo "[bootstrap] Testing HEC from host..."
HTTP_CODE=$(curl -s -o /tmp/acme_hec_test.json -w "%{http_code}" \
  "http://localhost:8088/services/collector/event" \
  -H "Authorization: Splunk ${HEC_TOKEN}" \
  -d "{\"event\":{\"bootstrap\":true,\"sourcetype\":\"${HEC_SOURCETYPE}\"}}") || HTTP_CODE="000"

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "[bootstrap] PASS — HEC returned HTTP 200"
else
  echo "[bootstrap] WARN — HEC test returned HTTP ${HTTP_CODE} (see /tmp/acme_hec_test.json)"
  echo "          Verify token in Splunk: Settings → Data Inputs → HTTP Event Collector"
fi

echo ""
echo "[bootstrap] Next steps:"
echo "  1. Install Splunk apps: ./scripts/splunk_install_apps.sh"
echo "  2. Splunk Search: index=${HEC_INDEX} earliest=-15m | stats count"
echo "  3. Open http://localhost:8000 (admin / password from .env)"
