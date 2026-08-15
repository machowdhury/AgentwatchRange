#!/bin/sh
# =============================================================================
# AgentWatch Range — In-network Splunk HEC bootstrap (runs inside Docker Compose)
# Enables HEC, creates index + token to match .env, verifies ingest on :8088.
# =============================================================================
set -eu

SPLUNK_HOST="${SPLUNK_HOST:-splunk}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-ACMEPassword2026!}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-acme-hec-token-0000-1111-2222-3333}"
HEC_INDEX="${SPLUNK_HEC_INDEX:-acme_agentic_telemetry}"
SIM_INDEX="${SPLUNK_SIM_INDEX:-security}"
HEC_SOURCETYPE="${SPLUNK_HEC_SOURCETYPE:-otel:agentic:json}"
HEC_INPUT_NAME="${SPLUNK_HEC_INPUT_NAME:-agentwatch-otel}"
AUTH="admin:${SPLUNK_PASSWORD}"
MGMT_URL="https://${SPLUNK_HOST}:8089"
HEC_URL_HTTP="http://${SPLUNK_HOST}:8088/services/collector/event"
HEC_URL_HTTPS="https://${SPLUNK_HOST}:8088/services/collector/event"
TMP_BODY="/tmp/hec_init_body.txt"

log() { printf '[hec-init] %s\n' "$*"; }

mgmt_request() {
  method="$1"
  path="$2"
  shift 2
  curl -sk -u "$AUTH" -X "$method" "${MGMT_URL}${path}" "$@" 2>/dev/null || true
}

mgmt_code() {
  method="$1"
  path="$2"
  shift 2
  mgmt_request "$method" "$path" -o /dev/null -w "%{http_code}" "$@" | tail -c 3
}

wait_for_mgmt_api() {
  log "Waiting for Splunk management API (${SPLUNK_HOST}:8089)..."
  i=1
  while [ "$i" -le 90 ]; do
    code="$(mgmt_code GET "/services/server/info")"
    if [ "$code" = "200" ]; then
      log "Splunk management API is up."
      return 0
    fi
    if [ "$code" = "401" ]; then
      log "ERROR: Splunk returned HTTP 401 — SPLUNK_PASSWORD in .env does not match this Splunk volume."
      log "       Fix: ./scripts/splunk_reset_admin_password.sh  OR  reset Splunk volume."
      return 1
    fi
    i=$((i + 1))
    sleep 5
  done
  log "ERROR: Splunk management API not ready after 7.5 minutes."
  return 1
}

ensure_index() {
  idx="$1"
  log "Ensuring index '${idx}' exists..."
  index_code="$(mgmt_code GET "/services/data/indexes/${idx}")"
  if [ "$index_code" = "200" ]; then
    log "Index '${idx}' already exists."
    return 0
  fi
  create_code="$(mgmt_code POST "/services/data/indexes" -d "name=${idx}" -d "datatype=event")"
  if [ "$create_code" = "200" ] || [ "$create_code" = "201" ]; then
    log "Index '${idx}' created."
    return 0
  fi
  log "ERROR: failed to create index '${idx}' (HTTP ${create_code})"
  mgmt_request GET "/services/data/indexes" -d "output_mode=json" | head -c 500 || true
  return 1
}

wait_after_restart() {
  i=1
  while [ "$i" -le 60 ]; do
    code="$(mgmt_code GET "/services/server/info")"
    if [ "$code" = "200" ]; then
      log "Splunk management API is back after restart."
      return 0
    fi
    i=$((i + 1))
    sleep 5
  done
  log "ERROR: Splunk did not come back after restart."
  return 1
}

test_hec_url() {
  url="$1"
  curl -s -o "${TMP_BODY}" -w "%{http_code}" \
    "${url}" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d "{\"event\":{\"hec_init\":true,\"sourcetype\":\"${HEC_SOURCETYPE}\"}}" 2>/dev/null || echo "000"
}

wait_for_mgmt_api || exit 1

# Splunk UI health can pass before inputs/HEC modules are ready.
sleep 10

log "Enabling HTTP Event Collector..."
hec_code="$(mgmt_code POST "/services/data/inputs/http/http/enable")"
if [ "$hec_code" = "200" ] || [ "$hec_code" = "201" ]; then
  log "HEC enabled."
else
  log "HEC enable returned HTTP ${hec_code} (may already be enabled)."
fi

log "Disabling HEC SSL (OTel uses plain HTTP inside Docker mesh)..."
ssl_code="$(mgmt_code POST "/services/data/inputs/http/http" -d "enableSSL=0")"
if [ "$ssl_code" = "200" ] || [ "$ssl_code" = "201" ]; then
  log "HEC SSL disabled — restarting splunkd to apply..."
  restart_code="$(mgmt_code POST "/services/admin/server/control/restart_splunkd")"
  if [ "$restart_code" = "200" ] || [ "$restart_code" = "201" ]; then
    sleep 20
    wait_after_restart || exit 1
    mgmt_code POST "/services/data/inputs/http/http/enable" >/dev/null || true
    sleep 5
  else
    log "WARN: splunkd restart returned HTTP ${restart_code}; continuing."
  fi
else
  log "HEC enableSSL=0 returned HTTP ${ssl_code} (may already be set)."
fi

# Splunk Docker image may already have created HEC from SPLUNK_HEC_TOKEN — ensure indexes first.
ensure_index "${HEC_INDEX}" || exit 1
ensure_index "${SIM_INDEX}" || exit 1

log "Checking if HEC already accepts events (Splunk image auto-config)..."
early_code="$(test_hec_url "${HEC_URL_HTTP}")"
if [ "$early_code" = "200" ]; then
  log "PASS — HEC already working (HTTP 200). Ensuring token allows ${HEC_INDEX} and ${SIM_INDEX}..."
  mgmt_request POST "/services/data/inputs/http/${HEC_INPUT_NAME}" \
    -d "index=${HEC_INDEX}" \
    -d "indexes=${HEC_INDEX},${SIM_INDEX}" >/dev/null 2>&1 || true
  log "Indexes ${HEC_INDEX} and ${SIM_INDEX} ensured."
  exit 0
fi
log "HEC not ready yet (HTTP ${early_code}); continuing bootstrap..."

log "Configuring HEC token input '${HEC_INPUT_NAME}'..."
for delete_name in "${HEC_INPUT_NAME}" "http%3A%2F%2F${HEC_INPUT_NAME}"; do
  delete_code="$(mgmt_code DELETE "/services/data/inputs/http/${delete_name}")"
  if [ "$delete_code" = "200" ]; then
    log "Removed previous HEC input (${delete_name})."
  fi
done

token_code="$(mgmt_code POST "/services/data/inputs/http" \
  -d "name=${HEC_INPUT_NAME}" \
  -d "token=${HEC_TOKEN}" \
  -d "index=${HEC_INDEX}" \
  -d "indexes=${HEC_INDEX},${SIM_INDEX}" \
  -d "sourcetype=${HEC_SOURCETYPE}" \
  -d "disabled=0")"
if [ "$token_code" = "200" ] || [ "$token_code" = "201" ]; then
  log "HEC token configured."
else
  log "WARN: HEC token create returned HTTP ${token_code}; checking existing inputs..."
  if mgmt_request GET "/services/data/inputs/http" | grep -q "${HEC_TOKEN}"; then
    log "Found existing HEC token in Splunk — continuing."
  else
    log "ERROR: no matching HEC token in Splunk."
    mgmt_request GET "/services/data/inputs/http" -d "output_mode=json" | head -c 800 || true
    exit 1
  fi
fi

log "Testing HEC ingest..."
test_code="000"
attempt=1
while [ "$attempt" -le 20 ]; do
  test_code="$(test_hec_url "${HEC_URL_HTTP}")"
  if [ "$test_code" = "200" ]; then
    log "PASS — HEC HTTP returned 200 (attempt ${attempt})."
    log "Splunk HEC bootstrap complete."
    exit 0
  fi
  log "HEC HTTP attempt ${attempt}/20 returned HTTP ${test_code}; retrying in 5s..."
  attempt=$((attempt + 1))
  sleep 5
done

log "WARN: HEC HTTP failed (last HTTP ${test_code}). Trying HTTPS..."
cat "${TMP_BODY}" 2>/dev/null || true
https_code="$(test_hec_url "${HEC_URL_HTTPS}")"
if [ "$https_code" = "200" ]; then
  log "PASS on HTTPS but not HTTP — HEC SSL is still enabled on this Splunk volume."
  log "Run from host: ./scripts/splunk_local_bootstrap.sh"
  log "Or set SPLUNK_HEC_ENDPOINT=https://splunk:8088/services/collector/event in .env and recreate otel_collector."
  exit 1
fi

log "ERROR: HEC test failed (HTTP ${test_code}, HTTPS ${https_code})."
log "Run from host: ./scripts/splunk_local_bootstrap.sh"
log "Then: docker compose restart otel_collector"
cat "${TMP_BODY}" 2>/dev/null || true
exit 1
