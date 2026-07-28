#!/bin/sh
# =============================================================================
# OrchestraACME — In-network Splunk HEC bootstrap (runs inside Docker Compose)
# Enables HEC, creates index + token to match .env, verifies ingest on :8088.
# =============================================================================
set -eu

SPLUNK_HOST="${SPLUNK_HOST:-splunk}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-ACMEPassword2026!}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-acme-hec-token-0000-1111-2222-3333}"
HEC_INDEX="${SPLUNK_HEC_INDEX:-acme_agentic_telemetry}"
HEC_SOURCETYPE="${SPLUNK_HEC_SOURCETYPE:-otel:agentic:json}"
HEC_INPUT_NAME="${SPLUNK_HEC_INPUT_NAME:-orchestra-acme-otel}"
AUTH="admin:${SPLUNK_PASSWORD}"
MGMT_URL="https://${SPLUNK_HOST}:8089"
HEC_URL="http://${SPLUNK_HOST}:8088/services/collector/event"

log() { printf '[hec-init] %s\n' "$*"; }

mgmt_code() {
  method="$1"
  path="$2"
  shift 2
  curl -sk -o /dev/null -w "%{http_code}" -u "$AUTH" -X "$method" "${MGMT_URL}${path}" "$@" || echo "000"
}

log "Waiting for Splunk management API (${SPLUNK_HOST}:8089)..."
ready=0
i=1
while [ "$i" -le 60 ]; do
  code="$(mgmt_code GET "/services/server/info")"
  if [ "$code" = "200" ]; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 5
done
if [ "$ready" -ne 1 ]; then
  log "ERROR: Splunk management API not ready after 5 minutes."
  exit 1
fi
log "Splunk management API is up."

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
  log "HEC SSL disabled."
else
  log "HEC enableSSL=0 returned HTTP ${ssl_code} (may already be set)."
fi
sleep 3

log "Ensuring index '${HEC_INDEX}' exists..."
index_code="$(mgmt_code GET "/services/data/indexes/${HEC_INDEX}")"
if [ "$index_code" = "200" ]; then
  log "Index already exists."
else
  create_code="$(mgmt_code POST "/services/data/indexes" -d "name=${HEC_INDEX}" -d "datatype=event")"
  if [ "$create_code" = "200" ] || [ "$create_code" = "201" ]; then
    log "Index created."
  else
    log "ERROR: failed to create index (HTTP ${create_code})"
    exit 1
  fi
fi

log "Configuring HEC token input '${HEC_INPUT_NAME}'..."
delete_code="$(mgmt_code DELETE "/services/data/inputs/http/${HEC_INPUT_NAME}")"
if [ "$delete_code" = "200" ]; then
  log "Removed previous HEC input."
fi

token_code="$(mgmt_code POST "/services/data/inputs/http" \
  -d "name=${HEC_INPUT_NAME}" \
  -d "token=${HEC_TOKEN}" \
  -d "index=${HEC_INDEX}" \
  -d "sourcetype=${HEC_SOURCETYPE}" \
  -d "disabled=0")"
if [ "$token_code" = "200" ] || [ "$token_code" = "201" ]; then
  log "HEC token configured."
else
  log "WARN: HEC token create returned HTTP ${token_code}; checking existing inputs..."
  if curl -sk -u "$AUTH" "${MGMT_URL}/services/data/inputs/http" | grep -q "${HEC_TOKEN}"; then
    log "Found existing token — continuing."
  else
    log "ERROR: no matching HEC token in Splunk."
    exit 1
  fi
fi

log "Testing HEC ingest on ${HEC_URL}..."
test_code="000"
attempt=1
while [ "$attempt" -le 15 ]; do
  test_code="$(curl -s -o /tmp/hec_test.json -w "%{http_code}" \
    "${HEC_URL}" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d "{\"event\":{\"hec_init\":true,\"sourcetype\":\"${HEC_SOURCETYPE}\"}}" || echo "000")"
  if [ "$test_code" = "200" ]; then
    log "PASS — HEC returned HTTP 200 (attempt ${attempt})."
    break
  fi
  log "HEC test attempt ${attempt}/15 returned HTTP ${test_code}; retrying in 4s..."
  attempt=$((attempt + 1))
  sleep 4
done
if [ "$test_code" != "200" ]; then
  log "ERROR: HEC test failed after retries (last HTTP ${test_code})"
  cat /tmp/hec_test.json 2>/dev/null || true
  exit 1
fi

log "Splunk HEC bootstrap complete."
