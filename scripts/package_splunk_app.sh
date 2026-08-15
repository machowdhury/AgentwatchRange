#!/usr/bin/env bash
# =============================================================================
# AgentWatch Range — Splunk App Packaging Script
# Builds an installable .tar.gz for Splunk Cloud and Splunk Enterprise.
#
# Usage:
#   ./scripts/package_splunk_app.sh
#
# Output:
#   dist/acme_genai_compliance-<VERSION>.tar.gz  (VERSION set below)
#
# Install on Splunk Cloud:
#   Apps → Browse more apps → Upload app → select the printed .tar.gz filename
#
# Install on Splunk Enterprise:
#   splunk install app dist/acme_genai_compliance-<VERSION>.tar.gz
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${ROOT_DIR}/splunk_app/splunk_compliance_app"
DIST_DIR="${ROOT_DIR}/dist"
APP_ID="acme_genai_compliance"
VERSION="2.10.1"
PACKAGE_NAME="${APP_ID}-${VERSION}"
STAGING_DIR="$(mktemp -d)"
TARGET_DIR="${STAGING_DIR}/${APP_ID}"

if [[ ! -d "${SRC_DIR}" ]]; then
  echo "ERROR: Source app not found at ${SRC_DIR}" >&2
  exit 1
fi

echo "[package] Syncing technique playbook lookups from taxonomy..."
python3 "${ROOT_DIR}/scripts/sync_splunk_lookups.py"
python3 "${ROOT_DIR}/scripts/sync_exercise_content.py"
python3 "${ROOT_DIR}/scripts/sync_exercise_runner_dashboard.py"

echo "[package] Staging ${APP_ID} v${VERSION}..."
mkdir -p "${TARGET_DIR}"
rsync -a \
  --exclude '.DS_Store' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "${SRC_DIR}/" "${TARGET_DIR}/"

mkdir -p "${DIST_DIR}"
# Remove stale packages so install scripts never pick an old tarball.
rm -f "${DIST_DIR}/${APP_ID}-"*.tar.gz
OUTPUT="${DIST_DIR}/${PACKAGE_NAME}.tar.gz"

echo "[package] Creating ${OUTPUT}..."
tar -czf "${OUTPUT}" -C "${STAGING_DIR}" "${APP_ID}"

rm -rf "${STAGING_DIR}"

echo "${OUTPUT}" > "${DIST_DIR}/.last_package"

echo "[package] Done."
echo ""
echo "  Installable package: ${OUTPUT}"
echo "  App folder name:     ${APP_ID}"
echo ""
echo "  Splunk Cloud:  Apps → Upload app → ${PACKAGE_NAME}.tar.gz"
echo "  Enterprise:    splunk install app ${OUTPUT}"
echo "  Local Docker:  ./scripts/splunk_install_app.sh"
