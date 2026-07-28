#!/usr/bin/env bash
# =============================================================================
# OrchestraACME — Install GenAI Compliance Splunk app into local Docker Splunk
# Delegates to splunk_install_apps.sh (MLTK + compliance).
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${ROOT}/scripts/splunk_install_apps.sh" "$@"
