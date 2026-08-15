#!/usr/bin/env bash
# =============================================================================
# AgentWatch Range — Splunk App Cloud / Enterprise Validation
# Checks packaging requirements aligned with Splunk Cloud vetting:
# https://dev.splunk.com/enterprise/docs/releaseapps/cloudvetting/
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="${ROOT_DIR}/splunk_app/splunk_compliance_app"
APP_ID="acme_genai_compliance"
ERRORS=0

fail() { echo "FAIL: $1" >&2; ERRORS=$((ERRORS + 1)); }
pass() { echo "OK:   $1"; }

echo "=== Splunk App Validation: ${APP_ID} ==="
echo ""

# 1. Package ID must match directory name used in tarball
PKG_ID="$(grep -E '^id\s*=' "${APP_DIR}/default/app.conf" | head -1 | awk -F= '{print $2}' | tr -d ' ')"
[[ "${PKG_ID}" == "${APP_ID}" ]] && pass "package id matches folder name (${APP_ID})" || fail "package id '${PKG_ID}' != '${APP_ID}'"

# 2. No bin/ scripts (Cloud vetting: no unmanaged custom commands)
if [[ -d "${APP_DIR}/bin" ]]; then
  fail "bin/ directory present — remove for Splunk Cloud private apps unless AppInspect-approved"
else
  pass "no bin/ directory (SPL + lookups only)"
fi

# 3. No local/ in source package
if [[ -d "${APP_DIR}/local" ]]; then
  fail "local/ directory must not ship in installable package"
else
  pass "no local/ directory in source"
fi

# 4. Required config files
for f in default/app.conf default/macros.conf default/props.conf default/transforms.conf metadata/default.meta; do
  [[ -f "${APP_DIR}/${f}" ]] && pass "found ${f}" || fail "missing ${f}"
done

# 5. Lookup transforms reference existing CSV files
while IFS= read -r line; do
  csv="${line#filename = }"
  [[ -f "${APP_DIR}/lookups/${csv}" ]] && pass "lookup file exists: ${csv}" || fail "missing lookup CSV: ${csv}"
done < <(grep -E '^filename = ' "${APP_DIR}/default/transforms.conf")

# 6. No KV store in transforms (requires collections.conf on Cloud)
if grep -q 'type = kv' "${APP_DIR}/default/transforms.conf" 2>/dev/null; then
  fail "KV store transform found — use collections.conf or remove for Cloud"
else
  pass "no KV store transforms in transforms.conf"
fi

# 7. Macro uses customer-editable index (not _internal)
if grep -q '_internal' "${APP_DIR}/default/macros.conf"; then
  fail "macros.conf references _internal index"
else
  pass "macros do not reference _internal"
fi

# 8. Saved searches ship disabled by default (Cloud best practice)
ENABLED_UNDISABLED="$(awk '/^\[/ {stanza=$0} /enableSched = 1/ {es=1} /disabled = 1/ {dis=1} /^\[/ && stanza!="" {if(es && !dis) print stanza; es=0; dis=0}' "${APP_DIR}/default/savedsearches.conf" | wc -l | tr -d ' ')"
if [[ "${ENABLED_UNDISABLED}" -gt 0 ]]; then
  fail "scheduled saved searches missing disabled=1 (Cloud: ship alerts off by default)"
else
  pass "all scheduled saved searches have disabled=1"
fi

# 9. Dashboard XML well-formed (basic check)
for xml in "${APP_DIR}"/default/data/ui/views/*.xml; do
  if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "${xml}" 2>/dev/null && pass "valid XML: $(basename "${xml}")" || fail "invalid XML: $(basename "${xml}")"
  else
    pass "XML check skipped (xmllint not installed): $(basename "${xml}")"
  fi
done

# 10. Version consistency
APP_VER="$(grep '^version' "${APP_DIR}/default/app.conf" | awk -F= '{print $2}' | tr -d ' ')"
PKG_VER="$(grep '^VERSION=' "${ROOT_DIR}/scripts/package_splunk_app.sh" | head -1 | cut -d'"' -f2)"
[[ "${APP_VER}" == "${PKG_VER}" ]] && pass "version ${APP_VER} matches package script" || fail "version mismatch app.conf=${APP_VER} package=${PKG_VER}"

# 11. Splunk UI Design System — color & theme (https://splunkui.splunk.com/DesignSystem/Accessibility/Color)
VIEWS_DIR="${APP_DIR}/default/data/ui/views"
if grep -rq 'theme="dark"' "${VIEWS_DIR}" 2>/dev/null; then
  fail 'forced theme="dark" on dashboard — omit theme to use Splunk UI tokens'
else
  pass "dashboards use Splunk UI theme (no forced dark)"
fi

BANNED_COLORS='00ff9d|00b4ff|7986cb|546e7a|4fc3f7|81c784|90caf9|0b1120|ffb74d'
if grep -rEi "${BANNED_COLORS}" "${VIEWS_DIR}" 2>/dev/null | grep -q .; then
  fail "non-Splunk palette hex found in dashboards (see splunk_app/DESIGN_SYSTEM.md)"
else
  pass "no banned custom palette colors in dashboards"
fi

if grep -rE 'style="[^"]*(color|background):#' "${VIEWS_DIR}" 2>/dev/null | grep -q .; then
  fail "inline HTML color/background styles — use Splunk theme inheritance"
else
  pass "HTML panels avoid inline color/background styles"
fi

# Phase 8 — OrchestraACME project rename (allowed legacy strings: README migration note, GitHub slug, clone folder)
PHASE8_HITS="$(rg -i 'orchestraacme|orchestra-acme|orchestra_acme' \
  --glob '!scripts/phase8_bulk_rename.py' \
  --glob '!README.md' \
  --glob '!prevbuild/**' \
  "${ROOT_DIR}" 2>/dev/null | rg -v 'github.com/machowdhury/OrchestraACME|cd OrchestraACME' || true)"
if [[ -n "${PHASE8_HITS}" ]]; then
  echo "${PHASE8_HITS}"
  fail "Phase 8 rename incomplete — unexpected OrchestraACME/orchestra-acme references"
else
  pass "Phase 8 rename grep clean (except README migration + GitHub slug)"
fi

echo ""
if [[ "${ERRORS}" -gt 0 ]]; then
  echo "=== ${ERRORS} validation error(s) ==="
  exit 1
fi
echo "=== All checks passed — ready for Splunk Enterprise and Splunk Cloud upload ==="
echo "Next: ./scripts/package_splunk_app.sh"
echo "Cloud: request private app install / AppInspect tag:cloud before production"
