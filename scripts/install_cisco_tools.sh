#!/usr/bin/env bash
# Optional: install Cisco AI Defense OSS CLIs on the host (not required for teach mode).
# https://github.com/cisco-ai-defense
set -euo pipefail

echo "=== AgentWatch Range — optional Cisco AI Defense tools ==="
echo "Lab teach mode works without these; install for full scanner fidelity."
echo ""

if command -v pip3 >/dev/null 2>&1; then
  pip3 install --user -r "$(dirname "$0")/../apps/requirements-cisco.txt" || true
else
  echo "pip3 not found — skip or use a venv"
fi

echo ""
echo "Verify:"
echo "  mcp-scanner --help   # https://github.com/cisco-ai-defense/mcp-scanner"
echo "  aibom --help         # https://github.com/cisco-ai-defense/aibom"
echo ""
echo "Splunk MLTK + Cisco TSM: install Machine Learning Toolkit, then:"
echo "  https://github.com/splunk/cisco-time-series-model"
echo "Foundation-Sec-8B on Ollama:"
echo "  https://huggingface.co/fdtn-ai/Foundation-Sec-8B"
