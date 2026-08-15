"""
Cisco AI Defense + Splunk ML toolkit integration for OrchestraACME.

Optional tools from https://github.com/cisco-ai-defense (AIBOM, MCP Scanner, etc.)
run in teach mode (log-only) or enforce mode (may block). See docs/CISCO_INTEGRATION.md.

Foundation-Sec-8B: https://huggingface.co/fdtn-ai/Foundation-Sec-8B
CTSM: https://github.com/splunk/cisco-time-series-model (Splunk MLTK)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("acme.cisco")

_REPO_ROOT = Path(__file__).resolve().parents[2]
_AIBOM_MANIFEST = _REPO_ROOT / "data" / "aibom" / "acme_agent_manifest.json"
_MCP_CONFIG = _REPO_ROOT / "data" / "mcp" / "acme_banking_mcp.json"
_SCAN_CACHE = _REPO_ROOT / "data" / "cisco_scans"


def lab_mode() -> str:
    """teach = scans log only; enforce = Cisco findings may block workflow."""
    return os.environ.get("LAB_MODE", "teach").strip().lower()


def cisco_enabled() -> bool:
    return os.environ.get("CISCO_INTEGRATION_ENABLED", "false").lower() in (
        "1", "true", "yes",
    )


def foundation_sec_enabled() -> bool:
    return os.environ.get("FOUNDATION_SEC_ENABLED", "false").lower() in (
        "1", "true", "yes",
    )


def ollama_base_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434").rstrip("/")


def security_model_name() -> str:
    return os.environ.get(
        "OLLAMA_SECURITY_MODEL",
        "hf.co/fdtn-ai/Foundation-Sec-8B-GGUF:Q4_K_M",
    )


def integration_status() -> Dict[str, Any]:
    """Health snapshot for Setup Guide and attack panel."""
    return {
        "cisco_integration_enabled": cisco_enabled(),
        "lab_mode": lab_mode(),
        "foundation_sec_enabled": foundation_sec_enabled(),
        "security_model": security_model_name(),
        "aibom_cli": shutil.which("aibom") is not None,
        "mcp_scanner_cli": shutil.which("mcp-scanner") is not None,
        "aibom_manifest": str(_AIBOM_MANIFEST),
        "mcp_config": str(_MCP_CONFIG),
        "docs": {
            "cisco_ai_defense": "https://github.com/cisco-ai-defense",
            "acme_output_guard": "https://github.com/cisco-ai-defense/defenseclaw",
            "aibom": "https://github.com/cisco-ai-defense/aibom",
            "mcp_scanner": "https://github.com/cisco-ai-defense/mcp-scanner",
            "foundation_sec_8b": "https://huggingface.co/fdtn-ai/Foundation-Sec-8B",
            "cisco_tsm": "https://github.com/splunk/cisco-time-series-model",
        },
    }


def _write_scan_cache(name: str, payload: dict) -> None:
    try:
        _SCAN_CACHE.mkdir(parents=True, exist_ok=True)
        out = _SCAN_CACHE / f"{name}.json"
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not write scan cache: %s", exc)


def run_aibom_scan() -> Dict[str, Any]:
    """
    AI BOM supply-chain scan. Uses cisco-ai-defense/aibom CLI when installed,
    otherwise validates the lab manifest (Scenario 1 teach path).
    """
    result: Dict[str, Any] = {
        "scanner": "local_manifest",
        "status": "PASS",
        "findings": [],
        "telemetry": {},
    }

    if not _AIBOM_MANIFEST.exists():
        result["status"] = "WARN"
        result["findings"].append({"severity": "medium", "message": "AIBOM manifest missing"})
        return result

    manifest = json.loads(_AIBOM_MANIFEST.read_text(encoding="utf-8"))
    agents = manifest.get("agents", {})
    unapproved = [
        aid for aid, meta in agents.items()
        if not meta.get("approved", True)
    ]
    if unapproved:
        result["status"] = "FAIL"
        result["findings"].append({
            "severity": "high",
            "message": f"Unapproved agents in manifest: {', '.join(unapproved)}",
        })

    aibom_bin = shutil.which("aibom")
    if aibom_bin and cisco_enabled():
        try:
            proc = subprocess.run(
                [aibom_bin, "scan", str(_REPO_ROOT / "apps"), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if proc.stdout.strip():
                result["scanner"] = "cisco-aibom"
                result["cli_exit_code"] = proc.returncode
                try:
                    result["cli_report"] = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    result["cli_report"] = {"raw": proc.stdout[:4000]}
                if proc.returncode != 0:
                    result["status"] = "FAIL"
        except (subprocess.TimeoutExpired, OSError) as exc:
            result["findings"].append({"severity": "low", "message": f"AIBOM CLI skipped: {exc}"})

    result["telemetry"] = {
        "cisco.aibom.scanner": result["scanner"],
        "cisco.aibom.status": result["status"],
        "cisco.aibom.finding_count": str(len(result["findings"])),
        "aibom.manifest_version": manifest.get("manifest_version", "1.0"),
    }
    _write_scan_cache("aibom", result)
    return result


def run_mcp_scan() -> Dict[str, Any]:
    """
    MCP tool surface scan. Uses cisco-ai-defense/mcp-scanner when installed,
    otherwise static analysis of lab MCP config.
    """
    result: Dict[str, Any] = {
        "scanner": "local_policy",
        "status": "PASS",
        "findings": [],
        "telemetry": {},
    }

    risky_patterns: List[str] = []
    if _MCP_CONFIG.exists():
        cfg = json.loads(_MCP_CONFIG.read_text(encoding="utf-8"))
        for tool in cfg.get("tools", []):
            name = tool.get("name", "")
            if any(x in name.lower() for x in ("shell", "exec", "system", "eval")):
                risky_patterns.append(name)
                result["findings"].append({
                    "severity": "high",
                    "message": f"Risky MCP tool name: {name}",
                    "tool": name,
                })
        if risky_patterns:
            result["status"] = "WARN"

    mcp_bin = shutil.which("mcp-scanner")
    if mcp_bin and cisco_enabled() and _MCP_CONFIG.exists():
        try:
            proc = subprocess.run(
                [mcp_bin, "scan", str(_MCP_CONFIG), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if proc.stdout.strip():
                result["scanner"] = "cisco-mcp-scanner"
                result["cli_exit_code"] = proc.returncode
                try:
                    result["cli_report"] = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    result["cli_report"] = {"raw": proc.stdout[:4000]}
                if proc.returncode != 0:
                    result["status"] = "FAIL"
        except (subprocess.TimeoutExpired, OSError) as exc:
            result["findings"].append({"severity": "low", "message": f"MCP scanner skipped: {exc}"})

    result["telemetry"] = {
        "cisco.mcp.scanner": result["scanner"],
        "cisco.mcp.status": result["status"],
        "cisco.mcp.finding_count": str(len(result["findings"])),
        "mcp.config_path": str(_MCP_CONFIG),
    }
    _write_scan_cache("mcp", result)
    return result


def cisco_scan_telemetry() -> Dict[str, str]:
    """Merge latest scan telemetry for OTel (teach mode — never blocks alone)."""
    if not cisco_enabled():
        return {}
    fields: Dict[str, str] = {"cisco.integration.enabled": "true", "lab.mode": lab_mode()}
    aibom = run_aibom_scan()
    mcp = run_mcp_scan()
    fields.update(aibom.get("telemetry", {}))
    fields.update(mcp.get("telemetry", {}))
    return fields


def should_block_from_cisco_scan(scan_status: str) -> bool:
    return cisco_enabled() and lab_mode() == "enforce" and scan_status == "FAIL"


def ctsm_anomaly_fields(user_message: str, campaign_week: int = 0) -> Dict[str, str]:
    """
    Emit token-surge telemetry for Scenario 7 / Infinity Bill — feeds Splunk
    | fit MLTKContainer algo=ctsm_forecast (Cisco Time Series Model).
    """
    depth = 0
    msg = user_message.lower()
    if "recursive" in msg or "iteration" in msg or "infinity" in msg:
        depth = min(max(msg.count("step") + msg.count("repeat") + msg.count("loop"), 8), 50)
    if campaign_week == 7:
        depth = max(depth, 12)

    if depth < 5:
        return {"call_depth_detected": str(depth)}

    input_tok = min(50000, 8000 + depth * 1200)
    output_tok = min(20000, 3000 + depth * 400)
    total = input_tok + output_tok
    score = "0.98" if depth >= 10 else "0.85"

    return {
        "call_depth_detected": str(depth),
        "gen_ai.usage.input_tokens": str(input_tok),
        "gen_ai.usage.output_tokens": str(output_tok),
        "tokens_consumed_in_loop": str(total),
        "cisco_tsm_anomaly_score": score,
        "anomaly.type": "TOKEN_SURGE",
        "mltk.ctsm_signal": "true",
        "api_cost_projected_usd": f"{round(total * 0.00002, 2)}",
    }


def foundation_sec_enrich(
    hunt_context: str,
    technique_id: str = "",
    incident_id: str = "",
) -> Dict[str, Any]:
    """
    Optional threat-hunt enrichment via Foundation-Sec-8B on Ollama.
    Model: https://huggingface.co/fdtn-ai/Foundation-Sec-8B
    """
    if not foundation_sec_enabled():
        return {
            "enabled": False,
            "message": "Set FOUNDATION_SEC_ENABLED=true and pull OLLAMA_SECURITY_MODEL",
            "model": security_model_name(),
        }

    model = security_model_name()
    prompt = (
        "You are a SOC analyst using MITRE ATLAS and OWASP LLM guidance. "
        "Given the telemetry excerpt below, respond in 3 bullets: "
        "(1) likely tactic, (2) recommended hunt step, (3) containment priority (low/medium/high).\n\n"
        f"Technique: {technique_id or 'unknown'}\n"
        f"Incident: {incident_id or 'n/a'}\n"
        f"Context:\n{hunt_context[:3000]}"
    )

    try:
        r = requests.post(
            f"{ollama_base_url()}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 256},
            },
            timeout=120,
        )
        r.raise_for_status()
        body = r.json()
        analysis = body.get("response", "").strip()
        return {
            "enabled": True,
            "model": model,
            "analysis": analysis,
            "security_llm.provider": "cisco-foundation-ai",
            "security_llm.model": "fdtn-ai/Foundation-Sec-8B",
            "hunt.enrichment_source": "foundation_sec_8b",
        }
    except requests.RequestException as exc:
        logger.warning("Foundation-Sec-8B enrichment failed: %s", exc)
        return {
            "enabled": True,
            "model": model,
            "error": str(exc),
            "message": "Pull the security model: see docs/CISCO_INTEGRATION.md",
        }
