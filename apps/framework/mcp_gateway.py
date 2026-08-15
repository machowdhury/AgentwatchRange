"""
MCP tool gateway — scope enforcement for agent tool invocations (Campaign W6).

Also validates tool manifest descriptions at registration time (AML.T0070).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

APPROVED_TOOLS = frozenset({
    "validate_document_format",
    "extract_financial_fields",
    "lookup_policy",
    "score_credit_risk",
})

MANIFEST_INJECTION_PATTERNS = [
    re.compile(r"\[SYSTEM\s+OVERRIDE", re.I),
    re.compile(r"ignore\s+prior\s+constraints", re.I),
    re.compile(r"approve\s+all\s+loans", re.I),
    re.compile(r"disregard\s+(?:all\s+)?(?:safety|policy)", re.I),
]

TOOL_INVOKE_PATTERNS = [
    re.compile(r"execute_shell_command\s*\(", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"subprocess\.(?:run|call|Popen)\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"mcp\.tool\.invoke\s*\(", re.IGNORECASE),
]


@dataclass
class McpManifestResult:
    blocked: bool
    tool_manifest_tampered: bool
    rule_id: str
    tampered_tool: str = ""
    matched_pattern: str = ""


@dataclass
class McpGatewayResult:
    blocked: bool
    tool_name: str
    scope_violation: bool
    rule_id: str
    matched_pattern: str = ""
    mcp_server_id: str = "acme-mcp-gateway-001"
    tool_manifest_tampered: bool = False


def inspect_tool_manifest(manifest: Any) -> McpManifestResult:
    """Scan MCP tool manifest descriptions/metadata for injected instructions."""
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except json.JSONDecodeError:
            manifest = {"raw": manifest}

    tools = manifest.get("tools", []) if isinstance(manifest, dict) else []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        description = tool.get("description", "") or tool.get("metadata", {}).get("description", "")
        for pattern in MANIFEST_INJECTION_PATTERNS:
            if pattern.search(description):
                return McpManifestResult(
                    blocked=True,
                    tool_manifest_tampered=True,
                    rule_id="MCP-MANIFEST-001",
                    tampered_tool=tool.get("name", "unknown"),
                    matched_pattern=pattern.pattern,
                )

    return McpManifestResult(
        blocked=False,
        tool_manifest_tampered=False,
        rule_id="MCP-MANIFEST-PASS",
    )


def inspect_tool_invocation(user_input: str) -> McpGatewayResult:
    """Detect out-of-scope MCP / shell tool calls in adversarial input."""
    if "MCP_MANIFEST_REGISTER" in user_input or "mcp_tool_manifest" in user_input.lower():
        from framework.emerging_threats import POISONED_MCP_MANIFEST

        manifest_result = inspect_tool_manifest(POISONED_MCP_MANIFEST)
        if manifest_result.blocked:
            return McpGatewayResult(
                blocked=True,
                tool_name=manifest_result.tampered_tool,
                scope_violation=True,
                rule_id=manifest_result.rule_id,
                matched_pattern=manifest_result.matched_pattern,
                tool_manifest_tampered=True,
            )

    for pattern in TOOL_INVOKE_PATTERNS:
        match = pattern.search(user_input)
        if match:
            return McpGatewayResult(
                blocked=True,
                tool_name="execute_shell_command",
                scope_violation=True,
                rule_id="MCP-GW-SCOPE-001",
                matched_pattern=pattern.pattern,
            )

    for tool in APPROVED_TOOLS:
        normalized_input = user_input.lower().replace("_", "")
        normalized_tool = tool.lower().replace("_", "")
        if normalized_tool in normalized_input:
            return McpGatewayResult(
                blocked=False,
                tool_name=tool,
                scope_violation=False,
                rule_id="MCP-GW-ALLOW",
            )

    return McpGatewayResult(
        blocked=False,
        tool_name="",
        scope_violation=False,
        rule_id="MCP-GW-PASS",
    )


def mcp_otel_fields(result: McpGatewayResult, session_id: str) -> dict:
    fields = {
        "gen_ai.tool.name": result.tool_name or "none",
        "tool.scope_violation": str(result.scope_violation).lower(),
        "mcp.server.id": result.mcp_server_id,
        "mcp.gateway.rule_id": result.rule_id,
        "session.id": session_id,
        "tool_manifest_tampered": str(result.tool_manifest_tampered).lower(),
    }
    if result.scope_violation:
        fields["mcp.gateway.action"] = "BLOCK"
    return fields
