"""
MCP tool gateway — scope enforcement for agent tool invocations (Campaign W6).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

APPROVED_TOOLS = frozenset({
    "validate_document_format",
    "extract_financial_fields",
    "lookup_policy",
    "score_credit_risk",
})

TOOL_INVOKE_PATTERNS = [
    re.compile(r"execute_shell_command\s*\(", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"subprocess\.(?:run|call|Popen)\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"mcp\.tool\.invoke\s*\(", re.IGNORECASE),
]


@dataclass
class McpGatewayResult:
    blocked: bool
    tool_name: str
    scope_violation: bool
    rule_id: str
    matched_pattern: str = ""
    mcp_server_id: str = "acme-mcp-gateway-001"


def inspect_tool_invocation(user_input: str) -> McpGatewayResult:
    """Detect out-of-scope MCP / shell tool calls in adversarial input."""
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
    }
    if result.scope_violation:
        fields["mcp.gateway.action"] = "BLOCK"
    return fields
