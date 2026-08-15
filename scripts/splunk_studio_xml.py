#!/usr/bin/env python3
"""Wrap Dashboard Studio JSON definitions in Splunk v2 dashboard XML."""

from __future__ import annotations

import json
import xml.sax.saxutils as xml_escape
from typing import Any


def wrap_studio_dashboard_xml(title: str, description: str, dashboard: dict[str, Any]) -> str:
    """
    Splunk registers Dashboard Studio views as XML (version=\"2\") with JSON in <definition>.
    Bare .json files under data/ui/views are not loaded as navigable views.
    """
    payload = json.dumps(dashboard, separators=(",", ":"))
    if "]]>" in payload:
        payload = payload.replace("]]>", "]]]]><![CDATA[>")
    label = xml_escape.escape(title)
    desc = xml_escape.escape(description)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<dashboard version="2" theme="light">\n'
        f"  <label>{label}</label>\n"
        f"  <description>{desc}</description>\n"
        f"  <definition><![CDATA[{payload}]]></definition>\n"
        "  <assets><![CDATA[{}]]></assets>\n"
        "</dashboard>\n"
    )
