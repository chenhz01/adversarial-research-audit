#!/usr/bin/env python3
"""Minimal zero-dependency MCP stdio server exposing the auditor as a tool.

Speaks the Model Context Protocol over stdio (JSON-RPC 2.0, newline-delimited
JSON). Implements the small subset most hosts need:

    initialize / notifications/initialized / tools/list / tools/call

Wire it into any MCP-compatible client:

    {
      "mcpServers": {
        "adversarial-research-audit": {
          "command": "python",
          "args": ["/path/to/mcp_server.py"]
        }
      }
    }

The `audit_report` tool takes the research-report JSON (audit-input-v1, see
protocols/audit-protocol.md) and returns the audit envelope (audit-output-v1).
"""
from __future__ import annotations

import json
import sys

import audit  # same directory

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "audit_report",
        "description": (
            "Audit an agentic research report for coverage fraud and evidence "
            "hygiene: full-set source, coverage arithmetic, cluster arithmetic, "
            "filter provenance, unjudged items; per-claim source verdicts. "
            "Input: audit-input-v1 JSON (see protocol)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "report": {
                    "type": "object",
                    "description": "The research report, audit-input-v1 schema",
                },
                "raw": {
                    "type": "string",
                    "description": "Alternative: the report as a JSON string",
                },
            },
            "anyOf": [{"required": ["report"]}, {"required": ["raw"]}],
        },
    }
]


MAX_RAW_CHARS = 1_000_000  # red-team finding PATCH-002: cap input to prevent DoS


def handle(msg: dict, state: dict) -> dict | None:
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": audit.ENGINE, "version": audit.VERSION},
            },
        }
    if method == "notifications/initialized":
        state["initialized"] = True
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        if (params.get("name") or "") != "audit_report":
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32602, "message": f"unknown tool {params.get('name')!r}"}}
        args = params.get("arguments") or {}
        report = args.get("report")
        if report is None:
            raw = args.get("raw") or ""
            if len(raw) > MAX_RAW_CHARS:
                return {"jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32602,
                                  "message": f"raw too large ({len(raw)} chars, max {MAX_RAW_CHARS})"}}
            try:
                report = json.loads(raw or "{}")
            except json.JSONDecodeError as exc:
                return {"jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32602, "message": f"raw is not JSON: {exc}"}}
        envelope = audit.audit(report)
        text = audit.render_text(envelope)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {"type": "text", "text": text},
                    {"type": "text", "text": json.dumps(envelope, ensure_ascii=False)},
                ],
                "isError": envelope.get("outputs", {}).get("verdict") == "FAIL",
            },
        }
    if msg_id is not None:
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32601, "message": f"method not supported: {method!r}"}}
    return None


def main() -> int:
    state: dict = {}
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            resp = handle(msg, state)
        except Exception as exc:  # never let the server die on one bad call
            resp = {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None,
                    "error": {"code": -32603, "message": f"internal error: {exc!r}"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
