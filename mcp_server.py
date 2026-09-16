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

import copy
import json
import os
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
                "verify_sources": {
                    "type": "boolean",
                    "default": False,
                    "description": "Verify public HTTP(S) claim sources and arm integrity gate 6",
                },
            },
            "anyOf": [{"required": ["report"]}, {"required": ["raw"]}],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "required": ["engine", "version", "inputs", "outputs", "confidence", "degraded", "trace_id"],
            "properties": {
                "engine": {"type": "string"},
                "version": {"type": "string"},
                "inputs": {"type": "object"},
                "outputs": {"type": "object"},
                "confidence": {"type": "number"},
                "degraded": {"type": "boolean"},
                "trace_id": {"type": "string"},
            },
        },
    }
]


MAX_RAW_CHARS = 1_000_000  # red-team finding PATCH-002: cap input to prevent DoS


def _invalid_params(msg_id: object, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32602, "message": message}}


def _allow_private_networks() -> bool:
    value = os.environ.get("ADVERSARIAL_RESEARCH_AUDIT_ALLOW_PRIVATE_NETWORKS", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
        if not isinstance(args, dict):
            return _invalid_params(msg_id, "arguments must be an object")
        report = args.get("report")
        if report is None:
            if "raw" not in args:
                return _invalid_params(msg_id, "one of report or raw is required")
            raw = args.get("raw")
            if not isinstance(raw, str):
                return _invalid_params(msg_id, "raw must be a string")
            if len(raw) > MAX_RAW_CHARS:
                return _invalid_params(msg_id,
                                       f"raw too large ({len(raw)} chars, max {MAX_RAW_CHARS})")
            try:
                report = json.loads(raw)
            except json.JSONDecodeError as exc:
                return _invalid_params(msg_id, f"raw is not JSON: {exc}")
        try:
            report_size = len(json.dumps(report, ensure_ascii=False, separators=(",", ":")))
        except (TypeError, ValueError) as exc:
            return _invalid_params(msg_id, f"report is not JSON-compatible: {exc}")
        if report_size > MAX_RAW_CHARS:
            return _invalid_params(msg_id,
                                   f"report too large ({report_size} chars, max {MAX_RAW_CHARS})")

        verify_requested = args.get("verify_sources", False)
        if not isinstance(verify_requested, bool):
            return _invalid_params(msg_id, "verify_sources must be a boolean")
        report = copy.deepcopy(report)
        verification_degraded = False
        if verify_requested:
            if not isinstance(report, dict):
                return _invalid_params(msg_id, "source verification requires report to be an object")
            integrity, verification_degraded = audit.verify_sources(
                report,
                allow_private_networks=_allow_private_networks(),
            )
            existing_integrity = report.get("integrity")
            if not isinstance(existing_integrity, dict):
                existing_integrity = {}
                report["integrity"] = existing_integrity
            existing_integrity.update(integrity)
        envelope = audit.audit(report)
        if verification_degraded:
            envelope["degraded"] = True
        text = audit.render_text(envelope)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {"type": "text", "text": text},
                    {"type": "text", "text": json.dumps(envelope, ensure_ascii=False)},
                ],
                "structuredContent": envelope,
                "isError": False,
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
