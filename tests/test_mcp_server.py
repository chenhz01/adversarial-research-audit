"""Contract tests for the zero-dependency MCP server."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import mcp_server  # noqa: E402


def _call(arguments: dict) -> dict:
    response = mcp_server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "audit_report", "arguments": arguments},
        },
        {},
    )
    assert response is not None
    return response


def _clean_report() -> dict:
    return json.loads((ROOT / "examples" / "clean_report.json").read_text(encoding="utf-8"))


class TestMcpContract(unittest.TestCase):
    def test_tool_schema_exposes_source_verification(self):
        tool = mcp_server.TOOLS[0]
        self.assertIn("verify_sources", tool["inputSchema"]["properties"])
        self.assertIn("outputSchema", tool)

    def test_pass_returns_matching_structured_content(self):
        response = _call({"report": _clean_report()})
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["outputs"]["verdict"], "PASS")
        self.assertEqual(json.loads(result["content"][1]["text"]), result["structuredContent"])

    def test_fail_is_a_business_result_not_transport_error(self):
        report = json.loads((ROOT / "examples" / "fraudulent_report.json").read_text(encoding="utf-8"))
        result = _call({"report": report})["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["outputs"]["verdict"], "FAIL")

    def test_raw_json_remains_supported(self):
        result = _call({"raw": json.dumps(_clean_report())})["result"]
        self.assertEqual(result["structuredContent"]["outputs"]["verdict"], "PASS")

    def test_malformed_raw_is_invalid_params(self):
        response = _call({"raw": "{"})
        self.assertEqual(response["error"]["code"], -32602)

    def test_object_input_is_size_limited_too(self):
        response = _call({"report": {"title": "x" * (mcp_server.MAX_RAW_CHARS + 1)}})
        self.assertEqual(response["error"]["code"], -32602)
        self.assertIn("too large", response["error"]["message"])

    def test_source_verification_marks_unknown_as_degraded(self):
        integrity = {
            "source_verification": {
                "total": 1,
                "alive": 0,
                "dead": 0,
                "unknown": 1,
                "hash_drift": 0,
                "dead_urls": [],
                "unknown_urls": ["https://example.invalid/source"],
            }
        }
        with mock.patch("audit.verify_sources", return_value=(integrity, True)) as verify:
            result = _call({"report": _clean_report(), "verify_sources": True})["result"]

        verify.assert_called_once()
        envelope = result["structuredContent"]
        self.assertTrue(envelope["degraded"])
        self.assertEqual(envelope["outputs"]["verdict"], "PASS")
        self.assertEqual(envelope["outputs"]["gates_passed"], "6/6")

    def test_semantic_result_is_deterministic(self):
        first = _call({"report": _clean_report()})["result"]["structuredContent"]
        second = _call({"report": _clean_report()})["result"]["structuredContent"]
        self.assertNotEqual(first["trace_id"], second["trace_id"])
        self.assertEqual(
            {key: value for key, value in first.items() if key != "trace_id"},
            {key: value for key, value in second.items() if key != "trace_id"},
        )


if __name__ == "__main__":
    unittest.main()
