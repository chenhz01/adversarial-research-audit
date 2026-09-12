"""Tests for the audit engine. Run: python -m unittest discover tests -v"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import audit  # noqa: E402


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class TestGates(unittest.TestCase):
    def test_fraud_fails_all_five(self):
        out = audit.audit(load("fraudulent_report.json"))
        self.assertEqual(out["outputs"]["verdict"], "FAIL")
        self.assertEqual(out["outputs"]["gates_passed"], "0/5")
        self.assertFalse(out["degraded"])

    def test_clean_passes(self):
        out = audit.audit(load("clean_report.json"))
        self.assertEqual(out["outputs"]["verdict"], "PASS")
        self.assertEqual(out["outputs"]["gates_passed"], "5/5")

    def test_missing_caveat_path(self):
        report = load("clean_report.json")
        report["coverage"] = {"examined": 12, "total": 20}  # partial, no unjudged
        report["clusters"][0]["count"], report["clusters"][1]["count"] = 7, 5
        report["filters"] = [{"criteria": "low users", "removed": 8}]
        out = audit.audit(report)
        # gate2: claims(7+5) + unjudged(0) == 12 OK; gate4 ok; gate5 FAIL only
        self.assertEqual(out["outputs"]["verdict"], "PASS-WITH-CAVEAT")

    def test_malformed_input_degraded(self):
        out = audit.audit("not-a-dict")  # type: ignore[arg-type]
        self.assertTrue(out["degraded"])

    def test_envelope_contract(self):
        out = audit.audit(load("clean_report.json"))
        for key in ("engine", "version", "inputs", "outputs", "confidence", "degraded", "trace_id"):
            self.assertIn(key, out)


class TestSourceDedup(unittest.TestCase):
    def test_duplicate_sources_count_once(self):
        report = {"claims": [{"id": "c1", "sources": [
            {"name": "a", "url": "https://x"},
            {"name": "mirror", "url": "https://x"},
            {"name": "mirror2", "url": "https://x"},
        ]}]}
        v = audit.judge_claims(report)[0]
        self.assertEqual(v["sources"], 1)
        self.assertEqual(v["verdict"], "single-source")

    def test_independent_sources_verified(self):
        report = {"claims": [{"id": "c1", "sources": [
            {"name": "a", "url": "https://x"},
            {"name": "b", "url": "https://y"},
        ]}]}
        v = audit.judge_claims(report)[0]
        self.assertEqual(v["verdict"], "verified")


if __name__ == "__main__":
    unittest.main()
