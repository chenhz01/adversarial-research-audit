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


class TestMalformedClaims(unittest.TestCase):
    def test_non_list_claims_never_raises(self):
        # audit() promises never to raise on malformed input; claims=5 (not a
        # list) must produce a verdict, not a TypeError (PATCH-016 round).
        report = {"title": "t", "claims": 5}
        env = audit.audit(report)
        self.assertIn("verdict", env["outputs"])

    def test_non_dict_claim_items_skipped(self):
        report = {"title": "t", "claims": ["junk", 42, {"id": "c1"}]}
        env = audit.audit(report)
        ids = [v["id"] for v in env["outputs"]["claim_verdicts"]]
        self.assertEqual(ids, ["c1"])


class TestPolicyBlockedGate(unittest.TestCase):
    """gate6 must not treat a policy block as a dead source, and must only fail
    on one when the caller explicitly asked for it (GodBlf finding 3)."""

    def _report(self, sv: dict) -> dict:
        return {"title": "t", "integrity": {"source_verification": sv}}

    def test_blocked_sources_do_not_fail_the_gate_by_default(self):
        ok, msg = audit.gate_integrity(self._report({
            "total": 2, "alive": 1, "dead": 0, "unknown": 0, "blocked": 1,
            "hash_drift": 0, "blocked_urls": ["http://127.0.0.1/x"]}))
        self.assertTrue(ok, msg)
        self.assertIn("blocked by policy", msg)
        self.assertIn("not counted as dead", msg)

    def test_dead_still_fails_the_gate(self):
        ok, msg = audit.gate_integrity(self._report({
            "total": 1, "alive": 0, "dead": 1, "unknown": 0, "blocked": 0,
            "hash_drift": 0, "dead_urls": ["https://gone.example/x"]}))
        self.assertFalse(ok)
        self.assertIn("dead/unreachable", msg)

    def test_policy_failure_only_when_explicitly_configured(self):
        ok, msg = audit.gate_integrity(self._report({
            "total": 1, "alive": 0, "dead": 0, "unknown": 0, "blocked": 1,
            "hash_drift": 0, "policy_blocked_failed": True}))
        self.assertFalse(ok, "fail_on_policy_block must fail the gate")
        self.assertIn("fail_on_policy_block", msg)


if __name__ == "__main__":
    unittest.main()
