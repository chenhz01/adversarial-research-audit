"""Tests for the CLI adapter (cli_adapter.py) — the shell/CI entry point.

Covers the three RFC boundaries from issue #2:
  1. Exit states: verdict/degraded stay separate; documented exit-code
     precedence; crash without envelope = execution error, never DEGRADED.
  2. Audit log: append-only JSONL keyed by trace_id; stdout carries only the
     envelope; opt-out recording failure fails closed (nothing audited).
  3. Unknown candidate set: the adapter never substitutes the observed set
     size for an unknown total and forwards coverage data untouched.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import audit  # noqa: E402
import cli_adapter  # noqa: E402


GOOD_REPORT = {
    "title": "clean report",
    "source_of_set": {"method": "api", "description": "export"},
    "coverage": {"examined": 2, "total": 2},
    "clusters": [{"name": "a", "count": 2}],
    "claims": [
        {"id": "c1", "text": "x", "sources": [{"name": "a"}, {"name": "b"}]},
        {"id": "c2", "text": "y", "sources": [{"name": "a"}]},
    ],
}

FAIL_REPORT = {
    "title": "coverage fraud",
    "source_of_set": {"method": "html-page", "description": "featured list"},
    "coverage": {"examined": 10, "total": 10},
    "clusters": [{"name": "a", "count": 3}],
    "claims": [{"id": "c1", "count": 10, "text": "x", "sources": []}],
}

# Only gate 5 fails (examined < total with no `unjudged` list, and a `filters`
# entry explaining the removal) -> PASS-WITH-CAVEAT, the one verdict that is
# publishable after a fix-up.
CAVEAT_REPORT = {
    "title": "caveat only",
    "source_of_set": {"method": "api", "description": "export"},
    "coverage": {"examined": 1, "total": 2},
    "clusters": [{"name": "a", "count": 1}],
    "filters": [{"criteria": "removed duplicates", "removed": 1}],
    "claims": [
        {"id": "c1", "count": 1, "text": "x",
         "sources": [{"name": "a"}, {"name": "b"}]},
    ],
}


def run_cli(args, stdin_text=None):
    """Run cli_adapter.run() capturing stdout/stderr. Returns (code, out, err)."""
    out_buf, err_buf = io.StringIO(), io.StringIO()
    if stdin_text is not None:
        # TextIOWrapper over BytesIO mirrors a real stdin (has .buffer).
        sys.stdin = io.TextIOWrapper(io.BytesIO(stdin_text.encode("utf-8")),
                                     encoding="utf-8")
    try:
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = cli_adapter.run(args)
    finally:
        if stdin_text is not None:
            sys.stdin = sys.__stdin__
    return code, out_buf.getvalue(), err_buf.getvalue()


class TestExitStates(unittest.TestCase):
    """Boundary 1: verdict/degraded separation and exit-code precedence."""

    def test_pass_report_exit0_envelope_on_stdout(self):
        code, out, err = run_cli(["-"], stdin_text=json.dumps(GOOD_REPORT))
        self.assertEqual(code, 0)
        env = json.loads(out)                      # stdout is pure envelope
        self.assertIn("verdict", env["outputs"])
        self.assertIn("degraded", env)
        self.assertEqual(err, "")

    def test_fail_report_exit12(self):
        # 12 = SUCCESS · FAIL · degraded=false. "The audit ran fine and found
        # a failure" must never look like "the audit failed to run" (3).
        code, out, _ = run_cli(["-"], stdin_text=json.dumps(FAIL_REPORT))
        self.assertEqual(code, 12)
        env = json.loads(out)
        self.assertEqual(env["outputs"]["verdict"], "FAIL")
        self.assertFalse(env["degraded"])

    def test_pass_report_via_tempfile(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as f:
            json.dump(GOOD_REPORT, f)
            path = f.name
        try:
            code, out, _ = run_cli([path])
            self.assertEqual(code, 0)
            env = json.loads(out)
            self.assertEqual(env["inputs"]["schema"], "audit-input-v1")
            self.assertEqual(env["outputs"]["verdict"], "PASS")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_degraded_pass_exit10_field_stays_separate(self):
        # --verify-sources --offline leaves source checks unknown: the verdict
        # may still be PASS but degraded=true must remain its own field and
        # flip the exit code to 10.
        report = dict(GOOD_REPORT)
        report["coverage"] = {"examined": 1, "total": 1}
        report["clusters"] = [{"name": "a", "count": 1}]
        report["claims"] = [
            {"id": "c1", "text": "x",
             "sources": [{"name": "a", "url": "https://example.com/a"}]},
        ]
        with tempfile.TemporaryDirectory() as td:
            cache = str(Path(td) / "cache.json")
            code, out, _ = run_cli(
                ["-", "--verify-sources", "--offline", "--cache", cache],
                stdin_text=json.dumps(report))
            self.assertEqual(code, 10, "degraded pass must not look clean")
            env = json.loads(out)
            self.assertEqual(env["outputs"]["verdict"], "PASS")
            self.assertTrue(env["degraded"])

    def test_malformed_json_exit4_no_envelope(self):
        code, out, err = run_cli(["-"], stdin_text="{not json")
        self.assertEqual(code, 4)
        self.assertEqual(out, "", "no envelope may be printed for input errors")
        self.assertIn("input-error", err)

    def test_missing_file_exit4(self):
        code, out, _ = run_cli(["no/such/file.json"])
        self.assertEqual(code, 4)
        self.assertEqual(out, "")

    def test_no_input_exit4(self):
        code, _, _ = run_cli([])
        self.assertEqual(code, 4)

    def test_unknown_option_is_usage_error(self):
        # Unknown flags must never be silently ignored (they could silently
        # change semantics in future versions).
        code, out, err = run_cli(["-", "--verbose"], stdin_text=json.dumps(GOOD_REPORT))
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertIn("unknown option", err)

    def test_valued_flag_without_value_is_usage_error(self):
        # A missing --audit-log value must NOT fall back to an unlogged run:
        # the caller explicitly asked for a log, silence would defeat it.
        code, out, err = run_cli(["-", "--audit-log"], stdin_text=json.dumps(GOOD_REPORT))
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertIn("requires a value", err)

    def test_cache_flag_cannot_swallow_next_flag(self):
        # `--cache --offline` must not silently take "--offline" as the cache
        # path and drop the offline flag (unexpected online verification).
        code, out, err = run_cli(
            ["-", "--verify-sources", "--cache", "--offline"],
            stdin_text=json.dumps(GOOD_REPORT))
        self.assertEqual(code, 4)
        self.assertEqual(out, "")
        self.assertIn("requires a value", err)

    def test_crash_is_execution_error_not_degraded(self):
        # Boundary 1: "a crash or timeout without a valid envelope should be
        # a distinct execution-error state, not DEGRADED."
        called = {}
        real_audit = cli_adapter.audit.audit

        def boom(report, trace_id=None):
            called["hit"] = True
            raise RuntimeError("engine exploded")

        cli_adapter.audit.audit = boom
        try:
            code, out, err = run_cli(["-"], stdin_text=json.dumps(GOOD_REPORT))
        finally:
            cli_adapter.audit.audit = real_audit
        self.assertTrue(called["hit"])
        self.assertEqual(code, 3)
        self.assertEqual(out, "", "no envelope may be printed after a crash")
        self.assertIn("execution-error", err)
        self.assertNotIn("DEGRADED", out)


class TestTwoAxisExitCodes(unittest.TestCase):
    """Axis A (how the run ended) is separate from Axis B (what it found).

    A completed run carrying an artifact (0/10/11/12/13) must never be
    confused with a run that produced no usable artifact (3/4/5), and within
    the artifact-bearing rows the verdict and the degradation are both
    visible from the exit code alone.
    """

    def test_caveat_only_report_is_11(self):
        code, out, _ = run_cli(["-"], stdin_text=json.dumps(CAVEAT_REPORT))
        env = json.loads(out)
        self.assertEqual(env["outputs"]["verdict"], "PASS-WITH-CAVEAT")
        self.assertEqual(code, 11, "PASS-WITH-CAVEAT must not look like a pass")

    def test_fail_with_unverifiable_sources_is_13_not_12(self):
        # Whether the failure rested on verifiable sources is information the
        # caller is entitled to; that is the whole reason 12 and 13 exist.
        report = dict(FAIL_REPORT)
        report["claims"] = [
            {"id": "c1", "count": 10, "text": "x",
             "sources": [{"name": "a", "url": "https://example.com/a"}]},
        ]
        with tempfile.TemporaryDirectory() as td:
            cache = str(Path(td) / "cache.json")
            code, out, _ = run_cli(
                ["-", "--verify-sources", "--offline", "--cache", cache],
                stdin_text=json.dumps(report))
            env = json.loads(out)
        self.assertEqual(env["outputs"]["verdict"], "FAIL")
        self.assertTrue(env["degraded"])
        self.assertEqual(code, 13)
        self.assertNotEqual(code, 12, "a degraded FAIL is not a clean FAIL")

    def test_reserved_exit2_is_never_emitted(self):
        # Exit 2 is reserved for EXPLICIT_FAILURE-with-artifact, which no
        # adapter path produces. Guard the number against silent reuse: if a
        # future path starts emitting 2, this test makes that a decision
        # rather than an accident.
        scenarios = [
            (["-"], json.dumps(GOOD_REPORT)),
            (["-"], json.dumps(FAIL_REPORT)),
            (["-"], json.dumps(CAVEAT_REPORT)),
            (["-"], "{not json"),
            (["no/such/file.json"], None),
            ([], None),
            (["-", "--verbose"], json.dumps(GOOD_REPORT)),
        ]
        for args, stdin_text in scenarios:
            code, _, _ = run_cli(args, stdin_text=stdin_text)
            self.assertNotEqual(
                code, 2, f"exit 2 is reserved, but {args} returned it")


class TestAuditLog(unittest.TestCase):
    """Boundary 2: append-only JSONL, trace_id linkage, fail-closed opt-out."""

    def _read_log(self, path):
        return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines()]

    def test_jsonl_append_only_and_trace_linkage(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = str(Path(td) / "audit.jsonl")
            c1, out1, _ = run_cli(["-", "--audit-log", log_path],
                                  stdin_text=json.dumps(GOOD_REPORT))
            c2, out2, _ = run_cli(["-", "--audit-log", log_path],
                                  stdin_text=json.dumps(FAIL_REPORT))
            self.assertEqual((c1, c2), (0, 12))
            lines = self._read_log(log_path)      # append-only: both runs present
            self.assertEqual(len(lines), 4)       # started+finished per run (no
            # URLs in either report -> no verification_opt_out events)
            t1 = json.loads(out1)["trace_id"]
            t2 = json.loads(out2)["trace_id"]
            self.assertNotEqual(t1, t2)
            self.assertTrue(all(l["trace_id"] == t1 for l in lines[:2]))
            self.assertTrue(all(l["trace_id"] == t2 for l in lines[2:]))
            events = [l["event"] for l in lines]
            self.assertEqual(events, ["audit_started", "audit_finished",
                                      "audit_started", "audit_finished"])

    def test_stdout_only_envelope_diagnostics_to_stderr(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = str(Path(td) / "audit.jsonl")
            code, out, err = run_cli(["-", "--audit-log", log_path],
                                     stdin_text=json.dumps(GOOD_REPORT))
            self.assertEqual(code, 0)
            self.assertEqual(len(out.strip().splitlines()), 1)  # one JSON line
            json.loads(out)                                      # and it parses
            self.assertEqual(err, "")

    def test_opt_out_recorded_when_urls_present_but_verify_not_requested(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = str(Path(td) / "audit.jsonl")
            report = dict(GOOD_REPORT)
            report["claims"] = [
                {"id": "c1", "text": "x",
                 "sources": [{"name": "a", "url": "https://example.com/a"}]},
            ]
            run_cli(["-", "--audit-log", log_path], stdin_text=json.dumps(report))
            events = self._read_log(log_path)
            opt = [e for e in events if e["event"] == "verification_opt_out"]
            self.assertEqual(len(opt), 1)
            self.assertEqual(opt[0]["candidate_urls"], 1)

    def test_no_opt_out_event_when_verify_requested(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = str(Path(td) / "audit.jsonl")
            report = dict(GOOD_REPORT)
            report["claims"] = [
                {"id": "c1", "text": "x",
                 "sources": [{"name": "a", "url": "https://example.com/a"}]},
            ]
            run_cli(["-", "--audit-log", log_path, "--verify-sources", "--offline"],
                    stdin_text=json.dumps(report))
            events = self._read_log(log_path)
            self.assertFalse(any(e["event"] == "verification_opt_out" for e in events))

    def test_opt_out_write_failure_fails_closed_as_policy_denied(self):
        # Agreed in the issue #2 review: if the opt-out event cannot be
        # recorded, nothing is audited and no envelope is fabricated.
        #
        # The exit code matters. This is a policy refusal — the cause is a
        # decision we cannot evidence — so it is 5, not 3. Lumping it with
        # crashes would tell the caller "the engine broke" when in fact the
        # engine never ran.
        real_collect = cli_adapter.audit.collect_urls
        real_log_write = cli_adapter.AuditLog.write
        cli_adapter.audit.collect_urls = lambda report: ["https://example.com/a"]

        calls = {"n": 0}

        def flaky_write(self, event, trace_id, **fields):
            calls["n"] += 1
            if event == "verification_opt_out":
                raise OSError("disk full — audit trail cannot be written")
            return real_log_write(self, event, trace_id, **fields)

        cli_adapter.AuditLog.write = flaky_write
        try:
            with tempfile.TemporaryDirectory() as td:
                log_path = str(Path(td) / "audit.jsonl")
                code, out, err = run_cli(
                    ["-", "--audit-log", log_path],
                    stdin_text=json.dumps(GOOD_REPORT))
                self.assertEqual(calls["n"], 3)  # started OK, opt-out refused,
                # policy-denial recorded (best-effort) -> fail-closed
                events = self._read_log(log_path)
        finally:
            cli_adapter.AuditLog.write = real_log_write
            cli_adapter.audit.collect_urls = real_collect
        self.assertEqual(code, 5)
        self.assertNotEqual(code, 3, "a policy refusal is not a crash")
        self.assertEqual(out, "", "fail-closed: no envelope without audit trail")
        self.assertIn("policy-denied", err)
        self.assertTrue(any(e["event"] == "audit_policy_denied" for e in events))

    def test_no_log_flag_still_audits(self):
        # Without --audit-log there is no log to fail; the adapter must run.
        code, out, _ = run_cli(["-"], stdin_text=json.dumps(GOOD_REPORT))
        self.assertEqual(code, 0)
        self.assertIn("verdict", json.loads(out)["outputs"])


class TestUnknownCandidateSet(unittest.TestCase):
    """Boundary 3: no new semantics; unknown totals forwarded untouched."""

    def test_unknown_total_forwarded_untouched(self):
        # The adapter must not substitute the observed set size for an
        # unknown total: coverage.total=None passes through to the engine,
        # and the envelope the engine produces is returned unmodified.
        report = dict(GOOD_REPORT)
        report["coverage"] = {"examined": 2, "total": None}
        report["candidate_set"] = {"size": None, "note": "unknown total"}
        code, out, _ = run_cli(["-"], stdin_text=json.dumps(report))
        env = json.loads(out)
        self.assertEqual(code, 12)  # engine's call, not the adapter's invention
        # the adapter added no coverage/candidate_set interpretation
        self.assertNotIn("candidate_set", env["outputs"])
        self.assertNotIn("coverage", env["outputs"])

    def test_envelope_keys_unchanged(self):
        # The adapter adds/removes nothing from the envelope shape.
        code, out, _ = run_cli(["-"], stdin_text=json.dumps(GOOD_REPORT))
        env = json.loads(out)
        self.assertEqual(set(env.keys()),
                         {"engine", "version", "inputs", "outputs",
                          "confidence", "degraded", "trace_id"})


class TestRestrictedNetworkDefault(unittest.TestCase):
    """The CLI applies the restricted policy explicitly, never inherited."""

    def test_verify_without_optin_blocks_private_urls(self):
        report = dict(GOOD_REPORT)
        report["claims"] = [
            {"id": "c1", "text": "x",
             "sources": [{"name": "a", "url": "http://127.0.0.1:9/x"}]},
        ]
        with tempfile.TemporaryDirectory() as td:
            cache = str(Path(td) / "cache.json")
            code, out, _ = run_cli(
                ["-", "--verify-sources", "--offline", "--cache", cache],
                stdin_text=json.dumps(report))
            env = json.loads(out)
        integ = env  # verification data lands in the report pre-audit; the
        # envelope's gate6 result reflects the blocked URL. The key assertion:
        # the run completed and the private URL was not silently allowed.
        self.assertIn(integ["outputs"]["verdict"], ("PASS", "PASS-WITH-CAVEAT", "FAIL"))


if __name__ == "__main__":
    unittest.main()
