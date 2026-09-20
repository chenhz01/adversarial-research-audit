#!/usr/bin/env python3
"""Thin CLI adapter for the audit pipeline (audit-input-v1 -> audit-output-v1).

This is the shell/CI counterpart of mcp_server.py: the MCP server adapts the
pipeline to MCP hosts, this adapter adapts it to command lines and pipelines.
Both emit the SAME unchanged audit envelope (engine, version, inputs, outputs,
confidence, degraded, trace_id) — the adapter layer adds no envelope semantics.

Design boundaries (ruled by the RFC discussion in issue #2, restated verbatim
in the PR description):

1. Exit states — `outputs.verdict` and `degraded` stay separate fields in the
   unchanged envelope; exit codes follow the two-axis table below. A crash
   without a valid envelope is a distinct execution state (3), never relabeled
   DEGRADED; a policy refusal we could not even record is its own state (5),
   not lumped in with crashes.

2. Audit log — an append-only JSONL log keyed by `trace_id`; stdout carries
   only the unchanged JSON envelope, all diagnostics go to stderr. If
   recording a verification opt-out fails, the adapter fails closed (exit 5,
   nothing audited, no envelope fabricated) — as agreed in the issue #2
   review.

3. Unknown candidate set — the adapter introduces no new semantics: it does
   not substitute the observed set size for an unknown total, and it forwards
   `coverage` / `candidate_set` data to the engine untouched. How `coverage`
   should represent unknown totals is deferred to a separate core-contract
   issue before any adapter change lands.

Usage:
    python cli_adapter.py report.json [--verify-sources] [--offline]
                                      [--cache PATH] [--audit-log PATH]
                                      [--quiet]
    cat report.json | python cli_adapter.py - [--audit-log audit.jsonl]

Exit codes — two orthogonal axes. The normative table lives in
`protocols/audit-protocol.md` § "Execution status and exit codes"; this
adapter implements it.

    Axis A — execution status (how the run ended):
      SUCCESS           completed and emitted a valid envelope
      EXPLICIT_FAILURE  terminated with a named reason, carried in the record
      SILENT_TIMEOUT    ended without a positive artifact — never a verdict
      USAGE_ERROR       malformed input; no audit attempted
      POLICY_DENIED     a refusal could not be recorded; fail closed

    Axis B — envelope fields: outputs.verdict in {PASS, PASS-WITH-CAVEAT,
      FAIL}, degraded in {true, false}.

    0   SUCCESS          PASS              degraded=false
    10  SUCCESS          PASS              degraded=true  (verdict unreliable:
                                                          some checks unknown)
    11  SUCCESS          PASS-WITH-CAVEAT  any
    12  SUCCESS          FAIL              degraded=false
    13  SUCCESS          FAIL              degraded=true
    2   EXPLICIT_FAILURE (reserved — see below)
    3   SILENT_TIMEOUT   no valid envelope: crash, failed start, or a refusal
                         we could not even record — never reported as DEGRADED
    4   USAGE_ERROR      no valid envelope: missing file, malformed JSON,
                         unknown option, missing option value, input too large,
                         or a syntactically valid envelope carrying no verdict
    5   POLICY_DENIED    the verification opt-out could not be recorded, so
                         nothing was audited and no envelope was produced

Precedence: the SUCCESS rows are decided by (verdict, degraded), in that
order; the non-SUCCESS rows occur only when no usable envelope exists. Note
that `degraded` never upgrades or downgrades a FAIL — 12 and 13 differ only
in whether the sources behind that FAIL were verifiable.

Exit 2 is reserved and no current path emits it. EXPLICIT_FAILURE means "a
named failure that still carries an artifact", and the adapter has no such
path today: a crash produces no artifact, so it lands on 3. Reserving the
number stops the protocol table's numbering from being silently reclaimed.

Zero dependencies. Python 3.8+.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit  # same directory

MAX_INPUT_CHARS = 1_000_000  # mirror mcp_server.MAX_RAW_CHARS (PATCH-002)

# Exit codes — the full two-axis table is in the module docstring and, as the
# normative spec, in protocols/audit-protocol.md.
EXIT_PASS = 0                 # SUCCESS · PASS             · degraded=false
EXIT_PASS_DEGRADED = 10       # SUCCESS · PASS             · degraded=true
EXIT_PASS_WITH_CAVEAT = 11    # SUCCESS · PASS-WITH-CAVEAT · any
EXIT_FAIL = 12                # SUCCESS · FAIL             · degraded=false
EXIT_FAIL_DEGRADED = 13       # SUCCESS · FAIL             · degraded=true
EXIT_NAMED_FAILURE = 2        # EXPLICIT_FAILURE — reserved: no path emits it
EXIT_EXECUTION_ERROR = 3      # no envelope (protocol state: SILENT_TIMEOUT)
EXIT_USAGE_ERROR = 4          # malformed input / envelope carrying no verdict
EXIT_POLICY_DENIED = 5        # opt-out not recordable → fail closed

_KNOWN_FLAGS = {"--verify-sources", "--offline", "--quiet"}
_VALUED_FLAGS = {"--cache", "--audit-log"}


class _InputError(Exception):
    """No valid envelope possible: missing/malformed/oversized input."""


class _ExecutionError(Exception):
    """No valid envelope possible: crash or fail-closed refusal."""


def _parse_args(args: List[str]):
    """Strict argument parsing: an unknown option or a valued flag missing its
    value is a usage error (exit 4) — never silently ignored. Silent fallbacks
    here could turn an explicitly requested audit log or offline run into an
    unlogged or online one, so the adapter refuses instead.

    Returns (input_path, flags, values)."""
    flags, values, positional = set(), {}, []
    i = 0
    while i < len(args):
        a = args[i]
        if a in _VALUED_FLAGS:
            if i + 1 >= len(args) or args[i + 1].startswith("--"):
                raise _InputError(f"option {a} requires a value")
            values[a] = args[i + 1]
            i += 2
        elif a in _KNOWN_FLAGS:
            flags.add(a)
            i += 1
        elif a.startswith("--"):
            raise _InputError(f"unknown option: {a}")
        else:
            positional.append(a)
            i += 1
    if len(positional) != 1:
        raise _InputError("exactly one input path (or '-') is required")
    return positional[0], flags, values


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _allow_private_networks() -> bool:
    """Explicit opt-in only (mirrors mcp_server): the restricted public-network
    policy is the default and is never inherited from a permissive default."""
    value = os.environ.get("ADVERSARIAL_RESEARCH_AUDIT_ALLOW_PRIVATE_NETWORKS", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


class AuditLog:
    """Append-only JSONL audit log, one JSON object per line, keyed by trace_id.

    Every write appends (never rewrites); callers decide whether a write
    failure is fatal (fail-closed) or best-effort.
    """

    def __init__(self, path: Optional[str]):
        self._path = path
        self._fh = None
        if path:
            # Open in append mode once; "a" never truncates existing content.
            self._fh = open(path, "a", encoding="utf-8")

    def write(self, event: str, trace_id: str, **fields) -> None:
        if self._fh is None:
            return
        record = {"event": event, "ts": _now(), "trace_id": trace_id}
        record.update(fields)
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()
        # fsync so a crash cannot lose the audit trail while leaving an
        # "audited" exit code behind.
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def _load_report(path: str) -> dict:
    if path == "-":
        # Explicit UTF-8: never inherit a platform-dependent stdin encoding.
        try:
            raw = sys.stdin.buffer.read().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _InputError(f"stdin is not valid UTF-8: {exc}") from exc
    else:
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise _InputError(f"cannot read input: {exc}") from exc
    if len(raw) > MAX_INPUT_CHARS:
        raise _InputError(f"input too large ({len(raw)} chars, max {MAX_INPUT_CHARS})")
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _InputError(f"input is not valid JSON: {exc}") from exc
    return report


def run(argv: List[str]) -> int:
    try:
        input_path, flags, values = _parse_args(list(argv))
    except _InputError as exc:
        print(f"input-error: {exc}", file=sys.stderr)
        print("usage: cli_adapter.py <report.json | -> [options]; "
              "see module docstring for exit codes", file=sys.stderr)
        return EXIT_USAGE_ERROR

    quiet = "--quiet" in flags
    do_verify = "--verify-sources" in flags
    offline = "--offline" in flags
    cache_path = values.get("--cache")

    try:
        report = _load_report(input_path)
    except _InputError as exc:
        print(f"input-error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    trace_id = str(uuid.uuid4())
    try:
        log = AuditLog(values.get("--audit-log"))
    except OSError as exc:
        print(f"execution-error: cannot open audit log: {exc}", file=sys.stderr)
        return EXIT_EXECUTION_ERROR

    try:
        # Boundary 2 (fail-closed): the audit must not run unlogged. A failure
        # to record the run's start aborts it as an execution error, and a
        # failure to record the verification opt-out refuses it as a policy
        # denial (exit 5) — either way we never fabricate an envelope that
        # cannot be traced. Ruled in the issue #2 review.
        log.write("audit_started", trace_id, input=input_path,
                  verify_sources=do_verify, offline=offline)

        url_count = len(audit.collect_urls(report)) if isinstance(report, dict) else 0
        if url_count and not do_verify:
            try:
                log.write("verification_opt_out", trace_id,
                          reason="claim URLs present but --verify-sources not requested",
                          candidate_urls=url_count)
            except Exception as exc:  # noqa: BLE001
                # Fail closed. Without a recorded opt-out the run would be
                # untraceable, so audit nothing and emit no envelope. This is
                # a policy refusal, not a crash: the cause is a decision we
                # cannot evidence, which is a different fact from an engine
                # failure. Record the refusal best-effort, then stop.
                try:
                    log.write("audit_policy_denied", trace_id, error=repr(exc))
                except Exception:  # the refusal itself must still be visible
                    pass
                print(f"policy-denied: verification opt-out cannot be recorded "
                      f"({exc!r}); nothing audited, no envelope produced",
                      file=sys.stderr)
                return EXIT_POLICY_DENIED

        degraded_verification = False
        if do_verify:
            integ, degraded_verification = audit.verify_sources(
                report, offline=offline, cache_path=cache_path,
                allow_private_networks=_allow_private_networks(),
            )
            report.setdefault("integrity", {}).update(integ)

        envelope = audit.audit(report, trace_id=trace_id)
        if degraded_verification:
            envelope["degraded"] = True  # unknown checks — say so loudly

        log.write("audit_finished", trace_id,
                  verdict=envelope.get("outputs", {}).get("verdict"),
                  degraded=envelope.get("degraded"))
    except Exception as exc:  # noqa: BLE001 — execution error, not degraded
        try:
            log.write("audit_execution_error", trace_id, error=repr(exc))
        except Exception:  # the refusal itself must still be visible
            pass
        print(f"execution-error: {exc!r} (no envelope produced; "
              f"this is not DEGRADED)", file=sys.stderr)
        return EXIT_EXECUTION_ERROR
    finally:
        log.close()

    # stdout carries ONLY the unchanged JSON envelope (single line, machine-
    # readable); the human-readable rendering is available via audit.py.
    if not quiet:
        sys.stdout.write(json.dumps(envelope, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    verdict = envelope.get("outputs", {}).get("verdict")
    degraded = bool(envelope.get("degraded"))
    # Axis B in precedence order. `degraded` never upgrades or downgrades a
    # FAIL: 12 and 13 differ only in whether the sources behind that FAIL were
    # verifiable, which is information the caller is entitled to.
    if verdict == "FAIL":
        return EXIT_FAIL_DEGRADED if degraded else EXIT_FAIL
    if verdict == "PASS-WITH-CAVEAT":
        return EXIT_PASS_WITH_CAVEAT
    if verdict == "PASS":
        return EXIT_PASS_DEGRADED if degraded else EXIT_PASS
    # A syntactically valid envelope carrying no recognizable verdict means the
    # input was not an audit report. That is a usage error, not a verdict — and
    # we must not invent one in either direction.
    return EXIT_USAGE_ERROR


def main(argv: List[str]) -> int:
    # run() handles every failure mode internally and never raises
    # _ExecutionError; this wrapper exists so future callers get a stable
    # non-envelope error path if the contract grows.
    try:
        return run(argv)
    except _ExecutionError as exc:
        print(f"execution-error: {exc}", file=sys.stderr)
        return EXIT_EXECUTION_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
