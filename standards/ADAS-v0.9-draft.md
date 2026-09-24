# Agent Delivery Acceptance Standard (ADAS) — v0.9 DRAFT

> **Status**: Public draft for comment (L1 — public spec, not yet adopted)
> **Author**: Chen (@chenhz01) · zhengming system · hcac4735@agent.qq.com
> **Origin**: Extracted from 100+ days of production agent-harness operations (516 skills, 74 governance rules, adversarial audit tooling)
> **Feedback**: Open an issue on this repo, or comment on the linked real-world audit.
> **Versioning**: SemVer. v1.0 freezes after first external review round.

---

## 0. Why this standard exists

AI agents increasingly *deliver work* (code, reports, audits, fixes). But there is no shared
contract for what "done" means. Today:

- Agents report success with no verifiable artifact.
- Silent failures (timeout, empty output, swallowed exceptions) are reported as success.
- Self-review is accepted as proof (the self-certification trap).
- Deleted/hidden work leaves no trace, so acceptance is unfalsifiable.

This standard defines the **minimum acceptance contract** between an agent (or agent operator)
and a receiver (human, CI pipeline, or another agent). It is deliberately small: 6 requirements,
each independently testable.

## 1. The Six Requirements

### R1 — Three-State Reporting (no silent success)

Every task outcome MUST be reported as exactly one of:

| State | Meaning | Required evidence |
|---|---|---|
| `SUCCESS` | Completed as specified | Artifact path + verification command output |
| `EXPLICIT_FAILURE` | Attempted, failed | Failure reason + reproduction command |
| `SILENT_TIMEOUT` | No trustworthy response within budget | Treated as **failure by default** |

*Rationale*: `return None`, empty `except: pass`, and unanswered timeouts are the three most
common false-success patterns observed in production harnesses. All three collapse into
`EXPLICIT_FAILURE`/`SILENT_TIMEOUT`.

### R2 — Artifact Rule (done means written, not said)

A task MAY be marked `SUCCESS` only if its deliverable is **written to a durable artifact**
(file, commit, database row) AND the report contains the artifact path. A verbal/report-only
claim of completion is `EXPLICIT_FAILURE` by definition.

### R3 — Independent Verifier Rule (no self-certification)

Acceptance decisions MUST be produced by a verifier that does **not share context or memory
with the producer**. The verifier asserts: exit code = 0, artifact exists, stdout contains a
pre-declared assertion string. A producer's own claim about its work is admissible as
*description*, never as *evidence*.

### R4 — Advisory-Not-Mandatory Rule (verifiers never auto-execute)

An automated verifier MAY flag (`FAIL`/`WARN`), but MUST NOT directly trigger irreversible
actions (delete, publish, push, reject, ban). Human review is required for every irreversible
consequence. *Rationale*: false positives are unavoidable; automating enforcement converts
verification errors into damages.

### R5 — Identity & Provenance Rule

- Deliverables involving commits MUST use an author identity bound to a real account
  (noreply identity or verified email); unbound identities make contributions invisible in
  audit graphs.
- Any packaged deliverable MUST be scanned for sensitive fields (`api_key`, `secret`,
  `token`, `credential`, `password`, chain-of-thought dumps) before delivery; scan result
  MUST be recorded.

### R6 — Coverage Honesty Rule

Any batch claim (tests run, files audited, issues reviewed) MUST state coverage as `N/N`.
Sampling MAY be used only when explicitly labeled (`sampled: N of M, selection method: ...`).

## 2. Conformance

A delivery conforms to ADAS v0.9 iff: all six requirements are satisfied and each is backed by
a machine-checkable evidence string (command + output excerpt) included in the delivery report.

Minimum evidence set (the "ADAS receipt"):

```text
STATE: SUCCESS
ARTIFACT: <path or commit sha>
VERIFY: <command>
OUTPUT: <first line(s) of verification output>
COVERAGE: N/N  (or: sampled N/M, method)
IDENTITY: <author email, bound: yes/no>
SENSITIVE_SCAN: clean | findings:<list>
```

## 3. Reference Implementation & First Real Audit

- Tooling: `audit.py`, `adapters/` in this repository (adversarial-research-audit).
- First public application: **audit of obra/superpowers issue #2332** (missing durable
  QA/acceptance artifact between plans and PRs — exactly the gap R1/R2 address). Pre-audit:
  [`audits/superpowers-2332-preaudit.md`](../audits/superpowers-2332-preaudit.md).

## 4. Relationship to Other Specs

- **Skill governance** (skill-spec, skill-audit-kit, skill-scorecard): ADAS is the delivery
  contract; skill governance is the producer-side quality system. A companion chapter is planned.
- **Prompt source packaging** (agentsrc): manifest MAY embed an ADAS receipt per release.

## 5. Changelog

- v0.9 (2026-09-24): first public draft. Six requirements extracted from production rules
  (three-state reporting, artifact rule, independent verifier, advisory-not-mandatory,
  identity/provenance, coverage honesty).
