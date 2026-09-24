# Pre-Audit: obra/superpowers #2332 — Durable QA/Acceptance Artifact

> **Audit ID**: ADAS-AUDIT-2026-001
> **Standard applied**: [ADAS v0.9 draft](../standards/ADAS-v0.9-draft.md) (R1, R2)
> **Target**: https://github.com/obra/superpowers/issues/2332
> **Related**: #2342 (executing-plans misreads last log line as test result — same root cause)
> **Auditor**: @chenhz01 (independent, no maintainer role in obra/superpowers)
> **Status**: PRE-AUDIT (framework + evidence collection plan; execution run requires local
> superpowers environment, scheduled next session)

## 1. Scope

superpowers `executing-plans` workflow: what durable artifact exists between "plan approved"
and "PR opened"? The issue reports there is none — workflow state lives in transcript text,
so acceptance is unfalsifiable after the session ends.

## 2. Claims Under Test

| # | Claim (from issue + our #2342 reproduction) | ADAS clause |
|---|---|---|
| C1 | No durable QA/acceptance artifact is produced between plan approval and PR | R2 (artifact rule) |
| C2 | Last log line of executing-plans is treated as the test result signal | R1 (three-state: false SUCCESS) |
| C3 | A masked failure can therefore be reported as success | R1 (silent failure collapse) |

## 3. Execution Plan (falsifiable)

1. Install superpowers in isolated harness; run `executing-plans` on a plan containing a
   deliberately failing step (control: passing step).
2. Capture: (a) whether a structured artifact file is written (expect: no → C1 confirmed);
   (b) the success-detection mechanism (expect: last-line heuristic → C2 confirmed);
   (c) whether the failing run reports `SUCCESS` (expect: yes → C3 confirmed).
3. Cross-check: grep implementation for the success signal parser; quote exact lines.
4. Counter-evidence check (before concluding): search repo for any existing QA-artifact
   mechanism added after the issue was filed.

## 4. Proposed Fix Direction (aligned with ADAS)

A minimal `qa-artifact.json` written at plan-execution end: `{plan, steps, each: {state:
SUCCESS|EXPLICIT_FAILURE, verify_cmd, output_excerpt}}` — satisfying R1+R2 without changing
superpowers' architecture. This is also the design already offered in our #2342 comment.

## 5. Provenance

- Evidence so far: our independent reproduction of #2342 on Node v22 (see issue comment,
  2026-09-23); third-party reproduction by @Navaneethp007 (2026-09-19).
- No maintainer relationship with obra/superpowers. Audit performed under ADAS R3/R4:
  findings are advisory; no automated action taken against the target repository.
