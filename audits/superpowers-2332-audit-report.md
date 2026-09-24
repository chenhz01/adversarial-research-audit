# Audit Report: obra/superpowers #2332 — Durable QA/Acceptance Artifact Layer

> **Audit ID**: ADAS-AUDIT-2026-001 (execution of the [pre-audit framework](superpowers-2332-preaudit.md))
> **Date**: 2026-09-24 · **Auditor**: @chenhz01 (independent; no maintainer role in obra/superpowers)
> **Target**: https://github.com/obra/superpowers/issues/2332 (open) · Related: #2342
> **Standard applied**: [ADAS v0.9 draft](../standards/ADAS-v0.9-draft.md) (R1 three-state, R2 artifact rule)
> **Versions examined**: vendored v6.3.0 (2026-08-12, the version the issue was filed against) **and** upstream HEAD v6.4.1 (`5bf4e78`, 2026-09-19) — version sensitivity disclosed in §6.

## 1. Verdict Summary

| Claim | v6.3.0 | HEAD v6.4.1 | Basis |
|---|---|---|---|
| C1 — no durable QA/acceptance artifact between plan approval and PR | **CONFIRMED** | **PARTIALLY CONFIRMED** (real improvement; terminal evidence still does not survive) | §3.1, §3.2 |
| C2 — last output line treated as the test-result signal | **CONFIRMED** | **MITIGATED** on the inline path (gate is a real exit code); residual gap in the ledger's evidence field | §3.3 |
| C3 — masked failure reportable as success | **CONFIRMED** (mechanism reproduced) | **LARGELY CLOSED** on inline path; two residual gaps | §3.4 |

**Overall**: the issue remains valid and should stay open. v6.4.1's native-execution rebuild (shipped one day after the issue) closes the in-session discipline gap but not the issue's core ask: a **terminal** QA/acceptance artifact that survives the workflow and ties acceptance to an exact revision.

## 2. Method (falsifiable)

1. Read `skills/executing-plans/SKILL.md` at both versions (v6.3.0 vendored; HEAD via Contents API, 2026-09-24).
2. Read upstream `skills/executing-plans/scripts/task-done` (HEAD) line by line.
3. Controlled experiment **EXP-001**: a 2-task plan with a deliberately deceptive test script (prints `All tests passed (34/34)` as its **last line**, exits **1**), plus a control task. Three passes: naive last-line reading; exit-code gate; gate-vs-evidence divergence.
4. Counter-evidence: upstream commits touching `executing-plans` since 2026-09-18 (1: the v6.4.1 release commit); code search `repo:obra/superpowers qa-artifact` → **0 hits**; issue thread (6 comments) read in full.

## 3. Findings

### 3.1 C1 on v6.3.0 — CONFIRMED
The v6.3.0 skill produces **no file whatsoever** between "plan approved" and "PR opened": progress lives in harness todos ("Mark as completed"), completion in chat. Directory contains only `SKILL.md`. Repo-wide search for any qa/acceptance artifact mechanism: 0 hits. EXP-001 file inventory after execution: only incidental files, no structured artifact.

### 3.2 C1 on HEAD v6.4.1 — PARTIALLY CONFIRMED
v6.4.1 adds a real durable layer: plan-scoped workspace `.superpowers/sdd/<plan>/`, ledger `progress.md`, and `task-done` which **keeps the full test output** (`task-N-tests.log`) and appends a completion line only when tests pass. Genuine progress. Three residuals, each quotable:

1. **Failure records nothing.** Script comment: "A failing run records nothing: the task is not complete." After a session loss, a ledger cannot distinguish *never ran* from *ran and failed* — the EXPLICIT_FAILURE state required by ADAS R1 is absent.
2. **The workspace is deleted on success.** Skill text: "When the final review is clean … delete this plan's workspace." The ledger and every test log — the only acceptance evidence tied to the revision range recorded in each line — are destroyed exactly when acceptance is granted. The surviving record is the chat message, which the issue itself identifies as insufficient.
3. **No terminal disposition artifact** (merge/accept/defer tied to revision) exists outside the deleted workspace. This is the issue's core ask and it remains unmet.

### 3.3 C2 — CONFIRMED on v6.3.0, MITIGATED at HEAD (inline path)
v6.3.0 defines no machine-checkable success signal; "Run verifications as specified" leaves signal interpretation to the model (the mechanism behind #2342). At HEAD, `task-done` gates on the command's real exit status (`rc=$?; [ "$rc" -ne 0 ] && exit "$rc"`), not output text — EXP-001 Pass B confirms the deceptive script is refused (exit 1, nothing recorded).

**Residual (new, minor)**: the ledger's evidence field is the **last non-empty line of output**, not the exit code:
```bash
last=$(grep -v '^[[:space:]]*$' "$log" | tail -n 1)
line="Task $n: complete (commits …, tests: $cmd → $last)"
```
EXP-001 Pass C: a script that prints `1 test failed: auth_edge_case` and exits **0** passes the gate and is ledgered as `tests: tricky.sh → 1 test failed: …` — a success line containing failure text. The gate is sound; the recorded evidence is cosmetic and can contradict it.

### 3.4 C3 — mechanism CONFIRMED; largely closed at HEAD
EXP-001 Pass A reproduces the masked-success mechanism end to end: `bash verify.sh | tail -1` yields "All tests passed (34/34)" with pipeline exit code 0. At HEAD the inline path requires the machine gate before any completion line, closing the main hole; residuals are the §3.2 failure-invisibility gap and the §3.3 cosmetic-evidence gap.

## 4. Fix Direction (updated, ADAS-aligned)

The pre-audit's `qa-artifact.json` proposal stands, with three amendments driven by v6.4.1:

1. Write it **outside the deleted workspace** (e.g. repo-root `.qa/`, committed with the branch) so acceptance evidence survives the workflow — ADAS R2.
2. Record `EXPLICIT_FAILURE` rows on failing runs (currently "records nothing") — ADAS R1 three-state.
3. Make the ledger evidence field structural (`exit_code`, `cmd`), not `tail -n 1` — closes the Pass-C divergence.

This is minimal: it wraps the existing `task-done`, which already collects everything needed.

## 5. Version-Sensitivity Disclosure

Our 2026-09-23 comment on #2342 analyzed the pre-v6.4.1 behavior. v6.4.1 (2026-09-19) materially changed `executing-plans`; findings there should be re-checked against the current release. We flag this ourselves rather than wait for it to be found.

## 6. Provenance & Reproducibility

- All upstream reads via GitHub Contents API on 2026-09-24 (~22:35 GMT+8); vendored v6.3.0 retained at `vendor/superpowers-external` in a private working copy.
- EXP-001 scripts are 10 lines of bash, reproduced verbatim in this report's method section; any party can rerun in under a minute.
- Counter-evidence timestamps: commits query `since=2026-09-18T00:00:00Z` → 1 commit (`5bf4e78`, release v6.4.1); code search 0 hits; issue thread last comment 2026-09-21.
- Confidence: verdicts 0.9+ (direct code reads + controlled experiment). Limitation: we audited the inline (`executing-plans`) path only; `subagent-driven-development` shares the workspace/ledger scripts and is expected to behave similarly but was not separately exercised.
- Independence: auditor holds no role, no funding relationship, and runs no automated action against the target repository (ADAS R3/R4).
