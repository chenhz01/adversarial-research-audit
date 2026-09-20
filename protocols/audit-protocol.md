# The Adversarial Research Audit Protocol (v1.1)

Agentic research tools (crawl → synthesize → wiki) produce knowledge bases that *look* trustworthy. This protocol is the missing layer: it audits those outputs for the five ways they lie without technically lying.

## Input contract

An audit input is a JSON document describing a research report:

```jsonc
{
  "title": "Audit of 260 browser extensions",
  "source_of_set": {                      // gate 1
    "method": "api | script | filesystem | html-page",
    "description": "WebExtensions API export, 2026-09-12"
  },
  "coverage": { "examined": 260, "total": 260 },   // gate 2
  "clusters": [                                    // gate 3
    { "name": "ad-blockers", "count": 40 },
    { "name": "password-managers", "count": 12 }
  ],
  "filters": [                                     // gate 4 (optional)
    { "criteria": "removed items with <1000 users", "removed": 31 }
  ],
  "claims": [                                      // claim-level sourcing
    {
      "id": "c1",
      "count": 40,                                 // optional: items this claim accounts for
      "text": "40/40 ad-blockers publish source",
      "sources": [
        { "name": "official docs", "url": "https://…" },
        { "name": "repo manifest", "url": "https://…" }
      ]
    }
  ],
  "unjudged": ["ext-259"]                          // gate 5 (required if examined < total)
}
```

## The five gates

| # | Gate | Fail condition |
|---|---|---|
| 1 | **Full-set source** | Set came from a curated page (`html-page`) — featured lists are biased subsets |
| 2 | **Coverage arithmetic** | `Σ(claim counts, default 1) + len(unjudged) != examined`, or `examined > total`, or missing — every examined item must be explicitly accounted for |
| 3 | **Cluster arithmetic** | Σ(cluster counts) != examined — the addition must reconcile exactly |
| 4 | **Filter provenance** | Items were removed (`examined < total`) but no `filters` entry explains them |
| 5 | **Unjudged listed** | `examined < total` but `unjudged` is empty/missing |

## Claim-level verdicts

Every claim is judged independently:

- **verified** — ≥ 2 sources
- **single-source** — exactly 1 source (usable, but labeled)
- **unverifiable** — 0 sources (cannot be used as evidence)

## Report verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | 5/5 gates pass — publishable |
| `PASS-WITH-CAVEAT` | Only gate 5 fails — publishable after adding `unjudged:` |
| `FAIL` | Any other gate fails — the report must be **regenerated at full coverage**, not annotated |

Why regenerate rather than disclaim? Because conclusions drawn from a biased subset can be wrong in ways no disclaimer reveals. Expense is the teacher.

## Execution status and exit codes

Two axes, deliberately orthogonal: **execution status** describes how the run
terminated; the **envelope** describes what the audit found. A completed run
can carry a business failure, and a run that produced no artifact cannot carry
a verdict at all.

**Axis A — execution status:**

| Status | Meaning |
|---|---|
| `SUCCESS` | Completed and emitted a valid envelope. An artifact exists, and it may itself be an explicit failure artifact. |
| `EXPLICIT_FAILURE` | Terminated with a named reason; the reason is carried in the record. |
| `SILENT_TIMEOUT` | Ended without a positive artifact. Never reported as a verdict. |
| `USAGE_ERROR` | Malformed input; no audit attempted. |
| `POLICY_DENIED` | A refusal could not be recorded; fail closed. |

**Axis B — envelope fields (the envelope itself is unchanged):**
`outputs.verdict` ∈ {`PASS`, `PASS-WITH-CAVEAT`, `FAIL`}, `degraded` ∈
{`true`, `false`}.

Exit-code precedence is deterministic, first match wins:

| Exit | Execution status | Envelope | verdict | degraded | Reading |
|---|---|---|---|---|---|
| 0  | SUCCESS          | present  | PASS              | false | clean pass |
| 10 | SUCCESS          | present  | PASS              | true  | pass, sources unverified |
| 11 | SUCCESS          | present  | PASS-WITH-CAVEAT  | any   | pass with named caveats |
| 12 | SUCCESS          | present  | FAIL              | false | business FAIL, artifact present |
| 13 | SUCCESS          | present  | FAIL              | true  | business FAIL + unverified sources |
| 2  | EXPLICIT_FAILURE | present  | —                 | —     | named failure, reason carried |
| 3  | SILENT_TIMEOUT   | absent   | —                 | —     | no artifact, so not a verdict |
| 4  | USAGE_ERROR      | absent   | —                 | —     | malformed input |
| 5  | POLICY_DENIED    | absent   | —                 | —     | refusal not recordable, fail closed |

Three rules fall out of the table:

- A completed run with an artifact can still be a business `FAIL`. Exit 12
  exists precisely so that "the audit ran fine and found a failure" is never
  confused with "the audit failed to run" (exit 3).
- A timeout without a valid envelope is an execution state, not an audit
  verdict — never `degraded`, and never `UNAUDITED`-by-assumption.
- `degraded` never upgrades or downgrades a `FAIL`. Exits 12 and 13 differ
  only in whether the sources behind that failure were verifiable.

**Reference implementation status.** `cli_adapter.py` implements this table.
Exit 2 is not emitted by any current path: `EXPLICIT_FAILURE` means "a named
failure that still carries an artifact", and the adapter has no such path today
(a crash produces no artifact, so it exits 3). The number is reserved rather
than reassigned, so the table's numbering cannot drift by accident.

## Output contract

The auditor emits a standard message envelope so pipelines can chain it:

```json
{
  "engine": "adversarial-research-audit",
  "version": "1.0.0",
  "inputs":  { "type": "json", "schema": "audit-input-v1" },
  "outputs": { "type": "json", "schema": "audit-output-v1" },
  "confidence": 0.0,
  "degraded": false,
  "trace_id": "<uuid>"
}
```

`degraded: true` means the audit itself was partial (e.g., input malformed) — downstream consumers must not treat it as a clean verdict.

## Non-goals

- Fact-checking the *content* of claims against the world (that needs the sources themselves)
- Plagiarism / style analysis
- Scoring writing quality

This protocol only audits the **coverage and evidence hygiene** of a research report. It is cheap, mechanical, and catches the most common lies.

## Changelog

| Version | Change |
|---|---|
| v1.0 | The five gates, claim-level verdicts, report verdicts, output envelope. |
| v1.1 | Added **Execution status and exit codes**: execution status split from the envelope's `verdict` / `degraded` fields, with a deterministic exit-code table. Triggered by external review (issue #2) — without it, "the audit could not run" and "the audit found a failure" were the same signal to a pipeline. |
