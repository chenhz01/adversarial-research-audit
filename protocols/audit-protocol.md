# The Adversarial Research Audit Protocol (v1.0)

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
