# adversarial-research-audit

**Audit layer for agentic research tools: catch coverage fraud and evidence hygiene failures before they reach your knowledge base.**

The agentic-research ecosystem is booming: agents crawl, synthesize, and deposit "knowledge" into wikis and reports. What none of them do is *adversarially check their own output*. The result is knowledge bases that look trustworthy and are unauditable.

This project is the missing audit layer — cheap, mechanical, and dependency-free. It checks the five ways a research report lies without technically lying:

| Gate | Fraud it catches |
|---|---|
| 1 · Full-set source | Set came from a curated HTML page (featured list ≠ full set) |
| 2 · Coverage arithmetic | Examined items not fully accounted for by claims + unjudged |
| 3 · Cluster arithmetic | Cluster counts that don't add up to the examined total |
| 4 · Filter provenance | 249 of 260 items silently dropped, no criteria logged |
| 5 · Unjudged listed | Partial coverage with an empty "couldn't judge" list |
| **6 · Integrity** *(armed when verification data is present)* | **Cited sources that don't exist, dangling links, stale summaries, dead URLs, hash drift** |

Plus per-claim verdicts: `verified` (≥2 independent sources) / `single-source` / `unverifiable`. Duplicate sources (same URL or name) count once — a mirror is not an independent source.

## Beyond arithmetic: real source verification

Two additions turn this from a checklist into actual verification:

**`verify.py` — source authenticity.** HTTP HEAD → content SHA-256, with on-disk caching, size caps, and honest failure semantics:

```
[ALIVE] https://example.com/a   status=200 sha256=9f2c1ab3c4d5 …
[DEAD ] https://example.com/b   status=404 http-404
[UNKNWN] https://example.com/c  status=None proxy-or-gateway-503: transport failed
```

Three honesty rules baked in:
- **Transport failure ≠ dead source.** A proxy/gateway 502/503/504 or a missing network yields `ok=None` (unknown) and marks the audit `degraded` — never "the source is dead".
- **Loopback bypasses egress proxies.** A sandbox/corporate `HTTP_PROXY` would otherwise turn every localhost check into a 502.
- **Hash drift is reported, not ignored.** Pass a recorded hash to detect silent content changes.

**`adapters/llm_wiki.py` — real adapter for [nashsu/llm_wiki](https://github.com/nashsu/llm_wiki) (18.9k★).** Grounded in that project's actual contract (`raw/sources/` → `wiki/{entities,concepts,sources,synthesis,comparisons}/`, YAML frontmatter with `sources[]`, `[[wikilink]]` cross-references), it verifies things arithmetic cannot:

- **Orphan citations** — a wiki page citing a source file that does not exist
- **Uncompiled sources** — raw sources no page ever cites (reported as a note, not a failure)
- **Dangling wikilinks** — `[[Page]]` pointing at nothing
- **Stale summaries** — source file newer than the page that summarizes it

```bash
python adapters/llm_wiki.py /path/to/my-wiki --audit      # → FAIL 5/6, gate6 names the real defects
python adapters/llm_wiki.py /path/to/my-wiki --json out.json
```

Shipped demo: `examples/llm-wiki-demo/` contains a deliberate ghost citation and a dangling link — run the command above against it to see gate 6 fire.

> **Honest boundary**: this tool audits *coverage arithmetic and evidence hygiene*. It does **not** verify that a cited source actually exists or says what the report claims — source authenticity is out of scope (see `protocols/audit-protocol.md` → Non-goals).

## The one-line pitch

> A report without `coverage: N/N` is a hypothesis, not a result.

## Usage

### CLI (zero dependencies, Python 3.8+)

```bash
python audit.py examples/fraudulent_report.json   # → FAIL (exit 1), shows all 5 gate violations
python audit.py examples/clean_report.json        # → PASS (exit 0)
```

```
verdict: FAIL  (0/5 gates passed)
  [FAIL] gate1 full-set source: set came from a curated HTML page — …
  [FAIL] gate2 coverage: examined (11) != accounted items …
  [FAIL] gate3 clusters: sum of cluster counts (10) != examined (11) — …
  [FAIL] gate4 filters: 249 items were dropped (11/260) but no filters entry explains the criteria
  [FAIL] gate5 unjudged: coverage is partial but 'unjudged' list is empty/missing …
claims: 0 verified / 1 single-source / 1 unverifiable
action: regenerate the report at full coverage; a disclaimer is not a fix
```

### MCP server (zero dependencies)

Expose the auditor to any MCP-compatible agent host:

```json
{
  "mcpServers": {
    "adversarial-research-audit": {
      "command": "python",
      "args": ["/path/to/mcp_server.py"]
    }
  }
}
```

The host gets one tool, `audit_report`: pass the report JSON, receive the verdict. `tools/call` returns `isError: true` for `FAIL` verdicts so agents can react.

### Pipeline integration

Output uses a standard message envelope (`engine` / `version` / `inputs` / `outputs` / `confidence` / `degraded` / `trace_id`) — see `protocols/audit-protocol.md`. `degraded: true` means the audit itself was partial; downstream must not treat it as a clean verdict.

## Why "regenerate", not "annotate"

A failed report can't be patched with a disclaimer — conclusions drawn from a biased subset can be wrong in ways the disclaimer doesn't reveal. The only fix is re-running at full coverage. That's deliberate: expense is what teaches agents to count first.

## Works with

Drop this into the pipeline of any research-aggregation tool (wiki-builders, research agents, report generators) as the last step before persistence. If your tool emits structured reports, writing an `audit-input-v1` adapter is ~20 lines.

## Collaboration / 合作

MIT, free to use. If your agent pipeline emits research reports at volume and you
want this audit layer wired into it — or you want the gates tuned to *your*
corpus, format and failure modes — write to **hcac4735@agent.qq.com** with the
subject `[adversarial-research-audit]`, or open an issue.

## License

MIT
