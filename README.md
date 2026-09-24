# adversarial-research-audit

> **Catch AI research reports that lie without lying — mechanical gates, zero dependencies**

机械闸门抓『没撒谎但撒谎』的研究报告：覆盖率算术/簇求和/过滤溯源/引用完整性（吸收 resilient-agent-toolkit 1&2 / trending-scout）

## Install (one line)
```bash
pip install adversarial-research-audit
```

## Why not X?
| | ARA | 人工审阅 |
|---|---|---|
| 速度 | 机械闸门秒级 | 小时级 |
| 稳定 | 规则可复现 | 因人而异 |

Topics: `ai-audit` · `research-integrity` · `agent` · `cli` · `zero-dependency`

---

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
[ALIVE  ] https://example.com/a  status=200 sha256=9f2c1ab3c4d5 …
[DEAD   ] https://example.com/b  status=404 http-404
[UNKNOWN] https://example.com/c  status=None proxy-or-gateway-503: transport failed
[BLOCKED] http://127.0.0.1/x     status=None policy-blocked: resolves only to non-public address(es)
```

Four outcomes, not two. Every result carries `outcome` ∈
`alive | dead | unknown | blocked`, and `ok` is its liveness projection
(`True` / `False` / `None`, where `None` covers both `unknown` and `blocked`):

- **`alive`** — the URL resolved and its content was hashed.
- **`dead`** — a definite answer that the source is not retrievable (e.g. 404).
- **`unknown`** — the transport failed, timed out, or the configuration was
  refused. Honest refusal to claim either way, never "the source is dead".
- **`blocked`** — a policy decision not to access the source. This is definite,
  but it establishes **nothing about liveness**, so it is reported separately
  and never aggregated as `dead`. Failing a run on a policy block is the
  explicit opt-in `fail_on_policy_block=True` (`--fail-on-policy-block`), never
  an emergent artefact of the aggregation.

Honesty rules baked in:
- **Transport failure ≠ dead source.** A proxy/gateway 502/503/504 or a missing network yields `outcome=unknown` and marks the audit `degraded` — never "the source is dead".
- **A body that never arrived is not a success.** If HEAD answers but the GET fails (timeout, TLS, redirect loop), the verification degrades to `unknown` instead of inheriting the HEAD stage's success.
- **A proxy is rejected, not silently trusted.** A configured proxy (explicit or from the environment) performs the DNS lookup itself, so address validation and the DNS-rebinding pin cannot run. Under the restricted default the verifier refuses that configuration with `proxy-policy-unsupported` rather than falling back to an unpinned opener; `allow_private_networks=True` is the explicit opt-in that accepts the weaker guarantee. Loopback and `NO_PROXY`-matched URLs never traverse an egress proxy and keep the pinned path.
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

> **Honest boundary**: this tool audits *coverage arithmetic and evidence hygiene* — including whether cited sources **exist** (via `verify.py`: HTTP status + content SHA-256; mirrors are never double-counted as independent). It does **not** establish *source independence* between two verified sources, nor whether the cited content actually **supports** the claim it is attached to — content fact-checking is out of scope (see `protocols/audit-protocol.md` → Non-goals). A passing audit is evidence hygiene, not factual verification of the report's claims.

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
    "research_audit": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/chenhz01/adversarial-research-audit.git@<commit-sha>",
        "adversarial-research-audit-mcp"
      ]
    }
  }
}
```

Replace `<commit-sha>` with a reviewed immutable revision. For local development,
`uvx --from /path/to/adversarial-research-audit adversarial-research-audit-mcp`
uses the checkout directly.

The host gets one tool, `audit_report`: pass the `audit-input-v1` report JSON and
receive the complete `audit-output-v1` envelope in both text and MCP
`structuredContent`. A report verdict of `FAIL` is a successful tool call whose
`outputs.verdict` is `FAIL`; MCP `isError` is reserved for invalid arguments or
execution failures.

Set `verify_sources: true` in the tool arguments to fetch public HTTP(S) claim
sources and arm gate 6. Transport failures remain `unknown` and set
`degraded: true`; they are never counted as dead links. Policy-blocked sources
are reported separately as `blocked` in `integrity.source_verification`
(`blocked` / `blocked_urls`) and are likewise never counted as dead — a policy
decision not to access a source is not evidence that it is dead. MCP source
verification blocks loopback, private, link-local, reserved, and other
non-public addresses, including redirect targets, and refuses a proxy
configuration under the restricted default (`proxy-policy-unsupported`) rather
than running an unpinned transport. Operators who intentionally audit trusted
intranet URLs may set `ADVERSARIAL_RESEARCH_AUDIT_ALLOW_PRIVATE_NETWORKS=1` in
the MCP server environment. This opt-in permits server-side requests to private
networks and should not be enabled for untrusted report inputs.

The MCP input is capped at 1,000,000 JSON characters. `verify_sources` defaults
to `false`, so enabling the server alone performs no outbound requests.

### Pipeline integration

Output uses a standard message envelope (`engine` / `version` / `inputs` / `outputs` / `confidence` / `degraded` / `trace_id`) — see `protocols/audit-protocol.md`. `degraded: true` means the audit itself was partial; downstream must not treat it as a clean verdict.

### CLI adapter for shell / CI pipelines

`cli_adapter.py` is the shell/CI counterpart of the MCP server: it emits the
same unchanged JSON envelope on stdout (single line, machine-readable) while
all diagnostics go to stderr, and it keeps an append-only JSONL audit log
keyed by `trace_id` (`--audit-log PATH`). Exit codes follow the protocol's
two-axis table — **execution status** (how the run ended) is separate from
`outputs.verdict` / `degraded` (what the audit found):

| Exit | Execution status | Envelope | verdict | degraded | Reading |
|------|------------------|----------|---------|----------|---------|
| 0  | SUCCESS | present | PASS | false | clean pass |
| 10 | SUCCESS | present | PASS | true | pass, sources unverified |
| 11 | SUCCESS | present | PASS-WITH-CAVEAT | any | pass with named caveats |
| 12 | SUCCESS | present | FAIL | false | business FAIL, artifact present |
| 13 | SUCCESS | present | FAIL | true | business FAIL + unverified sources |
| 2  | EXPLICIT_FAILURE | present | — | — | named failure, reason carried (reserved; no current path) |
| 3  | SILENT_TIMEOUT | absent | — | — | no artifact: crash or failed start — never `DEGRADED` |
| 4  | USAGE_ERROR | absent | — | — | malformed input, or an envelope carrying no verdict |
| 5  | POLICY_DENIED | absent | — | — | a refusal we could not record; fail closed |

The normative table lives in `protocols/audit-protocol.md` § "Execution status
and exit codes". `degraded` never upgrades or downgrades a `FAIL`: 12 and 13
differ only in whether the sources behind that failure were verifiable.

If recording a verification opt-out fails, the adapter fails closed (exit 5,
nothing audited) rather than producing an envelope that cannot be traced. That
is a *policy* refusal, not a crash — the exit code is different because "we
refused to proceed without a trail" and "the engine broke" are different facts.
The adapter introduces no envelope semantics: `coverage` data is forwarded to
the engine untouched, and an unknown candidate total is never replaced by the
observed set size (see the core-contract discussion in issue #2). Source
verification uses the same restricted public-network policy as the MCP server
(`ADVERSARIAL_RESEARCH_AUDIT_ALLOW_PRIVATE_NETWORKS=1` to opt in explicitly).

```bash
python cli_adapter.py report.json --verify-sources --audit-log audit.jsonl
cat report.json | python cli_adapter.py - --quiet   # CI: no stdout, exit code only
```

Argument parsing is strict: an unknown option, or a valued flag missing its
value (e.g. `--audit-log` with no path), is a usage error (exit 4) — never a
silent fallback, because a silently dropped `--audit-log` or `--offline`
would defeat the audit trail or trigger unexpected online verification.

(`audit.py`, the original text-output CLI, keeps its simple `0`/`1`/`2` codes
unchanged for backwards compatibility. The two-axis table above is the contract
for the pipeline-facing adapter, `cli_adapter.py`.)


## Why "regenerate", not "annotate"

A failed report can't be patched with a disclaimer — conclusions drawn from a biased subset can be wrong in ways the disclaimer doesn't reveal. The only fix is re-running at full coverage. That's deliberate: expense is what teaches agents to count first.

## Works with

Drop this into the pipeline of any research-aggregation tool (wiki-builders, research agents, report generators) as the last step before persistence. If your tool emits structured reports, writing an `audit-input-v1` adapter is ~20 lines.

## Collaboration / 合作

MIT, free to use — the code is complete, not a teaser. What a collaboration
unlocks is the part that **cannot** live in a public repo:

- **Integration** — this audit layer wired into *your* pipeline: custom
  adapters for your report format, CI/PR gating, MCP deployment.
- **Calibration** — gates tuned to *your* corpus, formats and real failure
  modes, instead of the generic defaults shipped here.
- **Hardening** — embedding-based source verification and dead-link sweeps at
  production scale for compliance-heavy environments.

Write to **hcac4735@agent.qq.com** with the subject
`[adversarial-research-audit collaboration]`, or open an issue.

## License

MIT
