#!/usr/bin/env python3
"""adversarial-research-audit — audit agentic research reports for coverage
and evidence hygiene (see protocols/audit-protocol.md).

Usage:
    python audit.py <report.json> [--json out.json] [--quiet]

Exit codes: 0 = PASS / PASS-WITH-CAVEAT, 1 = FAIL, 2 = bad usage / malformed input.

Zero dependencies. Python 3.8+.
"""
from __future__ import annotations

import json
import sys
import uuid

ENGINE = "adversarial-research-audit"
VERSION = "1.1.0"


# ---------------------------------------------------------------- gates

def gate_full_set_source(report: dict) -> tuple[bool, str]:
    src = report.get("source_of_set") or {}
    method = str(src.get("method", "")).lower()
    if not method:
        return False, "gate1 full-set source: missing source_of_set.method"
    if method == "html-page":
        return False, (
            "gate1 full-set source: set came from a curated HTML page — "
            "featured lists are biased subsets; enumerate via api/script/filesystem"
        )
    return True, f"gate1 ok (method={method})"


def gate_coverage(report: dict) -> tuple[bool, str]:
    cov = report.get("coverage")
    if not isinstance(cov, dict):
        return False, "gate2 coverage: missing coverage {examined, total}"
    examined, total = cov.get("examined"), cov.get("total")
    if not isinstance(examined, int) or not isinstance(total, int):
        return False, "gate2 coverage: examined/total must be integers"
    if not (0 < examined <= total):
        return False, f"gate2 coverage: examined ({examined}) must be in 1..{total}"
    claims, unjudged = report.get("claims", []), report.get("unjudged", [])
    accounted = sum(
        c.get("count", 1) if isinstance(c, dict) else 1 for c in claims
    ) + len(unjudged)
    if examined != accounted:
        return False, (
            f"gate2 coverage: examined ({examined}) != accounted items "
            f"(claims+counts {accounted - len(unjudged)} + unjudged {len(unjudged)}) "
            f"— every examined item must be explicitly accounted for"
        )
    return True, f"gate2 ok (examined {examined}/{total}, all accounted)"


def gate_cluster_arithmetic(report: dict) -> tuple[bool, str]:
    clusters = report.get("clusters", [])
    if not clusters:
        return True, "gate3 clusters: none declared (skipped)"
    examined = (report.get("coverage") or {}).get("examined")
    cluster_sum = sum(c.get("count", 0) for c in clusters if isinstance(c, dict))
    if examined is None:
        return False, "gate3 clusters: cannot verify without coverage.examined"
    if cluster_sum != examined:
        return False, (
            f"gate3 clusters: sum of cluster counts ({cluster_sum}) != "
            f"examined ({examined}) — show the addition in the report"
        )
    return True, f"gate3 ok ({' + '.join(str(c.get('count', 0)) for c in clusters)} = {cluster_sum})"


def gate_filter_provenance(report: dict) -> tuple[bool, str]:
    cov = report.get("coverage") or {}
    examined, total = cov.get("examined"), cov.get("total")
    if examined is None or total is None or examined >= total:
        return True, "gate4 filters: nothing removed (skipped)"
    filters = report.get("filters")
    if not filters:
        return False, (
            f"gate4 filters: {total - examined} items were dropped "
            f"({examined}/{total}) but no filters entry explains the criteria"
        )
    return True, f"gate4 ok ({len(filters)} filter(s) documented)"


def gate_unjudged(report: dict) -> tuple[bool, str]:
    cov = report.get("coverage") or {}
    examined, total = cov.get("examined"), cov.get("total")
    if examined is None or total is None or examined >= total:
        return True, "gate5 unjudged: full coverage (skipped)"
    unjudged = report.get("unjudged")
    if unjudged is None or len(unjudged) == 0:
        return False, (
            "gate5 unjudged: coverage is partial but 'unjudged' list is "
            "empty/missing — omissions must be explicit"
        )
    return True, f"gate5 ok ({len(unjudged)} item(s) listed)"


def gate_integrity(report: dict) -> tuple[bool, str]:
    """Gate 6 — only active when the input carries `integrity` data (adapters
    and --verify-sources produce it). This is where arithmetic hygiene becomes
    real verification: sources that do not exist, pages citing missing files,
    dangling links, stale summaries, dead URLs."""
    integ = report.get("integrity")
    if integ is None:
        return True, "gate6 integrity: no verification data supplied (skipped)"
    problems = []
    orphan = integ.get("orphan_citations") or []
    if orphan:
        problems.append(f"{len(orphan)} page(s) cite sources that do not exist")
    dangling = integ.get("dangling_links")
    n_dangling = len(dangling) if isinstance(dangling, list) else (dangling or 0)
    if n_dangling:
        problems.append(f"{n_dangling} dangling link(s)")
    stale = integ.get("stale_pages") or []
    if stale:
        problems.append(f"{len(stale)} stale page(s) (source changed after the summary)")
    sv = integ.get("source_verification") or {}
    if sv.get("dead"):
        problems.append(f"{sv['dead']} cited URL(s) are dead/unreachable")
    if sv.get("hash_drift"):
        problems.append(f"{sv['hash_drift']} source(s) failed content-hash check")
    uncited = integ.get("uncited_sources") or []
    note = f" (note: {len(uncited)} source(s) never compiled)" if uncited else ""
    if problems:
        return False, "gate6 integrity: " + "; ".join(problems) + note
    return True, "gate6 integrity: citations, links and hashes verified" + note


GATES = [
    ("gate1", gate_full_set_source),
    ("gate2", gate_coverage),
    ("gate3", gate_cluster_arithmetic),
    ("gate4", gate_filter_provenance),
    ("gate5", gate_unjudged),
]


# ---------------------------------------------------------------- claims

def judge_claims(report: dict) -> list[dict]:
    verdicts = []
    for c in report.get("claims", []):
        # dedupe sources: same URL or same name counts once — a mirror is not
        # an independent source (red-team finding PATCH-001)
        seen: set = set()
        unique = 0
        for s in c.get("sources", []):
            if not isinstance(s, dict):
                continue
            key = (s.get("url") or s.get("name") or "")
            if key and key in seen:
                continue
            seen.add(key)
            unique += 1
        if unique >= 2:
            verdict, confidence = "verified", 0.9
        elif unique == 1:
            verdict, confidence = "single-source", 0.55
        else:
            verdict, confidence = "unverifiable", 0.1
        verdicts.append(
            {"id": c.get("id"), "verdict": verdict, "confidence": confidence,
             "sources": unique}
        )
    return verdicts


# ---------------------------------------------------------------- engine

def audit(report: dict, trace_id: str | None = None) -> dict:
    """Run all gates. Returns the standard message envelope. Never raises on
    malformed input — returns a degraded envelope instead."""
    trace_id = trace_id or str(uuid.uuid4())
    envelope = {
        "engine": ENGINE,
        "version": VERSION,
        "inputs": {"type": "json", "schema": "audit-input-v1"},
        "outputs": {"type": "json", "schema": "audit-output-v1"},
        "confidence": 0.0,
        "degraded": False,
        "trace_id": trace_id,
    }
    if not isinstance(report, dict):
        envelope.update(degraded=True, outputs={"error": "input is not a JSON object"})
        return envelope

    gate_results, failed = [], []
    # gate6 (integrity) is armed only when the input carries verification data
    gates = GATES + ([("gate6", gate_integrity)] if "integrity" in report else [])
    for name, fn in gates:
        try:
            ok, msg = fn(report)
        except Exception as exc:  # defensive: a broken gate must not crash the audit
            ok, msg = False, f"{name} raised: {exc!r}"
        gate_results.append({"gate": name, "ok": ok, "message": msg})
        if not ok:
            failed.append(name)

    n_pass = sum(1 for g in gate_results if g["ok"])
    if not failed:
        verdict = "PASS"
        confidence = 0.9
    elif failed == ["gate5"]:
        verdict = "PASS-WITH-CAVEAT"
        confidence = 0.65
    else:
        verdict = "FAIL"
        confidence = 0.95

    claim_verdicts = judge_claims(report)
    counts = {v: sum(1 for c in claim_verdicts if c["verdict"] == v)
              for v in ("verified", "single-source", "unverifiable")}

    envelope["confidence"] = confidence
    envelope["outputs"] = {
        "verdict": verdict,
        "gates_passed": f"{n_pass}/{len(gate_results)}",
        "gates": gate_results,
        "failed_gates": failed,
        "claim_verdicts": claim_verdicts,
        "claim_summary": counts,
        "title": report.get("title", "(untitled)"),
    }
    return envelope


def render_text(out: dict) -> str:
    o = out.get("outputs", {})
    lines = [f"{ENGINE} v{VERSION} — trace {out.get('trace_id', '-')[:8]}"]
    lines.append(f"report: {o.get('title', '-')}")
    lines.append(f"verdict: {o.get('verdict')}  ({o.get('gates_passed')} gates passed)")
    for g in o.get("gates", []):
        mark = "PASS" if g["ok"] else "FAIL"
        lines.append(f"  [{mark}] {g['message']}")
    cs = o.get("claim_summary", {})
    lines.append(f"claims: {cs.get('verified', 0)} verified / "
                 f"{cs.get('single-source', 0)} single-source / "
                 f"{cs.get('unverifiable', 0)} unverifiable")
    if out.get("degraded"):
        lines.append("WARNING: audit degraded — treat verdict as unreliable")
    if o.get("verdict") == "FAIL":
        lines.append("action: regenerate the report at full coverage; a disclaimer is not a fix")
    return "\n".join(lines)


def collect_urls(report: dict) -> list:
    """All http(s) source URLs referenced by claims."""
    urls = []
    for c in report.get("claims", []):
        for s in c.get("sources", []):
            if isinstance(s, dict):
                u = s.get("url") or ""
                if isinstance(u, str) and u.lower().startswith(("http://", "https://")):
                    urls.append(u)
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def verify_sources(report: dict, offline: bool = False,
                   cache_path: str | None = None,
                   allow_private_networks: bool = False) -> tuple[dict, bool]:
    """Run the source verifier over claim URLs. Returns (integrity_blob, degraded)."""
    from verify import SourceVerifier

    urls = collect_urls(report)
    if not urls:
        return {"note": "no http(s) source URLs to verify"}, False
    v = SourceVerifier(
        cache_path=cache_path,
        offline=offline,
        allow_private_networks=allow_private_networks,
    )
    results = v.verify_many(urls)
    s = v.summary(results)
    dead = [r["url"] for r in results if r.get("ok") is False]
    unknown = [r["url"] for r in results if r.get("ok") is None]
    integ = {
        "source_verification": {
            "total": s["total"], "alive": s["alive"], "dead": s["dead"],
            "unknown": s["unknown"], "hash_drift": s["hash_drift"],
            "dead_urls": dead, "unknown_urls": unknown,
        }
    }
    return integ, s["degraded"]


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    quiet = "--quiet" in argv
    json_out = None
    if "--json" in argv:
        i = argv.index("--json")
        json_out = argv[i + 1] if i + 1 < len(argv) else None
    cache_path = None
    if "--cache" in argv:
        i = argv.index("--cache")
        cache_path = argv[i + 1] if i + 1 < len(argv) else None
    do_verify = "--verify-sources" in argv
    offline = "--offline" in argv
    if not args:
        print(__doc__)
        return 2
    try:
        with open(args[0], encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"malformed input: {exc}", file=sys.stderr)
        return 2

    degraded_verification = False
    if do_verify:
        integ, degraded_verification = verify_sources(report, offline=offline,
                                                     cache_path=cache_path)
        report.setdefault("integrity", {}).update(integ)

    envelope = audit(report)
    if degraded_verification:
        envelope["degraded"] = True          # network unavailable → say so loudly
    text = render_text(envelope)
    if not quiet:
        print(text)
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2, ensure_ascii=False)
    verdict = envelope.get("outputs", {}).get("verdict")
    return 0 if verdict in ("PASS", "PASS-WITH-CAVEAT") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
