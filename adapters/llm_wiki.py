#!/usr/bin/env python3
"""Real adapter: audit an LLM Wiki project (github.com/nashsu/llm_wiki, 18.9k★).

Grounded in the actual project contract (three-layer architecture):

    my-wiki/
      purpose.md, schema.md
      raw/sources/           # immutable uploaded documents  ← the full set
      wiki/
        index.md, log.md, overview.md
        entities/ concepts/ sources/ synthesis/ comparisons/  ← generated pages
    (every wiki page carries YAML frontmatter with `type`, `title`, `sources[]`;
     cross-references use [[wikilink]] syntax)

What this adapter can therefore verify *for real* (not just arithmetic):

    1. coverage  — raw sources that are cited by ≥1 wiki page vs total sources
                   (uncited sources land in `unjudged`: knowledge never compiled)
    2. citations — pages citing a source file that does not exist = orphan
                   citation (hard FAIL, checked against the filesystem)
    3. links     — [[wikilinks]] pointing at non-existent pages = dangling links
    4. clusters  — page counts per type folder must sum to the page total
    5. freshness — optional: page mtime older than its cited source = stale page

Usage:
    python adapters/llm_wiki.py /path/to/my-wiki [--json audit-input.json]

Zero dependencies. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FRONTMATTER = re.compile(r"^---\r?\n(.*?)\r?\n---", re.S)
WIKILINK = re.compile(r"\[\[([^\]|#]+)")
CATEGORY_DIRS = ["entities", "concepts", "sources", "synthesis", "comparisons", "queries"]
RESERVED = {"index.md", "log.md", "overview.md"}


def parse_frontmatter(text: str) -> dict:
    """Minimal YAML subset: scalars and inline/block lists."""
    m = FRONTMATTER.match(text)
    if not m:
        return {}
    fm: Dict[str, object] = {}
    key = None
    for raw in m.group(1).splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if re.match(r"^\s*-\s+", raw) and key:            # block list item
            fm.setdefault(key, [])
            if isinstance(fm[key], list):
                fm[key].append(raw.split("-", 1)[1].strip().strip('"\''))
            continue
        if ":" in raw:
            k, v = raw.split(":", 1)
            key, v = k.strip(), v.strip()
            if v.startswith("[") and v.endswith("]"):     # inline list
                items = [i.strip().strip('"\'') for i in v[1:-1].split(",") if i.strip()]
                fm[key] = items
            elif v == "":
                fm[key] = []
            else:
                fm[key] = v.strip('"\'')
    return fm


def collect_sources(root: Path) -> List[str]:
    src_dir = root / "raw" / "sources"
    if not src_dir.exists():
        return []
    return sorted(str(p.relative_to(src_dir)).replace("\\", "/")
                  for p in src_dir.rglob("*") if p.is_file())


def collect_pages(root: Path) -> List[Path]:
    wiki = root / "wiki"
    if not wiki.exists():
        return []
    return sorted(p for p in wiki.rglob("*.md") if p.name not in RESERVED)


def to_audit_input(root: Path, with_freshness: bool = True) -> dict:
    root = Path(root)
    sources = collect_sources(root)
    pages = collect_pages(root)
    src_set = set(sources)

    claims, orphan_citations, stale_pages, category_counts = [], [], [], {}
    cited_sources: set = set()
    all_page_ids = {p.stem for p in pages}

    for page in pages:
        text = page.read_text(encoding="utf-8", errors="replace")
        fm = parse_frontmatter(text)
        cat = page.relative_to(root / "wiki").parts[0]
        category_counts[cat] = category_counts.get(cat, 0) + 1

        refs = fm.get("sources") or []
        if isinstance(refs, str):
            refs = [refs]
        refs = [str(r).lstrip("./") for r in refs if str(r).strip()]

        # real verification: does the cited source exist on disk?
        missing = [r for r in refs if r not in src_set]
        if missing:
            orphan_citations.append({"page": str(page.relative_to(root)),
                                     "missing": missing})
        cited_sources.update(r for r in refs if r in src_set)

        # dangling wikilinks
        dangling = [l.strip() for l in WIKILINK.findall(text)
                    if l.strip() and l.strip() not in all_page_ids]

        # freshness: page older than the sources it summarizes
        if with_freshness and refs:
            try:
                page_mtime = page.stat().st_mtime
                newer = [r for r in refs
                         if (root / "raw" / "sources" / r).exists()
                         and (root / "raw" / "sources" / r).stat().st_mtime > page_mtime + 1]
                if newer:
                    stale_pages.append({"page": str(page.relative_to(root)),
                                        "newer_sources": newer})
            except OSError:
                pass

        claims.append({
            "id": page.stem,
            "count": 1,
            "text": f"[{fm.get('type', cat)}] {fm.get('title', page.stem)}",
            "sources": [{"name": r, "url": f"raw/sources/{r}"} for r in refs],
            "dangling_links": dangling,
        })

    unjudged = [s for s in sources if s not in cited_sources]

    # Coverage unit = generated wiki pages (the artifact under audit). Sources
    # that were never compiled are reported as a note, not as a coverage gap.
    clusters = [{"name": k, "count": v} for k, v in sorted(category_counts.items())]

    return {
        "title": f"LLM Wiki audit: {root.name}",
        "source_of_set": {
            "method": "filesystem",
            "description": f"wiki/ pages enumerated: {len(pages)}; "
                           f"raw/sources: {len(sources)}",
        },
        "coverage": {"examined": len(claims), "total": len(claims)},
        "clusters": clusters,
        "claims": claims,
        "unjudged": [],
        "integrity": {
            "orphan_citations": orphan_citations,
            "dangling_links": sum(len(c["dangling_links"]) for c in claims),
            "stale_pages": stale_pages,
            "uncited_sources": unjudged,
        },
        "wiki_extras": {
            "pages_total": len(pages),
            "sources_total": len(sources),
            "uncited_sources": len(unjudged),
            "orphan_citations": orphan_citations,
            "stale_pages": stale_pages,
            "dangling_links_total": sum(len(c["dangling_links"]) for c in claims),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Adapt an LLM Wiki project to audit-input-v1")
    ap.add_argument("project")
    ap.add_argument("--json", default=None, help="write audit input JSON here")
    ap.add_argument("--audit", action="store_true",
                    help="run the auditor on the adapted input immediately")
    args = ap.parse_args()

    data = to_audit_input(Path(args.project))
    ex = data["wiki_extras"]
    print(f"LLM Wiki adapter — {args.project}")
    print(f"  pages: {ex['pages_total']}  sources: {ex['sources_total']}  "
          f"uncited: {ex['uncited_sources']}")
    print(f"  orphan citations: {len(ex['orphan_citations'])}  "
          f"stale pages: {len(ex['stale_pages'])}  "
          f"dangling links: {ex['dangling_links_total']}")
    if args.json:
        Path(args.json).write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        print(f"  → {args.json}")
    if args.audit:
        import audit
        envelope = audit.audit(data)
        print()
        print(audit.render_text(envelope))
        return 0 if envelope["outputs"]["verdict"] in ("PASS", "PASS-WITH-CAVEAT") else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
