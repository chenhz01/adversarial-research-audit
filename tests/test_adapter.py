"""Tests for the real LLM Wiki adapter (adapters/llm_wiki.py).
Builds a temp project matching nashsu/llm_wiki's documented structure."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "adapters"))

import audit  # noqa: E402
import llm_wiki  # noqa: E402


def build_project(root: Path, *, orphan_citation=False, dangling=False, stale=False):
    src = root / "raw" / "sources"
    src.mkdir(parents=True)
    (src / "paper-a.md").write_text("source A", encoding="utf-8")
    (src / "paper-b.md").write_text("source B", encoding="utf-8")
    (src / "paper-c.md").write_text("never cited", encoding="utf-8")

    wiki = root / "wiki"
    (wiki / "entities").mkdir(parents=True)
    (wiki / "concepts").mkdir(parents=True)
    (wiki / "index.md").write_text("# catalog\n", encoding="utf-8")
    (wiki / "log.md").write_text("- ingest paper-a\n", encoding="utf-8")
    (wiki / "overview.md").write_text("global summary\n", encoding="utf-8")

    dangling_link = "\nSee [[Nope]] for details.\n" if dangling else ""
    (wiki / "entities" / "Karpathy.md").write_text(
        "---\ntype: entity\ntitle: Karpathy\nsources:\n  - paper-a.md\n---\n"
        "# Karpathy\nHe proposed the LLM Wiki pattern." + dangling_link,
        encoding="utf-8")

    refs = "  - paper-b.md\n"
    if orphan_citation:
        refs += "  - ghost-paper.md\n"
    (wiki / "concepts" / "WikiPattern.md").write_text(
        "---\ntype: concept\ntitle: Wiki Pattern\nsources:\n" + refs + "---\n"
        "# Wiki Pattern\nIncremental compilation of knowledge.\n",
        encoding="utf-8")

    if stale:
        # make the summary older than the source it cites
        import os, time
        old = time.time() - 10_000
        os.utime(wiki / "concepts" / "WikiPattern.md", (old, old))


class TestAdapter(unittest.TestCase):
    def test_clean_project_passes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "my-wiki"
            build_project(root)
            data = llm_wiki.to_audit_input(root)
            ex = data["wiki_extras"]
            self.assertEqual(ex["pages_total"], 2)        # index/log/overview skipped
            self.assertEqual(ex["sources_total"], 3)
            self.assertEqual(ex["uncited_sources"], 1)    # paper-c.md
            out = audit.audit(data)
            self.assertEqual(out["outputs"]["verdict"], "PASS")
            self.assertEqual(out["outputs"]["gates_passed"], "6/6")

    def test_orphan_citation_fails_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "my-wiki"
            build_project(root, orphan_citation=True)
            data = llm_wiki.to_audit_input(root)
            self.assertEqual(len(data["integrity"]["orphan_citations"]), 1)
            out = audit.audit(data)
            self.assertEqual(out["outputs"]["verdict"], "FAIL")
            self.assertIn("gate6", out["outputs"]["failed_gates"])

    def test_dangling_link_fails_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "my-wiki"
            build_project(root, dangling=True)
            data = llm_wiki.to_audit_input(root)
            self.assertEqual(data["integrity"]["dangling_links"], 1)
            out = audit.audit(data)
            self.assertEqual(out["outputs"]["verdict"], "FAIL")

    def test_stale_page_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "my-wiki"
            build_project(root, stale=True)
            data = llm_wiki.to_audit_input(root)
            self.assertGreaterEqual(len(data["integrity"]["stale_pages"]), 1)

    def test_backward_compat_plain_report_stays_five_gates(self):
        plain = {"source_of_set": {"method": "api"},
                 "coverage": {"examined": 1, "total": 1},
                 "clusters": [{"name": "x", "count": 1}],
                 "claims": [{"id": "c1", "count": 1, "sources": []}]}
        out = audit.audit(plain)
        self.assertEqual(out["outputs"]["gates_passed"], "5/5")


if __name__ == "__main__":
    unittest.main()
