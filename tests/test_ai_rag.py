"""Dedicated coverage for the dependency-free TF-IDF RAG index.

Pinned invariants:

1. The index gracefully handles missing inputs — empty index, empty
   query, missing file paths — without raising.
2. ``add_source`` only ingests the documented suffix allow-list and
   recurses into directories.
3. ``search`` ranks documents by TF-IDF, so a query that matches a
   distinctive token in only one document ranks that document above
   another that contains only common-to-both tokens.
4. ``search`` honours the ``limit`` argument.
5. Query and corpus tokenisation is case-insensitive.
6. The returned snippet format begins with the document id and
   contains a single-line summary of the document text.

These tests pin behaviour the copilot relies on (``RAGIndex.search``
feeds context into ``LLMProvider.complete``), so subtle regressions
in retrieval would otherwise only surface in copilot integration
output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.ai.rag import RAGIndex


# ---------------------------------------------------------------------------
# Empty / degenerate inputs
# ---------------------------------------------------------------------------


def test_empty_index_returns_no_results() -> None:
    index = RAGIndex()
    assert index.search("anything") == []


def test_empty_query_returns_no_results_even_with_docs() -> None:
    index = RAGIndex()
    index.add_text("doc-1", "the quick brown fox")
    assert index.search("") == []
    assert index.search("   ") == []


def test_query_with_no_matching_tokens_returns_empty() -> None:
    index = RAGIndex()
    index.add_text("doc-1", "alpha beta gamma")
    assert index.search("zeta") == []


# ---------------------------------------------------------------------------
# Source ingestion
# ---------------------------------------------------------------------------


def test_add_source_skips_missing_path(tmp_path: Path) -> None:
    """Non-existent sources are silently ignored (no exception)."""
    index = RAGIndex()
    index.add_source(tmp_path / "does-not-exist.md")
    assert index.search("anything") == []


def _snippet_doc_id(snippet: str) -> str:
    """Recover the doc_id from a search snippet.

    The snippet format is ``f"{doc_id}: {body}"`` and ``doc_id`` is the
    file path. On Windows that path contains a drive-letter colon, so a
    naive ``split(":", 1)`` is ambiguous — split on the literal ``": "``
    separator instead.
    """
    return snippet.rsplit(": ", 1)[0] if ": " in snippet else snippet.split(":", 1)[0]


def test_add_source_filters_by_extension(tmp_path: Path) -> None:
    """Only md / txt / json / yaml / yml are indexed; binaries are skipped."""
    (tmp_path / "kept.md").write_text("alpha included content", encoding="utf-8")
    (tmp_path / "skipped.bin").write_text("alpha binary blob", encoding="utf-8")
    (tmp_path / "skipped.py").write_text("alpha python source", encoding="utf-8")
    (tmp_path / "kept.txt").write_text("alpha plain text", encoding="utf-8")
    (tmp_path / "kept.yaml").write_text("alpha yaml doc", encoding="utf-8")

    index = RAGIndex([tmp_path])
    snippets = index.search("alpha", limit=10)
    sources = {_snippet_doc_id(snippet) for snippet in snippets}
    suffixes = {Path(src).suffix.lower() for src in sources}
    assert suffixes <= {".md", ".txt", ".json", ".yaml", ".yml"}
    # All three kept files with the matched token should appear.
    assert any(src.endswith("kept.md") for src in sources)
    assert any(src.endswith("kept.txt") for src in sources)
    assert any(src.endswith("kept.yaml") for src in sources)
    # Skipped extensions must not appear in the result set.
    assert not any(src.endswith("skipped.bin") for src in sources)
    assert not any(src.endswith("skipped.py") for src in sources)


def test_add_source_recurses_into_subdirectories(tmp_path: Path) -> None:
    nested = tmp_path / "nested" / "deeper"
    nested.mkdir(parents=True)
    (nested / "doc.md").write_text("nested keyword content", encoding="utf-8")

    index = RAGIndex([tmp_path])
    results = index.search("keyword")
    assert results, "expected nested document to be indexed"
    assert any("doc.md" in entry for entry in results)


def test_add_source_with_single_file_indexes_that_file(tmp_path: Path) -> None:
    file_path = tmp_path / "single.md"
    file_path.write_text("only document content", encoding="utf-8")

    index = RAGIndex([file_path])
    results = index.search("document")
    assert results
    assert results[0].startswith(str(file_path))


# ---------------------------------------------------------------------------
# Ranking / search semantics
# ---------------------------------------------------------------------------


def test_search_is_case_insensitive() -> None:
    index = RAGIndex()
    index.add_text("doc-1", "MITRE ATT&CK technique")
    upper = index.search("MITRE")
    lower = index.search("mitre")
    assert upper and lower
    assert upper == lower


def test_search_ranks_distinctive_token_above_common_token() -> None:
    """A query for a token unique to one doc must surface that doc first."""
    index = RAGIndex()
    index.add_text("common-1", "shared shared shared shared")
    index.add_text("common-2", "shared shared shared shared")
    index.add_text("distinct", "shared distinctive payload")

    results = index.search("distinctive")
    assert results, "expected a result for a token present in one document"
    assert results[0].startswith("distinct:"), (
        f"expected distinctive doc first, got: {results}"
    )


def test_search_honours_limit() -> None:
    index = RAGIndex()
    for idx in range(10):
        index.add_text(f"doc-{idx}", f"keyword body number {idx}")
    results = index.search("keyword", limit=3)
    assert len(results) == 3


def test_snippet_format_includes_doc_id_and_single_line_summary() -> None:
    index = RAGIndex()
    index.add_text("doc-fmt", "first line\nsecond line\nthird line")
    results = index.search("first")
    assert results
    snippet = results[0]
    assert snippet.startswith("doc-fmt:")
    # Snippet is collapsed to a single line — no embedded newlines.
    assert "\n" not in snippet


def test_snippet_truncates_long_documents() -> None:
    index = RAGIndex()
    long_text = "needle " + ("filler " * 500)
    index.add_text("doc-long", long_text)
    results = index.search("needle")
    assert results
    body = results[0].split(":", 1)[1].strip()
    # The snippet body cap is 600 chars in the implementation.
    assert len(body) <= 600


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_unreadable_file_does_not_break_indexing(tmp_path: Path, monkeypatch) -> None:
    """A read failure on one file must not prevent siblings from being indexed."""
    good = tmp_path / "good.md"
    bad = tmp_path / "bad.md"
    good.write_text("good keyword content", encoding="utf-8")
    bad.write_text("bad keyword content", encoding="utf-8")

    real_read_text = Path.read_text

    def flaky_read_text(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self == bad:
            raise OSError("simulated failure")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", flaky_read_text)

    index = RAGIndex([tmp_path])
    results = index.search("keyword", limit=10)
    sources = {_snippet_doc_id(entry) for entry in results}
    assert any(src.endswith("good.md") for src in sources)
    assert not any(src.endswith("bad.md") for src in sources)


@pytest.mark.parametrize(
    "extension",
    ["md", "txt", "json", "yaml", "yml"],
)
def test_each_supported_extension_is_indexed(
    tmp_path: Path, extension: str
) -> None:
    file_path = tmp_path / f"doc.{extension}"
    file_path.write_text("alpha content", encoding="utf-8")
    index = RAGIndex([tmp_path])
    assert index.search("alpha"), f"extension {extension} was not indexed"
