"""Simple dependency-free RAG index."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

TOKEN_RE = re.compile(r"[a-z0-9_]+", re.IGNORECASE)


def _tokenize(text: str) -> List[str]:
    return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]


def _tf(tokens: List[str]) -> Dict[str, float]:
    if not tokens:
        return {}
    counts: Dict[str, int] = {}
    for token in tokens:
        counts[token] = counts.get(token, 0) + 1
    total = float(len(tokens))
    return {token: count / total for token, count in counts.items()}


@dataclass(slots=True)
class Document:
    doc_id: str
    text: str
    tf: Dict[str, float]


class RAGIndex:
    """Small TF-IDF retriever for markdown/text/json content."""

    def __init__(self, sources: Iterable[Path] | None = None):
        self.docs: List[Document] = []
        self.df: Dict[str, int] = {}
        if sources:
            self.add_sources(sources)

    def add_text(self, doc_id: str, text: str) -> None:
        tokens = _tokenize(text)
        tf = _tf(tokens)
        self.docs.append(Document(doc_id=doc_id, text=text, tf=tf))
        for token in tf:
            self.df[token] = self.df.get(token, 0) + 1

    def _iter_source_files(self, source: Path) -> Iterable[Path]:
        if source.is_file():
            yield source
            return
        if source.is_dir():
            for path in source.rglob("*"):
                if path.is_file():
                    yield path

    def add_source(self, source: Path) -> None:
        if not source.exists():
            return
        for path in self._iter_source_files(source):
            if path.suffix.lower() not in {".md", ".txt", ".json", ".yaml", ".yml"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                # Best-effort indexing: unreadable files are intentionally skipped.
                continue  # nosec B112
            self.add_text(str(path), text)

    def add_sources(self, sources: Iterable[Path]) -> None:
        for source in sources:
            self.add_source(source)

    def search(self, query: str, limit: int = 5) -> List[str]:
        query_tokens = _tokenize(query)
        if not query_tokens or not self.docs:
            return []
        query_tf = _tf(query_tokens)
        total_docs = max(len(self.docs), 1)
        ranked: List[Tuple[float, str]] = []

        for doc in self.docs:
            score = 0.0
            for token, q_weight in query_tf.items():
                if token not in doc.tf:
                    continue
                idf = math.log((total_docs + 1) / (self.df.get(token, 0) + 1)) + 1.0
                score += q_weight * doc.tf[token] * idf
            if score > 0:
                snippet = doc.text[:600].replace("\n", " ").strip()
                ranked.append((score, f"{doc.doc_id}: {snippet}"))

        ranked.sort(key=lambda row: row[0], reverse=True)
        return [snippet for _, snippet in ranked[:limit]]
