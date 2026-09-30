"""KnowledgeIndex: builds, persists and searches the security knowledge base.

Search runs up to three rankers and fuses them with RRF:
  1. BM25 keywords          (exact identifiers: CWE-89, log4j-core)
  2. vector similarity      (meaning: "unsanitised input in SQL" ~ "SQL injection")
  3. metadata tag match     (chunks whose doc is tagged with the finding's CWE)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from archthreat.llm.base import Embedder
from archthreat.rag.bm25 import BM25Index, tokenize
from archthreat.rag.chunking import Chunk, chunk_document, load_markdown_docs
from archthreat.rag.hybrid import reciprocal_rank_fusion
from archthreat.rag.vectors import VectorIndex

MANIFEST = "manifest.json"
CHUNKS = "chunks.jsonl"
VECTORS = "embeddings.npy"

# Weighted RRF. Metadata matches on CWE/CVE identifiers are high-precision evidence, so the
# tag ranker counts double (carried over from VulnLens, where evals showed it was needed).
RANKER_WEIGHTS = {"bm25": 1.0, "vector": 1.0, "tag": 2.0}


@dataclass
class RetrievedChunk:
    chunk: Chunk
    score: float
    rank: int
    methods: list[str]


def _embed_text(chunk: Chunk) -> str:
    # Prepend title + section so a chunk's embedding knows what it is about
    # (a cheap version of Anthropic's "contextual retrieval" idea).
    return f"{chunk.title} | {chunk.section}\n{chunk.text}"


class KnowledgeIndex:
    def __init__(
        self,
        chunks: list[Chunk],
        embedder: Embedder | None = None,
        embeddings: np.ndarray | None = None,
    ) -> None:
        self.chunks = chunks
        self.embedder = embedder
        self.bm25 = BM25Index([tokenize(_embed_text(c)) for c in chunks])
        self.vectors: VectorIndex | None = None
        if embedder is not None:
            if embeddings is None:
                embeddings = np.array(embedder.embed([_embed_text(c) for c in chunks]))
            self.vectors = VectorIndex(embeddings)

    # ---------- build / persist ----------

    @classmethod
    def build(cls, knowledge_dir: str | Path, embedder: Embedder | None) -> KnowledgeIndex:
        chunks = [c for doc in load_markdown_docs(knowledge_dir) for c in chunk_document(doc)]
        if not chunks:
            raise ValueError(f"no markdown documents found in {knowledge_dir}")
        return cls(chunks, embedder)

    @staticmethod
    def corpus_hash(knowledge_dir: str | Path) -> str:
        h = hashlib.sha256()
        for p in sorted(Path(knowledge_dir).glob("*.md")):
            h.update(p.name.encode())
            h.update(p.read_bytes())
        return h.hexdigest()[:16]

    def save(self, directory: str | Path, corpus_hash: str = "") -> None:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / CHUNKS).open("w", encoding="utf-8") as fh:
            for c in self.chunks:
                fh.write(json.dumps(c.to_dict()) + "\n")
        if self.vectors is not None:
            np.save(directory / VECTORS, self.vectors.matrix)
        manifest = {
            "embedder": self.embedder.name if self.embedder else None,
            "embed_model": self.embedder.model if self.embedder else None,
            "dims": self.vectors.dims if self.vectors else None,
            "n_chunks": len(self.chunks),
            "corpus_hash": corpus_hash,
        }
        (directory / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, directory: str | Path, embedder: Embedder | None) -> KnowledgeIndex:
        directory = Path(directory)
        manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
        if embedder is not None and manifest.get("embed_model") != embedder.model:
            # Vectors from different models live in different spaces. Mixing them silently
            # returns garbage, so fail loudly instead.
            raise ValueError(
                f"index was built with '{manifest.get('embed_model')}' but the current embedder "
                f"is '{embedder.model}'. Delete the index directory to rebuild."
            )
        chunks = [
            Chunk(**json.loads(line))
            for line in (directory / CHUNKS).read_text(encoding="utf-8").splitlines()
        ]
        vectors_path = directory / VECTORS
        embeddings = np.load(vectors_path) if embedder and vectors_path.exists() else None
        return cls(chunks, embedder, embeddings)

    @classmethod
    def load_or_build(
        cls, knowledge_dir: str | Path, index_dir: str | Path, embedder: Embedder | None
    ) -> KnowledgeIndex:
        corpus = cls.corpus_hash(knowledge_dir)
        manifest_path = Path(index_dir) / MANIFEST
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            same_model = manifest.get("embed_model") == (embedder.model if embedder else None)
            if manifest.get("corpus_hash") == corpus and same_model:
                return cls.load(index_dir, embedder)
        index = cls.build(knowledge_dir, embedder)
        index.save(index_dir, corpus)
        return index

    # ---------- search ----------

    @staticmethod
    def tag_weight(tag: str) -> int:
        """Identifier tags are strong evidence, category tags are weak."""
        tag = tag.upper()
        if tag.startswith("CVE-"):
            return 3
        if tag.startswith("CWE-"):
            return 2
        return 1

    def _tag_ranking(self, tags: list[str]) -> list[int]:
        """Rank chunks by weighted tag overlap, then by tag specificity.

        A doc tagged only [sca, dependencies] is *about* dependency findings; a doc tagged
        [CWE-502, CWE-20, sast, sca] merely *mentions* them. So among equal overlaps, docs
        with fewer tags rank higher.
        """
        wanted = {t.upper() for t in tags}
        scored = []
        for i, chunk in enumerate(self.chunks):
            chunk_tags = {t.upper() for t in chunk.tags}
            overlap = wanted & chunk_tags
            if overlap:
                weight = sum(self.tag_weight(t) for t in overlap)
                scored.append((-weight, len(chunk_tags), i))
        return [i for _, _, i in sorted(scored)]

    def search(
        self, query: str, k: int = 5, tags: list[str] | None = None, candidates: int = 20
    ) -> list[RetrievedChunk]:
        rankings: dict[str, list[int]] = {
            "bm25": [i for i, _ in self.bm25.search(query, candidates)]
        }
        if self.vectors is not None and self.embedder is not None:
            qvec = np.array(self.embedder.embed([query])[0])
            rankings["vector"] = [i for i, _ in self.vectors.search(qvec, candidates)]
        if tags:
            tagged = self._tag_ranking(tags)
            if tagged:
                rankings["tag"] = tagged

        weights = [RANKER_WEIGHTS.get(name, 1.0) for name in rankings]
        fused = reciprocal_rank_fusion(list(rankings.values()), weights=weights)
        results: list[RetrievedChunk] = []
        for rank, (idx, score) in enumerate(fused[:k], start=1):
            methods = [name for name, ranking in rankings.items() if idx in ranking]
            results.append(RetrievedChunk(self.chunks[idx], score, rank, methods))
        return results
