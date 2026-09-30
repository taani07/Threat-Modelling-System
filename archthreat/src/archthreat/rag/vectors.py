"""Brute-force cosine similarity search with numpy.

For a few thousand chunks, brute force is exact and fast (one matrix-vector product).
Approximate indexes (HNSW in pgvector/OpenSearch, IVF in FAISS) only pay off at hundreds of
thousands of vectors; see docs/adr/0003-vector-store.md.
"""

from __future__ import annotations

import numpy as np


def normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=-1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    a_n, b_n = np.linalg.norm(a), np.linalg.norm(b)
    if a_n == 0 or b_n == 0:
        return 0.0
    return float(np.dot(a, b) / (a_n * b_n))


class VectorIndex:
    def __init__(self, embeddings: np.ndarray) -> None:
        if embeddings.ndim != 2:
            raise ValueError("embeddings must be a 2-D array (n_chunks, dims)")
        self.matrix = normalize(embeddings.astype(np.float32))

    @property
    def dims(self) -> int:
        return int(self.matrix.shape[1])

    def search(self, query: np.ndarray, k: int = 10) -> list[tuple[int, float]]:
        q = normalize(np.asarray(query, dtype=np.float32).reshape(1, -1))[0]
        if q.shape[0] != self.dims:
            raise ValueError(f"query has {q.shape[0]} dims, index has {self.dims}")
        sims = self.matrix @ q
        k = min(k, len(sims))
        top = np.argpartition(-sims, k - 1)[:k] if k else np.array([], dtype=int)
        top = top[np.argsort(-sims[top])]
        return [(int(i), float(sims[i])) for i in top]
