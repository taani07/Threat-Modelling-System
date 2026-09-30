"""BM25 keyword ranking, implemented from the formula.

BM25(q, d) = sum over terms t in q of
    IDF(t) * tf(t,d) * (k1 + 1) / (tf(t,d) + k1 * (1 - b + b * |d| / avgdl))

IDF(t) = ln(1 + (N - n(t) + 0.5) / (n(t) + 0.5))

Why keep keyword search in a RAG system? Embeddings are great at meaning ("SQL injection" ~
"unsanitised query") and bad at exact identifiers ("CWE-89", "CVE-2021-44228", "log4j-core").
Security text is full of identifiers.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Keep identifiers like cwe-89 and cve-2021-44228 as single tokens.
TOKEN_RE = re.compile(r"[a-z]+-\d+(?:-\d+)?|[a-z0-9]+(?:[._][a-z0-9]+)*")

STOPWORDS = frozenset(
    "a an and are as at be by for from has have in into is it its of on or that the this "
    "to was were will with can not no".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]


class BM25Index:
    def __init__(self, corpus: list[list[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.doc_freqs = [Counter(doc) for doc in corpus]
        self.doc_lens = [len(doc) for doc in corpus]
        self.n_docs = len(corpus)
        self.avgdl = (sum(self.doc_lens) / self.n_docs) if self.n_docs else 0.0
        df: Counter[str] = Counter()
        for doc in corpus:
            df.update(set(doc))
        self.idf = {
            term: math.log(1 + (self.n_docs - n + 0.5) / (n + 0.5)) for term, n in df.items()
        }

    def score(self, query_tokens: list[str], i: int) -> float:
        tf = self.doc_freqs[i]
        norm = self.k1 * (1 - self.b + self.b * self.doc_lens[i] / (self.avgdl or 1.0))
        total = 0.0
        for term in query_tokens:
            freq = tf.get(term, 0)
            if freq:
                total += self.idf[term] * freq * (self.k1 + 1) / (freq + norm)
        return total

    def search(self, query: str, k: int = 10) -> list[tuple[int, float]]:
        tokens = tokenize(query)
        scored = [(i, self.score(tokens, i)) for i in range(self.n_docs)]
        scored = [s for s in scored if s[1] > 0]
        scored.sort(key=lambda s: s[1], reverse=True)
        return scored[:k]
