"""Reciprocal Rank Fusion (Cormack, Clarke & Buettcher, SIGIR 2009).

RRF(d) = sum over rankings r of 1 / (k + rank_r(d)),   rank starts at 1, k = 60 by default.

Why RRF instead of adding scores? BM25 scores are unbounded and cosine scores live in [-1, 1],
so adding them needs fragile normalisation. RRF only uses ranks, so it combines any number of
rankers with no tuning.
"""

from __future__ import annotations


def reciprocal_rank_fusion(
    rankings: list[list[int]], k: int = 60, weights: list[float] | None = None
) -> list[tuple[int, float]]:
    """Fuse rankings. Optional per-ranking weights give weighted RRF:
    RRF(d) = sum_r w_r / (k + rank_r(d)).
    """
    weights = weights or [1.0] * len(rankings)
    if len(weights) != len(rankings):
        raise ValueError("need one weight per ranking")
    scores: dict[int, float] = {}
    for ranking, weight in zip(rankings, weights, strict=True):
        for rank, item in enumerate(ranking, start=1):
            scores[item] = scores.get(item, 0.0) + weight / (k + rank)
    return sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
