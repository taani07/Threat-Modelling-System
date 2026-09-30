"""Retrieval: chunking, BM25 keyword search, vector search, and hybrid fusion.

Everything here is written from scratch on purpose (no LangChain / LlamaIndex) so that each
piece can be explained in an interview. Swapping in a framework later is easy; explaining a
framework you never looked inside is not.
"""

from archthreat.rag.bm25 import BM25Index, tokenize
from archthreat.rag.chunking import Chunk, Document, chunk_document, load_markdown_docs
from archthreat.rag.hybrid import reciprocal_rank_fusion
from archthreat.rag.index import KnowledgeIndex, RetrievedChunk
from archthreat.rag.vectors import VectorIndex

__all__ = [
    "BM25Index",
    "Chunk",
    "Document",
    "KnowledgeIndex",
    "RetrievedChunk",
    "VectorIndex",
    "chunk_document",
    "load_markdown_docs",
    "reciprocal_rank_fusion",
    "tokenize",
]
