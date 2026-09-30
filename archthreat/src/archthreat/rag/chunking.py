"""Load markdown knowledge docs and split them into retrievable chunks.

Chunking strategy: split on markdown headings first (sections are natural units of meaning),
then split any section longer than `max_chars` into overlapping windows on paragraph
boundaries. Every chunk keeps its document's metadata (id, title, tags, source URL) so we can
filter, boost and cite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)


@dataclass
class Document:
    doc_id: str
    title: str
    text: str
    tags: list[str] = field(default_factory=list)
    source_url: str | None = None


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    title: str
    section: str
    text: str
    tags: list[str] = field(default_factory=list)
    source_url: str | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def parse_markdown(raw: str, fallback_id: str) -> Document:
    meta: dict = {}
    body = raw
    match = FRONT_MATTER_RE.match(raw)
    if match:
        meta = yaml.safe_load(match.group(1)) or {}
        body = raw[match.end() :]
    return Document(
        doc_id=str(meta.get("id", fallback_id)),
        title=str(meta.get("title", fallback_id)),
        text=body.strip(),
        tags=[str(t) for t in meta.get("tags", [])],
        source_url=meta.get("source_url"),
    )


def load_markdown_docs(directory: str | Path) -> list[Document]:
    paths = sorted(Path(directory).glob("*.md"))
    return [parse_markdown(p.read_text(encoding="utf-8"), p.stem) for p in paths]


def _sections(text: str) -> list[tuple[str, str]]:
    """Return (heading, body) pairs. Text before the first heading gets heading ''."""
    matches = list(HEADING_RE.finditer(text))
    if not matches:
        return [("", text)]
    sections: list[tuple[str, str]] = []
    if matches[0].start() > 0:
        sections.append(("", text[: matches[0].start()]))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections.append((m.group(2).strip(), text[m.end() : end]))
    return [(h, b.strip()) for h, b in sections if b.strip()]


def _split_long(paragraph: str, max_chars: int) -> list[str]:
    """Hard-split a single paragraph that is longer than max_chars, on whitespace."""
    if len(paragraph) <= max_chars:
        return [paragraph]
    pieces, current = [], ""
    for word in paragraph.split():
        if current and len(current) + 1 + len(word) > max_chars:
            pieces.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        pieces.append(current)
    return pieces


def _windows(paragraphs: list[str], max_chars: int, overlap: int) -> list[str]:
    paragraphs = [piece for p in paragraphs for piece in _split_long(p, max_chars)]
    windows: list[str] = []
    current = ""
    for para in paragraphs:
        candidate = f"{current}\n\n{para}" if current else para
        if len(candidate) <= max_chars or not current:
            current = candidate
            continue
        windows.append(current)
        tail = current[-overlap:] if overlap else ""
        current = f"{tail}\n\n{para}" if tail else para
    if current:
        windows.append(current)
    return windows


def chunk_document(doc: Document, max_chars: int = 900, overlap: int = 150) -> list[Chunk]:
    chunks: list[Chunk] = []
    for heading, body in _sections(doc.text):
        paragraphs = [p.strip() for p in body.split("\n\n") if p.strip()]
        for piece in _windows(paragraphs, max_chars, overlap):
            chunks.append(
                Chunk(
                    chunk_id=f"{doc.doc_id}#{len(chunks)}",
                    doc_id=doc.doc_id,
                    title=doc.title,
                    section=heading,
                    text=piece,
                    tags=list(doc.tags),
                    source_url=doc.source_url,
                )
            )
    return chunks
