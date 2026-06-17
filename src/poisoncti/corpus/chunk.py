"""Split normalized documents into overlapping, provenance-tagged passages.

Job
---
Convert each document into retrieval-sized chunks (config: chunk_tokens /
chunk_overlap). Every chunk inherits its parent's `source`, `doc_id`, and the
CVEs the document mentions, so retrieval results always carry "who said this" —
which the defense and evaluation rely on.

Inputs:  normalized docs from ingestion.cti_text
Outputs: chunk records {chunk_id, doc_id, source, text, mentions_cves} -> data/processed

Tokenization note
-----------------
We approximate "tokens" by whitespace-delimited words. For a small, curated CTI
corpus this is transparent and good enough; it avoids pulling a tokenizer
dependency. The chunk_id is `<doc_id>::<n>` so it is stable and traceable.
"""

from __future__ import annotations


def chunk_document(doc: dict, chunk_tokens: int, overlap: int) -> list[dict]:
    """Return overlapping chunk records for one document, preserving provenance."""
    words = doc["text"].split()
    if not words:
        return []
    step = max(1, chunk_tokens - overlap)
    chunks: list[dict] = []
    n = 0
    for start in range(0, len(words), step):
        piece = words[start : start + chunk_tokens]
        if not piece:
            break
        chunks.append(
            {
                "chunk_id": f"{doc['doc_id']}::{n}",
                "doc_id": doc["doc_id"],
                "source": doc["source"],
                "text": " ".join(piece),
                "mentions_cves": doc.get("mentions_cves", []),
            }
        )
        n += 1
        if start + chunk_tokens >= len(words):
            break  # last window reached the end; don't emit a duplicate tail
    return chunks


def chunk_corpus(docs: list[dict], chunk_tokens: int, overlap: int) -> list[dict]:
    """Chunk every document; return the flat list of chunk records."""
    out: list[dict] = []
    for doc in docs:
        out.extend(chunk_document(doc, chunk_tokens, overlap))
    return out
