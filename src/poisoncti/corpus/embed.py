"""Embed text chunks and queries using the local Ollama embedding model.

Job
---
Turn chunk text and queries into dense vectors via Ollama's embeddings endpoint
(default model: bge-m3). Using Ollama for embeddings keeps the whole stack on one
local server and avoids a heavy PyTorch / sentence-transformers dependency.

MODEL-SPECIFIC TASK PREFIXES (critical)
---------------------------------------
Different embedding models expect different (or no) task-instruction prefixes, and
sending the WRONG prefix corrupts the vectors:
  - bge-m3            : NO prefix for queries or documents (raw text).
  - nomic-embed-text  : "search_query: " for queries, "search_document: " for docs.
  - mxbai-embed-large : a query instruction for queries, none for documents.
`embed_query`/`embed_document` look the prefix up by model name (tag stripped), so
swapping the embed model in config automatically uses the right convention.
`embed_text` is the raw primitive (no prefix).

bge-m3 emits 1024-dim vectors (nomic was 768); the NumPy index is dimension-agnostic
and simply needs rebuilding after a model switch.

The `ollama` import is lazy so this module imports without a running server
(unit tests inject their own embedding function instead of calling Ollama).
"""

from __future__ import annotations

import numpy as np

# (query_prefix, document_prefix) per embedding model. Matched on the base name
# (tag stripped). Unknown models default to no prefix.
EMBED_PREFIXES = {
    "bge-m3": ("", ""),
    "nomic-embed-text": ("search_query: ", "search_document: "),
    "mxbai-embed-large": ("Represent this sentence for searching relevant passages: ", ""),
}
DEFAULT_PREFIXES = ("", "")


def _prefixes(model: str) -> tuple[str, str]:
    """Return (query_prefix, document_prefix) for `model` (tag stripped)."""
    return EMBED_PREFIXES.get(model.split(":")[0], DEFAULT_PREFIXES)


def embed_text(text: str, model: str, host: str) -> np.ndarray:
    """Embed a raw string verbatim (NO task prefix). Low-level primitive."""
    import ollama

    client = ollama.Client(host=host)
    resp = client.embeddings(model=model, prompt=text)
    return np.asarray(resp["embedding"], dtype=np.float32)


def embed_query(text: str, model: str, host: str) -> np.ndarray:
    """Embed a query, applying the model's query prefix (if any)."""
    return embed_text(_prefixes(model)[0] + text, model, host)


def embed_document(text: str, model: str, host: str) -> np.ndarray:
    """Embed a document, applying the model's document prefix (if any)."""
    return embed_text(_prefixes(model)[1] + text, model, host)


def embed_chunks(chunks: list[dict], model: str, host: str):
    """Embed every chunk's text as a document. Returns (matrix (n,d), chunk_ids)."""
    from tqdm import tqdm

    vectors = [embed_document(c["text"], model, host) for c in tqdm(chunks, desc="embed")]
    matrix = np.vstack(vectors).astype(np.float32) if vectors else np.zeros((0, 0), np.float32)
    return matrix, [c["chunk_id"] for c in chunks]
