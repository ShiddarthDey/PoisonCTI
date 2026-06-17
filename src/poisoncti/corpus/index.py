"""A small NumPy cosine-similarity index over chunk embeddings.

Job
---
Own the vector store: build an index from chunk embeddings, persist it with the
aligned chunk records, and answer top-k similarity queries. This is the retrieval
substrate the agent reads and the attack must climb in. Re-poisoning is just "add
one vector + record and rebuild," which mirrors a real corpus update.

Why NumPy, not faiss
--------------------
The CTI corpus is tiny (tens of chunks), so a brute-force cosine search over a
normalized matrix is exact, deterministic, dependency-light, and fully testable
without a server. Vectors are L2-normalized so cosine == inner product, and the
defense (M5) can read these similarity scores directly.

Index representation: a dict {"matrix": (n,d) float32 normalized, "chunks": [records]}.

Inputs:  embedding matrix + aligned chunk records
Outputs: a persisted index in data/processed; query -> ranked chunk records + scores
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np


def _normalize(matrix: np.ndarray) -> np.ndarray:
    matrix = np.asarray(matrix, dtype=np.float32)
    if matrix.size == 0:
        return matrix
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


def build_index(embeddings: np.ndarray, chunks: list[dict], out_dir: str) -> dict:
    """Create an index from embeddings + aligned chunk records, and persist it.

    `embeddings[i]` must correspond to `chunks[i]`. Returns the in-memory index.
    """
    if len(embeddings) != len(chunks):
        raise ValueError(f"embeddings ({len(embeddings)}) != chunks ({len(chunks)})")
    matrix = _normalize(embeddings)
    index = {"matrix": matrix, "chunks": list(chunks)}
    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)
    np.save(p / "vectors.npy", matrix)
    (p / "chunks.json").write_text(json.dumps(chunks, indent=2), encoding="utf-8")
    (p / "meta.json").write_text(
        json.dumps({"count": len(chunks), "dim": int(matrix.shape[1]) if matrix.size else 0}),
        encoding="utf-8",
    )
    return index


def load_index(index_dir: str) -> dict:
    """Load a persisted index (vectors + aligned chunk records)."""
    p = Path(index_dir)
    matrix = np.load(p / "vectors.npy")
    chunks = json.loads((p / "chunks.json").read_text(encoding="utf-8"))
    return {"matrix": matrix.astype(np.float32), "chunks": chunks}


def query(index: dict, query_vector: np.ndarray, top_k: int, min_score: float | None = None) -> list[dict]:
    """Return up to top_k chunk records with cosine scores, highest first.

    If `min_score` is set, chunks scoring below it are dropped, so the agent only
    sees genuinely relevant sources (keeps top_k from sweeping in unrelated CVEs).
    """
    matrix = index["matrix"]
    chunks = index["chunks"]
    if matrix.size == 0:
        return []
    q = np.asarray(query_vector, dtype=np.float32)
    qnorm = np.linalg.norm(q)
    if qnorm:
        q = q / qnorm
    sims = matrix @ q
    k = min(top_k, len(chunks))
    top = np.argsort(-sims)[:k]
    hits = [{**chunks[i], "score": float(sims[i])} for i in top]
    if min_score is not None:
        hits = [h for h in hits if h["score"] >= min_score]
    return hits
