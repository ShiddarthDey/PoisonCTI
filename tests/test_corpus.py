"""Tests for the RAG layer: chunking, the NumPy index, and retrieval.

These run without Ollama by supplying embeddings/embed_fn directly, so they prove
the retrieval *mechanics* (provenance, ranking, persistence) deterministically.
"""

import numpy as np
import pytest

from poisoncti.agent.retriever import retrieve
from poisoncti.corpus import chunk as chunker
from poisoncti.corpus import embed as embedder
from poisoncti.corpus import index as indexer


# --- model-aware embedding prefixes (bge-m3 none; nomic uses search_* prefixes) ---

def test_embed_query_prefix_is_model_specific(monkeypatch):
    seen = {}
    monkeypatch.setattr(embedder, "embed_text",
                        lambda text, model, host: seen.__setitem__(model, text) or np.zeros(3, np.float32))
    embedder.embed_query("log4j rce", "nomic-embed-text", "h")
    embedder.embed_query("log4j rce", "bge-m3", "h")
    assert seen["nomic-embed-text"] == "search_query: log4j rce"
    assert seen["bge-m3"] == "log4j rce"  # bge-m3 must NOT get a prefix


def test_embed_document_prefix_is_model_specific(monkeypatch):
    seen = {}
    monkeypatch.setattr(embedder, "embed_text",
                        lambda text, model, host: seen.__setitem__(model, text) or np.zeros(3, np.float32))
    embedder.embed_chunks([{"chunk_id": "c0", "text": "smb rce"}], "nomic-embed-text", "h")
    embedder.embed_chunks([{"chunk_id": "c0", "text": "smb rce"}], "bge-m3", "h")
    assert seen["nomic-embed-text"] == "search_document: smb rce"
    assert seen["bge-m3"] == "smb rce"

# --- chunking ---------------------------------------------------------------

DOC = {"doc_id": "d", "source": "cisa", "text": " ".join(f"w{i}" for i in range(10)),
       "mentions_cves": ["CVE-1"]}


def test_chunk_document_overlap_and_provenance():
    chunks = chunker.chunk_document(DOC, chunk_tokens=4, overlap=1)  # step = 3
    assert [c["chunk_id"] for c in chunks] == ["d::0", "d::1", "d::2"]
    # windows: [w0..w3], [w3..w6], [w6..w9] — note the shared boundary word (overlap)
    assert chunks[0]["text"].split()[-1] == "w3"
    assert chunks[1]["text"].split()[0] == "w3"
    assert chunks[2]["text"].split()[-1] == "w9"
    # provenance carried onto every chunk
    assert all(c["source"] == "cisa" and c["mentions_cves"] == ["CVE-1"] for c in chunks)


def test_chunk_empty_doc_yields_nothing():
    assert chunker.chunk_document({"doc_id": "d", "source": "s", "text": "   "}, 4, 1) == []


# --- index ------------------------------------------------------------------

CHUNKS = [
    {"chunk_id": "c0", "doc_id": "d0", "source": "cisa", "text": "a"},
    {"chunk_id": "c1", "doc_id": "d1", "source": "vendor_blog", "text": "b"},
    {"chunk_id": "c2", "doc_id": "d2", "source": "otx_pulse", "text": "c"},
]
VECS = np.array([[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]], dtype=np.float32)


def test_query_ranks_by_cosine():
    index = {"matrix": indexer._normalize(VECS), "chunks": CHUNKS}
    hits = indexer.query(index, np.array([1.0, 0.05], dtype=np.float32), top_k=2)
    assert hits[0]["chunk_id"] == "c0"           # closest to the x-axis query
    assert len(hits) == 2
    assert hits[0]["score"] >= hits[1]["score"]  # sorted descending
    assert "source" in hits[0]                    # provenance preserved


def test_min_score_filters_weak_hits():
    index = {"matrix": indexer._normalize(VECS), "chunks": CHUNKS}
    q = np.array([1.0, 0.0], dtype=np.float32)  # aligned to c0; c1 is orthogonal (score 0)
    all_hits = indexer.query(index, q, top_k=3)
    filtered = indexer.query(index, q, top_k=3, min_score=0.5)
    assert len(all_hits) == 3
    assert all(h["score"] >= 0.5 for h in filtered)
    assert len(filtered) < len(all_hits)  # the orthogonal/low-similarity chunk is dropped


def test_build_index_rejects_length_mismatch():
    with pytest.raises(ValueError):
        indexer.build_index(VECS[:2], CHUNKS, out_dir="unused")


def test_index_save_load_roundtrip(tmp_path):
    built = indexer.build_index(VECS, CHUNKS, out_dir=str(tmp_path / "idx"))
    loaded = indexer.load_index(str(tmp_path / "idx"))
    assert loaded["chunks"] == CHUNKS
    assert np.allclose(loaded["matrix"], built["matrix"])


# --- retriever (embed_fn injected; no server) -------------------------------

def test_retrieve_uses_injected_embed_fn():
    index = {"matrix": indexer._normalize(VECS), "chunks": CHUNKS}
    hits = retrieve("anything", index, top_k=1, embed_model="m", host="h",
                    embed_fn=lambda _t: np.array([0.0, 1.0], dtype=np.float32))
    assert hits[0]["chunk_id"] == "c1"  # query aligned to the y-axis vector


def test_retrieve_restrict_cve_excludes_other_cves():
    chunks = [
        {"chunk_id": "x0", "source": "cisa", "text": "t", "mentions_cves": ["CVE-A"]},
        {"chunk_id": "x1", "source": "vendor_blog", "text": "t", "mentions_cves": ["CVE-B"]},
        {"chunk_id": "x2", "source": "otx_pulse", "text": "t", "mentions_cves": ["CVE-A"]},
    ]
    vecs = indexer._normalize(np.array([[1, 0, 0], [0, 1, 0], [0, 0, 1]], np.float32))
    index = {"matrix": vecs, "chunks": chunks}
    # query is CLOSEST to x1 (the off-target CVE-B chunk) — exactly the contamination case
    qfn = lambda _t: np.array([0.0, 0.9, 0.4], np.float32)
    unrestricted = retrieve("q", index, 3, "m", "h", embed_fn=qfn)
    assert unrestricted[0]["chunk_id"] == "x1"             # off-target would top the list
    restricted = retrieve("q", index, 3, "m", "h", embed_fn=qfn, restrict_cve="CVE-A")
    assert [h["chunk_id"] for h in restricted] == ["x2", "x0"]  # only CVE-A, ranked
    assert all("CVE-A" in h["mentions_cves"] for h in restricted)
