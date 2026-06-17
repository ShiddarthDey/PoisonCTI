"""Retrieve the top-k CTI chunks for a query.

Job
---
Bridge between a natural-language query and the corpus index: embed the query,
ask the index for the top_k most similar chunks, and return them WITH similarity
scores and source provenance. These chunks are exactly the "sources" the agent
reasons over — and the same set the defense inspects for cross-source agreement.

Inputs:  query string, loaded index, top_k, embed model + host
Outputs: ranked chunk records [{chunk_id, doc_id, source, text, mentions_cves, score}]

`embed_fn` can be injected to decouple retrieval from Ollama (used in tests);
by default it embeds the query with corpus.embed.embed_query, which applies the
model-correct query prefix (none for bge-m3). Documents are embedded with the
matching document convention at index time — see corpus/embed.py.
"""

from __future__ import annotations

from poisoncti.corpus import embed as _embed
from poisoncti.corpus import index as _index


def retrieve(query: str, index: dict, top_k: int, embed_model: str, host: str,
             embed_fn=None, min_score: float | None = None, restrict_cve: str | None = None) -> list[dict]:
    """Embed the query and return the retrieved chunks with scores+provenance.

    `min_score` (if set) drops weakly-similar chunks. `restrict_cve` (if set) keeps
    only chunks whose mentions_cves includes that CVE — preventing cross-CVE
    contamination — by ranking the whole corpus, filtering to the CVE, then cutting
    to top_k (so the kept set is the CVE's most-similar sources, never another CVE's).
    """
    fn = embed_fn or (lambda text: _embed.embed_query(text, embed_model, host))
    query_vector = fn(query)
    if restrict_cve is None:
        return _index.query(index, query_vector, top_k, min_score=min_score)
    pool = _index.query(index, query_vector, len(index["chunks"]), min_score=min_score)
    return [h for h in pool if restrict_cve in h.get("mentions_cves", [])][:top_k]
