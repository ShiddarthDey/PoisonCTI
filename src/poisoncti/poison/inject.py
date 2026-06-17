"""Inject a poisoned document into the corpus and rebuild the index.

Job
---
Take a crafted payload (from payloads.py), tag it as one more CTI source, chunk
and embed it like any honest document, add it to the corpus, and rebuild the
cosine index. This mirrors a real corpus update: the agent and retriever are untouched —
only the data changes. Injection returns a clean handle so the experiment can
diff "clean index" vs "poisoned index" for the same items.

Inputs:  clean corpus/index, one poisoned document, corpus config
Outputs: a poisoned index (+ record of what/where was injected)
"""

from __future__ import annotations


def inject_document(poison_doc: dict, clean_corpus_dir: str, out_dir: str, cfg: dict) -> dict:
    """Add one poisoned doc to a copy of the corpus, rebuild the index, return its handle."""
    raise NotImplementedError
