"""Corpus: turn normalized CTI documents into a retrievable vector index (RAG).

This is the layer the attack targets and the defense inspects. It answers "given
a query, which CTI passages does the agent see?" — and therefore which passages a
single poisoned document must outrank to steer the answer.

Submodules:
    chunk -- split documents into overlapping passages, keeping source provenance
    embed -- embed chunks with the Ollama embedding model (bge-m3)
    index -- build / query a NumPy cosine-similarity index over those embeddings
"""
