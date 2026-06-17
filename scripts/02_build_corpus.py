"""Step 02 — build the retrieval indexes the agent needs.

Builds TWO bge-m3 indexes into data/processed:
  - corpus_index : normalized CTI docs -> chunk -> embed -> cosine index. The
    honest baseline corpus the agent reads (step 03) and the attack injects (step 04).
  - attack_index : the ~700 MITRE ATT&CK techniques ("name. description") embedded
    once, used by the catalog-grounded ATT&CK mapper (agent.attack_mapper).

Requires a running Ollama server with the embedding model pulled:
    ollama pull bge-m3

Usage:
    python scripts/02_build_corpus.py            # config/settings.yaml
    python scripts/02_build_corpus.py --test     # config/settings.test.yaml
    python scripts/02_build_corpus.py --demo "remote code execution in Apache Log4j"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from poisoncti.agent.retriever import retrieve
from poisoncti.corpus import chunk as chunker
from poisoncti.corpus import embed as embedder
from poisoncti.corpus import index as indexer
from poisoncti.utils.io import load_config


def _check_ollama(host: str, model: str) -> None:
    try:
        import ollama

        ollama.Client(host=host).embeddings(model=model, prompt="ping")
    except Exception as exc:  # noqa: BLE001 - surface a clear, actionable message
        sys.exit(
            f"Cannot reach Ollama embeddings ({model} @ {host}): {exc}\n"
            f"Start Ollama and run `ollama pull {model}`."
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="use config/settings.test.yaml")
    parser.add_argument("--demo", metavar="QUERY", help="run a sample retrieval after building")
    args = parser.parse_args()

    cfg = load_config("config/settings.test.yaml" if args.test else "config/settings.yaml")
    model, host = cfg["models"]["embed"], cfg["models"]["host"]
    _check_ollama(host, model)

    docs = json.loads((Path(cfg["paths"]["data_interim"]) / "cti_docs.json").read_text("utf-8"))
    chunks = chunker.chunk_corpus(docs, cfg["corpus"]["chunk_tokens"], cfg["corpus"]["chunk_overlap"])
    print(f"Chunked {len(docs)} docs -> {len(chunks)} chunks")

    matrix, _ = embedder.embed_chunks(chunks, model, host)
    out_dir = str(Path(cfg["paths"]["data_processed"]) / "corpus_index")
    index = indexer.build_index(matrix, chunks, out_dir)
    print(f"Built corpus index: {len(chunks)} vectors, dim {matrix.shape[1]} -> {out_dir}")

    # ATT&CK technique index (for catalog-grounded mapping) -------------------
    techniques = json.loads((Path(cfg["paths"]["data_interim"]) / "techniques.json").read_text("utf-8"))
    trecords = [
        {"chunk_id": t["attack_id"], "attack_id": t["attack_id"], "name": t["name"],
         "tactics": t.get("tactics", []), "text": f"{t['name']}. {t.get('description', '')}"}
        for t in techniques
    ]
    tmatrix, _ = embedder.embed_chunks(trecords, model, host)
    attack_dir = str(Path(cfg["paths"]["data_processed"]) / "attack_index")
    indexer.build_index(tmatrix, trecords, attack_dir)
    print(f"Built ATT&CK index: {len(trecords)} techniques, dim {tmatrix.shape[1]} -> {attack_dir}")

    if args.demo:
        print(f"\nDemo retrieval for: {args.demo!r}")
        for hit in retrieve(args.demo, index, cfg["corpus"]["top_k"], model, host):
            print(f"  {hit['score']:.3f}  [{hit['source']}] {hit['chunk_id']}: {hit['text'][:80]}...")


if __name__ == "__main__":
    main()
