"""Retrieval-discrimination diagnostic (run on a machine with Ollama).

Answers: at the configured top_k, for a single-CVE query, how many chunks come
back and from how many DISTINCT CVEs? If queries sweep in unrelated CVEs, the
"retrieve relevant sources" step isn't selecting anything and the poison would be
present regardless of relevance. This script measures that and suggests a
min_score floor if separation is poor.

For each study CVE that has CTI, it uses the NVD description as the query and reports:
  - n_hits, and how many DISTINCT CVEs those hits mention,
  - whether the queried CVE's own chunk is rank 1,
  - the score gap between the best on-target and best off-target chunk.

Usage:
    python scripts/diagnose_retrieval.py            # config/settings.yaml
    python scripts/diagnose_retrieval.py --test     # config/settings.test.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from poisoncti.agent.retriever import retrieve
from poisoncti.corpus import index as indexer
from poisoncti.utils.io import load_config


def _check_ollama(host: str, model: str) -> None:
    try:
        import ollama

        ollama.Client(host=host).embeddings(model=model, prompt="ping")
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Cannot reach Ollama ({model} @ {host}): {exc}\nStart Ollama and `ollama pull {model}`.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    cfg = load_config("config/settings.test.yaml" if args.test else "config/settings.yaml")
    model, host = cfg["models"]["embed"], cfg["models"]["host"]
    top_k, min_score = cfg["corpus"]["top_k"], cfg["corpus"].get("min_score")
    _check_ollama(host, model)

    index = indexer.load_index(str(Path(cfg["paths"]["data_processed"]) / "corpus_index"))
    records = json.loads((Path(cfg["paths"]["data_raw"]) / "cves.json").read_text("utf-8"))
    cve_text = {r["cve_id"]: r["description"] for r in records}

    # CVEs that actually have at least one chunk in the corpus
    cves_with_cti = sorted({c for ch in index["chunks"] for c in ch.get("mentions_cves", [])})

    print(f"Corpus: {len(index['chunks'])} chunks | top_k={top_k} min_score={min_score}\n")
    print(f"{'CVE':<18} {'hits':>4} {'#CVEs':>6} {'rank1?':>7} {'gap':>7}")
    rank1 = 0
    distinct_counts = []
    on_off_gaps = []
    for cve in cves_with_cti:
        if cve not in cve_text:
            continue
        hits = retrieve(cve_text[cve], index, top_k, model, host, min_score=min_score)
        distinct = {c for h in hits for c in h.get("mentions_cves", [])}
        on = next((h["score"] for h in hits if cve in h.get("mentions_cves", [])), None)
        off = next((h["score"] for h in hits if cve not in h.get("mentions_cves", [])), None)
        is_rank1 = bool(hits and cve in hits[0].get("mentions_cves", []))
        rank1 += is_rank1
        distinct_counts.append(len(distinct))
        gap = (on - off) if (on is not None and off is not None) else None
        if gap is not None:
            on_off_gaps.append(gap)
        print(f"{cve:<18} {len(hits):>4} {len(distinct):>6} {str(is_rank1):>7} "
              f"{(f'{gap:+.3f}' if gap is not None else '   -'):>7}")

    n = len(distinct_counts) or 1
    print(f"\nrank-1 on-target: {rank1}/{len(distinct_counts)} "
          f"({100*rank1/n:.0f}%) | avg distinct CVEs/query: {sum(distinct_counts)/n:.1f}")
    print("--- demo queries ---")
    for q, expect in [("remote code execution in Apache Log4j", "Log4Shell"),
                      ("SMB remote code execution Windows", "EternalBlue, NOT Log4Shell")]:
        hits = retrieve(q, index, top_k, model, host, min_score=min_score)
        print(f"\nQ: {q!r}  (expect: {expect})")
        for h in hits:
            print(f"  {h['score']:.3f} [{h['source']}] {h['mentions_cves']} {h['chunk_id']}")
    if on_off_gaps:
        lo = min(on_off_gaps)
        print(f"\nIf separation is weak, set corpus.min_score between off- and on-target "
              f"scores (smallest on-vs-off gap seen: {lo:+.3f}).")


if __name__ == "__main__":
    main()
