"""Embedding-space homogeneity diagnostic (run on a machine with Ollama).

Tests the hypothesis that clean CTI docs for DIFFERENT CVEs are semantically too
similar to retrieve on. Embeds every doc (with the search_document prefix), then:

  1. Global off-diagonal cosine stats over all docs, and the % of cross-CVE pairs
     at >= 0.70 cosine (a homogeneous corpus shows most pairs that high).
  2. A focused labeled cosine matrix for a few illustrative docs (4 web-RCE docs
     plus one non-RCE contrast doc).
  3. For each demo query (search_query prefix), the ranked cosine to every doc,
     so you can see whether generic-RCE docs outrank the CVE-specific one.

A healthy corpus: low cross-CVE cosine, the on-target doc clearly top for its
query. A homogeneous corpus: cross-CVE cosine ~0.7+, query matches the generic
theme. This ALSO previews the M5 risk: if honest sources for different CVEs are
all ~0.7 similar, the consistency check has little signal to separate them.

Usage:
    python scripts/diagnose_embeddings.py            # config/settings.yaml
    python scripts/diagnose_embeddings.py --test     # config/settings.test.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from itertools import combinations
from pathlib import Path

import numpy as np

from poisoncti.corpus import embed as embedder
from poisoncti.utils.io import load_config

FOCUS = [
    "cti-eternalblue-cisa",
    "cti-log4shell-cisa",
    "cti-struts-cisa",
    "cti-drupalgeddon2-cisa",
    "cti-heartbleed-cisa",  # non-RCE contrast (info disclosure)
]
DEMOS = [
    ("remote code execution in Apache Log4j", "Log4Shell / CVE-2021-44228"),
    ("SMB remote code execution Windows", "EternalBlue / CVE-2017-0144"),
]


def _norm(m: np.ndarray) -> np.ndarray:
    return m / np.clip(np.linalg.norm(m, axis=1, keepdims=True), 1e-9, None)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--model", help="override embed model for an A/B "
                        "(e.g. bge-m3, mxbai-embed-large); pull it first with `ollama pull`")
    args = parser.parse_args()
    cfg = load_config("config/settings.test.yaml" if args.test else "config/settings.yaml")
    model = args.model or cfg["models"]["embed"]
    host = cfg["models"]["host"]

    try:
        import ollama

        ollama.Client(host=host).embeddings(model=model, prompt="ping")
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Cannot reach Ollama ({model} @ {host}): {exc}")

    docs = json.loads((Path(cfg["paths"]["data_interim"]) / "cti_docs.json").read_text("utf-8"))
    ids = [d["doc_id"] for d in docs]
    cve_of = {d["doc_id"]: (d["mentions_cves"][0] if d["mentions_cves"] else "?") for d in docs}
    print(f"Embedding {len(docs)} docs with model={model} ...")
    # embed_document applies the model-correct document prefix (none for bge-m3),
    # so vectors match the real pipeline without depending on chunk-dict shape.
    vecs = [embedder.embed_document(d["text"], model, host) for d in docs]
    mat = _norm(np.vstack(vecs).astype(np.float32))
    sims = mat @ mat.T

    # 1) global cross-CVE cosine stats
    cross = [sims[i, j] for i, j in combinations(range(len(ids)), 2)
             if cve_of[ids[i]] != cve_of[ids[j]]]
    cross = np.array(cross)
    print(f"\n[1] Cross-CVE pairwise cosine (different CVEs), n={len(cross)} pairs:")
    print(f"    mean={cross.mean():.3f}  median={np.median(cross):.3f} "
          f"min={cross.min():.3f}  max={cross.max():.3f}")
    for thr in (0.6, 0.7, 0.75):
        print(f"    % cross-CVE pairs >= {thr}: {100*(cross >= thr).mean():.0f}%")

    # 2) focused labeled matrix
    idx = {d: i for i, d in enumerate(ids)}
    present = [d for d in FOCUS if d in idx]
    print("\n[2] Focused cosine matrix (different CVEs should be LOW):")
    short = [d.replace("cti-", "").replace("-cisa", "")[:12] for d in present]
    print("            " + "".join(f"{s:>13}" for s in short))
    for a in present:
        row = "".join(f"{sims[idx[a], idx[b]]:>13.3f}" for b in present)
        print(f"{a.replace('cti-','').replace('-cisa','')[:12]:>12}{row}")

    # 3) demo query rankings
    print("\n[3] Demo query -> doc cosine (top 8):")
    for q, expect in DEMOS:
        qv = embedder.embed_query(q, model, host)
        qv = qv / np.clip(np.linalg.norm(qv), 1e-9, None)
        qsims = mat @ qv
        order = np.argsort(-qsims)[:8]
        print(f"\n  Q: {q!r}  (expect: {expect})")
        for r, i in enumerate(order, 1):
            print(f"    {r}. {qsims[i]:.3f}  {cve_of[ids[i]]:<16} {ids[i]}")


if __name__ == "__main__":
    main()
