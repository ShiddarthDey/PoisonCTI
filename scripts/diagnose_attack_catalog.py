"""ATT&CK catalog-discrimination diagnostic (run on a machine with Ollama).

GATE before grounded mapping is trusted. The ~700 ATT&CK techniques are described
in similar security language, so the catalog itself may be embedding-homogeneous —
the SAME risk we fixed for the CTI corpus. This checks two things:

  1. Cross-technique cosine stats over the catalog under bge-m3 (is the catalog
     itself homogeneous? mean / median / % of pairs above thresholds).
  2. Labeled probe descriptions with known-correct techniques: does the correct
     technique land in the top-k, and with score separation over the rest?

Needs the attack index built by scripts/02_build_corpus.py.

Usage:
    python scripts/diagnose_attack_catalog.py            # config/settings.yaml
    python scripts/diagnose_attack_catalog.py --test     # config/settings.test.yaml
    python scripts/diagnose_attack_catalog.py --model bge-m3
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

from poisoncti.corpus import embed as embedder
from poisoncti.corpus import index as indexer
from poisoncti.utils.io import load_config

# EFFECT-level probes: hand-written proxies of the kind of "effect" sentence the
# agent now emits (its own-words outcome, not low-level mechanism), phrased WITHOUT
# any ATT&CK technique names so the test is not pre-loaded with the answers. These
# are a controlled catalog check; the AUTHORITATIVE anti-leakage gate is the agent's
# real emitted text in `scripts/03_run_baseline.py --test` (EternalBlue = the SMB
# case, Log4Shell = the JNDI case). (probe, acceptable technique IDs; subs count.)
PROBES = [
    ("without any credentials, a remote attacker on the network gains the ability to run "
     "their own code on a vulnerable server and use it to reach other machines", {"T1210"}),
    ("an external unauthenticated attacker gains an initial foothold by abusing a flaw in "
     "an application that is reachable from the internet", {"T1190"}),
    ("an attacker who already has access harvests account passwords and secret keys from "
     "the memory of a running system", {"T1003"}),
    ("the attacker gets their code to run by convincing a person to open a file that was "
     "delivered to them", {"T1204"}),
    ("by submitting data that a public-facing application records, an unauthenticated attacker "
     "makes the server download and run code that the attacker controls", {"T1190", "T1059"}),
]
TOP_K = 5


def _correct(attack_id: str, expected: set) -> bool:
    base = attack_id.split(".")[0]
    return any(base == e.split(".")[0] for e in expected)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--model", help="override embed model (e.g. bge-m3)")
    args = parser.parse_args()
    cfg = load_config("config/settings.test.yaml" if args.test else "config/settings.yaml")
    model = args.model or cfg["models"]["embed"]
    host = cfg["models"]["host"]

    idx = indexer.load_index(str(Path(cfg["paths"]["data_processed"]) / "attack_index"))
    mat, recs = idx["matrix"], idx["chunks"]
    if mat.size == 0:
        sys.exit("attack_index is empty — run scripts/02_build_corpus.py first.")

    # [1] catalog homogeneity ------------------------------------------------
    sims = mat @ mat.T
    iu = np.triu_indices(len(recs), k=1)
    cross = sims[iu]
    print(f"[1] Cross-technique cosine over {len(recs)} techniques "
          f"({len(cross)} pairs), model={model}:")
    print(f"    mean={cross.mean():.3f}  median={np.median(cross):.3f}  "
          f"min={cross.min():.3f}  max={cross.max():.3f}")
    for thr in (0.6, 0.7, 0.8):
        print(f"    % pairs >= {thr}: {100 * (cross >= thr).mean():.0f}%")

    # [2] labeled probes -----------------------------------------------------
    print("\n[2] Probe -> top-5 techniques (* = correct):")
    top1, topk = 0, 0
    try:
        embedder.embed_query("ping", model, host)
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"\nCannot reach Ollama ({model} @ {host}): {exc}")

    for desc, expected in PROBES:
        qv = embedder.embed_query(desc, model, host)
        qv = qv / np.clip(np.linalg.norm(qv), 1e-9, None)
        qsims = mat @ qv
        order = np.argsort(-qsims)
        print(f"\n  {desc!r}  (expect {sorted(expected)})")
        for rank, i in enumerate(order[:TOP_K], 1):
            mark = "*" if _correct(recs[i]["attack_id"], expected) else " "
            print(f"    {mark} {rank}. {qsims[i]:.3f}  {recs[i]['attack_id']:<10} {recs[i]['name']}")
        first = next((r for r, i in enumerate(order, 1) if _correct(recs[i]["attack_id"], expected)), None)
        best_correct = max((qsims[i] for i in order if _correct(recs[i]["attack_id"], expected)), default=None)
        best_wrong = max((qsims[i] for i in order if not _correct(recs[i]["attack_id"], expected)), default=None)
        gap = (best_correct - best_wrong) if (best_correct is not None and best_wrong is not None) else None
        print(f"    -> correct rank: {first}; best-correct vs best-wrong gap: "
              f"{(f'{gap:+.3f}' if gap is not None else 'n/a')}")
        top1 += (first == 1)
        topk += (first is not None and first <= 3)

    print(f"\nProbes: correct rank-1 {top1}/{len(PROBES)}, correct in top-3 {topk}/{len(PROBES)}")
    print("PASS heuristic: most probes correct in top-3 with positive gap, and catalog "
          "mean cosine not pathologically high (cf. CTI corpus was 0.78 when broken).")


if __name__ == "__main__":
    main()
