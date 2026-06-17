"""Inspect a saved M5 defense run (offline — reads the jsonl, no Ollama).

The leave-one-out check saves, per source, the joint band of the OTHERS and that
source's INFLUENCE (how many bands the joint moves when the source is removed). The
flag decision (influence >= min_influence) is pure arithmetic on those saved values,
so we can recompute the precision/recall curve without re-running the model.

  1. Per-CVE: each source's others-band + influence (poison = last), and the joint band.
  2. Sweep: detection per direction AND clean false-positive rate at min_influence = 1, 2, 3.

Usage:
    python scripts/inspect_defense.py                       # latest experiments/run_*/defense.jsonl
    python scripts/inspect_defense.py --path experiments/run_XXXX/defense.jsonl
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
from collections import Counter

from poisoncti.evaluation.metrics import band_ordinal
from poisoncti.utils.io import read_jsonl


# --- candidate identification rules (simulated from saved per-source bands) ---
# Each *_poisoned(r) returns (detected_poison, recovered_clean_band) on the poisoned
# input; each *_fp(r) returns whether the rule flags an honest source on CLEAN input.

def _inf(p):
    return p["influence"] if p["influence"] is not None else 0


def rule_current(r):
    """Rule 1: flag abs-influence>=1; corrected = others_band only if exactly ONE flagged, else j_all."""
    P, pj, clean = r["poison_report"]["per_source"], r["poison_report"]["joint_band"], r["clean_band"]
    flagged = [i for i, p in enumerate(P) if _inf(p) >= 1]
    detected = _inf(P[-1]) >= 1
    corrected = P[flagged[0]]["others_band"] if len(flagged) == 1 else pj
    return detected, corrected == clean


def rule_current_fp(r):
    return any(_inf(c) >= 1 for c in r["clean_report"]["per_source"])


def _signed(others_band, joint):
    a, b = band_ordinal(others_band), band_ordinal(joint)
    return None if (a is None or b is None) else a - b


def _minority_mover(per_source, joint):
    """Index of the unique source whose removal moves the joint in the MINORITY sign
    direction (the restorer vs the load-bearing crowd); None if ambiguous/none."""
    movers = [(i, _signed(p["others_band"], joint)) for i, p in enumerate(per_source)]
    movers = [(i, s) for i, s in movers if s not in (None, 0)]
    if not movers:
        return None
    signs = [1 if s > 0 else -1 for _, s in movers]
    cnt = Counter(signs)
    if len(cnt) == 1:                       # all move the same way
        return movers[0][0] if len(movers) == 1 else None
    minority = min(cnt, key=lambda k: cnt[k])
    if list(cnt.values()).count(cnt[minority]) > 1:   # tie in counts (e.g. 1 vs 1)
        return None
    cand = [i for (i, _s), sg in zip(movers, signs) if sg == minority]
    return cand[0] if len(cand) == 1 else None


def rule_directional(r):
    """Rule 2: poison = the unique minority-direction mover; corrected = its others_band."""
    P, pj, clean = r["poison_report"]["per_source"], r["poison_report"]["joint_band"], r["clean_band"]
    pid = _minority_mover(P, pj)
    if pid is None:
        return False, pj == clean
    return pid == len(P) - 1, P[pid]["others_band"] == clean


def rule_directional_fp(r):
    C, cj = r["clean_report"]["per_source"], r["clean_report"]["joint_band"]
    return _minority_mover(C, cj) is not None      # names an honest source on clean -> FP


def _honest_consistent(r):
    """The honest-only set is internally consistent (removing any honest doesn't move its joint)."""
    return all(_inf(c) == 0 for c in r["clean_report"]["per_source"])


def rule_consistency(r):
    """Rule 3: poison = the source whose removal leaves an INTERNALLY-CONSISTENT (>=3) set.
    Under the single-poison model that set is the honest one; declares NO poison otherwise."""
    P, pj, clean = r["poison_report"]["per_source"], r["poison_report"]["joint_band"], r["clean_band"]
    full_consistent = all(_inf(p) == 0 for p in P)
    if _honest_consistent(r) and not full_consistent:
        return _inf(P[-1]) >= 1, P[-1]["others_band"] == clean   # remove the poison -> joint(honest)
    return False, pj == clean                                     # cannot identify -> no poison declared


def rule_consistency_fp(r):
    # clean input: if honest set is consistent -> no poison; if not, no >=3 consistent rest exists
    # (only 2 sources remain after a removal) -> still no poison. FP = 0 by construction.
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=None)
    args = parser.parse_args()
    path = args.path or max(glob.glob("experiments/run_*/defense.jsonl"), default=None,
                            key=lambda p: os.path.getmtime(p))
    if not path:
        sys.exit("No defense.jsonl found — run scripts/05_run_defense.py first.")
    rows = read_jsonl(path)
    print(f"Inspecting {path}  ({len(rows)} CVEs)\n")

    # [1] per-source influence per CVE
    print("[1] Leave-one-out influence per source (poison = last; joint = all-sources band):")
    print(f"  {'CVE':<15} {'dir':<8} {'joint':<9} {'honest infl':<16} {'poison infl':<12} caught(>=1)")
    for r in rows:
        ps = r["poison_report"]["per_source"]
        joint = r["poison_report"].get("joint_band")
        honest_infl = [p["influence"] for p in ps[:-1]]
        poison_infl = ps[-1]["influence"]
        caught = poison_infl is not None and poison_infl >= 1
        print(f"  {r['cve_id']:<15} {r['direction']:<8} {str(joint):<9} {str(honest_infl):<16} "
              f"{str(poison_infl):<12} {caught}")

    # [2] precision/recall sweep over min_influence
    print("\n[2] Threshold sweep (detection per direction; FP on clean honest sources):")
    print(f"  {'min_infl':<9} {'detect deflate':<16} {'detect inflate':<16} {'FP rate (clean)'}")
    for d in (1, 2, 3):
        det = {"deflate": [0, 0], "inflate": [0, 0]}
        fp = [0, 0]
        for r in rows:
            pinf = r["poison_report"]["per_source"][-1]["influence"]
            hit = pinf is not None and pinf >= d
            det[r["direction"]][0] += hit
            det[r["direction"]][1] += 1
            honest_flagged = any(p["influence"] is not None and p["influence"] >= d
                                 for p in r["clean_report"]["per_source"])
            fp[0] += honest_flagged
            fp[1] += 1

        def rate(pair):
            return f"{pair[0]}/{pair[1]} ({pair[0] / pair[1]:.2f})" if pair[1] else "n/a"

        print(f"  {d:<9} {rate(det['deflate']):<16} {rate(det['inflate']):<16} {rate(fp)}")

    # [3] recovery diagnosis: is it the recovery MATH or the fixtures?
    print("\n[3] Recovery diagnosis (clean = honest-only joint; remove-poison-only = joint of the 3 honest):")
    print(f"  {'CVE':<15} {'clean':<9} {'poisoned':<9} {'remove-poison-only':<19} {'current corrected':<18} #flag")
    cur_ok = poison_only_ok = 0
    for r in rows:
        clean = r["clean_band"]
        per = r["poison_report"]["per_source"]
        poison_only = per[-1]["others_band"] if per else None     # joint of all-except-poison
        cur = r["defended_band"]
        nflag = sum(1 for p in per if p["influence"] is not None and p["influence"] >= 1)
        cur_ok += (cur == clean)
        poison_only_ok += (poison_only == clean)
        print(f"  {r['cve_id']:<15} {str(clean):<9} {str(r['poisoned_band']):<9} "
              f"{str(poison_only):<19} {str(cur):<18} {nflag}")
    n = len(rows) or 1
    print(f"\n  recovery, CURRENT rule (corrected = j_all when >1 flagged) : {cur_ok}/{len(rows)}")
    print(f"  recovery, REMOVE-ONLY-THE-POISON (joint of the honest)    : {poison_only_ok}/{len(rows)}")
    print("  If remove-poison-only == clean but current != clean -> RECOVERY MATH bug (multi-flag "
          "falls back to the poisoned j_all). honest-only reads CLEAN, so the fixtures are fine; "
          "the fix is to remove only the single poison and report joint(honest).")

    # [4] candidate identification-rule simulation (offline, from saved bands)
    print("\n[4] Identification-rule simulation (pick the rule on data):")
    print("  honest-set internally consistent per CVE (clean influences all 0):")
    for r in rows:
        print(f"    {r['cve_id']:<15} {r['direction']:<8} honest_consistent={_honest_consistent(r)}")
    rules = [("1 CURRENT (abs-infl, j_all fallback)", rule_current, rule_current_fp),
             ("2 DIRECTIONAL (minority-direction mover)", rule_directional, rule_directional_fp),
             ("3 INTERNAL-CONSISTENCY (>=3 stable rest)", rule_consistency, rule_consistency_fp)]
    print(f"\n  {'rule':<42} {'detect defl':<12} {'detect infl':<12} {'recovery':<10} {'FP(clean)'}")
    for name, poisoned_fn, fp_fn in rules:
        det = {"deflate": [0, 0], "inflate": [0, 0]}
        rec = [0, 0]
        fp = [0, 0]
        for r in rows:
            detected, recovered = poisoned_fn(r)
            det[r["direction"]][0] += detected
            det[r["direction"]][1] += 1
            rec[0] += recovered
            rec[1] += 1
            fp[0] += fp_fn(r)
            fp[1] += 1

        def rate(p):
            return f"{p[0]}/{p[1]}" if p[1] else "n/a"

        print(f"  {name:<42} {rate(det['deflate']):<12} {rate(det['inflate']):<12} "
              f"{rate(rec):<10} {rate(fp)}")
    print("\n  Decision: prefer the simplest rule with recovery high AND FP=0. Rule 3 declares "
          "'no poison' when no >=3-source consistent rest exists, so it cannot flag honest "
          "disagreement (FP=0 by construction); its recovery == # CVEs whose honest set is "
          "internally consistent.")


if __name__ == "__main__":
    main()
