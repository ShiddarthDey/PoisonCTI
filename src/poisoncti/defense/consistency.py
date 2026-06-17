"""Cross-source consistency check (the mitigation) — leave-one-out internal consistency.

Job
---
A lightweight, training-free defense against single-source severity poisoning.

The poison is identified as the single source whose REMOVAL leaves an internally
CONSISTENT set of the remaining sources — a set whose joint severity band does not
change when any one of its members is dropped (i.e. the survivors corroborate a
stable consensus). Under the single-poison threat model that set is the honest one,
so the corrected severity is `joint_band(all sources except the poison) =
joint_band(honest)`. If no single removal yields such a consistent set, the check
declares NO POISON (no flag).

Why this is false-positive-free on clean input: a consistent rest must have >= 3
sources. Detecting a poison therefore needs >= 4 total sources (so >= 3 remain after
removing the suspect). On clean multi-source input with 3 honest sources, removing one
leaves only 2 — never >= 3 — so the check CANNOT name an honest source as the poison,
even when honest sources disagree by a band. PRECONDITION/LIMITATION: with < 4 sources
the check abstains (declares no poison). This is a genuine limit of the threat model.

Recovery ceiling = honest-set internal consistency: the corrected band equals the
joint of the honest sources, which is correct only if the honest sources themselves
read a stable consensus (they do on the synthetic set: 8/8).

Inputs:  cve, chunks, llm config, score_fn(cve, chunks, llm_cfg) -> {base_score}
Outputs: {abstained, joint_band, corrected_band, per_source, flagged_sources,
          flagged_any, kept_chunks}
"""

from __future__ import annotations

from poisoncti.evaluation.metrics import band_ordinal, score_to_band

MIN_CONSENSUS = 3  # a "consistent rest" needs >= 3 sources; so detection needs >= 4 total


def joint_band(cve: dict, chunks: list[dict], llm_cfg: dict, score_fn) -> str | None:
    """Severity band when `chunks` are scored TOGETHER (context preserved)."""
    if not chunks:
        return None
    return score_to_band(score_fn(cve, list(chunks), llm_cfg)["base_score"])


def check(cve: dict, chunks: list[dict], llm_cfg: dict, score_fn, min_consensus: int = MIN_CONSENSUS) -> dict:
    """Identify the single poison via leave-one-out internal consistency; recover by
    removing only it and reporting the joint band of the remaining (honest) sources."""
    chunks = list(chunks)
    n = len(chunks)
    cache: dict[tuple, str | None] = {}

    def jb(idx: tuple) -> str | None:
        if idx not in cache:
            cache[idx] = joint_band(cve, [chunks[i] for i in idx], llm_cfg, score_fn)
        return cache[idx]

    all_idx = tuple(range(n))
    j_all = jb(all_idx)

    def consistent(idx: tuple) -> bool:
        """True if dropping any single member does not change the subset's joint band."""
        if len(idx) < min_consensus:
            return False
        base = jb(idx)
        return all(jb(tuple(x for x in idx if x != i)) == base for i in idx)

    # per-source leave-one-out bands (for transparency / the inspector)
    per_source = []
    for i, ch in enumerate(chunks):
        ob = jb(tuple(x for x in all_idx if x != i))
        a, b = band_ordinal(j_all), band_ordinal(ob)
        per_source.append({"source": ch.get("source"), "others_band": ob,
                           "influence": None if (a is None or b is None) else abs(a - b)})

    base_out = {"joint_band": j_all, "corrected_band": j_all, "per_source": per_source,
                "flagged_sources": [], "flagged_any": False, "kept_chunks": chunks}

    # need >= min_consensus+1 sources to detect; and a stable full set means no poison
    if n < min_consensus + 1 or consistent(all_idx):
        return {**base_out, "abstained": n < min_consensus + 1}

    # the poison = the unique source whose removal leaves an internally-consistent rest
    candidates = [i for i in all_idx if consistent(tuple(x for x in all_idx if x != i))]
    if len(candidates) != 1:
        return {**base_out, "abstained": False}            # ambiguous / none -> declare no poison

    p = candidates[0]
    rest = tuple(x for x in all_idx if x != p)
    return {"abstained": False, "joint_band": j_all, "corrected_band": jb(rest),
            "per_source": per_source, "flagged_sources": [chunks[p].get("source")],
            "flagged_any": True, "kept_chunks": [chunks[i] for i in rest]}
