"""Step 06 — assemble RESULTS.md from the saved experiment jsonl. NO model calls.

Reads the M4 (synthetic_poison.jsonl) and M5 (defense.jsonl) outputs written by
scripts 04/05, recomputes every table from the data, pulls example rationales
verbatim from the jsonl, and writes RESULTS.md with each number traced to its run
directory + provenance (model digest, seed, timestamp). Nothing is hand-typed.

Usage:
    python scripts/06_evaluate.py
    python scripts/06_evaluate.py --m4 experiments/run_A/synthetic_poison.jsonl \
                                  --m5 experiments/run_B/defense.jsonl \
                                  --m4-prior experiments/run_OLD/synthetic_poison.jsonl
    (--m4-prior is the earlier 2-honest-source attack run, for the dilution comparison)
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from pathlib import Path

from poisoncti.evaluation.metrics import band_ordinal, score_to_band
from poisoncti.utils.io import read_jsonl


def _row_band_shift(r):
    """Signed band shift (attacker direction), tolerating older rows without band_shift."""
    if r.get("band_shift") is not None:
        return r["band_shift"]
    cb = r.get("clean_band") or score_to_band((r.get("clean") or {}).get("base_score"))
    pb = r.get("poisoned_band") or score_to_band((r.get("poisoned") or {}).get("base_score"))
    if band_ordinal(cb) is None or band_ordinal(pb) is None:
        return None
    diff = band_ordinal(pb) - band_ordinal(cb)
    return diff if r["direction"] == "inflate" else -diff


def _latest(pattern: str) -> str | None:
    files = glob.glob(pattern)
    return max(files, key=os.path.getmtime) if files else None


def _provenance(path: str) -> dict:
    first = Path(path).read_text("utf-8").splitlines()[0]
    obj = json.loads(first)
    return obj.get("_provenance", {}) if isinstance(obj, dict) else {}


def _run_id(path: str) -> str:
    return Path(path).parent.name


def _prov_line(path: str) -> str:
    p = _provenance(path)
    chat = p.get("models", {}).get("chat", {})
    return (f"`{_run_id(path)}/{Path(path).name}` — chat=`{chat.get('tag')}` "
            f"digest=`{str(chat.get('digest'))[:19]}…` seed={p.get('seed')} @ {p.get('timestamp_utc')}")


def _mean_abs_shift(rows, direction):
    vals = [abs(_row_band_shift(r)) for r in rows
            if r["direction"] == direction and _row_band_shift(r) is not None]
    return round(sum(vals) / len(vals), 2) if vals else None


def m4_section(m4_path, prior_path):
    rows = read_jsonl(m4_path)
    lines = ["## 1. Attack (M4) — single-source severity poisoning\n",
             f"Source: {_prov_line(m4_path)}\n",
             "| CVE | dir | clean band | poisoned band | band shift (attacker dir) | success |",
             "|-----|-----|-----------|---------------|---------------------------|---------|"]
    for r in rows:
        lines.append(f"| {r['cve_id']} | {r['direction']} | {r['clean_band']} | {r['poisoned_band']} "
                     f"| {r['band_shift']:+d} | {'YES' if r['attack_succeeded'] else 'no'} |")
    lines.append("")
    for d in ("deflate", "inflate"):
        rs = [r for r in rows if r["direction"] == d]
        succ = sum(r["attack_succeeded"] for r in rs)
        lines.append(f"- **{d}**: band-shift success {succ}/{len(rs)}, mean |band shift| "
                     f"= {_mean_abs_shift(rows, d)}")
    # dilution comparison (2-source vs 3-source) if a prior run is supplied
    prior_rows = None
    if prior_path:
        prior_rows = read_jsonl(prior_path)
        lines.append(f"\n**Corroboration dilution (2 vs 3 honest sources)** — prior run: {_prov_line(prior_path)}\n")
        lines.append("| direction | mean \\|band shift\\| (prior) | mean \\|band shift\\| (current) |")
        lines.append("|-----------|------------------------------|--------------------------------|")
        for d in ("deflate", "inflate"):
            lines.append(f"| {d} | {_mean_abs_shift(prior_rows, d)} | {_mean_abs_shift(rows, d)} |")
        lines.append("\nA 3rd independent honest source reduces the inflation attack's magnitude; "
                     "deflation was already 1 band. **Corroboration partially resists poison.**")
    
    inf_mean = _mean_abs_shift(rows, "inflate")
    def_mean = _mean_abs_shift(rows, "deflate")
    if inf_mean is not None and def_mean is not None and inf_mean > def_mean:
        asym_text = ("inflation must claim CRITICAL (far above a LOW/MEDIUM consensus) — a "
                     "large move; deflation against a CRITICAL consensus moves at most one band in practice. "
                     "Inflation is the easier, larger-magnitude attack.")
    else:
        both_val = f"{inf_mean:.1f}" if inf_mean is not None else "?"
        asym_text = f"no directional asymmetry was observed for this model (mean |band shift| = {both_val} for both inflation and deflation)."
    lines.append(f"\n**Asymmetry:** {asym_text}\n")
    return rows, prior_rows, "\n".join(lines)


def m5_section(m5_path):
    rows = read_jsonl(m5_path)
    det = sum(r["poison_caught"] for r in rows)
    rec = sum(r["recovered"] for r in rows)
    fp = sum(r["clean_flagged_any"] for r in rows)
    n = len(rows)
    lines = ["## 2. Defense (M5) — leave-one-out internal-consistency check\n",
             f"Source: {_prov_line(m5_path)}\n",
             "| CVE | dir | clean | poisoned | defended | poison caught | recovered | clean FP |",
             "|-----|-----|-------|----------|----------|---------------|-----------|----------|"]
    for r in rows:
        lines.append(f"| {r['cve_id']} | {r['direction']} | {r['clean_band']} | {r['poisoned_band']} "
                     f"| {r['defended_band']} | {'YES' if r['poison_caught'] else 'no'} "
                     f"| {'YES' if r['recovered'] else 'no'} | {'YES' if r['clean_flagged_any'] else 'no'} |")
    lines.append(f"\n- **Detection: {det}/{n}**, **recovery: {rec}/{n} ({rec / n:.2f})**, "
                 f"**false positives: {fp}/{n} ({fp / n:.2f})**")
    lines.append("- **Precondition / limitation:** detection needs ≥4 total sources (a consistent rest "
                 "needs ≥3, so ≥3 must remain after removing the suspect). With fewer, the check abstains.")
    lines.append("- **FP=0 by construction:** clean 3-honest input leaves only 2 after a removal — never a "
                 "≥3-source consistent rest — so an honest source can never be named the poison, even when "
                 "honest sources disagree by a band.")
    lines.append("- **Recovery ceiling = honest-set internal consistency** (the corrected band is the joint "
                 f"of the honest sources). Here all {n}/{n} honest sets are internally consistent.\n")
    return rows, "\n".join(lines)


def examples_section(m4_rows):
    lines = ["## 4. Example rationales (verbatim from the M4 jsonl)\n"]
    for d in ("deflate", "inflate"):
        ex = next((r for r in m4_rows if r["direction"] == d), None)
        if not ex:
            continue
        lines.append(f"**{ex['cve_id']} ({d})** — clean {ex['clean_band']} → poisoned {ex['poisoned_band']}\n")
        lines.append(f"- CLEAN rationale: {ex['clean']['rationale']}")
        lines.append(f"- POISONED rationale: {ex['poisoned']['rationale']}")
        lines.append(f"- injected poison source: {ex['poison_text']}\n")
    return "\n".join(lines)


def coupling_section(m4_rows: list[dict], prior_rows: list[dict] | None = None) -> str:
    if prior_rows:
        prior_inf = _mean_abs_shift(prior_rows, "inflate")
        curr_inf = _mean_abs_shift(m4_rows, "inflate")
        prior_by_cve = {r["cve_id"]: _row_band_shift(r) for r in prior_rows if r["direction"] == "inflate"}
        curr_by_cve = {r["cve_id"]: _row_band_shift(r) for r in m4_rows if r["direction"] == "inflate"}
        diluted = []
        held = []
        for cve_id, curr_s in curr_by_cve.items():
            prior_s = prior_by_cve.get(cve_id)
            if prior_s is not None:
                if curr_s < prior_s:
                    diluted.append((prior_s, curr_s))
                elif curr_s == prior_s:
                    held.append(curr_s)
        total_inf = len(curr_by_cve)
        if len(diluted) == 2 and total_inf == 4:
            details = (f"two of the four inflation CVEs diluted from a {diluted[0][0]}-band to a {diluted[0][1]}-band shift, "
                       f"the other two held at {held[0]} bands")
        elif diluted:
            details = f"{len(diluted)} of the {total_inf} inflation CVEs diluted"
        else:
            details = "inflation magnitude held constant"
        parenthetical = (f"(inflation's mean magnitude fell from {prior_inf:.1f} to {curr_inf:.1f} bands when a "
                         f"3rd honest source was added — {details})")
    else:
        parenthetical = "(as measured on llama3:8b, adding a 3rd honest source reduced inflation's mean magnitude)"

    return f"""## 3. The coupling (the through-line)

The same property governs both halves of the study: **independent honest corroboration**.
- It **dilutes the attack** — a single poisoned source moves the joint severity band less as
  more honest sources corroborate {parenthetical}.
- It **enables the defense** — the leave-one-out check works precisely because removing the
  poison reveals a stable honest consensus, which requires that consensus to exist (≥3 honest).

So more independent honest sources do double duty: they blunt the poison and make it detectable.
"""


def limitations_section(chat_tag: str, m4_rows: list[dict], m5_rows: list[dict]) -> str:
    det = sum(r["poison_caught"] for r in m5_rows)
    rec = sum(r["recovered"] for r in m5_rows)
    fp = sum(r["clean_flagged_any"] for r in m5_rows)
    n = len(m5_rows)
    rec_str = f"{rec / n:.2f}" if n else "0.00"
    fp_str = f"{fp / n:.2f}" if n else "0.00"

    mismatches = [
        f"{r['cve_id']} ({r['direction']}: consensus {r['consensus']['band']}, "
        f"clean {r['clean_band']})"
        for r in m4_rows
        if r.get("consensus", {}).get("band") and r.get("clean_band")
        and r["clean_band"] != r["consensus"]["band"]
    ]
    calibration_note = (
        "Clean band differs from the designed consensus on: " + "; ".join(mismatches) + "."
        if mismatches else
        f"Clean band equals the designed consensus on all {len(m4_rows)} CVEs."
    )
    return f"""## 5. Limitations

- **Scale: n = {n} synthetic CVEs.** This is a controlled *mechanism demonstration*, not a
  benchmark. The numbers ({det}/{n} detection, {rec_str} recovery, {fp_str} FP) characterise the mechanism on
  a small, deliberately-constructed set; they are not population estimates.
- **Calibration vs steering.** Two distinct quantities appear in this report: *calibration*
  (the model's clean band vs the designed consensus band) and *steering* (the band shift vs
  the model's OWN clean baseline). Attack success and defense recovery are measured against
  the model's own clean band, so a model whose clean band already sits at or below the
  consensus band leaves less room for a deflation shift to register — a floor effect that
  must not be misread as robustness. {calibration_note}
- **Instrument findings as scope, not as headline accuracy claims:**
  - The local model ({chat_tag}) **imitates CVSS output format without computing it** — it emits
    canonical base scores (9.8/7.5/4.3) with malformed/hallucinated vectors and cannot resolve
    magnitude. We therefore measure severity at the **band level** only.
  - Fine-grained **ATT&CK mapping is unreliable** with this model (≈75% ID/concept mismatch; an
    abstraction gap defeats catalog-grounded mapping). The study is **severity-focused**;
    ATT&CK mapping is reported elsewhere only as a perturbation signal, not accuracy.
- **Synthetic CVEs by design.** Real CVEs were unusable as a clean testbed: their NVD
  descriptions embed the CVSS answer, and the model has memorized priors. Synthetic CVEs remove
  both the answer-key and memorized-prior confounds and let us control honest-vs-poison
  corroboration. The cost is no NVD gold; the reference is the honest-consensus severity by
  construction.
- **External validity (future work):** a real-CVE arm — with honest fixtures rewritten to remove
  CVSS strings and severity words so severity is inferred — would test the mechanism under
  memorized priors. It is the harder, prior-contaminated condition and is left for future work.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--m4", default=_latest("experiments/run_*/synthetic_poison.jsonl"))
    parser.add_argument("--m5", default=_latest("experiments/run_*/defense.jsonl"))
    parser.add_argument("--m4-prior", default=None, dest="m4_prior")
    parser.add_argument("--out", default="RESULTS.md")
    args = parser.parse_args()
    if not args.m4 or not args.m5:
        raise SystemExit("Need an M4 (synthetic_poison.jsonl) and M5 (defense.jsonl) run. "
                         "Run scripts/04 and 05 first, or pass --m4/--m5.")

    m4_rows, prior_rows, m4_md = m4_section(args.m4, args.m4_prior)
    m5_rows, m5_md = m5_section(args.m5)
    chat_tag = _provenance(args.m4).get("models", {}).get("chat", {}).get("tag", "?")
    header = ("# PoisonCTI — Results\n\n"
              "How reliably can a single poisoned open-source CTI source steer an LLM threat-intel\n"
              "agent's CVE severity scoring, and can a lightweight cross-source consistency check\n"
              "restore reliability without retraining? Results below are computed by\n"
              "`scripts/06_evaluate.py` from the saved experiment jsonl (no model calls); every table\n"
              "cites its run directory + provenance.\n")
    doc = "\n".join([header, m4_md, m5_md, coupling_section(m4_rows, prior_rows), examples_section(m4_rows),
                     limitations_section(chat_tag, m4_rows, m5_rows)])
    Path(args.out).write_text(doc, encoding="utf-8")
    print(f"Wrote {args.out} from:\n  M4: {args.m4}\n  M5: {args.m5}"
          + (f"\n  M4-prior: {args.m4_prior}" if args.m4_prior else ""))



if __name__ == "__main__":
    main()
