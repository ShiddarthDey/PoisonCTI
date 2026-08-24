"""Diagnose the suspicious score uniformity (byte-identical CVSS scores across CVEs).

cve_scorer does NOT round/snap (base_score = float(model_output)), so any discreteness
is the MODEL emitting canonical CVSS anchors under temp=0. This checks three things on
the synthetic CVEs' HONEST sources (clean condition):

  1. RAW output: print the model's exact base_score + vector + severity (no rounding).
  2. Magnitude sensitivity: do CVEs designed at different consensus (e.g. CVE-2099-0001 at
     9.5 vs CVE-2099-0002 at 9.8) get DIFFERENT raw scores, or does the model bucket both?
  3. Temperature variance: re-score each CVE `--reps` times at `--temp` (default 0.3) with
     DIFFERENT seeds. If scores spread (9.5/9.7/9.8...), the temp=0 uniformity is a
     quantization artifact and the honest finding is "mean drift with anchor-snapping";
     if they stay locked, the scorer is genuinely coarse.

Requires Ollama. Uses config/settings.yaml. Persists per-CVE results (raw temp=0
score/vector + the temp sweep with per-rep seeds) to
experiments/<run>/score_quantization_probe.jsonl with a provenance stamp, like the
numbered pipeline steps — the numbers in the paper must be file-traceable.

    python scripts/probe_score_quantization.py
    python scripts/probe_score_quantization.py --cves CVE-2099-0001 CVE-2099-0002 --reps 5 --temp 0.3
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from poisoncti.agent import cve_scorer
from poisoncti.utils.io import load_config, new_run_dir, write_jsonl
from poisoncti.utils.reproducibility import build_provenance, set_global_seed


def _check_ollama(host: str, model: str) -> None:
    try:
        import ollama

        ollama.Client(host=host).chat(model=model, messages=[{"role": "user", "content": "ping"}],
                                      options={"temperature": 0, "num_predict": 1})
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Cannot reach Ollama chat ({model} @ {host}): {exc}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cves", nargs="+", default=["CVE-2099-0001", "CVE-2099-0002"])
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--temp", type=float, default=0.3)
    args = parser.parse_args()

    cfg = load_config("config/settings.yaml")
    seed = cfg["seed"]
    set_global_seed(seed)
    model, host = cfg["models"]["chat"], cfg["models"]["host"]
    _check_ollama(host, model)
    provenance = build_provenance(cfg, verify=True)
    run_dir = new_run_dir(cfg["paths"]["experiments"], provenance)
    rows = []
    synth = {c["cve_id"]: c for c in json.loads(Path("data/synthetic/synthetic_cves.json").read_text("utf-8"))["cves"]}

    baseline = {}
    for cve_id in args.cves:
        cve = synth[cve_id]
        rec = {"cve_id": cve_id, "description": cve["neutral_description"]}
        honest = cve["honest_sources"]
        consensus = cve["consensus"]

        print("=" * 78)
        print(f"{cve_id}  (designed consensus {consensus['base_score']} {consensus['band']})")

        # (1)+(2) raw deterministic baseline (temp=0)
        out0 = cve_scorer.score_cve(rec, honest, {"model": model, "host": host,
                                                  "options": {"temperature": 0.0, "seed": seed}})
        baseline[cve_id] = out0["base_score"]
        print(f"  temp=0 RAW: base_score={out0['base_score']}  severity={out0['severity']}  "
              f"vector={out0['vector']!r}")

        # (3) temperature variance with distinct seeds
        vals = []
        for r in range(args.reps):
            out = cve_scorer.score_cve(rec, honest, {"model": model, "host": host,
                                                     "options": {"temperature": args.temp, "seed": seed + r + 1}})
            vals.append(out["base_score"])
            print(f"  temp={args.temp} seed={seed + r + 1}: base_score={out['base_score']}  vector={out['vector']!r}")
        nums = [v for v in vals if v is not None]
        if nums:
            print(f"  --> spread: distinct={sorted(set(nums))}  min={min(nums)} max={max(nums)} "
                  f"range={round(max(nums) - min(nums), 2)}")
        rows.append({
            "cve_id": cve_id,
            "designed_consensus": {"base_score": consensus["base_score"], "band": consensus["band"]},
            "temp0": {"base_score": out0["base_score"], "severity": out0["severity"],
                      "vector": out0["vector"]},
            "temp_probe": {"temperature": args.temp,
                           "scores": [{"seed": seed + r + 1, "base_score": v} for r, v in enumerate(vals)],
                           "distinct": sorted(set(nums)),
                           "range": round(max(nums) - min(nums), 2) if nums else None},
        })

    print("=" * 78)
    print("Magnitude sensitivity (temp=0): " +
          "  ".join(f"{c}={baseline.get(c)}" for c in args.cves))
    print("If different-consensus CVEs share one score -> the model buckets by severity class.")
    print("If temp>0 spreads -> uniformity is a temp=0 anchor-snapping artifact (report mean drift).")

    out_path = str(Path(run_dir) / "score_quantization_probe.jsonl")
    write_jsonl(rows, out_path, provenance=provenance)
    print(f"\nSaved -> {out_path}")


if __name__ == "__main__":
    main()
