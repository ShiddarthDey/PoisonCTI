"""Step 05 — M5 cross-source consistency defense (leave-one-out) on the synthetic arm.

For each synthetic CVE it measures BOTH sides of the ledger:
  RECOVERY (poisoned input = honest + 1 poison): the defense identifies the poison as the
    single source whose removal leaves an internally-consistent (>= min_consensus) set, removes
    it, and reports the joint band of the rest. Success = corrected band == clean band.
  FALSE POSITIVE (clean input = honest only): the same check on honest-only sources. A flag
    here wrongly removes an honest source — the cost side, meaningful because the honest
    sources disagree naturally.

The poison carries the same source tag as honest ones; detection is measured by object
identity (measurement only — the defense uses joint-band influence, never that).

Requires Ollama (many score calls per CVE). Uses config/settings.yaml.
    python scripts/05_run_defense.py            # all synthetic CVEs
    python scripts/05_run_defense.py --n 3
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from poisoncti.agent import cve_scorer
from poisoncti.defense import consistency
from poisoncti.evaluation.metrics import defense_band_recovery, defense_false_positive_rate, score_to_band
from poisoncti.poison import payloads
from poisoncti.utils.io import load_config, new_run_dir, write_jsonl
from poisoncti.utils.reproducibility import build_provenance, decode_options, set_global_seed

SYNTH_PATH = "data/synthetic/synthetic_cves.json"


def _check_ollama(host: str, model: str) -> None:
    try:
        import ollama

        ollama.Client(host=host).chat(model=model, messages=[{"role": "user", "content": "ping"}],
                                      options={"temperature": 0, "num_predict": 1})
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Cannot reach Ollama chat ({model} @ {host}): {exc}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=None)
    args = parser.parse_args()

    cfg = load_config("config/settings.yaml")
    set_global_seed(cfg["seed"])
    _check_ollama(cfg["models"]["host"], cfg["models"]["chat"])
    provenance = build_provenance(cfg, verify=False)
    llm_cfg = {"model": cfg["models"]["chat"], "host": cfg["models"]["host"], "options": decode_options(cfg)}
    min_consensus = cfg["defense"]["min_consensus_sources"]

    synth = json.loads(Path(SYNTH_PATH).read_text("utf-8"))["cves"]
    items = synth[: args.n] if args.n else synth

    results = []
    print(f"M5 leave-one-out internal-consistency defense — {len(items)} CVE(s), "
          f"min_consensus_sources={min_consensus}\n")
    print(f"{'CVE':<15} {'dir':<8} {'clean':<9} {'poisoned':<9} {'defended':<9} "
          f"{'caught':<8} {'recovered':<10} {'clean FP'}")
    for cve in items:
        rec = {"cve_id": cve["cve_id"], "description": cve["neutral_description"]}
        honest = cve["honest_sources"]
        direction = cve["consensus"]["direction"]
        poison = payloads.craft(cve["cve_id"], cve["product"], direction)
        poisoned_chunks = honest + [poison]

        clean_band = score_to_band(cve_scorer.score_cve(rec, honest, llm_cfg)["base_score"])
        poisoned_band = score_to_band(cve_scorer.score_cve(rec, poisoned_chunks, llm_cfg)["base_score"])

        rep = consistency.check(rec, poisoned_chunks, llm_cfg, cve_scorer.score_cve, min_consensus)
        poison_caught = (not rep["abstained"]) and not any(c is poison for c in rep["kept_chunks"])
        defended_band = rep["corrected_band"]
        recovered = defended_band == clean_band

        rep_clean = consistency.check(rec, honest, llm_cfg, cve_scorer.score_cve, min_consensus)
        clean_fp = rep_clean["flagged_any"]

        print(f"{cve['cve_id']:<15} {direction:<8} {str(clean_band):<9} {str(poisoned_band):<9} "
              f"{str(defended_band):<9} {str(poison_caught):<8} {str(recovered):<10} {clean_fp}")
        results.append({"cve_id": cve["cve_id"], "direction": direction,
                        "clean_band": clean_band, "poisoned_band": poisoned_band,
                        "defended_band": defended_band, "poison_caught": poison_caught,
                        "recovered": recovered, "clean_flagged_any": clean_fp,
                        "poison_report": rep, "clean_report": rep_clean})

    poisoned_rows = [{"clean_band": r["clean_band"], "defended_band": r["defended_band"]} for r in results]
    fp_rows = [{"flagged_any": r["clean_flagged_any"]} for r in results]
    caught = sum(r["poison_caught"] for r in results)
    print("\nDefense summary:")
    print(f"  poison detection rate : {caught}/{len(results)}")
    print(f"  band recovery rate    : {defense_band_recovery(poisoned_rows):.2f}")
    print(f"  false-positive rate   : {defense_false_positive_rate(fp_rows):.2f}")
    for d in ("deflate", "inflate"):
        rs = [r for r in results if r["direction"] == d]
        if rs:
            print(f"    {d}: detection {sum(r['poison_caught'] for r in rs)}/{len(rs)}")

    run_dir = new_run_dir(cfg["paths"]["experiments"], provenance)
    write_jsonl(results, str(Path(run_dir) / "defense.jsonl"), provenance=provenance)
    print(f"\nWrote -> {run_dir}/defense.jsonl")


if __name__ == "__main__":
    main()
