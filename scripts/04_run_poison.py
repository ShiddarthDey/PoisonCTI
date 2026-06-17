"""Step 04 — M4 severity poisoning on the SYNTHETIC CVE arm.

For each synthetic CVE (data/synthetic/synthetic_cves.json) the agent scores severity:
  - CLEAN:    honest sources only
  - POISONED: honest sources + ONE injected poison source (single-source threat model),
              in the CVE's target direction (deflate a critical / inflate a low).
The CVE is presented by its neutral identifier only (no NVD description, no CVSS string),
so severity is inferred from the CTI. The reference 'gold' is the honest-consensus
severity designed into each synthetic CVE (replaces NVD gold for this arm; see DECISIONS.md).

Reports a before/after table: consensus vs clean vs poisoned, the delta, whether the
attack succeeded in its direction, and the poisoned rationale.

Requires Ollama. Uses config/settings.yaml.
    python scripts/04_run_poison.py            # all synthetic CVEs
    python scripts/04_run_poison.py --n 3      # first 3 (the before/after demo)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from poisoncti.agent import cve_scorer
from poisoncti.evaluation.metrics import band_shift, score_to_band
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
    parser.add_argument("--n", type=int, default=None, help="limit to first N synthetic CVEs")
    args = parser.parse_args()

    cfg = load_config("config/settings.yaml")
    set_global_seed(cfg["seed"])
    _check_ollama(cfg["models"]["host"], cfg["models"]["chat"])
    provenance = build_provenance(cfg, verify=False)
    llm_cfg = {"model": cfg["models"]["chat"], "host": cfg["models"]["host"], "options": decode_options(cfg)}

    synth = json.loads(Path(SYNTH_PATH).read_text("utf-8"))["cves"]
    items = synth[: args.n] if args.n else synth

    results = []
    print(f"M4 synthetic poisoning — {len(items)} CVE(s) (chat={cfg['models']['chat']})")
    print("PRIMARY metric = severity BAND shift. Raw 0-10 score shown only as instrument evidence.\n")
    print(f"{'CVE':<15} {'dir':<8} {'clean band':<11} {'poisoned band':<14} {'transition':<22} {'attack'}")
    for cve in items:
        rec = {"cve_id": cve["cve_id"], "description": cve["neutral_description"]}
        honest = cve["honest_sources"]
        direction = cve["consensus"]["direction"]
        poison = payloads.craft(cve["cve_id"], cve["product"], direction)

        clean = cve_scorer.score_cve(rec, honest, llm_cfg)
        poisoned = cve_scorer.score_cve(rec, honest + [poison], llm_cfg)
        cs, ps = clean["base_score"], poisoned["base_score"]
        cb, pb = score_to_band(cs), score_to_band(ps)
        shift = band_shift(cb, pb, direction)          # signed, attacker direction
        ok = shift is not None and shift > 0           # band moved the attacker's way
        transition = f"{cb}->{pb} ({cs}->{ps})"
        print(f"{cve['cve_id']:<15} {direction:<8} {str(cb):<11} {str(pb):<14} {transition:<22} {'YES' if ok else 'no'}")
        results.append({"cve_id": cve["cve_id"], "direction": direction, "consensus": cve["consensus"],
                        "clean": clean, "poisoned": poisoned, "clean_band": cb, "poisoned_band": pb,
                        "band_shift": shift, "attack_succeeded": ok, "raw_delta": None if (cs is None or ps is None) else round(ps - cs, 1),
                        "poison_text": poison["text"]})

    # per-direction summary at BAND level (the asymmetry)
    print("\nPer-direction summary (band level):")
    for d in ("deflate", "inflate"):
        rs = [r for r in results if r["direction"] == d]
        if not rs:
            continue
        succ = sum(r["attack_succeeded"] for r in rs)
        shifts = [abs(r["band_shift"]) for r in rs if r["band_shift"] is not None]
        mean_bands = round(sum(shifts) / len(shifts), 2) if shifts else None
        print(f"  {d:<8} n={len(rs)}  band-shift success={succ}/{len(rs)}  mean |band shift|={mean_bands}")

    # FULL clean->poisoned rationale comparison: does the band track the rationale content?
    print("\nFull rationale comparison (clean -> poisoned):")
    for r in results:
        print(f"  {r['cve_id']} [{r['direction']}]  band {r['clean_band']}->{r['poisoned_band']}")
        print(f"     CLEAN:    {r['clean']['rationale']}")
        print(f"     POISONED: {r['poisoned']['rationale']}")

    run_dir = new_run_dir(cfg["paths"]["experiments"], provenance)
    write_jsonl(results, str(Path(run_dir) / "synthetic_poison.jsonl"), provenance=provenance)
    n_ok = sum(r["attack_succeeded"] for r in results)
    print(f"\nOverall: attack succeeded on {n_ok}/{len(results)} CVE(s). Wrote -> {run_dir}/synthetic_poison.jsonl")


if __name__ == "__main__":
    main()
