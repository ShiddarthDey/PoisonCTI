"""Step 03 — run the agent on the CLEAN corpus.

Produces baseline ATT&CK mappings + CVE severities for every study item; these are
the reference outputs that poisoning (step 04) is measured against. Prints a
per-CVE summary (retrieved sources, predicted techniques, predicted vs gold
severity) and writes the raw results to experiments/<run>/baseline.jsonl with a
provenance stamp.

Requires a running Ollama server with the chat + embed models pulled and pinned
(whatever tags config/settings.yaml selects), e.g.:
    ollama pull <chat-tag> && ollama pull bge-m3
    python scripts/00_pin_models.py            # or: --add <chat-tag> to extend the lock

Usage:
    python scripts/03_run_baseline.py --test        # 2-CVE smoke (settings.test.yaml)
    python scripts/03_run_baseline.py               # full study set
    python scripts/03_run_baseline.py --test --no-verify   # skip digest-pin check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from poisoncti.agent import pipeline
from poisoncti.corpus import index as indexer
from poisoncti.utils.io import load_config, new_run_dir, write_jsonl
from poisoncti.utils.reproducibility import build_provenance, set_global_seed


def _check_ollama(host: str, model: str) -> None:
    try:
        import ollama

        ollama.Client(host=host).chat(
            model=model, messages=[{"role": "user", "content": "ping"}],
            options={"temperature": 0, "num_predict": 1},
        )
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Cannot reach Ollama chat ({model} @ {host}): {exc}\n"
                 f"Start Ollama and run `ollama pull {model}`.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="use config/settings.test.yaml")
    parser.add_argument("--no-verify", action="store_true", help="skip model-digest pin check")
    args = parser.parse_args()

    cfg = load_config("config/settings.test.yaml" if args.test else "config/settings.yaml")
    set_global_seed(cfg["seed"])
    _check_ollama(cfg["models"]["host"], cfg["models"]["chat"])
    provenance = build_provenance(cfg, verify=not args.no_verify)

    paths = cfg["paths"]
    corpus_index = indexer.load_index(str(Path(paths["data_processed"]) / "corpus_index"))
    attack_index = indexer.load_index(str(Path(paths["data_processed"]) / "attack_index"))
    records = json.loads((Path(paths["data_raw"]) / "cves.json").read_text("utf-8"))
    gold = {g["cve_id"]: g for g in
            json.loads((Path(paths["gold"]) / "severity_gold.json").read_text("utf-8"))}

    items = records[: cfg["ingestion"]["max_cves"]]
    print(f"Running CLEAN baseline on {len(items)} CVE(s) "
          f"(chat={cfg['models']['chat']}, embed={cfg['models']['embed']})\n")

    results = pipeline.run_items(items, corpus_index, attack_index, cfg)

    for r in results:
        g = gold.get(r["cve_id"], {})
        print("=" * 78)
        print(f"{r['cve_id']}")
        print("  retrieved (source, score, mentions):")
        for c in r["retrieved"]:
            on = "*" if r["cve_id"] in c["mentions_cves"] else " "
            print(f"   {on} {c['score']:.3f} [{c['source']}] {c['mentions_cves']}")
        print("  behaviors -> tactic -> mapped techniques (score = cosine + tactic bonus):")
        for beh, pb in zip(r["attack_behaviors"], r["attack_per_behavior"]):
            print(f"     effect:    {beh['effect']}")
            print(f"     mechanism: {beh['mechanism']}")
            print(f"     tactic(s): {beh['tactics'] or '(none tagged)'}")
            for t in pb["techniques"]:
                tag = " +tactic" if t["tactic_match"] else ""
                print(f"        {t['score']:.3f} (cos {t['cosine']:.3f}{tag})  {t['id']} ({t['name']})")
        agg = ", ".join(f"{m['id']} {m['score']:.3f}" for m in r["attack_mapping"]) or "(none)"
        print(f"  AGGREGATED top techniques: {agg}")
        sev = r["severity"]
        print(f"  Severity predicted: {sev['base_score']} ({sev['severity']})   "
              f"GOLD: {g.get('base_score')} ({g.get('base_severity')})")

    print("=" * 78)
    run_dir = new_run_dir(paths["experiments"], provenance)
    write_jsonl(results, str(Path(run_dir) / "baseline.jsonl"), provenance=provenance)
    print(f"Wrote {len(results)} results -> {run_dir}/baseline.jsonl")


if __name__ == "__main__":
    main()
