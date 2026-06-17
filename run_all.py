"""run_all.py — regenerate every result and figure from scratch, deterministically.

This is the single reproduce command (also wired to `make reproduce`). It:
  1. loads config and sets the global seed,
  2. verifies the live Ollama models match config/models.lock.json (digest pins),
  3. builds the provenance stamp (model digests + seed + timestamp),
  4. runs the pipeline steps 01..06 in order, stopping at the first failure.

Steps are executed as subprocesses so each is independently runnable and so a
crash in one is isolated. Provenance is passed via the POISONCTI_RUN env so every
results file written by a step can stamp the same run identity.

Usage:
    python run_all.py            # full reproduce
    python run_all.py --no-verify   # skip live digest check (e.g. offline dry run)
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from poisoncti.utils.io import load_config
from poisoncti.utils.reproducibility import build_provenance, set_global_seed

# Generated artifacts removed by --clean. Inputs (data/raw, data/gold, data/poison,
# data/seed_cti, config) are NEVER touched.
CLEAN_GLOBS = [
    "data/interim/*",
    "data/processed/*",
    "experiments/run_*",
    "results/*",
]

STEPS = [
    "scripts/01_download_data.py",
    "scripts/02_build_corpus.py",
    "scripts/03_run_baseline.py",
    "scripts/04_run_poison.py",
    "scripts/05_run_defense.py",
    "scripts/06_evaluate.py",
]


def clean() -> None:
    """Delete generated corpora, runs, and results; keep .gitkeep and all inputs."""
    removed = 0
    for pattern in CLEAN_GLOBS:
        for path in glob.glob(pattern):
            if path.endswith(".gitkeep"):
                continue
            p = Path(path)
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            removed += 1
    print(f"--clean: removed {removed} generated path(s). Inputs untouched.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip live model-digest verification against the lock",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="remove generated artifacts (interim/processed/runs/results) and exit",
    )
    args = parser.parse_args()

    if args.clean:
        clean()
        return 0

    cfg = load_config()
    set_global_seed(cfg["seed"])
    provenance = build_provenance(cfg, verify=not args.no_verify)

    print("PoisonCTI reproduce — provenance:")
    print(json.dumps(provenance, indent=2))

    env = dict(os.environ)
    env["POISONCTI_RUN"] = json.dumps(provenance)

    for step in STEPS:
        print(f"\n=== {step} ===", flush=True)
        result = subprocess.run([sys.executable, step], env=env)
        if result.returncode != 0:
            print(f"\nFAILED at {step} (exit {result.returncode}). Stopping.")
            return result.returncode

    print("\nAll steps completed. Results in results/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
