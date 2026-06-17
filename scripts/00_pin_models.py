"""Step 00 — pin the Ollama models by exact digest.

Queries the local Ollama server for the digest + details of each model tag in
config/settings.yaml, writes them to config/models.lock.json, and prints a
Markdown snippet to paste into the README's reproducibility table.

Run this ONCE on the machine that will produce results (after `ollama pull`),
then COMMIT config/models.lock.json. Every subsequent run verifies live models
against this lock and aborts on drift.

Usage:
    python scripts/00_pin_models.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from poisoncti.utils.io import load_config
from poisoncti.utils.reproducibility import MODELS_LOCK_PATH, resolve_model_digests


def _ollama_version() -> str | None:
    try:
        return subprocess.run(
            ["ollama", "--version"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> None:
    cfg = load_config()
    resolved = resolve_model_digests(cfg)
    lock = {
        "_comment": "Machine-resolved Ollama model pins. Regenerate with "
        "`python scripts/00_pin_models.py`. COMMIT this file.",
        "ollama_version": _ollama_version(),
        "resolved_utc": datetime.now(timezone.utc).isoformat(),
        "models": resolved,
    }
    Path(MODELS_LOCK_PATH).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {MODELS_LOCK_PATH}\n")

    missing = [r for r in resolved if not resolved[r].get("digest")]
    if missing:
        sys.exit(
            f"ERROR: no digest resolved for {missing}. The lock is the reproducibility "
            f"anchor and must not have null digests. Confirm the models are pulled "
            f"(`ollama list`) and re-run."
        )

    print("Paste into README under 'Reproducibility':\n")
    print("| role | tag | digest | size | quant |")
    print("|------|-----|--------|------|-------|")
    for role in ("chat", "embed"):
        m = resolved[role]
        print(f"| {role} | `{m['tag']}` | `{m['digest']}` | {m['parameter_size']} | {m['quantization']} |")


if __name__ == "__main__":
    main()
