"""Step 00 — pin the Ollama models by exact digest.

Queries the local Ollama server for the digest + details of each model tag in
config/settings.yaml and merges them into config/models.lock.json, keyed by tag.
The lock can hold SEVERAL tags per role (e.g. llama3:8b + mistral:7b for the
cross-model replication); merging is append-only — existing pins for other tags
are preserved.

Run this ONCE per model on the machine that will produce results (after
`ollama pull`), then COMMIT config/models.lock.json. Every subsequent run
verifies the CONFIGURED tag against this lock and aborts on drift (or on an
unpinned tag).

Usage:
    python scripts/00_pin_models.py                       # pin the configured tags
    python scripts/00_pin_models.py --add mistral:7b      # pin an extra chat model
    python scripts/00_pin_models.py --add nomic-embed-text --role embed
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from poisoncti.utils.io import load_config
from poisoncti.utils.reproducibility import MODELS_LOCK_PATH, resolve_model_digests

_COMMENT = ("Machine-resolved Ollama model pins, keyed by tag. Extend with "
            "`python scripts/00_pin_models.py --add <tag>`. COMMIT this file.")


def _ollama_version() -> str | None:
    try:
        return subprocess.run(
            ["ollama", "--version"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--add", metavar="TAG", default=None,
                        help="pin this tag (default role: chat) instead of the configured "
                             "chat tag; the configured embed tag is always (re-)resolved too")
    parser.add_argument("--role", choices=("chat", "embed"), default="chat",
                        help="role for --add (default: chat)")
    args = parser.parse_args()

    cfg = load_config()
    if args.add:
        cfg["models"][args.role] = args.add
    resolved = resolve_model_digests(cfg)

    missing = [r for r in resolved if not resolved[r].get("digest")]
    if missing:
        sys.exit(
            f"ERROR: no digest resolved for {missing}. The lock is the reproducibility "
            f"anchor and must not have null digests. Confirm the models are pulled "
            f"(`ollama list`) and re-run."
        )

    # Append-only merge: pins are keyed by tag; pins for other tags are preserved.
    lock_path = Path(MODELS_LOCK_PATH)
    lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {}
    lock["_comment"] = _COMMENT
    lock["ollama_version"] = _ollama_version()
    lock["resolved_utc"] = datetime.now(timezone.utc).isoformat()
    models = lock.setdefault("models", {})
    for role in ("chat", "embed"):
        m = resolved[role]
        models.setdefault(role, {})[m["tag"]] = {
            "digest": m["digest"],
            "parameter_size": m["parameter_size"],
            "quantization": m["quantization"],
        }
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {MODELS_LOCK_PATH}\n")

    print("Paste into README under 'Reproducibility':\n")
    print("| role | tag | digest | size | quant |")
    print("|------|-----|--------|------|-------|")
    for role in ("chat", "embed"):
        for tag, m in models.get(role, {}).items():
            print(f"| {role} | `{tag}` | `{m['digest']}` | {m['parameter_size']} | {m['quantization']} |")


if __name__ == "__main__":
    main()
