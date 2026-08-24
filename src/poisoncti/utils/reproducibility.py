"""Reproducibility controls: seeding, model-digest pinning, and provenance.

Job
---
Everything that makes a run repeatable and self-describing lives here:

  - set_global_seed(seed)     -- seed Python `random` and NumPy so any sampling
                                 (study-set selection, tie-breaks) is deterministic.
  - decode_options(cfg)       -- the Ollama options dict (temperature=0 + seed)
                                 that EVERY agent call must pass, so generation is
                                 greedy and seeded.
  - resolve_model_digests(cfg)-- ask the local Ollama server for the exact content
                                 digest of each configured model tag.
  - verify_model_pins(cfg)    -- compare live digests against config/models.lock.json
                                 and raise on drift, so results can't be produced by
                                 a silently-updated model.
  - build_provenance(cfg)     -- assemble the metadata stamped into every results
                                 file: model names + digests, seed, timestamp,
                                 package version, and Ollama version.

Third-party imports (ollama) are done lazily inside functions so this module stays
importable without a running server (e.g. in unit tests).
"""

from __future__ import annotations

import json
import os
import random
from datetime import datetime, timezone
from pathlib import Path

MODELS_LOCK_PATH = "config/models.lock.json"


def set_global_seed(seed: int) -> None:
    """Seed all process-level RNGs used by the pipeline (Python, NumPy, hash)."""
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:
        # NumPy is a hard dep in practice; tolerate its absence so seeding still
        # works in a minimal environment.
        pass


def decode_options(cfg: dict) -> dict:
    """Return the Ollama `options` every agent call must use: greedy + seeded."""
    return {
        "temperature": float(cfg["models"]["temperature"]),
        "seed": int(cfg["seed"]),
    }


def _get(obj, key, default=None):
    """Read `key` from a dict OR an attribute object (ollama client may return either)."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def digest_lookup(client) -> dict:
    """Map model tag -> digest from `ollama list`.

    The digest lives in `list()`, NOT in `show()` (show() returns modelfile/details
    but no digest) — sourcing it from show() is why the lockfile captured null.
    """
    listing = _get(client.list(), "models", []) or []
    out: dict = {}
    for m in listing:
        name = _get(m, "model") or _get(m, "name")
        if name:
            out[name] = _get(m, "digest")
    return out


def match_digest(digests: dict, tag: str):
    """Find the digest for `tag`, tolerating an implicit ':latest' and bare base names."""
    if tag in digests:
        return digests[tag]
    if ":" not in tag and f"{tag}:latest" in digests:
        return digests[f"{tag}:latest"]
    base = tag.split(":")[0]
    for name, dig in digests.items():
        if name.split(":")[0] == base:
            return dig
    return None


def resolve_model_digests(cfg: dict) -> dict:
    """Query the local Ollama server for each configured tag's exact digest.

    Returns {"chat": {tag, digest, parameter_size, quantization}, "embed": {...}}.
    Digest comes from `list()`; parameter_size/quantization from `show().details`.
    Requires a running Ollama server with the models pulled.
    """
    import ollama

    client = ollama.Client(host=cfg["models"]["host"])
    digests = digest_lookup(client)
    out: dict = {}
    for role, tag in (("chat", cfg["models"]["chat"]), ("embed", cfg["models"]["embed"])):
        details = _get(client.show(tag), "details", {}) or {}
        out[role] = {
            "tag": tag,
            "digest": match_digest(digests, tag),
            "parameter_size": _get(details, "parameter_size"),
            "quantization": _get(details, "quantization_level"),
        }
    return out


def load_lock(path: str = MODELS_LOCK_PATH) -> dict:
    """Load the committed model lockfile."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_model_pins(cfg: dict, lock_path: str = MODELS_LOCK_PATH) -> None:
    """Raise RuntimeError if live model digests differ from the committed lock.

    The lock maps tag -> pin per role, so several chat models can be pinned side
    by side (multi-model replication). Only the CONFIGURED tags are verified, and
    each must already be pinned. If the local model has been re-pulled/updated,
    its digest will not match the lock and the run is aborted rather than
    silently producing different numbers.
    """
    lock = load_lock(lock_path)
    live = resolve_model_digests(cfg)
    for role in ("chat", "embed"):
        tag = live[role]["tag"]
        entry = lock.get("models", {}).get(role, {}).get(tag)
        if entry is None:
            raise RuntimeError(
                f"{lock_path} has no pin for '{role}' model '{tag}'. "
                f"Run `python scripts/00_pin_models.py --add {tag} --role {role}` to pin it."
            )
        locked = entry.get("digest")
        if locked is None:
            raise RuntimeError(
                f"{lock_path} has a null digest for '{role}' model '{tag}'. "
                f"Re-run `python scripts/00_pin_models.py --add {tag} --role {role}` to pin it."
            )
        if live[role]["digest"] != locked:
            raise RuntimeError(
                f"Model digest drift for '{role}' ({tag}): "
                f"lock={locked} live={live[role]['digest']}. "
                f"Re-pin intentionally or restore the pinned model."
            )


def build_provenance(cfg: dict, verify: bool = False) -> dict:
    """Assemble the metadata block stamped into every results file.

    With verify=False the digests come from the committed lock (no server needed);
    with verify=True they are re-resolved live and checked against the lock. The
    lock is keyed by tag, so the configured models' pins are looked up by name.
    """
    from poisoncti import __version__

    if verify:
        verify_model_pins(cfg, MODELS_LOCK_PATH)
    lock = load_lock(MODELS_LOCK_PATH)
    chat_tag, embed_tag = cfg["models"]["chat"], cfg["models"]["embed"]
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "seed": int(cfg["seed"]),
        "temperature": float(cfg["models"]["temperature"]),
        "poisoncti_version": __version__,
        "ollama_version": lock.get("ollama_version"),
        "models": {
            "chat": {"tag": chat_tag, "digest": lock["models"]["chat"][chat_tag]["digest"]},
            "embed": {"tag": embed_tag, "digest": lock["models"]["embed"][embed_tag]["digest"]},
        },
    }
