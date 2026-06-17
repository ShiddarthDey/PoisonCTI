"""I/O helpers: config loading, JSON/JSONL, and provenance-stamped run dirs.

Job
---
One place for the formats the project uses, so paths, serialization, and the
provenance stamp are consistent everywhere. Every results writer here attaches a
provenance block (model names+digests, seed, timestamp) so each output file is
self-describing and reproducible.

Implemented now (model-independent): config loading, JSON/JSONL read/write,
provenance stamping, and run-directory creation with a manifest.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_CONFIG = "config/settings.yaml"
EXAMPLE_CONFIG = "config/settings.example.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge `override` onto `base` (override wins)."""
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str = DEFAULT_CONFIG, example: str = EXAMPLE_CONFIG) -> dict:
    """Load YAML config, layering `path` over the committed example for defaults.

    The example file documents every key and supplies defaults; the local
    settings.yaml need only override what differs. If settings.yaml is absent we
    fall back to the example so a fresh checkout still runs.
    """
    import yaml

    base = yaml.safe_load(Path(example).read_text(encoding="utf-8")) or {}
    p = Path(path)
    if p.exists():
        override = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return _deep_merge(base, override)
    return base


def read_jsonl(path: str) -> list[dict]:
    """Read a JSONL file into a list of dicts (skips a leading _provenance line)."""
    rows: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if "_provenance" in obj and len(obj) == 1:
            continue  # provenance header line, not a data row
        rows.append(obj)
    return rows


def write_jsonl(rows: list[dict], path: str, provenance: dict | None = None) -> None:
    """Write dicts as JSONL. If `provenance` is given, write it as the first line.

    Stamping provenance into the file itself means model digest + seed + timestamp
    travel with the results — you can never lose track of how a file was produced.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        if provenance is not None:
            f.write(json.dumps({"_provenance": provenance}) + "\n")
        for row in rows:
            f.write(json.dumps(row) + "\n")


def write_json(obj: dict, path: str, provenance: dict | None = None) -> None:
    """Write a JSON object, embedding `provenance` under `_provenance` if given."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(obj)
    if provenance is not None:
        payload = {"_provenance": provenance, **payload}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_json(path: str) -> dict:
    """Read a JSON object file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def new_run_dir(experiments_dir: str, provenance: dict) -> str:
    """Create experiments/<UTC-timestamp>/ with a manifest.json provenance stamp.

    The timestamped directory + manifest is the per-run reproducibility record:
    it captures exactly which model digest and seed produced the run's outputs.
    """
    ts = provenance["timestamp_utc"].replace(":", "").replace("-", "").replace(".", "_")
    run_dir = Path(experiments_dir) / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json({"manifest": True}, str(run_dir / "manifest.json"), provenance=provenance)
    return str(run_dir)
