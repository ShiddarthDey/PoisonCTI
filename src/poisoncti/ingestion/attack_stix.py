"""Parse the MITRE ATT&CK STIX bundle into a technique catalog.

Job
---
Load the enterprise-attack STIX 2.1 bundle (a single large JSON file from the
mitre-attack/attack-stix-data repo) and extract the techniques we map against:
ATT&CK ID (e.g. "T1059.001"), name, tactic(s), description, and sub-technique
flag. This catalog is the closed label space the agent's `attack_mapper` must
choose from, and the reference the gold set is expressed in.

Inputs:  data/raw/enterprise-attack.json   (downloaded by scripts/01)
Outputs: list of technique records          ->  data/interim/techniques.json

Implementation note
-------------------
The STIX bundle is plain JSON, so we parse it with the stdlib and skip the heavy
`stix2` dependency. Techniques are `attack-pattern` objects; the ATT&CK ID lives
in `external_references` where source_name == "mitre-attack"; tactics live in
`kill_chain_phases` for the "mitre-attack" kill chain. Revoked and deprecated
techniques are dropped so the label space is current.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_bundle(path: str) -> list[dict]:
    """Read the STIX bundle JSON and return its `objects` list."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data.get("objects", [])


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _tactics(obj: dict) -> list[str]:
    return [
        ph["phase_name"]
        for ph in obj.get("kill_chain_phases", [])
        if ph.get("kill_chain_name") == "mitre-attack"
    ]


def extract_techniques(objects: list[dict]) -> list[dict]:
    """Return technique records {attack_id, name, tactics, is_subtechnique, description}.

    Drops revoked/deprecated objects so the label space matches the live matrix.
    """
    techniques: list[dict] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = _attack_id(obj)
        if not attack_id:
            continue
        techniques.append(
            {
                "attack_id": attack_id,
                "name": obj.get("name", ""),
                "tactics": _tactics(obj),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "description": (obj.get("description") or "").strip(),
            }
        )
    techniques.sort(key=lambda t: t["attack_id"])
    return techniques


def save_catalog(techniques: list[dict], out_path: str) -> None:
    """Persist the technique catalog to data/interim for downstream use."""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(techniques, indent=2), encoding="utf-8")
