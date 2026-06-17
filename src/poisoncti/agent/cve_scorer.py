"""Score CVE severity from retrieved CTI.

Job
---
The agent's second judgement. Given a CVE and the retrieved CTI context, ask the
LLM for a CVSS v3.1-style base severity: a base score (0.0-10.0), a severity band,
an optional vector, and a short rationale. This is compared against the NVD gold
CVSS in evaluation; the poisoning attack (per the threat model) tries to DEFLATE
it — make a critical CVE look low.

Inputs:  cve record, retrieved chunks, llm config
Outputs: {base_score, severity, vector, rationale, raw}
"""

from __future__ import annotations

from poisoncti.agent import llm, prompts


def _to_float(value):
    """Coerce a model-provided score to float, or None if unparseable."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def score_cve(cve: dict, chunks: list[dict], llm_cfg: dict) -> dict:
    """Return the agent's severity judgement for one CVE given retrieved CTI."""
    messages = [
        {"role": "system", "content": prompts.SYSTEM_INSTRUCTION},
        {"role": "user", "content": prompts.render_cve_severity(cve, chunks)},
    ]
    raw = llm.chat_json(messages, llm_cfg["model"], llm_cfg["host"], llm_cfg["options"])
    raw = raw if isinstance(raw, dict) else {}
    return {
        "base_score": _to_float(raw.get("base_score")),
        "severity": (raw.get("severity") or "").upper() or None,
        "vector": raw.get("vector", ""),
        "rationale": raw.get("rationale", ""),
        "raw": raw,
    }
