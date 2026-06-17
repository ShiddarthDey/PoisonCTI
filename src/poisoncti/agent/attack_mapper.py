"""Map retrieved CTI to MITRE ATT&CK techniques via catalog-grounded similarity.

Job
---
The first of the agent's two judgements. Rather than trusting a small model to
recall ATT&CK T-codes (it mismatched ID<->concept ~75% on clean data — correct
intent, wrong code), we:

  1. ask the model for plain-language attacker BEHAVIOR statements (no IDs/names),
     grounded only in the CTI context;
  2. embed each behavior (bge-m3) and match it against the official technique
     catalog index (each technique = "name. description" embedded once at build
     time), keeping the top-k techniques per behavior above an optional cosine floor;
  3. aggregate across behaviors (best score per technique), cap the total, and
     return techniques with CANONICAL names by construction.

So predicted IDs come from the catalog via similarity — they always match the
described concept, and there are no hallucinated or wrong-for-concept IDs.

Inputs:  cve, retrieved chunks, attack_index (loaded technique index), llm_cfg,
         map_cfg {embed_model, host, top_k, max_techniques, min_score}, optional embed_fn
Outputs: {techniques: [{id, name}], mapping: [{id, name, score, behavior}],
          behaviors: [...], rationale}
"""

from __future__ import annotations

from poisoncti.agent import llm, prompts
from poisoncti.corpus import embed as _embed
from poisoncti.corpus import index as _index

# The 12 enterprise tactics, as catalog phase_names (what technique.tactics holds).
TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
}


def _norm_tactic(t: str) -> str:
    """Map a display tactic name ('Lateral Movement') to a catalog phase ('lateral-movement')."""
    return (t or "").strip().lower().replace(" ", "-")


def _normalize_behavior(b) -> dict:
    """Coerce a behavior to {effect, mechanism, tactics}. We map on `effect`; a bare
    string (looser model output) is treated as the effect with no tactic."""
    if isinstance(b, str):
        return {"effect": b.strip(), "mechanism": "", "tactics": []}
    if not isinstance(b, dict):
        return {"effect": "", "mechanism": "", "tactics": []}
    tac = b.get("tactic") or b.get("tactics") or []
    if isinstance(tac, str):
        tac = [tac]
    tactics = [p for p in (_norm_tactic(t) for t in tac) if p in TACTICS][:2]  # up to two
    return {"effect": (b.get("effect") or "").strip(),
            "mechanism": (b.get("mechanism") or "").strip(), "tactics": tactics}


def map_to_attack(cve: dict, chunks: list[dict], attack_index: dict, llm_cfg: dict,
                  map_cfg: dict, embed_fn=None) -> dict:
    """Map the CVE to ATT&CK techniques via model behaviors + catalog similarity.

    Mapping is on the model's `effect` text (its own-words abstraction), with a SOFT
    tactic prior: adjusted = cosine + alpha * [behavior tactic intersects technique
    tactics]. Additive only — a technique in a non-matching tactic keeps its raw
    cosine and still competes, so a mis-tagged tactic can never drop the correct
    technique. The bonus is applied over the FULL catalog (not just top-k by cosine),
    so a correct technique buried deep by surface vocabulary can still be lifted.
    """
    messages = [
        {"role": "system", "content": prompts.SYSTEM_INSTRUCTION},
        {"role": "user", "content": prompts.render_attack_behaviors(cve, chunks)},
    ]
    raw = llm.chat_json(messages, llm_cfg["model"], llm_cfg["host"], llm_cfg["options"])
    raw = raw if isinstance(raw, dict) else {}
    behaviors = [b for b in (_normalize_behavior(x) for x in (raw.get("behaviors") or []))
                 if b["effect"] or b["mechanism"]]

    fn = embed_fn or (lambda t: _embed.embed_query(t, map_cfg["embed_model"], map_cfg["host"]))
    alpha = float(map_cfg.get("tactic_bonus", 0.0))
    full_k = len(attack_index["chunks"])

    best: dict[str, dict] = {}      # attack_id -> best adjusted mapping across behaviors
    per_behavior: list[dict] = []
    for b in behaviors:
        query_text = b["effect"] or b["mechanism"]
        qv = fn(query_text)
        scored = []
        for tech in _index.query(attack_index, qv, full_k, min_score=map_cfg.get("min_score")):
            cos = round(float(tech["score"]), 3)
            match = bool(b["tactics"] and set(tech.get("tactics", [])) & set(b["tactics"]))
            scored.append({"id": tech["attack_id"], "name": tech["name"], "cosine": cos,
                           "score": round(cos + (alpha if match else 0.0), 3), "tactic_match": match})
        scored.sort(key=lambda m: -m["score"])
        top = scored[: map_cfg["top_k"]]
        per_behavior.append({"effect": query_text, "tactics": b["tactics"], "techniques": top})
        for m in top:
            if m["id"] not in best or m["score"] > best[m["id"]]["score"]:
                best[m["id"]] = {**m, "effect": query_text}

    ranked = sorted(best.values(), key=lambda m: -m["score"])[: map_cfg.get("max_techniques", 4)]
    return {
        "techniques": [{"id": m["id"], "name": m["name"]} for m in ranked],
        "mapping": ranked,
        "per_behavior": per_behavior,
        "behaviors": behaviors,
        "rationale": raw.get("rationale", ""),
    }
