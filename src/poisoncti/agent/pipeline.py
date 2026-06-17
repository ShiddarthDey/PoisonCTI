"""Orchestrate the agent: retrieve -> ATT&CK map -> CVE severity.

Job
---
The agent's single entry point. For a CVE item it retrieves CTI, runs the
attack_mapper and cve_scorer, and returns one structured result plus the evidence
(retrieved chunks) used. The pipeline accepts an OPTIONAL defense hook so the same
code path serves the clean, poisoned, and defended conditions — the agent's own
logic never changes between conditions, keeping the comparison honest.

The retrieval query is the CVE's NVD description (the same query form validated in
scripts/diagnose_retrieval.py at 90% rank-1 on-target).

Inputs:  item (CVE record), loaded index, technique catalog, config, optional defense
Outputs: {cve_id, query, retrieved[], techniques[], severity{}, defense_report?}
"""

from __future__ import annotations

from poisoncti.agent import attack_mapper, cve_scorer
from poisoncti.agent.retriever import retrieve
from poisoncti.utils.reproducibility import decode_options


def _llm_cfg(cfg: dict) -> dict:
    return {"model": cfg["models"]["chat"], "host": cfg["models"]["host"],
            "options": decode_options(cfg)}


def _map_cfg(cfg: dict) -> dict:
    am = cfg["attack_mapping"]
    return {"embed_model": cfg["models"]["embed"], "host": cfg["models"]["host"],
            "top_k": am["top_k"], "max_techniques": am["max_techniques"],
            "min_score": am.get("min_score"), "tactic_bonus": am.get("tactic_bonus", 0.0)}


def _evidence(chunks: list[dict]) -> list[dict]:
    return [
        {"chunk_id": c["chunk_id"], "source": c.get("source"),
         "score": round(float(c["score"]), 3), "mentions_cves": c.get("mentions_cves", [])}
        for c in chunks
    ]


def run_item(item: dict, corpus_index: dict, attack_index: dict, cfg: dict, defense=None) -> dict:
    """Run retrieve->map->score for one CVE item; apply `defense` if provided.

    ATT&CK is mapped via catalog-grounded similarity (agent.attack_mapper) over
    `attack_index`. `defense` (M5) is a callable(chunks) -> {"kept_chunks": [...], ...};
    when given, the agent reasons over the kept chunks and the report is attached.
    """
    host = cfg["models"]["host"]
    query = item["description"]
    restrict_cve = item["cve_id"] if cfg["corpus"].get("restrict_to_cve") else None
    chunks = retrieve(query, corpus_index, cfg["corpus"]["top_k"], cfg["models"]["embed"], host,
                      min_score=cfg["corpus"].get("min_score"), restrict_cve=restrict_cve)

    defense_report = None
    if defense is not None:
        defense_report = defense(chunks)
        chunks = defense_report.get("kept_chunks", chunks)

    llm_cfg = _llm_cfg(cfg)
    mapped = attack_mapper.map_to_attack(item, chunks, attack_index, llm_cfg, _map_cfg(cfg))
    severity = cve_scorer.score_cve(item, chunks, llm_cfg)
    return {
        "cve_id": item.get("cve_id"),
        "query": query,
        "retrieved": _evidence(chunks),
        "techniques": mapped["techniques"],
        "attack_behaviors": mapped["behaviors"],
        "attack_mapping": mapped["mapping"],
        "attack_per_behavior": mapped["per_behavior"],
        "attack_rationale": mapped["rationale"],
        "severity": severity,
        "defense_report": defense_report,
    }


def run_items(items: list[dict], corpus_index: dict, attack_index: dict, cfg: dict, defense=None) -> list[dict]:
    """Run the pipeline over a list of CVE items and return their results."""
    return [run_item(it, corpus_index, attack_index, cfg, defense=defense) for it in items]
