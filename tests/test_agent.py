"""Agent tests: prompts, catalog-grounded ATT&CK mapping, severity, pipeline.

All run without Ollama by monkeypatching llm.chat_json and injecting embeddings.
"""

import numpy as np

from poisoncti.agent import attack_mapper, cve_scorer, llm, pipeline, prompts
from poisoncti.corpus import index as indexer

CHUNKS = [
    {"chunk_id": "c0", "source": "cisa", "text": "log4j jndi rce", "mentions_cves": ["CVE-1"], "score": 0.7},
    {"chunk_id": "c1", "source": "vendor_blog", "text": "exploitation", "mentions_cves": ["CVE-1"], "score": 0.6},
]
CVE = {"cve_id": "CVE-1", "description": "a critical rce in log4j"}

# tiny ATT&CK index: T1190 on the x-axis, T1059 on the y-axis
ATTACK_RECS = [{"attack_id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"]},
               {"attack_id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"]}]
ATTACK_INDEX = {"matrix": indexer._normalize(np.array([[1.0, 0.0], [0.0, 1.0]], np.float32)),
                "chunks": ATTACK_RECS}
MAP_CFG = {"embed_model": "e", "host": "h", "top_k": 2, "max_techniques": 4,
           "min_score": None, "tactic_bonus": 0.0}
LLM_CFG = {"model": "m", "host": "h", "options": {}}


# --- prompts ---------------------------------------------------------------

def test_behaviors_prompt_includes_cve_and_source_context():
    text = prompts.render_attack_behaviors(CVE, CHUNKS)
    assert "CVE-1" in text and "log4j" in text
    assert "[source: cisa]" in text and "[source: vendor_blog]" in text
    assert '"effect"' in text and '"mechanism"' in text          # both fields elicited
    assert '"tactic"' in text and "Lateral Movement" in text     # tactic prior (12-way)
    assert "Do NOT reference MITRE ATT&CK technique names" in text
    # anti-leak: the prompt must not hand the model ATT&CK TECHNIQUE phrasings
    assert "exploitation of a remote service" not in text.lower()
    assert "public-facing application" not in text.lower()


def test_format_context_handles_empty():
    assert "no CTI" in prompts.format_context([])


# --- llm json parsing ------------------------------------------------------

def test_llm_loads_extracts_json_from_noise():
    assert llm._loads('here you go: {"base_score": 9.8} thanks') == {"base_score": 9.8}


# --- catalog-grounded ATT&CK mapping ---------------------------------------

def test_map_grounds_effect_to_catalog_technique(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {
        "behaviors": [{"effect": "attacker gains an initial foothold on an internet-facing host",
                       "mechanism": "crafted request"}],
        "rationale": "r"})
    # the EFFECT text embeds near the T1190 axis
    out = attack_mapper.map_to_attack(CVE, CHUNKS, ATTACK_INDEX, LLM_CFG, MAP_CFG,
                                      embed_fn=lambda _t: np.array([1.0, 0.1], np.float32))
    assert out["techniques"][0] == {"id": "T1190", "name": "Exploit Public-Facing Application"}
    assert out["behaviors"][0]["mechanism"] == "crafted request"   # mechanism kept
    assert out["mapping"][0]["score"] > 0.9
    assert out["mapping"][0]["effect"].startswith("attacker gains")  # mapped on effect


def test_map_accepts_bare_string_behavior_as_effect(monkeypatch):
    # robustness: a looser model that returns a plain string is treated as the effect
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"behaviors": ["run commands on the host"]})
    out = attack_mapper.map_to_attack(CVE, CHUNKS, ATTACK_INDEX, LLM_CFG, MAP_CFG,
                                      embed_fn=lambda _t: np.array([0.05, 1.0], np.float32))
    assert out["techniques"][0]["id"] == "T1059"
    assert out["behaviors"][0]["effect"] == "run commands on the host"


# --- (c) soft tactic prior -------------------------------------------------

# T1210 (Lateral Movement) vs T1547 (Persistence) — the EternalBlue failure shape
TAC_INDEX = {"matrix": indexer._normalize(np.array([[1.0, 0.0], [0.0, 1.0]], np.float32)),
             "chunks": [{"attack_id": "T1210", "name": "Exploitation of Remote Services",
                         "tactics": ["lateral-movement"]},
                        {"attack_id": "T1547", "name": "Kernel Modules", "tactics": ["persistence"]}]}


def test_tactic_prior_lifts_correct_technique_over_surface_winner(monkeypatch):
    # behavior embeds CLOSER to the wrong technique by cosine (0.8 vs 0.6) — the bug
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {
        "behaviors": [{"effect": "exploit a remote service to run code and reach other hosts",
                       "mechanism": "kernel-level control", "tactic": ["Lateral Movement"]}]})
    qfn = lambda _t: np.array([0.6, 0.8], np.float32)

    no_prior = attack_mapper.map_to_attack(CVE, CHUNKS, TAC_INDEX, LLM_CFG,
                                           {**MAP_CFG, "tactic_bonus": 0.0}, embed_fn=qfn)
    assert no_prior["techniques"][0]["id"] == "T1547"   # surface winner without the prior

    with_prior = attack_mapper.map_to_attack(CVE, CHUNKS, TAC_INDEX, LLM_CFG,
                                             {**MAP_CFG, "tactic_bonus": 0.3}, embed_fn=qfn)
    assert with_prior["techniques"][0]["id"] == "T1210"   # tactic bonus flips it
    pb = with_prior["per_behavior"][0]
    assert pb["tactics"] == ["lateral-movement"]
    t1210 = next(t for t in pb["techniques"] if t["id"] == "T1210")
    assert t1210["tactic_match"] and t1210["score"] == round(0.6 + 0.3, 3)


def test_tactic_prior_never_excludes_on_wrong_tag(monkeypatch):
    # mis-tagged tactic (wrong) must NOT drop the correct technique — additive only
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {
        "behaviors": [{"effect": "run code on the host", "mechanism": "m", "tactic": ["Persistence"]}]})
    qfn = lambda _t: np.array([1.0, 0.0], np.float32)  # strongly cosine-aligned to T1210
    out = attack_mapper.map_to_attack(CVE, CHUNKS, TAC_INDEX, LLM_CFG,
                                      {**MAP_CFG, "tactic_bonus": 0.1}, embed_fn=qfn)
    # T1547 gets the (wrong-tag) bonus but T1210's raw cosine still wins -> not excluded
    assert out["techniques"][0]["id"] == "T1210"


def test_tactic_normalization_and_cap():
    b = attack_mapper._normalize_behavior(
        {"effect": "e", "mechanism": "m", "tactic": ["Lateral Movement", "Bogus", "Command and Control"]})
    assert b["tactics"] == ["lateral-movement", "command-and-control"]  # invalid dropped, capped at 2


def test_map_uses_canonical_name_not_model_text(monkeypatch):
    # even if the behavior text says "web shell", the mapped name is the catalog's
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"behaviors": ["run commands via interpreter"]})
    out = attack_mapper.map_to_attack(CVE, CHUNKS, ATTACK_INDEX, LLM_CFG, MAP_CFG,
                                      embed_fn=lambda _t: np.array([0.05, 1.0], np.float32))
    assert out["techniques"][0] == {"id": "T1059", "name": "Command and Scripting Interpreter"}


def test_map_min_score_filters_weak_matches(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"behaviors": ["something vague"]})
    cfg = {**MAP_CFG, "min_score": 0.999}            # higher than the 0.995 match
    out = attack_mapper.map_to_attack(CVE, CHUNKS, ATTACK_INDEX, LLM_CFG, cfg,
                                      embed_fn=lambda _t: np.array([1.0, 0.1], np.float32))
    assert out["techniques"] == []                   # nothing above the floor


def test_map_dedups_and_keeps_best_score_across_behaviors(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"behaviors": ["b1", "b2"]})
    # both behaviors map to T1190 but with different query vectors
    vecs = iter([np.array([1.0, 0.3], np.float32), np.array([1.0, 0.0], np.float32)])
    out = attack_mapper.map_to_attack(CVE, CHUNKS, ATTACK_INDEX, LLM_CFG, MAP_CFG,
                                      embed_fn=lambda _t: next(vecs))
    ids = [t["id"] for t in out["techniques"]]
    assert ids.count("T1190") == 1                   # de-duplicated
    assert out["mapping"][0]["score"] == 1.0         # kept the stronger match


# --- cve_scorer ------------------------------------------------------------

def test_score_cve_parses_and_normalizes(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {
        "base_score": "9.8", "severity": "critical", "vector": "AV:N", "rationale": "r"})
    out = cve_scorer.score_cve(CVE, CHUNKS, LLM_CFG)
    assert out["base_score"] == 9.8 and out["severity"] == "CRITICAL"


def test_score_cve_tolerates_bad_score(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"base_score": "n/a"})
    assert cve_scorer.score_cve(CVE, CHUNKS, LLM_CFG)["base_score"] is None


# --- pipeline orchestration ------------------------------------------------

CFG = {"models": {"chat": "m", "embed": "e", "host": "h", "temperature": 0.0},
       "corpus": {"top_k": 3, "min_score": None},
       "attack_mapping": {"top_k": 2, "max_techniques": 4, "min_score": None},
       "seed": 1}


def _patch_pipeline(monkeypatch, chunks=CHUNKS):
    monkeypatch.setattr(pipeline, "retrieve", lambda *a, **k: list(chunks))
    monkeypatch.setattr(pipeline.attack_mapper, "map_to_attack",
                        lambda *a, **k: {"techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
                                         "mapping": [], "per_behavior": [],
                                         "behaviors": [{"effect": "e", "mechanism": "m", "tactics": ["execution"]}],
                                         "rationale": "r"})
    monkeypatch.setattr(pipeline.cve_scorer, "score_cve",
                        lambda *a, **k: {"base_score": 9.8, "severity": "CRITICAL", "vector": "", "rationale": "r"})


def test_run_item_shape(monkeypatch):
    _patch_pipeline(monkeypatch)
    r = pipeline.run_item(CVE, corpus_index={}, attack_index={}, cfg=CFG)
    assert r["cve_id"] == "CVE-1"
    assert [c["chunk_id"] for c in r["retrieved"]] == ["c0", "c1"]
    assert r["techniques"][0]["id"] == "T1190"
    assert r["attack_behaviors"] == [{"effect": "e", "mechanism": "m", "tactics": ["execution"]}]
    assert r["attack_per_behavior"] == []
    assert r["severity"]["base_score"] == 9.8
    assert r["defense_report"] is None


def test_run_item_defense_hook_filters_chunks(monkeypatch):
    _patch_pipeline(monkeypatch)
    r = pipeline.run_item(CVE, corpus_index={}, attack_index={}, cfg=CFG,
                          defense=lambda chunks: {"kept_chunks": [], "flagged": True})
    assert r["retrieved"] == []
    assert r["defense_report"]["flagged"] is True
