"""PoisonCTI — measuring single-source CTI poisoning of an LLM threat-intel agent.

Package map (data flows top-to-bottom):

    ingestion  -> sources (ATT&CK STIX, NVD, CTI text) into normalized records
    corpus     -> normalized CTI docs into a retrievable vector index (the RAG layer)
    agent      -> the system under study: retrieve -> ATT&CK map + CVE severity score
    poison     -> the attack: craft and inject ONE poisoned source into the corpus
    defense    -> the mitigation: a cross-source consistency check at retrieval time
    evaluation -> gold labels, metrics (drift + ASR), and the experiment runner
    utils      -> shared I/O and logging helpers

Nothing in `agent` may import from `poison` or `defense`: the agent must stay
unaware of both so that any steering is attributable to corpus data alone.
"""

__version__ = "0.0.1"
