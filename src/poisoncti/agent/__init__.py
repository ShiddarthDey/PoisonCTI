"""Agent: the LLM threat-intel system under study.

Given a query (a threat description or a CVE), it retrieves relevant CTI chunks
and uses a local LLM to (a) map to MITRE ATT&CK techniques and (b) score CVE
severity. This package MUST NOT import from `poison` or `defense`: the agent stays
unaware of both, so any measured steering is attributable to corpus data alone.
The defense hooks in only via the pipeline's configuration, not the agent's logic.

Submodules:
    llm           -- thin Ollama chat client (the only place we talk to the model)
    retriever     -- query -> top-k CTI chunks (wraps corpus.index)
    prompts       -- every prompt template, centralized for auditability
    attack_mapper -- retrieved CTI -> ATT&CK technique IDs (from the catalog label space)
    cve_scorer    -- retrieved CTI + CVE -> severity score/vector
    pipeline      -- orchestrate retrieve -> map -> score into one agent call
"""
