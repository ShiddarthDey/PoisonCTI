# Threat model (plain English)

We study an LLM-based threat-intelligence agent that ingests open-source CTI
(CISA advisories, vendor blogs, OTX-style pulses) into a retrieval corpus and,
when asked about a threat or a CVE, retrieves the most relevant CTI text and
uses a local LLM to (a) map the activity to MITRE ATT&CK techniques and (b) score
the CVE's severity. The **attacker** is an ordinary open-source contributor: they
cannot retrain the model, change the prompts, or touch the agent's code — they
can only get **a single poisoned document accepted into the public CTI corpus**,
exactly as anyone can publish a blog post or submit a pulse. Their **goal** is to
steer the agent's output: make it attribute the wrong ATT&CK technique, or inflate
/deflate a CVE's severity, for chosen items — while the poisoned source looks
plausible and the other (honest) sources remain unchanged. The **defender**
controls only the agent side and wants a *lightweight, no-retraining* fix: a
cross-source consistency check that flags when one source disagrees with the
broader retrieved evidence, restoring reliable output without rebuilding the model.
**In scope:** content-level data poisoning of the retrieval corpus and a
retrieval-time consistency defense. **Out of scope:** model weight/training
attacks, prompt injection of the system prompt, compromising Ollama or the host,
and network-level tampering — these are assumed trusted so we can isolate the
single-poisoned-source question cleanly.
