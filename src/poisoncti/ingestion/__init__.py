"""Ingestion: turn raw public sources into clean, normalized records.

This layer answers "what does each source say," NOT "how do we retrieve it"
(that is `corpus`). Keeping the two apart means the poisoning attack operates on
the corpus — the realistic injection point — without touching these parsers.

Submodules:
    attack_stix -- MITRE ATT&CK STIX bundle  -> technique catalog (ID, name, tactic, desc)
    nvd         -- NVD API                    -> CVE records + gold CVSS labels
    cti_text    -- CISA/blog/OTX-style text   -> cleaned documents with provenance
"""
