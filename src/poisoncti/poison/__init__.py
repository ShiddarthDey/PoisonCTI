"""Poison: the single-source data-poisoning attack.

Models an ordinary open-source contributor who can only get ONE crafted document
accepted into the public CTI corpus — no retraining, no prompt access, no code
access. The document is designed to be retrieved for chosen items and to steer the
agent's ATT&CK mapping or CVE severity toward an attacker-chosen target.

Submodules:
    payloads -- strategies for crafting the poisoned text (target technique / inflate-deflate severity)
    inject   -- insert the crafted document into the corpus and rebuild the index
"""
