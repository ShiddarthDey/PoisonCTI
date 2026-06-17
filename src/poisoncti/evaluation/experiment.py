"""Run the experiment conditions and log raw results.

Job
---
Drive the agent over the study items under the three conditions and persist
everything needed to recompute metrics later:

    clean    -- agent on the unmodified corpus            (baseline)
    poison   -- agent on the single-injected-source corpus (attack)
    defended -- poison corpus + cross-source consistency   (mitigation)

For each (condition, item) it records the agent output, the retrieved evidence,
and any defense report into experiments/<run_id>/. Keeping raw outputs separate
from metric computation means you can re-score with new metrics without re-running
the (slow, local) LLM.

Reproducibility contract: the runner calls set_global_seed(cfg["seed"]) and
verify_model_pins(cfg) before any generation, and stamps the provenance block
(model digests + seed + timestamp) into every output file via utils.io. When
invoked through run_all.py the shared provenance arrives in the POISONCTI_RUN
env var so all steps of one reproduce share a single run identity.

Inputs:  study items, clean+poison indexes, catalog, config
Outputs: experiments/<run_id>/{clean,poison,defended}.jsonl + run manifest
"""

from __future__ import annotations


def run_condition(name: str, items: list[dict], index, catalog, cfg: dict, defense=None) -> list[dict]:
    """Run all items under one named condition; return (and persist) raw outputs."""
    raise NotImplementedError


def run_experiment(cfg: dict) -> str:
    """Run clean+poison+defended over the study set; return the run_id/output dir."""
    raise NotImplementedError
