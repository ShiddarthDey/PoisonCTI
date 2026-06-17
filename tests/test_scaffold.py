"""Scaffold sanity tests.

Confirms the package and every submodule import cleanly (i.e. modules are
importable shells, not broken). Real metric/parser tests arrive with the logic.
"""

import importlib

import pytest

MODULES = [
    "poisoncti",
    "poisoncti.ingestion.attack_stix",
    "poisoncti.ingestion.nvd",
    "poisoncti.ingestion.cti_text",
    "poisoncti.corpus.chunk",
    "poisoncti.corpus.embed",
    "poisoncti.corpus.index",
    "poisoncti.agent.llm",
    "poisoncti.agent.retriever",
    "poisoncti.agent.prompts",
    "poisoncti.agent.attack_mapper",
    "poisoncti.agent.cve_scorer",
    "poisoncti.agent.pipeline",
    "poisoncti.poison.payloads",
    "poisoncti.poison.inject",
    "poisoncti.defense.consistency",
    "poisoncti.evaluation.gold",
    "poisoncti.evaluation.metrics",
    "poisoncti.evaluation.experiment",
    "poisoncti.utils.io",
    "poisoncti.utils.logging",
]


@pytest.mark.parametrize("module", MODULES)
def test_module_imports(module):
    assert importlib.import_module(module) is not None
