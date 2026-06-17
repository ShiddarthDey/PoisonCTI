"""Tests for the M4 poison payloads and the synthetic-CVE fixtures."""

import json
from pathlib import Path

import pytest

from poisoncti.poison import payloads

SYNTH = json.loads(Path("data/synthetic/synthetic_cves.json").read_text("utf-8"))["cves"]


# --- payloads --------------------------------------------------------------

def test_craft_deflation_mentions_cve_and_argues_lower():
    p = payloads.craft_deflation("CVE-2099-0001", "Nimbus Cache Server")
    assert p["mentions_cves"] == ["CVE-2099-0001"]
    assert "CVE-2099-0001" in p["text"] and "Nimbus Cache Server" in p["text"]
    assert "overstated" in p["text"].lower()  # deflation register


def test_craft_inflation_argues_higher():
    p = payloads.craft_inflation("CVE-2099-0003", "Atlas Reporting Console")
    assert "CVE-2099-0003" in p["text"] and "Atlas Reporting Console" in p["text"]
    assert "emergency" in p["text"].lower() and "unauthenticated" in p["text"].lower()


def test_craft_dispatch_and_invalid_direction():
    assert payloads.craft("X", "P", "deflate")["text"].startswith("Re-assessment")
    assert payloads.craft("X", "P", "inflate")["text"].startswith("Urgent")
    with pytest.raises(ValueError):
        payloads.craft("X", "P", "sideways")


# --- synthetic fixtures (guard against the answer-key bug) ------------------

def test_synthetic_honest_sources_do_not_leak_the_severity_answer():
    banned = ["critical", "cvss", "base score", "severe"]  # the model must INFER, not read
    for cve in SYNTH:
        for s in cve["honest_sources"]:
            t = s["text"].lower()
            for b in banned:
                assert b not in t, f"{cve['cve_id']} honest source leaks '{b}'"


def test_synthetic_set_covers_both_directions():
    dirs = [c["consensus"]["direction"] for c in SYNTH]
    assert dirs.count("deflate") >= 2 and dirs.count("inflate") >= 2  # balanced, both directions
    assert len(SYNTH) >= 6  # scaled set


def test_poison_length_control_matches_honest_sources():
    # the effect must come from CONTENT, not the poison being longer/more vivid than peers
    honest_lens = [len(s["text"].split()) for c in SYNTH for s in c["honest_sources"]]
    lo, hi = min(honest_lens), max(honest_lens)
    d, i = len(payloads.DEFLATION.split()), len(payloads.INFLATION.split())
    assert lo <= d <= hi and lo <= i <= hi   # poison within the honest length range
    assert abs(d - i) <= 3                    # deflation ~= inflation length (asymmetry not a length artifact)


def test_synthetic_cves_well_formed():
    for cve in SYNTH:
        assert cve["cve_id"].startswith("CVE-2099-")          # clearly fictional
        assert cve["neutral_description"] and cve["product"]
        assert cve["consensus"]["band"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert len(cve["honest_sources"]) >= 2                 # multi-source realism
