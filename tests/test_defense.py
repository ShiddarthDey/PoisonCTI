"""Tests for the internal-consistency defense (stub joint scorer; no model)."""

from poisoncti.defense import consistency

CVE = {"cve_id": "CVE-2099-0001", "description": "X"}


def _joint(cve, chunks, llm_cfg):
    """Stub JOINT scorer modelling a stable honest consensus that a poison disrupts:
    any set WITHOUT the poison reads CRITICAL (9.6); any set WITH the poison reads HIGH (8.0);
    the poison alone reads LOW (2.0). So the honest set is internally consistent and any set
    containing the poison becomes consistent only once the poison is removed."""
    has_poison = any("_p" in c for c in chunks)
    honest = [c for c in chunks if "_h" in c]
    if not honest:
        return {"base_score": 2.0}
    return {"base_score": 8.0 if has_poison else 9.6}


def _h():
    return {"source": "honest", "_h": 1, "text": "h"}


def _p():
    return {"source": "vendor_blog", "_p": 1, "text": "p"}


def test_identifies_poison_and_recovers_clean_band():
    honest = [_h(), _h(), _h()]
    poison = _p()
    rep = consistency.check(CVE, honest + [poison], {}, _joint)
    assert rep["abstained"] is False
    assert rep["joint_band"] == "HIGH"                 # poison dragged the joint
    assert rep["flagged_sources"] == ["vendor_blog"]   # poison identified
    assert poison not in rep["kept_chunks"] and all(h in rep["kept_chunks"] for h in honest)
    assert rep["corrected_band"] == "CRITICAL"         # joint of the honest rest, restored


def test_abstains_below_four_sources():
    # 3 sources -> a removal leaves only 2 (< min_consensus) -> abstain, never flags
    rep = consistency.check(CVE, [_h(), _h(), _p()], {}, _joint)
    assert rep["abstained"] is True
    assert rep["flagged_any"] is False
    assert len(rep["kept_chunks"]) == 3


def test_no_false_positive_on_clean_input():
    # clean 3-honest input abstains (FP-free by construction)
    rep = consistency.check(CVE, [_h(), _h(), _h()], {}, _joint)
    assert rep["abstained"] is True
    assert rep["flagged_any"] is False


def test_no_poison_when_full_set_already_consistent():
    # 4 honest, NO poison: the full set is internally consistent -> declare no poison
    rep = consistency.check(CVE, [_h(), _h(), _h(), _h()], {}, _joint)
    assert rep["abstained"] is False
    assert rep["flagged_any"] is False
    assert rep["corrected_band"] == "CRITICAL"         # unchanged joint, nothing removed


def test_joint_band_helper():
    assert consistency.joint_band(CVE, [_h()], {}, _joint) == "CRITICAL"
    assert consistency.joint_band(CVE, [], {}, _joint) is None
