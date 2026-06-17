"""Tests for the band-level severity metrics (pure; no model)."""

from poisoncti.evaluation import metrics as m


def test_score_to_band_ranges_and_boundaries():
    assert m.score_to_band(9.8) == "CRITICAL"
    assert m.score_to_band(9.0) == "CRITICAL"      # lower boundary
    assert m.score_to_band(8.9) == "HIGH"
    assert m.score_to_band(7.0) == "HIGH"
    assert m.score_to_band(6.9) == "MEDIUM"
    assert m.score_to_band(4.0) == "MEDIUM"
    assert m.score_to_band(3.9) == "LOW"
    assert m.score_to_band(0.1) == "LOW"
    assert m.score_to_band(0.0) == "NONE"
    assert m.score_to_band(None) is None


def test_band_shift_signed_in_attacker_direction():
    # inflation success: MEDIUM -> CRITICAL is +2 toward the attacker's goal
    assert m.band_shift("MEDIUM", "CRITICAL", "inflate") == 2
    # deflation success: CRITICAL -> HIGH is +1 toward the attacker's goal
    assert m.band_shift("CRITICAL", "HIGH", "deflate") == 1
    # no movement
    assert m.band_shift("CRITICAL", "CRITICAL", "deflate") == 0
    # wrong way (deflation that went UP) is negative
    assert m.band_shift("HIGH", "CRITICAL", "deflate") == -1
    assert m.band_shift("CRITICAL", None, "deflate") is None


def test_severity_band_asr():
    rows = [
        {"clean_band": "CRITICAL", "poisoned_band": "HIGH", "direction": "deflate"},      # +1 success
        {"clean_band": "CRITICAL", "poisoned_band": "CRITICAL", "direction": "deflate"},  # 0 fail
        {"clean_band": "MEDIUM", "poisoned_band": "CRITICAL", "direction": "inflate"},    # +2 success
    ]
    assert m.severity_band_asr(rows) == 2 / 3


def test_defense_band_recovery_and_fp():
    rec = [{"clean_band": "CRITICAL", "defended_band": "CRITICAL"},   # restored
           {"clean_band": "CRITICAL", "defended_band": "HIGH"}]       # not restored
    assert m.defense_band_recovery(rec) == 0.5
    fp = [{"flagged_any": True}, {"flagged_any": False}, {"flagged_any": False}, {"flagged_any": False}]
    assert m.defense_false_positive_rate(fp) == 0.25
