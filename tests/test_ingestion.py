"""Unit tests for the ingestion parsers (pure functions, no network)."""

from poisoncti.ingestion import attack_stix, cti_text, nvd

# --- ATT&CK STIX -----------------------------------------------------------

MINI_BUNDLE_OBJECTS = [
    {
        "type": "attack-pattern",
        "name": "Exploit Public-Facing Application",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
        "description": "Adversaries exploit a public-facing application.",
    },
    {
        "type": "attack-pattern",
        "name": "Deprecated Thing",
        "x_mitre_deprecated": True,
        "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
    },
    {
        "type": "attack-pattern",
        "name": "Revoked Thing",
        "revoked": True,
        "external_references": [{"source_name": "mitre-attack", "external_id": "T8888"}],
    },
    {"type": "course-of-action", "name": "Not a technique"},
]


def test_extract_techniques_filters_and_maps():
    techs = attack_stix.extract_techniques(MINI_BUNDLE_OBJECTS)
    assert len(techs) == 1
    t = techs[0]
    assert t["attack_id"] == "T1190"
    assert t["tactics"] == ["initial-access"]
    assert t["is_subtechnique"] is False
    assert "public-facing" in t["description"]


# --- NVD --------------------------------------------------------------------

SAMPLE_CVE = {
    "id": "CVE-2021-44228",
    "descriptions": [
        {"lang": "en", "value": "Apache Log4j2 JNDI RCE."},
        {"lang": "es", "value": "ignored"},
    ],
    "references": [{"url": "https://example.test/a"}, {"source": "nourl"}],
    "metrics": {
        "cvssMetricV2": [{"cvssData": {"baseScore": 9.3, "vectorString": "AV:N"}}],
        "cvssMetricV31": [
            {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/..."}}
        ],
    },
}


def test_extract_record_picks_english_and_urls():
    rec = nvd.extract_record(SAMPLE_CVE)
    assert rec["cve_id"] == "CVE-2021-44228"
    assert rec["description"] == "Apache Log4j2 JNDI RCE."
    assert rec["references"] == ["https://example.test/a"]


def test_extract_gold_prefers_v31():
    gold = nvd.extract_gold_severity(SAMPLE_CVE)
    assert gold["cvss_version"] == "3.1"
    assert gold["base_score"] == 10.0
    assert gold["base_severity"] == "CRITICAL"


def test_extract_gold_handles_missing_metrics():
    gold = nvd.extract_gold_severity({"id": "CVE-0000-0000", "metrics": {}})
    assert gold["base_score"] is None and gold["cvss_version"] is None


# --- CTI text ---------------------------------------------------------------


def test_normalize_cleans_and_requires_fields():
    docs = cti_text.normalize(
        [{"doc_id": "d1", "source": "cisa", "text": "a\r\n\n\n\nb   c", "mentions_cves": ["CVE-1"]}]
    )
    assert docs[0]["text"] == "a\n\nb c"
    assert docs[0]["mentions_cves"] == ["CVE-1"]


def test_normalize_rejects_missing_required_field():
    import pytest

    with pytest.raises(ValueError):
        cti_text.normalize([{"doc_id": "d1", "source": "cisa"}])  # no text
