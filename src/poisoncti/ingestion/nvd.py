"""Fetch CVE records and gold severity labels from the NVD API.

Job
---
Fetch the pinned study-set CVEs from the National Vulnerability Database, one
exact CVE ID at a time (deterministic). For each CVE we keep the description
(feeds the corpus / scorer) and the official **CVSS base score + vector** — the
gold severity label the evaluation measures drift against.

Inputs:  NVD REST API (cves/2.0?cveId=...), optional NVD_API_KEY
Outputs: CVE records  -> data/raw/cves.json ; gold severity -> data/gold/severity_gold.json

Notes
-----
- Rate limits: ~5 req/30s without a key, ~50 req/30s with one. We sleep between
  calls accordingly and retry on 403/429/503 with backoff.
- We prefer CVSS v3.1, then v3.0, then v2, and record which version supplied the
  gold label so reporting is honest about provenance.
"""

from __future__ import annotations

import time

import requests

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _sleep_for(api_key: str | None) -> float:
    """Polite per-request delay to stay under NVD rate limits."""
    return 0.8 if api_key else 6.5


def fetch_cve(cve_id: str, api_key: str | None = None, max_retries: int = 4) -> dict | None:
    """Fetch a single CVE object by ID; returns the `cve` dict or None if absent."""
    headers = {"apiKey": api_key} if api_key else {}
    backoff = 5.0
    for attempt in range(max_retries):
        resp = requests.get(NVD_ENDPOINT, params={"cveId": cve_id}, headers=headers, timeout=30)
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            return vulns[0]["cve"] if vulns else None
        if resp.status_code in (403, 429, 503):
            time.sleep(backoff)
            backoff *= 2
            continue
        resp.raise_for_status()
    raise RuntimeError(f"NVD fetch failed for {cve_id} after {max_retries} retries")


def fetch_cves(cve_ids: list[str], api_key: str | None = None) -> list[dict]:
    """Fetch each CVE ID in order, respecting rate limits. Skips IDs not found."""
    delay = _sleep_for(api_key)
    out: list[dict] = []
    for i, cve_id in enumerate(cve_ids):
        cve = fetch_cve(cve_id, api_key)
        if cve is not None:
            out.append(cve)
        if i < len(cve_ids) - 1:
            time.sleep(delay)
    return out


def extract_record(cve: dict) -> dict:
    """Pull the fields the corpus/agent need: id, description, dates, references."""
    descriptions = cve.get("descriptions", [])
    english = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    return {
        "cve_id": cve.get("id"),
        "description": english.strip(),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": refs,
    }


def extract_gold_severity(cve: dict) -> dict:
    """Pull {cve_id, cvss_version, base_score, base_severity, vector} as gold.

    Prefers CVSS v3.1 -> v3.0 -> v2; records which version was used.
    """
    metrics = cve.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        base_severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        return {
            "cve_id": cve.get("id"),
            "cvss_version": version,
            "base_score": data.get("baseScore"),
            "base_severity": base_severity,
            "vector": data.get("vectorString"),
        }
    return {
        "cve_id": cve.get("id"),
        "cvss_version": None,
        "base_score": None,
        "base_severity": None,
        "vector": None,
    }
