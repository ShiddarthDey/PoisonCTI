"""Load gold labels.

Job
---
Provide the trusted reference the PRIMARY metric compares against:
    - severity gold: NVD CVSS base score/vector per CVE (from ingestion.nvd).

ATT&CK technique gold is intentionally NOT here. After the M3 finding (a small
local model cannot reliably map fine-grained ATT&CK; see DECISIONS.md), mapping is
a SECONDARY axis measured as poison-induced CHANGE, not accuracy vs a gold
technique. So the hand-curated CVE->technique gold set and its inter-annotator
(Cohen's kappa) step are DROPPED — there is no technique ground truth to maintain,
and severity gold (NVD CVSS, exact) carries the study.

Inputs:  data/gold/severity_gold.json
Outputs: severity gold lookup
"""

from __future__ import annotations


def load_severity_gold(path: str) -> dict:
    """Return {cve_id: {base_score, base_severity, vector, cvss_version}}."""
    raise NotImplementedError
