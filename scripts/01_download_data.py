"""Step 01 — download and parse all public source data.

Fetches the three free sources and writes normalized outputs:
  - MITRE ATT&CK enterprise STIX bundle  -> data/raw/enterprise-attack.json
        parsed technique catalog          -> data/interim/techniques.json
  - NVD CVE study set (pinned IDs)        -> data/raw/cves.json
        gold CVSS severity labels         -> data/gold/severity_gold.json
  - Seed CTI documents (committed)        -> data/interim/cti_docs.json

Usage:
    python scripts/01_download_data.py            # uses config/settings.yaml
    python scripts/01_download_data.py --test     # uses config/settings.test.yaml
    python scripts/01_download_data.py --force-stix  # re-download the STIX bundle
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import requests
from dotenv import load_dotenv
from tqdm import tqdm

from poisoncti.ingestion import attack_stix, cti_text, nvd
from poisoncti.utils.io import load_config

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def download_stix(raw_path: Path, force: bool) -> None:
    if raw_path.exists() and not force:
        print(f"  STIX bundle already present ({raw_path}); skipping download.")
        return
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"  Downloading ATT&CK STIX bundle -> {raw_path} ...")
    with requests.get(STIX_URL, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        with raw_path.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=1 << 16):
                f.write(chunk)
    print(f"  Downloaded {raw_path.stat().st_size / 1e6:.1f} MB.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="use config/settings.test.yaml")
    parser.add_argument("--force-stix", action="store_true", help="re-download the STIX bundle")
    args = parser.parse_args()

    load_dotenv()
    cfg = load_config("config/settings.test.yaml" if args.test else "config/settings.yaml")
    paths = cfg["paths"]
    ing = cfg["ingestion"]

    # 1) MITRE ATT&CK ---------------------------------------------------------
    print("[1/3] MITRE ATT&CK")
    stix_path = Path(paths["data_raw"]) / "enterprise-attack.json"
    download_stix(stix_path, args.force_stix)
    techniques = attack_stix.extract_techniques(attack_stix.load_bundle(str(stix_path)))
    catalog_path = Path(paths["data_interim"]) / "techniques.json"
    attack_stix.save_catalog(techniques, str(catalog_path))
    n_sub = sum(t["is_subtechnique"] for t in techniques)
    print(f"  Parsed {len(techniques)} techniques ({n_sub} sub-techniques) -> {catalog_path}")

    # 2) NVD CVEs + gold severity --------------------------------------------
    print("[2/3] NVD CVEs")
    study = json.loads(Path(ing["study_set_path"]).read_text(encoding="utf-8"))
    cve_ids = study["cve_ids"][: ing["max_cves"]]
    api_key = os.getenv(ing["nvd_api_key_env"])
    print(f"  Fetching {len(cve_ids)} CVEs (api_key={'yes' if api_key else 'no'}) ...")
    cves = nvd.fetch_cves(cve_ids, api_key)
    records = [nvd.extract_record(c) for c in cves]
    gold = [nvd.extract_gold_severity(c) for c in cves]
    Path(paths["data_raw"]).mkdir(parents=True, exist_ok=True)
    (Path(paths["data_raw"]) / "cves.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    Path(paths["gold"]).mkdir(parents=True, exist_ok=True)
    (Path(paths["gold"]) / "severity_gold.json").write_text(json.dumps(gold, indent=2), encoding="utf-8")
    found = {r["cve_id"] for r in records}
    missing = [c for c in cve_ids if c not in found]
    print(f"  Retrieved {len(records)} CVEs with gold CVSS; missing: {missing or 'none'}")
    for g in gold:
        print(f"    {g['cve_id']}: CVSS {g['cvss_version']} {g['base_score']} ({g['base_severity']})")

    # 3) Seed CTI -------------------------------------------------------------
    print("[3/3] Seed CTI")
    docs = cti_text.normalize(cti_text.load_raw_documents(ing["seed_cti_dir"]))
    cti_path = Path(paths["data_interim"]) / "cti_docs.json"
    cti_path.parent.mkdir(parents=True, exist_ok=True)
    cti_path.write_text(json.dumps(docs, indent=2), encoding="utf-8")
    by_source: dict[str, int] = {}
    for d in docs:
        by_source[d["source"]] = by_source.get(d["source"], 0) + 1
    print(f"  Normalized {len(docs)} CTI docs by source: {by_source} -> {cti_path}")

    print("\nDone. Ingestion outputs written to data/interim, data/raw, data/gold.")


if __name__ == "__main__":
    main()
