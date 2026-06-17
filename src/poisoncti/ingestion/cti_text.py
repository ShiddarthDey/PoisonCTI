"""Normalize seed CTI documents into clean records with provenance.

Job
---
Read the committed seed CTI documents (CISA advisories, vendor blogs, OTX-style
pulses) and produce uniform records: cleaned text plus metadata (source name,
url, date, a stable doc_id, and which CVEs the document discusses). Provenance
matters because the whole study turns on "which source said what": the defense
uses source identity, and the attack adds exactly one *new* source.

Inputs:  data/seed_cti/*.json  (committed fixtures, one document per file)
Outputs: normalized documents  ->  data/interim/cti_docs.json

Seed-CTI format (one JSON object per file):
    {doc_id, source, url, date, title, text, mentions_cves: [...]}

`source` is one of {cisa, vendor_blog, otx_pulse, ...}. The injected poison
document (M4) is just one more record with the same shape and a new source tag.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REQUIRED_FIELDS = ("doc_id", "source", "text")


def load_raw_documents(seed_dir: str) -> list[dict]:
    """Read every *.json seed CTI file in `seed_dir` into a list of dicts."""
    docs: list[dict] = []
    for path in sorted(Path(seed_dir).glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc.setdefault("_file", path.name)
        docs.append(doc)
    return docs


def clean_text(raw_text: str) -> str:
    """Collapse whitespace and trim, preserving substantive content."""
    text = raw_text.replace("\r\n", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def normalize(raw_docs: list[dict]) -> list[dict]:
    """Return uniform document records ready for chunking in `corpus`."""
    normalized: list[dict] = []
    for doc in raw_docs:
        missing = [f for f in REQUIRED_FIELDS if not doc.get(f)]
        if missing:
            raise ValueError(f"seed CTI doc {doc.get('_file', doc.get('doc_id'))} missing {missing}")
        normalized.append(
            {
                "doc_id": doc["doc_id"],
                "source": doc["source"],
                "url": doc.get("url", ""),
                "date": doc.get("date", ""),
                "title": doc.get("title", ""),
                "text": clean_text(doc["text"]),
                "mentions_cves": doc.get("mentions_cves", []),
            }
        )
    return normalized
