"""Security taxonomy reference extraction and normalization.

Deterministically extracts CWE, CVE, OWASP, CAPEC and MITRE ATT&CK references from
(untrusted) document text or operator metadata. Pure functions — no I/O, no model calls.
References are normalized to canonical upper-case forms and deduplicated.
"""
from __future__ import annotations

import re

_PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "cwe": re.compile(r"\bCWE-\d{1,5}\b", re.I),
    "capec": re.compile(r"\bCAPEC-\d{1,5}\b", re.I),
    # OWASP Top 10 (A01:2021) and API Top 10 (API1:2023) style identifiers.
    "owasp": re.compile(r"\b(?:API\d{1,2}|A\d{1,2}):20\d{2}\b"),
    # ATT&CK technique ids, e.g. T1190 or T1059.001.
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}

REFERENCE_TYPES = tuple(_PATTERNS)


def _normalize(ref_type: str, value: str) -> str:
    value = value.strip()
    return value.upper() if ref_type in ("cve", "cwe", "capec", "attack") else value.upper()


def extract_references(text) -> dict:
    """Return {ref_type: sorted unique refs} found in ``text``."""
    text = str(text or "")
    found = {}
    for ref_type, pattern in _PATTERNS.items():
        hits = {_normalize(ref_type, match.group(0)) for match in pattern.finditer(text)}
        if hits:
            found[ref_type] = sorted(hits)
    return found


def merge_references(*reference_maps) -> dict:
    """Union several {ref_type: [refs]} maps into one normalized, deduplicated map."""
    merged: dict[str, set] = {}
    for ref_map in reference_maps:
        if not isinstance(ref_map, dict):
            continue
        for ref_type, values in ref_map.items():
            if ref_type not in _PATTERNS:
                continue
            bucket = merged.setdefault(ref_type, set())
            for value in (values if isinstance(values, (list, tuple, set)) else [values]):
                bucket.add(_normalize(ref_type, str(value)))
    return {ref_type: sorted(values) for ref_type, values in merged.items() if values}


def flatten_references(reference_map: dict) -> list[tuple]:
    """Return a sorted list of (ref_type, value) pairs for persistence."""
    pairs = []
    for ref_type, values in (reference_map or {}).items():
        for value in values:
            pairs.append((ref_type, value))
    return sorted(pairs)
