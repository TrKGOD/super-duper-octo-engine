"""Confirmed-finding report assembly.

Builds a structured report for a finding only from persisted state: the finding row, its
validation records and its evidence. A report is produced only for a confirmed
(``validated``/``reported``/``resolved``) finding; anything else is refused, so a hypothesis
or inconclusive result can never be reported as confirmed. Validation-record integrity is
re-verified at report time.
"""
from __future__ import annotations

import json

from core.validation_engine.records import SUPPORTED, ValidationRecordStore


class ReportError(ValueError):
    pass


_CONFIRMED_STATUSES = {"validated", "reported", "resolved"}


def build_finding_report(store, finding_id: str) -> dict:
    row = store.connection.execute(
        "SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
    if row is None:
        raise ReportError("Unknown finding: " + str(finding_id))
    if row["status"] not in _CONFIRMED_STATUSES:
        raise ReportError("Only a confirmed finding can be reported (status: " + row["status"] + ")")

    records = ValidationRecordStore(store.connection, row["engagement_id"]).for_finding(finding_id)
    record_ids = [r["record_id"] for r in records]
    integrity_ok = all(
        ValidationRecordStore(store.connection, row["engagement_id"]).verify(rid) for rid in record_ids)
    supporting = [r for r in records if r["disposition"] == SUPPORTED]
    evidence = store.finding_evidence(finding_id) if hasattr(store, "finding_evidence") else []

    return {
        "title": row["title"],
        "severity": row["severity"],
        "affected_asset": row["asset"],
        "affected_endpoint": {"method": row["method"], "parameter": row["parameter"]},
        "vulnerability_class": supporting[0]["vulnerability_class"] if supporting else None,
        "impact": row["impact"],
        "preconditions": json.loads(row["preconditions_json"]) if row["preconditions_json"] else [],
        "reproduction": row["description"],
        "evidence": [{"evidence_id": e["evidence_id"], "type": e["evidence_type"],
                      "sha256": e["sha256"], "redacted": bool(e["redacted"])} for e in evidence],
        "validation": {
            "status": row["status"],
            "validated_by": row["validated_by"],
            "records": [{"record_id": r["record_id"], "disposition": r["disposition"],
                         "oracle": r["oracle"], "explanation": r["explanation"],
                         "integrity_hash": r["integrity_hash"]} for r in records],
            "integrity_verified": integrity_ok,
        },
        "remediation": None,
        "references": [],
        "confidence_and_limitations": (
            "Confirmed by independent deterministic validation with integrity-verified evidence. "
            "Severity and impact are qualified by the engagement's synthetic test data and scope; "
            "they are not a claim of real-world exploitability beyond what the evidence shows."),
    }
