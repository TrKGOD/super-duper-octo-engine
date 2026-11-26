"""Validation record model, integrity hashing and persistence.

A validation record is the independent, tamper-evident result of one validation run. It
stores references and a comparison summary — never raw bodies, secrets or tokens — plus a
SHA-256 integrity hash over its material fields so a stored record cannot be silently
altered without detection.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from core.store import new_id, utc_now

SUPPORTED = "SUPPORTED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"
DISPOSITIONS = (SUPPORTED, REFUTED, INCONCLUSIVE)


def integrity_hash(material: dict) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass
class ValidationRecord:
    engagement_id: str
    vulnerability_class: str
    oracle: str
    disposition: str
    explanation: str
    validator_id: str = "exploit-validation-engine"
    validator_version: str = "1.0"
    finding_id: str | None = None
    hypothesis_id: str | None = None
    comparison: dict = field(default_factory=dict)
    request_refs: list = field(default_factory=list)
    response_refs: list = field(default_factory=list)
    baseline_refs: list = field(default_factory=list)
    sanitized: bool = True
    record_id: str = field(default_factory=lambda: new_id("vrec"))
    created_at: str = field(default_factory=utc_now)

    def material(self) -> dict:
        """The fields the integrity hash covers (everything substantive except the hash)."""
        return {
            "engagement_id": self.engagement_id, "vulnerability_class": self.vulnerability_class,
            "oracle": self.oracle, "disposition": self.disposition, "explanation": self.explanation,
            "validator_id": self.validator_id, "validator_version": self.validator_version,
            "finding_id": self.finding_id, "hypothesis_id": self.hypothesis_id,
            "comparison": self.comparison, "request_refs": sorted(self.request_refs),
            "response_refs": sorted(self.response_refs), "baseline_refs": sorted(self.baseline_refs),
            "sanitized": bool(self.sanitized), "created_at": self.created_at,
        }

    def integrity(self) -> str:
        return integrity_hash(self.material())

    def to_dict(self) -> dict:
        return {"record_id": self.record_id, **self.material(), "integrity_hash": self.integrity()}


class ValidationRecordStore:
    def __init__(self, connection, engagement_id: str):
        self.connection = connection
        self.engagement_id = engagement_id

    def persist(self, record: ValidationRecord) -> str:
        with self.connection:
            self.connection.execute(
                "INSERT INTO validation_records(record_id,engagement_id,finding_id,hypothesis_id,"
                "vulnerability_class,oracle,validator_id,validator_version,disposition,explanation,"
                "comparison_json,request_refs_json,response_refs_json,baseline_refs_json,sanitized,"
                "integrity_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.record_id, self.engagement_id, record.finding_id, record.hypothesis_id,
                 record.vulnerability_class, record.oracle, record.validator_id, record.validator_version,
                 record.disposition, record.explanation, json.dumps(record.comparison, sort_keys=True),
                 json.dumps(record.request_refs), json.dumps(record.response_refs),
                 json.dumps(record.baseline_refs), 1 if record.sanitized else 0,
                 record.integrity(), record.created_at))
        return record.record_id

    def get(self, record_id: str) -> dict | None:
        row = self.connection.execute(
            "SELECT * FROM validation_records WHERE record_id=? AND engagement_id=?",
            (record_id, self.engagement_id)).fetchone()
        return self._row(row) if row else None

    def for_finding(self, finding_id: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM validation_records WHERE finding_id=? AND engagement_id=? ORDER BY created_at",
            (finding_id, self.engagement_id)).fetchall()
        return [self._row(row) for row in rows]

    def verify(self, record_id: str) -> bool:
        """Recompute the integrity hash and confirm the stored record is unaltered."""
        row = self.connection.execute(
            "SELECT * FROM validation_records WHERE record_id=? AND engagement_id=?",
            (record_id, self.engagement_id)).fetchone()
        if row is None:
            return False
        material = {
            "engagement_id": row["engagement_id"], "vulnerability_class": row["vulnerability_class"],
            "oracle": row["oracle"], "disposition": row["disposition"], "explanation": row["explanation"],
            "validator_id": row["validator_id"], "validator_version": row["validator_version"],
            "finding_id": row["finding_id"], "hypothesis_id": row["hypothesis_id"],
            "comparison": json.loads(row["comparison_json"]),
            "request_refs": sorted(json.loads(row["request_refs_json"])),
            "response_refs": sorted(json.loads(row["response_refs_json"])),
            "baseline_refs": sorted(json.loads(row["baseline_refs_json"])),
            "sanitized": bool(row["sanitized"]), "created_at": row["created_at"],
        }
        return integrity_hash(material) == row["integrity_hash"]

    @staticmethod
    def _row(row) -> dict:
        return {
            "record_id": row["record_id"], "engagement_id": row["engagement_id"],
            "finding_id": row["finding_id"], "hypothesis_id": row["hypothesis_id"],
            "vulnerability_class": row["vulnerability_class"], "oracle": row["oracle"],
            "validator_id": row["validator_id"], "validator_version": row["validator_version"],
            "disposition": row["disposition"], "explanation": row["explanation"],
            "comparison": json.loads(row["comparison_json"]),
            "request_refs": json.loads(row["request_refs_json"]),
            "response_refs": json.loads(row["response_refs_json"]),
            "baseline_refs": json.loads(row["baseline_refs_json"]),
            "sanitized": bool(row["sanitized"]), "integrity_hash": row["integrity_hash"],
            "created_at": row["created_at"],
        }
