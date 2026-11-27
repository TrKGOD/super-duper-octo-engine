"""Validation record model, integrity hashing and persistence.

A validation record is the independent, tamper-evident result of one validation run. It
stores references and a comparison summary — never raw bodies, secrets or tokens — plus a
SHA-256 integrity hash over its material fields so a stored record cannot be silently
altered without detection.

Evidence chain (migration 014): ``evidence_verified`` states whether the oracle ran on
evidence that was *resolved from the vault and integrity-checked by the engine itself*, and
``evidence_hashes`` lists exactly which artifacts (role, id, SHA-256, producing execution)
that was. ``evidence_requests`` records what further evidence an inconclusive result needs.
These fields enter the integrity hash only when they are set, so every record written before
they existed still verifies unchanged.
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


def _hash_key(item: dict):
    return (str(item.get("role", "")), str(item.get("evidence_id", "")))


def chain_material(base: dict, *, evidence_verified: bool, evidence_hashes: list,
                   evidence_requests: list) -> dict:
    """Add the evidence-chain fields to ``base`` only when they carry information."""
    material = dict(base)
    if evidence_verified or evidence_hashes:
        material["evidence_verified"] = bool(evidence_verified)
        material["evidence_hashes"] = sorted(evidence_hashes, key=_hash_key)
    if evidence_requests:
        material["evidence_requests"] = list(evidence_requests)
    return material


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
    evidence_verified: bool = False
    evidence_hashes: list = field(default_factory=list)
    evidence_requests: list = field(default_factory=list)
    record_id: str = field(default_factory=lambda: new_id("vrec"))
    created_at: str = field(default_factory=utc_now)

    def material(self) -> dict:
        """The fields the integrity hash covers (everything substantive except the hash)."""
        base = {
            "engagement_id": self.engagement_id, "vulnerability_class": self.vulnerability_class,
            "oracle": self.oracle, "disposition": self.disposition, "explanation": self.explanation,
            "validator_id": self.validator_id, "validator_version": self.validator_version,
            "finding_id": self.finding_id, "hypothesis_id": self.hypothesis_id,
            "comparison": self.comparison, "request_refs": sorted(self.request_refs),
            "response_refs": sorted(self.response_refs), "baseline_refs": sorted(self.baseline_refs),
            "sanitized": bool(self.sanitized), "created_at": self.created_at,
        }
        return chain_material(base, evidence_verified=self.evidence_verified,
                              evidence_hashes=self.evidence_hashes,
                              evidence_requests=self.evidence_requests)

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
                "integrity_hash,created_at,evidence_verified,evidence_hashes_json,evidence_requests_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.record_id, self.engagement_id, record.finding_id, record.hypothesis_id,
                 record.vulnerability_class, record.oracle, record.validator_id, record.validator_version,
                 record.disposition, record.explanation, json.dumps(record.comparison, sort_keys=True),
                 json.dumps(record.request_refs), json.dumps(record.response_refs),
                 json.dumps(record.baseline_refs), 1 if record.sanitized else 0,
                 record.integrity(), record.created_at, 1 if record.evidence_verified else 0,
                 json.dumps(sorted(record.evidence_hashes, key=_hash_key)),
                 json.dumps(record.evidence_requests)))
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

    def for_hypothesis(self, hypothesis_id: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM validation_records WHERE hypothesis_id=? AND engagement_id=? ORDER BY created_at",
            (hypothesis_id, self.engagement_id)).fetchall()
        return [self._row(row) for row in rows]

    def verify(self, record_id: str) -> bool:
        """Recompute the integrity hash and confirm the stored record is unaltered."""
        row = self.connection.execute(
            "SELECT * FROM validation_records WHERE record_id=? AND engagement_id=?",
            (record_id, self.engagement_id)).fetchone()
        if row is None:
            return False
        base = {
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
        material = chain_material(
            base, evidence_verified=bool(row["evidence_verified"]),
            evidence_hashes=json.loads(row["evidence_hashes_json"]),
            evidence_requests=json.loads(row["evidence_requests_json"]))
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
            "evidence_verified": bool(row["evidence_verified"]),
            "evidence_hashes": json.loads(row["evidence_hashes_json"]),
            "evidence_requests": json.loads(row["evidence_requests_json"]),
            "created_at": row["created_at"],
        }
