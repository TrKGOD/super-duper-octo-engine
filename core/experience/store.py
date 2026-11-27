"""Validated Experience Memory — record model and persistent store.

A dedicated, reusable-across-engagements store (its own SQLite database, like the Knowledge
Base, kept separate from any single engagement's evidence). It holds only sanitized,
independently validated experience: no credentials, session secrets, tokens, raw response
bodies or personal data — evidence is referenced by id, never copied. Retrieval is advisory:
a past success is never evidence that a new target is vulnerable, and never authorization to
act on a different engagement.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core.redaction import redact
from core.store import new_id, utc_now

STATUSES = ("active", "under_review", "deprecated")
_ADVISORY = ("Advisory validated experience from another engagement; it is not evidence that "
             "the current target is vulnerable and confers no authorization to act.")


def _redact(value) -> str | None:
    if value is None:
        return None
    return redact(str(value))


def _host(asset: str) -> str:
    parsed = urlsplit(str(asset))
    return (parsed.hostname or str(asset)).lower()


@dataclass
class ExperienceRecord:
    vulnerability_category: str
    source_engagement_id: str
    attack_surface: str = ""
    technology: str | None = None
    technology_version: str | None = None
    prerequisites: list = field(default_factory=list)
    required_identity: str | None = None
    required_privilege: str | None = None
    endpoint_characteristics: dict = field(default_factory=dict)
    tooling: list = field(default_factory=list)
    execution_methodology: str | None = None
    validation_methodology: str | None = None
    evidence_reference_ids: list = field(default_factory=list)
    expected_behavior: str | None = None
    actual_behavior: str | None = None
    false_positive_conditions: list = field(default_factory=list)
    remediation: str | None = None
    related_graph_entities: list = field(default_factory=list)
    related_knowledge_patterns: list = field(default_factory=list)
    confidence: float = 0.6

    def sanitized(self) -> "ExperienceRecord":
        """Return a copy with free-text fields redacted and only reference ids kept."""
        return ExperienceRecord(
            vulnerability_category=self.vulnerability_category,
            source_engagement_id=self.source_engagement_id,
            attack_surface=str(self.attack_surface),
            technology=self.technology, technology_version=self.technology_version,
            prerequisites=[_redact(p) for p in self.prerequisites],
            required_identity=self.required_identity, required_privilege=self.required_privilege,
            endpoint_characteristics={k: _redact(v) if isinstance(v, str) else v
                                      for k, v in self.endpoint_characteristics.items()},
            tooling=list(self.tooling),
            execution_methodology=_redact(self.execution_methodology),
            validation_methodology=_redact(self.validation_methodology),
            evidence_reference_ids=[str(e) for e in self.evidence_reference_ids],
            expected_behavior=_redact(self.expected_behavior),
            actual_behavior=_redact(self.actual_behavior),
            false_positive_conditions=[_redact(c) for c in self.false_positive_conditions],
            remediation=_redact(self.remediation),
            related_graph_entities=list(self.related_graph_entities),
            related_knowledge_patterns=list(self.related_knowledge_patterns),
            confidence=float(self.confidence),
        )

    def signature(self) -> str:
        material = "|".join([
            self.vulnerability_category.strip().lower(),
            _host(self.attack_surface),
            str(self.endpoint_characteristics.get("method", "")).upper(),
            str(self.endpoint_characteristics.get("path", self.endpoint_characteristics.get("parameter", ""))),
        ])
        return "sig_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


class ExperienceError(ValueError):
    pass


_MINT_KEY = object()


class PromotionTicket:
    """Proof that a finding passed the promotion gate.

    ``ExperienceStore.add`` used to accept any record and stamp it ``validated``, so the "only
    validated findings" rule lived solely in ``promote_finding`` and could be bypassed by calling
    the store directly. The store now requires a ticket, which only :mod:`core.experience.promotion`
    can mint after checking the finding and its verified validation record. (It is an in-process
    guard against accidental bypass, not a defence against hostile code in the same process.)
    """
    __slots__ = ("finding_id", "validation_record_id", "engagement_id")

    def __init__(self, finding_id: str, validation_record_id: str, engagement_id: str, *, _key=None):
        if _key is not _MINT_KEY:
            raise ExperienceError("A PromotionTicket can only be issued by the promotion gate")
        self.finding_id = finding_id
        self.validation_record_id = validation_record_id
        self.engagement_id = engagement_id


class ExperienceStore:
    def __init__(self, connection):
        self.connection = connection
        self.connection.row_factory = __import__("sqlite3").Row
        self.init()

    def init(self) -> None:
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS experience_records(
              experience_id TEXT PRIMARY KEY,
              signature TEXT NOT NULL,
              version INTEGER NOT NULL DEFAULT 1,
              status TEXT NOT NULL CHECK(status IN ('active','under_review','deprecated')),
              vulnerability_category TEXT NOT NULL,
              technology TEXT, technology_version TEXT, attack_surface TEXT,
              prerequisites_json TEXT NOT NULL DEFAULT '[]',
              required_identity TEXT, required_privilege TEXT,
              endpoint_characteristics_json TEXT NOT NULL DEFAULT '{}',
              tooling_json TEXT NOT NULL DEFAULT '[]',
              execution_methodology TEXT, validation_methodology TEXT,
              evidence_reference_ids_json TEXT NOT NULL DEFAULT '[]',
              expected_behavior TEXT, actual_behavior TEXT,
              final_disposition TEXT NOT NULL DEFAULT 'validated',
              confidence REAL NOT NULL DEFAULT 0.6,
              false_positive_conditions_json TEXT NOT NULL DEFAULT '[]',
              remediation TEXT,
              related_graph_entities_json TEXT NOT NULL DEFAULT '[]',
              related_knowledge_patterns_json TEXT NOT NULL DEFAULT '[]',
              source_engagement_id TEXT NOT NULL,
              retrieval_count INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              UNIQUE(signature, version))""")
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_experience_category ON experience_records(vulnerability_category,status)")
        existing = {row[1] for row in self.connection.execute("PRAGMA table_info(experience_records)")}
        for column in ("promotion_finding_id", "promotion_record_id"):      # provenance of the promotion
            if column not in existing:
                self.connection.execute(f"ALTER TABLE experience_records ADD COLUMN {column} TEXT")
        self.connection.commit()

    def add(self, record: ExperienceRecord, *, ticket: PromotionTicket,
            promoted_by: str = "validation-agent") -> str:
        if not isinstance(ticket, PromotionTicket) or ticket.engagement_id != record.source_engagement_id:
            raise ExperienceError("Experience can only be added through the promotion gate "
                                  "(a valid PromotionTicket for the source engagement is required)")
        record = record.sanitized()
        signature = record.signature()
        now = utc_now()
        # Versioning + confidence recalculation: a repeat validation of the same signature
        # supersedes the prior active record and raises confidence (capped).
        prior = self.connection.execute(
            "SELECT experience_id,version,confidence FROM experience_records "
            "WHERE signature=? AND status='active' ORDER BY version DESC LIMIT 1", (signature,)).fetchone()
        version = 1
        confidence = record.confidence
        if prior is not None:
            version = prior["version"] + 1
            confidence = min(0.95, max(record.confidence, float(prior["confidence"]) + 0.1))
            self.connection.execute(
                "UPDATE experience_records SET status='deprecated',updated_at=? WHERE experience_id=?",
                (now, prior["experience_id"]))
        experience_id = new_id("exp")
        self.connection.execute(
            "INSERT INTO experience_records(experience_id,signature,version,status,vulnerability_category,"
            "technology,technology_version,attack_surface,prerequisites_json,required_identity,required_privilege,"
            "endpoint_characteristics_json,tooling_json,execution_methodology,validation_methodology,"
            "evidence_reference_ids_json,expected_behavior,actual_behavior,final_disposition,confidence,"
            "false_positive_conditions_json,remediation,related_graph_entities_json,related_knowledge_patterns_json,"
            "source_engagement_id,created_at,updated_at,promotion_finding_id,promotion_record_id) "
            "VALUES(?,?,?,'active',?,?,?,?,?,?,?,?,?,?,?,?,?,?,'validated',?,?,?,?,?,?,?,?,?,?)",
            (experience_id, signature, version, record.vulnerability_category, record.technology,
             record.technology_version, record.attack_surface, json.dumps(record.prerequisites),
             record.required_identity, record.required_privilege,
             json.dumps(record.endpoint_characteristics), json.dumps(record.tooling),
             record.execution_methodology, record.validation_methodology,
             json.dumps(record.evidence_reference_ids), record.expected_behavior, record.actual_behavior,
             confidence, json.dumps(record.false_positive_conditions), record.remediation,
             json.dumps(record.related_graph_entities), json.dumps(record.related_knowledge_patterns),
             record.source_engagement_id, now, now, ticket.finding_id, ticket.validation_record_id))
        self.connection.commit()
        return experience_id

    def get(self, experience_id: str) -> dict | None:
        row = self.connection.execute(
            "SELECT * FROM experience_records WHERE experience_id=?", (experience_id,)).fetchone()
        return self._row(row) if row else None

    def deprecate(self, experience_id: str, reason: str | None = None) -> None:
        self.connection.execute(
            "UPDATE experience_records SET status='deprecated',updated_at=? WHERE experience_id=?",
            (utc_now(), experience_id))
        self.connection.commit()

    def mark_under_review(self, experience_id: str) -> None:
        self.connection.execute(
            "UPDATE experience_records SET status='under_review',updated_at=? WHERE experience_id=?",
            (utc_now(), experience_id))
        self.connection.commit()

    def list(self, *, status: str | None = "active") -> list[dict]:
        if status is None:
            rows = self.connection.execute("SELECT * FROM experience_records ORDER BY created_at").fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM experience_records WHERE status=? ORDER BY created_at", (status,)).fetchall()
        return [self._row(row) for row in rows]

    def search(self, *, category: str | None = None, technology: str | None = None,
               query: str | None = None, limit: int = 5) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM experience_records WHERE status='active'").fetchall()
        tokens = set((query or "").lower().split())
        scored = []
        for row in rows:
            score = 0.0
            if category and row["vulnerability_category"].lower() == category.lower():
                score += 2.0
            if technology and row["technology"] and technology.lower() in row["technology"].lower():
                score += 1.5
            if tokens:
                blob = " ".join(str(row[k] or "") for k in ("execution_methodology", "validation_methodology",
                                                            "vulnerability_category", "attack_surface")).lower()
                score += 0.5 * len(tokens & set(blob.split()))
            if score > 0 or not (category or technology or tokens):
                scored.append((score, row))
        scored.sort(key=lambda item: (item[0], item[1]["confidence"]), reverse=True)
        selected = [row for _, row in scored[:limit]]
        for row in selected:
            self.connection.execute(
                "UPDATE experience_records SET retrieval_count=retrieval_count+1 WHERE experience_id=?",
                (row["experience_id"],))
        self.connection.commit()
        return [{**self._row(row), "advisory": _ADVISORY} for row in selected]

    @staticmethod
    def _row(row) -> dict:
        return {
            "experience_id": row["experience_id"], "signature": row["signature"], "version": row["version"],
            "status": row["status"], "vulnerability_category": row["vulnerability_category"],
            "technology": row["technology"], "technology_version": row["technology_version"],
            "attack_surface": row["attack_surface"], "prerequisites": json.loads(row["prerequisites_json"]),
            "required_identity": row["required_identity"], "required_privilege": row["required_privilege"],
            "endpoint_characteristics": json.loads(row["endpoint_characteristics_json"]),
            "tooling": json.loads(row["tooling_json"]),
            "execution_methodology": row["execution_methodology"],
            "validation_methodology": row["validation_methodology"],
            "evidence_reference_ids": json.loads(row["evidence_reference_ids_json"]),
            "expected_behavior": row["expected_behavior"], "actual_behavior": row["actual_behavior"],
            "final_disposition": row["final_disposition"], "confidence": row["confidence"],
            "false_positive_conditions": json.loads(row["false_positive_conditions_json"]),
            "remediation": row["remediation"],
            "related_graph_entities": json.loads(row["related_graph_entities_json"]),
            "related_knowledge_patterns": json.loads(row["related_knowledge_patterns_json"]),
            "source_engagement_id": row["source_engagement_id"], "retrieval_count": row["retrieval_count"],
            "promotion_finding_id": row["promotion_finding_id"],
            "promotion_record_id": row["promotion_record_id"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }
