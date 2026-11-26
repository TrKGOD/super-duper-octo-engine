"""Vulnerability-hypothesis model, lifecycle and persistence.

A hypothesis is an evidence-anchored, testable claim about one target entity. Its status
follows an explicit lifecycle; the discovering step can never jump straight to a confirmed
finding (that is the validation engine's job). Hypotheses deduplicate on a deterministic
signature so the same (category, target, identity) is tracked once.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from core.store import utc_now


class PlannerError(ValueError):
    pass


# Lifecycle. SUPPORTED/REFUTED are terminal.
STATUSES = ("PROPOSED", "READY", "RUNNING", "SUPPORTED", "REFUTED", "INCONCLUSIVE", "BLOCKED", "DEFERRED")
_TRANSITIONS = {
    "PROPOSED": {"READY", "BLOCKED", "DEFERRED"},
    "READY": {"RUNNING", "DEFERRED", "BLOCKED"},
    "RUNNING": {"SUPPORTED", "REFUTED", "INCONCLUSIVE", "BLOCKED"},
    "BLOCKED": {"READY", "DEFERRED"},
    "DEFERRED": {"READY", "BLOCKED"},
    "INCONCLUSIVE": {"DEFERRED", "READY"},
    "SUPPORTED": set(),
    "REFUTED": set(),
}


def can_transition(current: str, new: str) -> bool:
    if current not in _TRANSITIONS:
        return False
    return new == current or new in _TRANSITIONS[current]


def hypothesis_id(engagement_id: str, category: str, target_node_id: str | None,
                  required_identity: str | None) -> str:
    raw = "\x00".join([engagement_id, category, target_node_id or "", required_identity or ""])
    return "hyp_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


@dataclass
class Hypothesis:
    engagement_id: str
    category: str
    test_class: str
    proposed_test: str
    target_node_id: str | None = None
    target_label: str | None = None
    skill: str | None = None
    required_identity: str | None = None
    required_state: str | None = None
    preconditions: list = field(default_factory=list)
    supporting_evidence: list = field(default_factory=list)
    contradictory_evidence: list = field(default_factory=list)
    expected_outcomes: str | None = None
    risk: str = "medium"
    state_changing: bool = False
    confidence: float = 0.0

    @property
    def id(self) -> str:
        return hypothesis_id(self.engagement_id, self.category, self.target_node_id, self.required_identity)


class HypothesisStore:
    def __init__(self, connection, engagement_id: str):
        self.connection = connection
        self.engagement_id = engagement_id

    def upsert(self, hyp: Hypothesis) -> str:
        hid = hyp.id
        now = utc_now()
        with self.connection:
            row = self.connection.execute(
                "SELECT hypothesis_id FROM planner_hypotheses WHERE hypothesis_id=? AND engagement_id=?",
                (hid, self.engagement_id)).fetchone()
            if row is None:
                self.connection.execute(
                    "INSERT INTO planner_hypotheses(hypothesis_id,engagement_id,category,test_class,skill,"
                    "target_node_id,target_label,required_identity,required_state,preconditions_json,"
                    "supporting_evidence_json,contradictory_evidence_json,proposed_test,expected_outcomes,"
                    "risk,state_changing,confidence,score,score_breakdown_json,status,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,'{}','PROPOSED',?,?)",
                    (hid, self.engagement_id, hyp.category, hyp.test_class, hyp.skill,
                     hyp.target_node_id, hyp.target_label, hyp.required_identity, hyp.required_state,
                     json.dumps(hyp.preconditions), json.dumps(hyp.supporting_evidence),
                     json.dumps(hyp.contradictory_evidence), hyp.proposed_test, hyp.expected_outcomes,
                     hyp.risk, 1 if hyp.state_changing else 0, float(hyp.confidence), now, now))
            else:
                # Refresh evidence/confidence without disturbing the lifecycle status.
                self.connection.execute(
                    "UPDATE planner_hypotheses SET supporting_evidence_json=?,contradictory_evidence_json=?,"
                    "confidence=MAX(confidence,?),updated_at=? WHERE hypothesis_id=? AND engagement_id=?",
                    (json.dumps(hyp.supporting_evidence), json.dumps(hyp.contradictory_evidence),
                     float(hyp.confidence), now, hid, self.engagement_id))
        return hid

    def get(self, hid: str) -> dict | None:
        row = self.connection.execute(
            "SELECT * FROM planner_hypotheses WHERE hypothesis_id=? AND engagement_id=?",
            (hid, self.engagement_id)).fetchone()
        return self._row(row) if row else None

    def list(self, status: str | None = None) -> list[dict]:
        if status is None:
            rows = self.connection.execute(
                "SELECT * FROM planner_hypotheses WHERE engagement_id=? ORDER BY score DESC,hypothesis_id",
                (self.engagement_id,)).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM planner_hypotheses WHERE engagement_id=? AND status=? ORDER BY score DESC,hypothesis_id",
                (self.engagement_id, status)).fetchall()
        return [self._row(row) for row in rows]

    def set_status(self, hid: str, new_status: str, reason: str | None = None) -> None:
        if new_status not in STATUSES:
            raise PlannerError("Unknown status: " + str(new_status))
        current = self.get(hid)
        if current is None:
            raise PlannerError("Unknown hypothesis: " + str(hid))
        if not can_transition(current["status"], new_status):
            raise PlannerError(f"Invalid hypothesis transition {current['status']} -> {new_status}")
        with self.connection:
            self.connection.execute(
                "UPDATE planner_hypotheses SET status=?,status_reason=?,"
                "attempts=attempts+?,updated_at=? WHERE hypothesis_id=? AND engagement_id=?",
                (new_status, reason, 1 if new_status == "RUNNING" else 0, utc_now(), hid, self.engagement_id))

    def set_score(self, hid: str, score: float, breakdown: dict) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE planner_hypotheses SET score=?,score_breakdown_json=?,updated_at=? "
                "WHERE hypothesis_id=? AND engagement_id=?",
                (float(score), json.dumps(breakdown, sort_keys=True), utc_now(), hid, self.engagement_id))

    def add_evidence(self, hid: str, refs, *, supporting: bool = True) -> None:
        current = self.get(hid)
        if current is None:
            raise PlannerError("Unknown hypothesis: " + str(hid))
        column = "supporting_evidence_json" if supporting else "contradictory_evidence_json"
        key = "supporting_evidence" if supporting else "contradictory_evidence"
        merged = list(dict.fromkeys(list(current[key]) + list(refs)))
        with self.connection:
            self.connection.execute(
                f"UPDATE planner_hypotheses SET {column}=?,updated_at=? WHERE hypothesis_id=? AND engagement_id=?",
                (json.dumps(merged), utc_now(), hid, self.engagement_id))

    @staticmethod
    def _row(row) -> dict:
        return {
            "hypothesis_id": row["hypothesis_id"], "category": row["category"],
            "test_class": row["test_class"], "skill": row["skill"],
            "target_node_id": row["target_node_id"], "target_label": row["target_label"],
            "required_identity": row["required_identity"], "required_state": row["required_state"],
            "preconditions": json.loads(row["preconditions_json"]),
            "supporting_evidence": json.loads(row["supporting_evidence_json"]),
            "contradictory_evidence": json.loads(row["contradictory_evidence_json"]),
            "proposed_test": row["proposed_test"], "expected_outcomes": row["expected_outcomes"],
            "risk": row["risk"], "state_changing": bool(row["state_changing"]),
            "confidence": row["confidence"], "score": row["score"],
            "score_breakdown": json.loads(row["score_breakdown_json"]),
            "status": row["status"], "status_reason": row["status_reason"], "attempts": row["attempts"],
        }
