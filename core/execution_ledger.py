"""Persistent execution state machine and crash reconciliation.

Every tool run, HTTP broker request and browser action is one row in ``executions`` with an
explicit state machine and an append-only event trail. The ledger answers three questions the
framework could not answer before:

* *What happened to this execution?*  — status, timestamps, resource usage, evidence, failure.
* *After a crash, is it safe to run it again?* — only an operator can decide, because the
  external request may already have been sent. Nothing here ever re-executes anything.
* *Which evidence came from which execution?* — ``evidence.execution_id`` (migration 014).

State machine::

    CREATED -> QUEUED -> AUTHORIZED -> RUNNING -> COMPLETED | FAILED | PARTIAL | CANCELLED
                                          |
                                          +-> INTERRUPTED            (process died; request NOT dispatched)
                                          +-> RECONCILIATION_REQUIRED (process died; request MAY have been sent)
    INTERRUPTED / RECONCILIATION_REQUIRED --(operator resolve)--> COMPLETED | FAILED | CANCELLED

Transitions are compare-and-swap inside ``BEGIN IMMEDIATE``: two writers can never both move an
execution out of the same state. A RUNNING execution holds a *lease*; only when the lease has
lapsed is it considered abandoned, so a long-running live tool is never mistaken for a crash.
"""
from __future__ import annotations

import json
import os
import time
import uuid

from core.errors import FAILURE_CLASSES
from core.redaction import redact, redact_value
from core.store import new_id, utc_now

STATES = ("CREATED", "QUEUED", "AUTHORIZED", "RUNNING", "COMPLETED", "FAILED", "PARTIAL",
          "CANCELLED", "INTERRUPTED", "RECONCILIATION_REQUIRED")
TERMINAL = frozenset({"COMPLETED", "FAILED", "PARTIAL", "CANCELLED"})
NEEDS_OPERATOR = frozenset({"INTERRUPTED", "RECONCILIATION_REQUIRED"})
TRANSITIONS = {
    "CREATED": {"QUEUED", "AUTHORIZED", "FAILED", "CANCELLED", "INTERRUPTED"},
    "QUEUED": {"AUTHORIZED", "FAILED", "CANCELLED", "INTERRUPTED"},
    "AUTHORIZED": {"RUNNING", "FAILED", "CANCELLED", "INTERRUPTED"},
    "RUNNING": {"COMPLETED", "FAILED", "PARTIAL", "CANCELLED", "INTERRUPTED", "RECONCILIATION_REQUIRED"},
    "INTERRUPTED": {"RECONCILIATION_REQUIRED", "COMPLETED", "FAILED", "CANCELLED"},
    "RECONCILIATION_REQUIRED": {"COMPLETED", "FAILED", "CANCELLED"},
    "COMPLETED": set(), "FAILED": set(), "PARTIAL": set(), "CANCELLED": set(),
}
KINDS = ("tool", "http", "browser", "validation")
RESOLUTIONS = {"completed": "COMPLETED", "failed_no_effect": "FAILED", "abandoned": "CANCELLED"}


class ExecutionError(RuntimeError):
    pass


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


class ExecutionLedger:
    def __init__(self, connection, *, owner: str | None = None, lease_seconds: float = 120.0,
                 clock=time.time):
        self.connection = connection
        self.owner = owner or f"pid{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.lease_seconds = float(lease_seconds)
        self.clock = clock

    # -- internals ---------------------------------------------------------------------
    def _row(self, execution_id: str, engagement_id: str | None = None):
        row = self.connection.execute("SELECT * FROM executions WHERE execution_id=?",
                                      (execution_id,)).fetchone()
        if row is None or (engagement_id is not None and row["engagement_id"] != engagement_id):
            # An execution of another engagement is indistinguishable from a missing one.
            raise ExecutionError("Unknown execution: " + str(execution_id))
        return row

    def _transition(self, execution_id, to_status, *, actor, expected=None, fields=None,
                    detail=None, engagement_id=None):
        """Atomically move ``execution_id`` to ``to_status`` (compare-and-swap)."""
        if to_status not in STATES:
            raise ExecutionError("Unknown execution status: " + str(to_status))
        fields = dict(fields or {})
        with self._immediate():
            row = self._row(execution_id, engagement_id)
            current = row["status"]
            if expected is not None and current not in expected:
                raise ExecutionError(f"Execution is {current}, expected one of {sorted(expected)}")
            if to_status not in TRANSITIONS[current]:
                raise ExecutionError(f"Invalid execution transition {current} -> {to_status}")
            now = utc_now()
            assignments = {"status": to_status, "updated_at": now, **fields}
            if to_status in TERMINAL or to_status in NEEDS_OPERATOR:
                assignments.setdefault("finished_at", now)
                assignments["lease_expires_at"] = None       # settled: nothing left to expire
            else:
                assignments["lease_expires_at"] = self.clock() + self.lease_seconds
            sets = ", ".join(f"{key}=?" for key in assignments)
            updated = self.connection.execute(
                f"UPDATE executions SET {sets} WHERE execution_id=? AND status=?",
                (*assignments.values(), execution_id, current))
            if updated.rowcount != 1:
                raise ExecutionError("Concurrent transition lost the race for " + execution_id)
            self.connection.execute(
                "INSERT INTO execution_events(execution_id,engagement_id,from_status,to_status,actor,"
                "detail_json,created_at) VALUES(?,?,?,?,?,?,?)",
                (execution_id, row["engagement_id"], current, to_status, actor,
                 _json(redact_value(detail or {})), now))
        return to_status

    def _immediate(self):
        ledger = self

        class _Tx:
            def __enter__(self_inner):
                self_inner.nested = ledger.connection.in_transaction
                if not self_inner.nested:
                    ledger.connection.execute("BEGIN IMMEDIATE")
                return self_inner

            def __exit__(self_inner, exc_type, *_):
                if self_inner.nested:           # the caller owns the transaction
                    return False
                if exc_type is None:
                    ledger.connection.commit()
                else:
                    ledger.connection.rollback()
                return False
        return _Tx()

    # -- lifecycle ---------------------------------------------------------------------
    def create(self, *, engagement_id: str, kind: str, tool_id: str, execution_profile: str,
               task_id: str | None = None, request: dict | None = None,
               side_effect_risk: str = "read_only", external_ref: str | None = None,
               actor: str = "pipeline") -> str:
        if kind not in KINDS:
            raise ExecutionError("Unknown execution kind: " + str(kind))
        if side_effect_risk not in ("read_only", "state_changing"):
            raise ExecutionError("Unknown side_effect_risk: " + str(side_effect_risk))
        execution_id = new_id("exec")
        now = utc_now()
        with self._immediate():
            if self.connection.execute("SELECT 1 FROM engagements WHERE engagement_id=?",
                                       (engagement_id,)).fetchone() is None:
                raise ExecutionError("Unknown engagement: " + str(engagement_id))
            self.connection.execute(
                "INSERT INTO executions(execution_id,engagement_id,task_id,kind,tool_id,execution_profile,"
                "status,side_effect_risk,request_json,external_ref,owner,lease_expires_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,'CREATED',?,?,?,?,?,?,?)",
                (execution_id, engagement_id, task_id, kind, tool_id, execution_profile,
                 side_effect_risk, _json(redact_value(request or {})), external_ref,
                 self.owner, self.clock() + self.lease_seconds, now, now))
            self.connection.execute(
                "INSERT INTO execution_events(execution_id,engagement_id,from_status,to_status,actor,"
                "detail_json,created_at) VALUES(?,?,NULL,'CREATED',?,'{}',?)",
                (execution_id, engagement_id, actor, now))
        return execution_id

    def queue(self, execution_id: str, *, actor: str = "pipeline") -> None:
        self._transition(execution_id, "QUEUED", actor=actor)

    def authorize(self, execution_id: str, authorization: dict, *, actor: str = "policy") -> None:
        """Record the deterministic policy verdict. Only an explicit *allow* authorizes."""
        if not isinstance(authorization, dict) or authorization.get("decision") != "allow" \
                or not authorization.get("source"):
            raise ExecutionError("Authorization requires an explicit 'allow' decision and its source")
        self._transition(execution_id, "AUTHORIZED", actor=actor,
                         fields={"authorization_json": _json(redact_value(authorization))},
                         detail={"source": authorization["source"]})

    def start(self, execution_id: str, *, actor: str = "executor") -> None:
        self._transition(execution_id, "RUNNING", actor=actor,
                         fields={"started_at": utc_now(), "owner": self.owner})

    def mark_dispatched(self, execution_id: str) -> None:
        """Record that the external request may now have left this process.

        From this point a crash can no longer be classed "no effect": it requires an operator
        to reconcile, because the target may have processed the request.
        """
        with self._immediate():
            row = self._row(execution_id)
            if row["status"] != "RUNNING":
                raise ExecutionError("Only a RUNNING execution can be marked dispatched")
            self.connection.execute(
                "UPDATE executions SET request_dispatched=1, updated_at=? WHERE execution_id=?",
                (utc_now(), execution_id))

    def heartbeat(self, execution_id: str) -> None:
        with self._immediate():
            self.connection.execute(
                "UPDATE executions SET lease_expires_at=?, updated_at=? WHERE execution_id=? AND status='RUNNING'",
                (self.clock() + self.lease_seconds, utc_now(), execution_id))

    def complete(self, execution_id: str, *, evidence_refs=(), exit_status: int | None = None,
                 resource_usage: dict | None = None, partial: bool = False,
                 actor: str = "executor") -> None:
        self._transition(execution_id, "PARTIAL" if partial else "COMPLETED", actor=actor, expected={"RUNNING"},
                         fields={"evidence_refs_json": _json(list(dict.fromkeys(evidence_refs))),
                                 "exit_status": exit_status,
                                 "resource_usage_json": _json(resource_usage or {})})

    def fail(self, execution_id: str, *, failure_class: str, message: str, actor: str = "executor",
             uncertain_outcome: bool | None = None) -> str:
        """Fail an execution; returns the resulting status.

        If the request may have been dispatched and the execution is state-changing (or the
        caller says the outcome is uncertain) the result is ``RECONCILIATION_REQUIRED``, not
        ``FAILED``: "it errored" is not the same as "it had no effect".
        """
        if failure_class not in FAILURE_CLASSES:
            raise ExecutionError("Unknown failure class: " + str(failure_class))
        row = self._row(execution_id)
        uncertain = uncertain_outcome if uncertain_outcome is not None else (
            bool(row["request_dispatched"]) and row["side_effect_risk"] == "state_changing")
        status = "RECONCILIATION_REQUIRED" if (uncertain and row["status"] == "RUNNING") else "FAILED"
        self._transition(execution_id, status, actor=actor, fields={
            "failure_json": _json({"class": failure_class, "message": redact(str(message))[:500]})})
        return status

    def cancel(self, execution_id: str, *, reason: str, actor: str = "operator") -> None:
        self._transition(execution_id, "CANCELLED", actor=actor, detail={"reason": redact(reason)[:300]})

    # -- recovery ----------------------------------------------------------------------
    def reconcile_stale(self, *, engagement_id: str | None = None, actor: str = "reconciler") -> list[dict]:
        """Move executions whose lease lapsed out of the live states; **never re-runs anything**.

        * request not dispatched      -> ``INTERRUPTED``
        * request possibly dispatched -> ``RECONCILIATION_REQUIRED``
        Both then wait for an explicit :meth:`resolve` by an operator.
        """
        clauses = ["status IN ('CREATED','QUEUED','AUTHORIZED','RUNNING')",
                   "lease_expires_at IS NOT NULL", "lease_expires_at < ?"]
        params: list = [self.clock()]
        if engagement_id is not None:
            clauses.append("engagement_id=?")
            params.append(engagement_id)
        rows = self.connection.execute(
            "SELECT execution_id,status,request_dispatched FROM executions WHERE " + " AND ".join(clauses),
            params).fetchall()
        moved = []
        for row in rows:
            target = "RECONCILIATION_REQUIRED" if (row["status"] == "RUNNING" and row["request_dispatched"]) \
                else "INTERRUPTED"
            try:
                self._transition(row["execution_id"], target, actor=actor, expected={row["status"]},
                                 detail={"reason": "lease expired; owner presumed dead",
                                         "request_dispatched": bool(row["request_dispatched"])})
            except ExecutionError:
                continue                       # settled concurrently by its (live) owner: leave it
            moved.append({"execution_id": row["execution_id"], "to": target})
        return moved

    def resolve(self, execution_id: str, *, operator: str, resolution: str, reason: str,
                evidence_refs=(), engagement_id: str | None = None) -> str:
        """The only way out of INTERRUPTED / RECONCILIATION_REQUIRED: an explicit operator decision.

        ``completed``         the operator confirmed the action took effect (evidence may be attached)
        ``failed_no_effect``  the operator confirmed it had no effect on the target
        ``abandoned``         the operator closes it without a conclusion
        """
        if resolution not in RESOLUTIONS:
            raise ExecutionError("resolution must be one of " + ", ".join(sorted(RESOLUTIONS)))
        if not isinstance(operator, str) or not operator.strip() or not isinstance(reason, str) \
                or len(reason.strip()) < 10:
            raise ExecutionError("Reconciliation requires a named operator and a reason (>= 10 characters)")
        decision = {"decided_by": operator.strip(), "resolution": resolution,
                    "reason": redact(reason.strip())[:500], "decided_at": utc_now()}
        self._transition(
            execution_id, RESOLUTIONS[resolution], actor=operator.strip(), expected=NEEDS_OPERATOR,
            engagement_id=engagement_id,
            fields={"reconciliation_json": _json(decision),
                    "evidence_refs_json": _json(list(dict.fromkeys(evidence_refs)))
                    if evidence_refs else self._row(execution_id)["evidence_refs_json"]},
            detail=decision)
        return RESOLUTIONS[resolution]

    # -- reads -------------------------------------------------------------------------
    def get(self, execution_id: str, engagement_id: str | None = None) -> dict:
        return self._as_dict(self._row(execution_id, engagement_id))

    def list(self, engagement_id: str, *, status: str | None = None, task_id: str | None = None) -> list[dict]:
        clauses, params = ["engagement_id=?"], [engagement_id]
        if status is not None:
            clauses.append("status=?"); params.append(status)
        if task_id is not None:
            clauses.append("task_id=?"); params.append(task_id)
        rows = self.connection.execute(
            "SELECT * FROM executions WHERE " + " AND ".join(clauses) + " ORDER BY created_at,execution_id",
            params).fetchall()
        return [self._as_dict(row) for row in rows]

    def pending_reconciliation(self, engagement_id: str) -> list[dict]:
        return [e for e in self.list(engagement_id) if e["status"] in NEEDS_OPERATOR]

    def events(self, execution_id: str, engagement_id: str | None = None) -> list[dict]:
        self._row(execution_id, engagement_id)
        rows = self.connection.execute(
            "SELECT from_status,to_status,actor,detail_json,created_at FROM execution_events "
            "WHERE execution_id=? ORDER BY event_id", (execution_id,)).fetchall()
        return [{"from": r["from_status"], "to": r["to_status"], "actor": r["actor"],
                 "detail": json.loads(r["detail_json"]), "at": r["created_at"]} for r in rows]

    @staticmethod
    def _as_dict(row) -> dict:
        return {
            "execution_id": row["execution_id"], "engagement_id": row["engagement_id"],
            "task_id": row["task_id"], "kind": row["kind"], "tool_id": row["tool_id"],
            "execution_profile": row["execution_profile"], "status": row["status"],
            "side_effect_risk": row["side_effect_risk"],
            "authorization": json.loads(row["authorization_json"]),
            "request": json.loads(row["request_json"]), "external_ref": row["external_ref"],
            "request_dispatched": bool(row["request_dispatched"]),
            "created_at": row["created_at"], "started_at": row["started_at"],
            "finished_at": row["finished_at"], "exit_status": row["exit_status"],
            "resource_usage": json.loads(row["resource_usage_json"]),
            "evidence_refs": json.loads(row["evidence_refs_json"]),
            "failure": json.loads(row["failure_json"]) if row["failure_json"] else None,
            "reconciliation": json.loads(row["reconciliation_json"]) if row["reconciliation_json"] else None,
        }
