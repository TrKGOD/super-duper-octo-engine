"""SQLite persistence with transactional lifecycle and evidence integrity."""
import json
import re
import sqlite3
import uuid
from pathlib import PurePosixPath
from datetime import datetime, timezone

from core.validation import (
    FindingValidationError,
    validate_finding,
    validate_finding_transition,
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_id(prefix):
    return prefix + "_" + uuid.uuid4().hex


class StateStore:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        self.connection = sqlite3.connect(self.db_path, timeout=5.0, isolation_level="DEFERRED")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        if self.db_path != ":memory:":
            self.connection.execute("PRAGMA journal_mode=WAL")

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def append_audit(self, engagement_id, actor, event_type, details):
        self.connection.execute(
            "INSERT INTO audit_events(engagement_id,actor,event_type,details_json,created_at) VALUES(?,?,?,?,?)",
            (engagement_id, actor, event_type, json.dumps(details, sort_keys=True), utc_now()),
        )

    def create_engagement(self, engagement_id, authorization_reference, scope, rules, status="draft"):
        now = utc_now()
        with self.connection:
            self.connection.execute(
                "INSERT INTO engagements VALUES(?,?,?,?,?,?,?)",
                (engagement_id, authorization_reference, status, json.dumps(scope), json.dumps(rules), now, now),
            )
            self.append_audit(engagement_id, "operator", "engagement.created", {"status": status})

    def create_task(self, engagement_id, agent, input_data):
        task_id = new_id("task")
        with self.connection:
            self.connection.execute(
                "INSERT INTO tasks(task_id,engagement_id,agent,status,input_json) VALUES(?,?,?,'queued',?)",
                (task_id, engagement_id, agent, json.dumps(input_data)),
            )
            self.append_audit(
                engagement_id, agent, "task.created",
                {"task_id": task_id, "task_key": input_data.get("task_key")},
            )
        return task_id

    def update_task(self, task_id, status, output_data=None):
        transitions = {
            "queued": {"running", "blocked", "needs_operator", "failed"},
            "running": {"completed", "blocked", "needs_operator", "failed"},
            "blocked": {"queued"},
            "needs_operator": {"queued"},
            "failed": {"queued"},
            "completed": set(),
        }
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT engagement_id,agent,status FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if row is None:
                raise KeyError(task_id)
            if status not in transitions or (
                status != row["status"] and status not in transitions[row["status"]]
            ):
                raise ValueError("Invalid task status transition: " + row["status"] + " -> " + status)
            now = utc_now()
            self.connection.execute(
                """UPDATE tasks SET status=?,output_json=?,
                   started_at=CASE WHEN ?='running' AND started_at IS NULL THEN ? ELSE started_at END,
                   completed_at=? WHERE task_id=?""",
                (
                    status, json.dumps(output_data) if output_data is not None else None,
                    status, now,
                    now if status in {"completed", "blocked", "needs_operator", "failed"} else None,
                    task_id,
                ),
            )
            self.append_audit(
                row["engagement_id"], row["agent"], "task.status_changed",
                {"task_id": task_id, "from": row["status"], "to": status},
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def start_agent_run(self, engagement_id, agent, model=None, task_id=None):
        run_id, now = new_id("run"), utc_now()
        with self.connection:
            if task_id is not None:
                task = self.connection.execute(
                    "SELECT engagement_id,agent,status FROM tasks WHERE task_id=?", (task_id,)
                ).fetchone()
                if task is None or task["engagement_id"] != engagement_id or task["agent"] != agent:
                    raise ValueError("Agent run does not match the persisted task")
                if task["status"] != "running":
                    raise ValueError("Agent run requires a running task")
            self.connection.execute(
                """INSERT INTO agent_runs(run_id,engagement_id,agent,model,status,started_at,task_id)
                   VALUES(?,?,?,?,'running',?,?)""",
                (run_id, engagement_id, agent, model, now, task_id),
            )
            self.append_audit(
                engagement_id, agent, "agent_run.started",
                {"run_id": run_id, "model": model, "task_id": task_id},
            )
        return run_id

    def finish_agent_run(self, run_id, status, input_tokens=None, output_tokens=None, cost_usd=None):
        if status not in {"completed", "failed", "blocked", "needs_operator"}:
            raise ValueError("Unsupported agent run status")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT engagement_id,agent,status FROM agent_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if row is None:
                raise KeyError(run_id)
            if row["status"] != "running":
                raise ValueError("Only running agent runs can be finished")
            self.connection.execute(
                """UPDATE agent_runs SET status=?,input_tokens=?,output_tokens=?,cost_usd=?,completed_at=?
                   WHERE run_id=?""",
                (status, input_tokens, output_tokens, cost_usd, utc_now(), run_id),
            )
            self.append_audit(
                row["engagement_id"], row["agent"], "agent_run.finished",
                {"run_id": run_id, "status": status},
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def finish_agent_run_for_task(self, task_id, status):
        row = self.connection.execute(
            """SELECT run_id FROM agent_runs
               WHERE task_id=? AND status='running' ORDER BY started_at DESC LIMIT 1""",
            (task_id,),
        ).fetchone()
        if row is None:
            raise ValueError("No running agent run exists for task: " + task_id)
        self.finish_agent_run(row["run_id"], status)

    @staticmethod
    def _validate_evidence_path(local_path):
        if not isinstance(local_path, str) or not local_path.strip():
            raise ValueError("Evidence local_path is required")
        path = PurePosixPath(local_path)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != ".local":
            raise ValueError("Evidence paths must be relative and confined under .local/")
        return str(path)

    def record_evidence(
        self, engagement_id, evidence_type, local_path, captured_by,
        sha256=None, redacted=True, captured_at=None,
    ):
        local_path = self._validate_evidence_path(local_path)
        if not evidence_type or not captured_by:
            raise ValueError("Evidence type and captured_by are required")
        if sha256 is not None and (
            not isinstance(sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", sha256)
        ):
            raise ValueError("sha256 must contain exactly 64 hexadecimal characters")
        evidence_id = new_id("evidence")
        timestamp = captured_at or utc_now()
        with self.connection:
            exists = self.connection.execute(
                "SELECT 1 FROM engagements WHERE engagement_id=?", (engagement_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(engagement_id)
            self.connection.execute(
                """INSERT INTO evidence
                   (evidence_id,engagement_id,finding_id,evidence_type,local_path,sha256,redacted,captured_at,captured_by)
                   VALUES(?,?,NULL,?,?,?,?,?,?)""",
                (evidence_id, engagement_id, evidence_type, local_path, sha256, int(bool(redacted)), timestamp, captured_by),
            )
            self.append_audit(
                engagement_id, captured_by, "evidence.recorded",
                {"evidence_id": evidence_id, "evidence_type": evidence_type, "sha256": sha256},
            )
        return evidence_id

    def validate_evidence_refs_for_engagement(self, engagement_id, evidence_refs):
        """Verify every handoff evidence ID exists and belongs to this engagement."""
        if not isinstance(evidence_refs, list) or any(
            not isinstance(ref, str) or not ref.strip() for ref in evidence_refs
        ):
            raise FindingValidationError("evidence_refs must be a list of non-empty evidence IDs")
        if len(set(evidence_refs)) != len(evidence_refs):
            raise FindingValidationError("evidence_refs cannot contain duplicate IDs")
        for evidence_id in evidence_refs:
            row = self.connection.execute(
                "SELECT engagement_id FROM evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            if row is None or row["engagement_id"] != engagement_id:
                raise FindingValidationError("Unknown or out-of-engagement evidence reference: " + evidence_id)

    def _validate_evidence_refs(self, engagement_id, finding_id, evidence_refs):
        if not isinstance(evidence_refs, list) or any(
            not isinstance(ref, str) or not ref.strip() for ref in evidence_refs
        ):
            raise FindingValidationError("evidence_refs must be a list of non-empty evidence IDs")
        if len(set(evidence_refs)) != len(evidence_refs):
            raise FindingValidationError("evidence_refs cannot contain duplicate IDs")
        for evidence_id in evidence_refs:
            row = self.connection.execute(
                "SELECT engagement_id,finding_id FROM evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            if row is None:
                raise FindingValidationError("Unknown evidence reference: " + evidence_id)
            if row["engagement_id"] != engagement_id:
                raise FindingValidationError("Evidence belongs to a different engagement: " + evidence_id)
            if row["finding_id"] not in (None, finding_id):
                raise FindingValidationError("Evidence is already linked to another finding: " + evidence_id)

    def record_finding(self, finding):
        validate_finding(finding)
        evidence_refs = finding.get("evidence_refs", [])
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._validate_evidence_refs(finding["engagement_id"], finding["finding_id"], evidence_refs)
            now = utc_now()
            self.connection.execute(
                """INSERT INTO findings
                   (finding_id,engagement_id,title,status,severity,asset,method,parameter,description,impact,
                    evidence_refs_json,proposed_by,validated_by,created_at,updated_at,preconditions_json,validation_notes)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding["finding_id"], finding["engagement_id"], finding["title"], finding["status"],
                    finding.get("severity", "unknown"), finding["asset"], finding.get("method"),
                    finding.get("parameter"), finding["description"], finding.get("impact"),
                    json.dumps(evidence_refs), finding["proposed_by"], finding.get("validated_by"),
                    now, now, json.dumps(finding.get("preconditions", [])), finding.get("validation_notes"),
                ),
            )
            for evidence_id in evidence_refs:
                self.connection.execute(
                    "UPDATE evidence SET finding_id=? WHERE evidence_id=? AND finding_id IS NULL",
                    (finding["finding_id"], evidence_id),
                )
            self.append_audit(
                finding["engagement_id"], finding["proposed_by"], "finding.recorded",
                {"finding_id": finding["finding_id"], "status": finding["status"], "evidence_refs": evidence_refs},
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def transition_finding(self, finding_id, next_status, actor, validation_notes=None, evidence_refs=None):
        """Apply an atomic, audited lifecycle transition with evidence ownership checks."""
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("A non-empty transition actor is required")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT * FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
            if row is None:
                raise KeyError(finding_id)
            current = row["status"]
            validate_finding_transition(current, next_status)
            validator = actor.strip() if next_status in {"validated", "reported"} else row["validated_by"]
            if next_status in {"validated", "reported"} and validator == row["proposed_by"]:
                raise FindingValidationError("The proposing agent cannot validate its own finding")
            refs = json.loads(row["evidence_refs_json"]) if evidence_refs is None else evidence_refs
            self._validate_evidence_refs(row["engagement_id"], finding_id, refs)
            notes = validation_notes if validation_notes is not None else row["validation_notes"]
            candidate = {
                "finding_id": row["finding_id"], "engagement_id": row["engagement_id"],
                "title": row["title"], "status": next_status, "asset": row["asset"],
                "description": row["description"], "evidence_refs": refs,
                "proposed_by": row["proposed_by"], "validated_by": validator,
                "validation_notes": notes,
            }
            validate_finding(candidate)
            for evidence_id in refs:
                self.connection.execute(
                    "UPDATE evidence SET finding_id=? WHERE evidence_id=? AND finding_id IS NULL",
                    (finding_id, evidence_id),
                )
            self.connection.execute(
                """UPDATE findings SET status=?,validated_by=?,validation_notes=?,
                   evidence_refs_json=?,updated_at=? WHERE finding_id=?""",
                (next_status, validator, notes, json.dumps(refs), utc_now(), finding_id),
            )
            self.append_audit(
                row["engagement_id"], actor.strip(), "finding.status_changed",
                {"finding_id": finding_id, "from": current, "to": next_status, "evidence_refs": refs},
            )
            self.connection.commit()
            return next_status
        except Exception:
            self.connection.rollback()
            raise

    def audit_events(self, engagement_id):
        rows = self.connection.execute(
            """SELECT event_id,actor,event_type,details_json,created_at
               FROM audit_events WHERE engagement_id=? ORDER BY event_id""",
            (engagement_id,),
        ).fetchall()
        return [{**dict(row), "details": json.loads(row["details_json"])} for row in rows]

    def finding_evidence(self, finding_id):
        rows = self.connection.execute(
            """SELECT evidence_id,evidence_type,local_path,sha256,redacted,captured_at,captured_by
               FROM evidence WHERE finding_id=? ORDER BY captured_at,evidence_id""",
            (finding_id,),
        ).fetchall()
        return [dict(row) for row in rows]
