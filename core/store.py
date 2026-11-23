"""SQLite state store for engagements, tasks, agent runs, findings and audit events."""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from core.validation import validate_finding, validate_finding_transition, FindingValidationError

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")

def new_id(prefix):
    return prefix + "_" + uuid.uuid4().hex

class StateStore:
    def __init__(self,db_path):
        self.connection=sqlite3.connect(str(db_path))
        self.connection.row_factory=sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
    def close(self): self.connection.close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()
    def append_audit(self,engagement_id,actor,event_type,details):
        self.connection.execute("INSERT INTO audit_events(engagement_id,actor,event_type,details_json,created_at) VALUES(?,?,?,?,?)",(engagement_id,actor,event_type,json.dumps(details,sort_keys=True),utc_now()))
    def create_engagement(self,engagement_id,authorization_reference,scope,rules,status="draft"):
        now=utc_now()
        with self.connection:
            self.connection.execute("INSERT INTO engagements VALUES(?,?,?,?,?,?,?)",(engagement_id,authorization_reference,status,json.dumps(scope),json.dumps(rules),now,now))
            self.append_audit(engagement_id,"operator","engagement.created",{"status":status})
    def create_task(self,engagement_id,agent,input_data):
        task_id=new_id("task")
        with self.connection:
            self.connection.execute("INSERT INTO tasks(task_id,engagement_id,agent,status,input_json) VALUES(?,?,?,'queued',?)",(task_id,engagement_id,agent,json.dumps(input_data)))
            self.append_audit(engagement_id,agent,"task.created",{"task_id":task_id,"task_key":input_data.get("task_key")})
        return task_id
    def update_task(self,task_id,status,output_data=None):
        transitions={"queued":{"running","blocked","needs_operator","failed"},"running":{"completed","blocked","needs_operator","failed"},"blocked":{"queued"},"needs_operator":{"queued"},"failed":{"queued"},"completed":set()}
        row=self.connection.execute("SELECT engagement_id,agent,status FROM tasks WHERE task_id=?",(task_id,)).fetchone()
        if row is None: raise KeyError(task_id)
        if status not in transitions or (status!=row["status"] and status not in transitions[row["status"]]):
            raise ValueError("Invalid task status transition: "+row["status"]+" -> "+status)
        now=utc_now()
        with self.connection:
            self.connection.execute("UPDATE tasks SET status=?,output_json=?,started_at=CASE WHEN ?='running' AND started_at IS NULL THEN ? ELSE started_at END,completed_at=? WHERE task_id=?",(status,json.dumps(output_data) if output_data is not None else None,status,now,now if status in {"completed","blocked","needs_operator","failed"} else None,task_id))
            self.append_audit(row["engagement_id"],row["agent"],"task.status_changed",{"task_id":task_id,"from":row["status"],"to":status})
    def start_agent_run(self,engagement_id,agent,model=None,task_id=None):
        run_id,now=new_id("run"),utc_now()
        with self.connection:
            self.connection.execute("INSERT INTO agent_runs(run_id,engagement_id,agent,model,status,started_at,task_id) VALUES(?,?,?,?,'running',?,?)",(run_id,engagement_id,agent,model,now,task_id))
            self.append_audit(engagement_id,agent,"agent_run.started",{"run_id":run_id,"model":model,"task_id":task_id})
        return run_id
    def finish_agent_run(self,run_id,status,input_tokens=None,output_tokens=None,cost_usd=None):
        if status not in {"completed","failed","blocked","needs_operator"}: raise ValueError("Unsupported agent run status")
        row=self.connection.execute("SELECT engagement_id,agent,status FROM agent_runs WHERE run_id=?",(run_id,)).fetchone()
        if row is None: raise KeyError(run_id)
        if row["status"]!="running": raise ValueError("Only running agent runs can be finished")
        with self.connection:
            self.connection.execute("UPDATE agent_runs SET status=?,input_tokens=?,output_tokens=?,cost_usd=?,completed_at=? WHERE run_id=?",(status,input_tokens,output_tokens,cost_usd,utc_now(),run_id))
            self.append_audit(row["engagement_id"],row["agent"],"agent_run.finished",{"run_id":run_id,"status":status})
    def finish_agent_run_for_task(self,task_id,status):
        row=self.connection.execute("SELECT run_id FROM agent_runs WHERE task_id=? AND status='running' ORDER BY started_at DESC LIMIT 1",(task_id,)).fetchone()
        if row is None: raise ValueError("No running agent run exists for task: "+task_id)
        self.finish_agent_run(row["run_id"],status)
    def record_finding(self,finding):
        validate_finding(finding); now=utc_now()
        with self.connection:
            self.connection.execute("""INSERT INTO findings (finding_id,engagement_id,title,status,severity,asset,method,parameter,description,impact,evidence_refs_json,proposed_by,validated_by,created_at,updated_at,preconditions_json,validation_notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(finding["finding_id"],finding["engagement_id"],finding["title"],finding["status"],finding.get("severity","unknown"),finding["asset"],finding.get("method"),finding.get("parameter"),finding["description"],finding.get("impact"),json.dumps(finding.get("evidence_refs",[])),finding["proposed_by"],finding.get("validated_by"),now,now,json.dumps(finding.get("preconditions",[])),finding.get("validation_notes")))
            self.append_audit(finding["engagement_id"],finding["proposed_by"],"finding.recorded",{"finding_id":finding["finding_id"],"status":finding["status"]})
    def audit_events(self,engagement_id):
        rows=self.connection.execute("SELECT event_id,actor,event_type,details_json,created_at FROM audit_events WHERE engagement_id=? ORDER BY event_id",(engagement_id,)).fetchall()
        return [{**dict(r),"details":json.loads(r["details_json"])} for r in rows]


    def transition_finding(self, finding_id, next_status, actor, validation_notes=None, evidence_refs=None):
        """Apply an audited, independently validated finding lifecycle transition."""
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("A non-empty transition actor is required")
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
        notes = validation_notes if validation_notes is not None else row["validation_notes"]
        candidate = {
            "finding_id": row["finding_id"], "engagement_id": row["engagement_id"],
            "title": row["title"], "status": next_status, "asset": row["asset"],
            "description": row["description"], "evidence_refs": refs,
            "proposed_by": row["proposed_by"], "validated_by": validator,
            "validation_notes": notes,
        }
        validate_finding(candidate)
        now = utc_now()
        with self.connection:
            self.connection.execute(
                """UPDATE findings SET status=?,validated_by=?,validation_notes=?,
                   evidence_refs_json=?,updated_at=? WHERE finding_id=?""",
                (next_status, validator, notes, json.dumps(refs), now, finding_id)
            )
            self.append_audit(
                row["engagement_id"], actor.strip(), "finding.status_changed",
                {"finding_id": finding_id, "from": current, "to": next_status}
            )
        return next_status
