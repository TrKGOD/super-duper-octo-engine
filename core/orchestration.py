"""Deterministic workflow coordinator for plans, agent tasks and handoffs."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from core.store import StateStore

ROOT = Path(__file__).resolve().parents[1]
HANDOFF_SCHEMA = json.loads((ROOT / "templates/handoff.schema.json").read_text(encoding="utf-8"))
HANDOFF_VALIDATOR = Draft202012Validator(HANDOFF_SCHEMA, format_checker=FormatChecker())
ALLOWED_AGENTS = {
    "recon-agent", "enumeration-agent", "technology-profiler", "scope-analyst",
    "vulnerability-agent", "validation-agent", "exploitation-agent",
    "impact-analyst", "duplicate-checker", "reporting-agent",
}


class WorkflowError(ValueError):
    """Raised when a plan or handoff violates the workflow contract."""


def _scope_assets(scope):
    keys = ("allowed_domains", "allowed_ips", "allowed_cidrs", "allowed_applications")
    return {str(value).strip() for key in keys for value in scope.get(key, []) if str(value).strip()}


def _validate_plan(plan, scope):
    tasks = plan.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise WorkflowError("Plan must contain a non-empty tasks array")
    keys = set()
    allowed_scope = _scope_assets(scope)
    for task in tasks:
        key = task.get("task_key")
        if not isinstance(key, str) or not key.strip() or key in keys:
            raise WorkflowError("Every task needs a unique task_key")
        keys.add(key)
        if task.get("agent") not in ALLOWED_AGENTS:
            raise WorkflowError("Agent is not allowlisted: " + str(task.get("agent")))
        if not task.get("objective") or not task.get("completion_criteria"):
            raise WorkflowError("Task requires objective and completion_criteria: " + key)
        subset = task.get("scope_subset", [])
        if not isinstance(subset, list) or any(item not in allowed_scope for item in subset):
            raise WorkflowError("Task scope exceeds the explicit engagement allowlist: " + key)
        if task.get("active_testing", False):
            raise WorkflowError("Active-testing tasks are disabled in this runtime")
    for task in tasks:
        dependencies = task.get("depends_on", [])
        if not isinstance(dependencies, list) or any(dep not in keys or dep == task["task_key"] for dep in dependencies):
            raise WorkflowError("Invalid dependency in task: " + task["task_key"])
    remaining = {task["task_key"]: set(task.get("depends_on", [])) for task in tasks}
    completed = set()
    while remaining:
        ready = [key for key, deps in remaining.items() if deps <= completed]
        if not ready:
            raise WorkflowError("Plan contains a dependency cycle")
        for key in ready:
            completed.add(key)
            del remaining[key]
    return tasks


class Workflow:
    def __init__(self, db_path):
        self.store = StateStore(db_path)

    def close(self):
        self.store.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def initialize(self, config):
        required = ("engagement_id", "authorization_reference", "scope", "rules_of_engagement")
        missing = [key for key in required if not config.get(key)]
        if missing:
            raise WorkflowError("Missing engagement fields: " + ", ".join(missing))
        if not isinstance(config["scope"], dict) or not isinstance(config["rules_of_engagement"], dict):
            raise WorkflowError("scope and rules_of_engagement must be objects")
        if config["rules_of_engagement"].get("execution_enabled") is not False:
            raise WorkflowError("Initialize requires execution_enabled=false")
        engagement_id = config["engagement_id"]
        exists = self.store.connection.execute(
            "SELECT 1 FROM engagements WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        if exists:
            raise WorkflowError("Engagement already exists: " + engagement_id)
        self.store.create_engagement(
            engagement_id, config["authorization_reference"], config["scope"],
            config["rules_of_engagement"], status="draft"
        )
        return engagement_id

    def create_plan(self, engagement_id, plan):
        row = self.store.connection.execute(
            "SELECT scope_json,status FROM engagements WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        if not row:
            raise WorkflowError("Unknown engagement: " + engagement_id)
        if row["status"] not in {"draft", "approved", "active"}:
            raise WorkflowError("Engagement is not available for planning")
        tasks = _validate_plan(plan, json.loads(row["scope_json"]))
        existing = {
            item[0] for item in self.store.connection.execute(
                "SELECT json_extract(input_json,'$.task_key') FROM tasks WHERE engagement_id=?",
                (engagement_id,)
            )
        }
        if any(task["task_key"] in existing for task in tasks):
            raise WorkflowError("Plan contains a task_key already used by this engagement")
        created = {}
        for task in tasks:
            created[task["task_key"]] = self.store.create_task(
                engagement_id, task["agent"], {
                    "task_key": task["task_key"],
                    "objective": task["objective"],
                    "depends_on": task.get("depends_on", []),
                    "scope_subset": task.get("scope_subset", []),
                    "expected_outputs": task.get("expected_outputs", []),
                    "completion_criteria": task["completion_criteria"],
                    "constraints": task.get("constraints", ["passive analysis only", "no network requests"]),
                }
            )
        return [
            {"task_key": task["task_key"], "task_id": created[task["task_key"]], "agent": task["agent"]}
            for task in tasks
        ]

    def start_task(self, task_id, model=None):
        row = self.store.connection.execute(
            "SELECT engagement_id,agent,status,input_json FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if not row:
            raise WorkflowError("Unknown task: " + task_id)
        if row["status"] != "queued":
            raise WorkflowError("Task is not queued: " + row["status"])
        task_input = json.loads(row["input_json"])
        for dependency_key in task_input.get("depends_on", []):
            dependency = self.store.connection.execute(
                "SELECT status FROM tasks WHERE engagement_id=? AND json_extract(input_json,'$.task_key')=?",
                (row["engagement_id"], dependency_key)
            ).fetchone()
            if not dependency or dependency["status"] != "completed":
                raise WorkflowError("Dependency is not completed: " + dependency_key)
        self.store.update_task(task_id, "running")
        return self.store.start_agent_run(
            row["engagement_id"], row["agent"], model=model, task_id=task_id
        )

    def accept_handoff(self, task_id, handoff):
        errors = list(HANDOFF_VALIDATOR.iter_errors(handoff))
        if errors:
            raise WorkflowError("Invalid handoff: " + "; ".join(error.message for error in errors))
        row = self.store.connection.execute(
            "SELECT engagement_id,agent,status,input_json FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if not row:
            raise WorkflowError("Unknown task: " + task_id)
        if row["status"] != "running":
            raise WorkflowError("Only running tasks can submit handoffs")
        if (
            handoff["task_id"] != task_id
            or handoff["engagement_id"] != row["engagement_id"]
            or handoff["agent"] != row["agent"]
        ):
            raise WorkflowError("Handoff identity does not match persisted task")
        task_input = json.loads(row["input_json"])
        assigned_scope = set(task_input.get("scope_subset", []))
        if any(asset not in assigned_scope for asset in handoff["scope_subset"]):
            raise WorkflowError("Handoff scope exceeds task scope")
        status = "blocked" if handoff["status"] == "partial" else handoff["status"]
        self.store.update_task(task_id, status, handoff)
        self.store.finish_agent_run_for_task(task_id, status)

    def record_finding(self, engagement_id, finding):
        if finding.get("engagement_id") != engagement_id:
            raise WorkflowError("Finding engagement_id does not match requested engagement")
        exists = self.store.connection.execute(
            "SELECT 1 FROM engagements WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        if not exists:
            raise WorkflowError("Unknown engagement: " + engagement_id)
        self.store.record_finding(finding)

    def status(self, engagement_id):
        engagement = self.store.connection.execute(
            "SELECT engagement_id,status FROM engagements WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        if not engagement:
            raise WorkflowError("Unknown engagement: " + engagement_id)
        rows = self.store.connection.execute(
            "SELECT task_id,agent,status,input_json FROM tasks WHERE engagement_id=? ORDER BY rowid",
            (engagement_id,)
        ).fetchall()
        tasks = []
        for row in rows:
            data = json.loads(row["input_json"])
            tasks.append({
                "task_id": row["task_id"], "task_key": data.get("task_key"),
                "agent": row["agent"], "status": row["status"], "objective": data.get("objective")
            })
        return {"engagement_id": engagement["engagement_id"], "status": engagement["status"], "tasks": tasks}
