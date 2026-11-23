"""Deterministic workflow coordinator for plans, agent tasks and handoffs."""
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from core.store import StateStore, utc_now
from core.evidence import EvidenceVault, EvidenceError
from core.active_executor import _validate_request, _validate_request_scope
from core.execution_policy import validate_execution_limits

ROOT = Path(__file__).resolve().parents[1]
HANDOFF_SCHEMA = json.loads((ROOT / "templates/handoff.schema.json").read_text(encoding="utf-8"))
HANDOFF_VALIDATOR = Draft202012Validator(HANDOFF_SCHEMA, format_checker=FormatChecker())
PLAN_SCHEMA = json.loads((ROOT / "templates/plan.schema.json").read_text(encoding="utf-8"))
PLAN_VALIDATOR = Draft202012Validator(PLAN_SCHEMA, format_checker=FormatChecker())
ALLOWED_AGENTS = {
    "recon-agent", "enumeration-agent", "technology-profiler", "scope-analyst",
    "vulnerability-agent", "validation-agent", "exploitation-agent", "active-testing-agent",
    "impact-analyst", "duplicate-checker", "reporting-agent",
}


class WorkflowError(ValueError):
    """Raised when a plan or handoff violates the workflow contract."""


def _scope_assets(scope):
    keys = ("allowed_domains", "allowed_ips", "allowed_cidrs", "allowed_applications")
    return {str(value).strip() for key in keys for value in scope.get(key, []) if str(value).strip()}


def _validate_plan(plan, scope):
    errors = list(PLAN_VALIDATOR.iter_errors(plan))
    if errors:
        raise WorkflowError("Invalid plan schema: " + "; ".join(error.message for error in errors))
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
        active = task.get("active_testing", False)
        active_agents = {"active-testing-agent", "recon-agent", "enumeration-agent", "vulnerability-agent", "exploitation-agent", "validation-agent"}
        if active and task.get("agent") not in active_agents:
            raise WorkflowError("Active tasks require an allowlisted scoped assessment specialist")
        scanner_agents = {"recon-agent", "enumeration-agent", "vulnerability-agent", "active-testing-agent"}
        if active and not task.get("request_files") and task.get("agent") not in scanner_agents:
            raise WorkflowError("Active reproduction/validation tasks require pinned request manifests")
        if not active and task.get("agent") == "active-testing-agent":
            raise WorkflowError("active-testing-agent requires active_testing=true")
        if active:
            for item in task.get("request_files", []):
                path = Path(item.get("path", ""))
                if path.is_absolute() or ".." in path.parts or path.parts[:2] != (".local", "requests") or path.suffix.lower() != ".json":
                    raise WorkflowError("Active request manifests must be JSON files under .local/requests/")
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
    def __init__(self, db_path, project_root=ROOT):
        self.store = StateStore(db_path)
        self.project_root = Path(project_root).resolve()

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
        execution_mode = config.get("execution_mode", config["rules_of_engagement"].get("execution_mode", "active"))
        if execution_mode not in {"active", "passive"}:
            raise WorkflowError("execution_mode must be either active or passive")
        rules = dict(config["rules_of_engagement"])
        rules["execution_mode"] = execution_mode
        configured_window = rules.get("testing_window") or {}
        if not configured_window.get("start") and not configured_window.get("end") and config.get("testing_window"):
            rules["testing_window"] = config["testing_window"]
        self.store.create_engagement(
            engagement_id, config["authorization_reference"], config["scope"],
            rules, status="draft"
        )
        return engagement_id

    def approve_engagement(self, engagement_id, operator, authorization_reference,
                           confirm_written_authorization=False, confirm_scope=False,
                           confirm_rules=False):
        if not all((confirm_written_authorization, confirm_scope, confirm_rules)):
            raise WorkflowError("Approval requires explicit confirmation of written authorization, scope, and rules")
        if not isinstance(operator, str) or not operator.strip():
            raise WorkflowError("A named operator is required for approval")
        row = self.store.connection.execute(
            "SELECT status,authorization_reference,scope_json,rules_json FROM engagements WHERE engagement_id=?",
            (engagement_id,),
        ).fetchone()
        if row is None:
            raise WorkflowError("Unknown engagement: " + engagement_id)
        if row["status"] not in {"draft", "approved"}:
            raise WorkflowError("Only draft engagements can be approved")
        if authorization_reference != row["authorization_reference"] or not authorization_reference.strip() or "REQUIRED" in authorization_reference.upper() or "REPLACE" in authorization_reference.upper():
            raise WorkflowError("The supplied authorization reference must exactly match a real, non-placeholder reference")
        scope = json.loads(row["scope_json"])
        scope_keys = ("allowed_domains", "allowed_ips", "allowed_cidrs", "allowed_applications")
        if not any(scope.get(key) for key in scope_keys):
            raise WorkflowError("Cannot approve an engagement with an empty target allowlist")
        rules = json.loads(row["rules_json"])
        if rules.get("execution_mode", "active") != "active":
            raise WorkflowError("Active execution is disabled by this engagement's execution_mode")
        allowed_classes = set(rules.get("allowed_test_classes", []))
        if "http-read-only" not in allowed_classes:
            raise WorkflowError("Active HTTP requires http-read-only in allowed_test_classes")
        if "state-changing-http" in allowed_classes and rules.get("human_approval_required_for_state_changes") is not True:
            raise WorkflowError("State-changing HTTP must require per-request human approval")
        try:
            _, _, request_budget = validate_execution_limits(rules)
        except ValueError as exc:
            raise WorkflowError(str(exc)) from exc
        rules["max_requests_per_engagement"] = request_budget
        rules.update({
            "execution_enabled": True,
            "authorization_verified": True,
            "approved_by": operator.strip(),
            "approved_at": utc_now(),
        })
        with self.store.connection:
            self.store.connection.execute(
                "UPDATE engagements SET status='active',rules_json=?,updated_at=? WHERE engagement_id=?",
                (json.dumps(rules, sort_keys=True), utc_now(), engagement_id),
            )
            self.store.append_audit(
                engagement_id, operator.strip(), "engagement.active_approved",
                {"authorization_reference": authorization_reference, "scope_confirmed": True,
                 "rules_confirmed": True, "allowed_test_classes": sorted(allowed_classes)},
            )
        return {"engagement_id": engagement_id, "status": "active", "approved_by": operator.strip()}

    def pause_engagement(self, engagement_id, operator, reason):
        if not isinstance(operator, str) or not operator.strip() or not isinstance(reason, str) or len(reason.strip()) < 5:
            raise WorkflowError("Pausing requires a named operator and a reason")
        row = self.store.connection.execute(
            "SELECT status,rules_json FROM engagements WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        if row is None:
            raise WorkflowError("Unknown engagement: " + engagement_id)
        if row["status"] != "active":
            raise WorkflowError("Only active engagements can be paused")
        rules = json.loads(row["rules_json"])
        rules["execution_enabled"] = False
        with self.store.connection:
            self.store.connection.execute(
                "UPDATE engagements SET status='paused',rules_json=?,updated_at=? WHERE engagement_id=?",
                (json.dumps(rules, sort_keys=True), utc_now(), engagement_id),
            )
            self.store.append_audit(
                engagement_id, operator.strip(), "engagement.paused", {"reason": reason.strip()},
            )
        return {"engagement_id": engagement_id, "status": "paused"}

    def create_plan(self, engagement_id, plan):
        row = self.store.connection.execute(
            "SELECT scope_json,status,rules_json,authorization_reference FROM engagements WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        if not row:
            raise WorkflowError("Unknown engagement: " + engagement_id)
        if row["status"] not in {"draft", "approved", "active"}:
            raise WorkflowError("Engagement is not available for planning")
        tasks = _validate_plan(plan, json.loads(row["scope_json"]))
        rules = json.loads(row["rules_json"])
        active_request_ids = {
            item["request_id"] for item in self.store.connection.execute(
                "SELECT request_id FROM active_request_log WHERE engagement_id=?", (engagement_id,)
            ).fetchall()
        }
        planned_request_ids = set()
        planned_request_count = 0
        if any(task.get("active_testing") for task in tasks):
            if row["status"] != "active" or rules.get("execution_mode", "active") != "active" or rules.get("execution_enabled") is not True or rules.get("authorization_verified") is not True:
                raise WorkflowError("Active tasks require an explicitly approved active engagement")
            if not row["authorization_reference"] or "REQUIRED" in row["authorization_reference"].upper():
                raise WorkflowError("Active tasks require a non-placeholder written authorization reference")
        for task in tasks:
            if task.get("active_testing"):
                for manifest in task.get("request_files", []):
                    candidate = self.project_root / manifest["path"]
                    if candidate.is_symlink():
                        raise WorkflowError("Active request manifests must not be symlinks")
                    try:
                        resolved = candidate.resolve(strict=True)
                        requests_root = (self.project_root / ".local" / "requests").resolve(strict=True)
                    except OSError as exc:
                        raise WorkflowError("Active request manifest is missing: " + manifest["path"]) from exc
                    if self.project_root.joinpath(".local").is_symlink() or self.project_root.joinpath(".local", "requests").is_symlink() or not requests_root.is_relative_to(self.project_root) or not resolved.is_file() or not resolved.is_relative_to(requests_root) or resolved.stat().st_size > 65536:
                        raise WorkflowError("Active request manifest must be a regular file under .local/requests and at most 64 KiB")
                    raw = resolved.read_bytes()
                    if hashlib.sha256(raw).hexdigest() != manifest["sha256"]:
                        raise WorkflowError("Active request manifest SHA-256 does not match plan: " + manifest["path"])
                    try:
                        request_data = json.loads(raw)
                        if request_data["request_id"] in active_request_ids or request_data["request_id"] in planned_request_ids:
                            raise WorkflowError("Active request_id has already been used or is duplicated in this plan")
                        planned_request_ids.add(request_data["request_id"])
                        planned_request_count += 1
                        method = _validate_request(request_data)
                        allowed_classes = set(rules.get("allowed_test_classes", []))
                        if method == "POST":
                            if "state-changing-http" not in allowed_classes or rules.get("human_approval_required_for_state_changes") is not True:
                                raise WorkflowError("POST is not authorized by the engagement rules")
                        elif "http-read-only" not in allowed_classes:
                            raise WorkflowError("Read-only HTTP is not authorized by the engagement rules")
                        _validate_request_scope(request_data["url"], json.loads(row["scope_json"]), task.get("scope_subset", []))
                    except Exception as exc:
                        raise WorkflowError("Invalid or out-of-scope active request manifest " + manifest["path"] + ": " + str(exc)) from exc
        if planned_request_count:
            request_budget = rules.get("max_requests_per_engagement", 20)
            used_count = len(active_request_ids)
            if planned_request_count > request_budget - used_count:
                raise WorkflowError("Active plan exceeds the remaining engagement HTTP request budget")
        for task in tasks:
            try:
                self.store.validate_evidence_refs_for_engagement(
                    engagement_id, task.get("evidence_refs", [])
                )
            except ValueError as exc:
                raise WorkflowError(str(exc)) from exc
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
                    "constraints": task.get("constraints", ["active HTTP broker only"] if task.get("active_testing") else ["passive analysis only", "no network requests"]),
                    "domain": task.get("domain"),
                    "skill_tags": task.get("skill_tags", []),
                    "evidence_refs": task.get("evidence_refs", []),
                    "active_testing": task.get("active_testing", False),
                    "request_files": task.get("request_files", []),
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
        if task_input.get("active_testing"):
            gate = self.store.connection.execute(
                "SELECT status,rules_json FROM engagements WHERE engagement_id=?", (row["engagement_id"],)
            ).fetchone()
            active_rules = json.loads(gate["rules_json"]) if gate else {}
            if not gate or gate["status"] != "active" or active_rules.get("execution_mode", "active") != "active" or active_rules.get("execution_enabled") is not True or active_rules.get("authorization_verified") is not True:
                raise WorkflowError("Active task cannot start without a currently approved engagement")
        for dependency_key in task_input.get("depends_on", []):
            dependency = self.store.connection.execute(
                "SELECT status FROM tasks WHERE engagement_id=? AND json_extract(input_json,'$.task_key')=?",
                (row["engagement_id"], dependency_key)
            ).fetchone()
            if not dependency or dependency["status"] != "completed":
                raise WorkflowError("Dependency is not completed: " + dependency_key)
        try:
            return self.store.start_task_with_run(task_id, model=model)
        except ValueError as exc:
            raise WorkflowError(str(exc)) from exc

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
        try:
            self.store.validate_evidence_refs_for_engagement(row["engagement_id"], handoff["evidence_refs"])
        except ValueError as exc:
            raise WorkflowError(str(exc)) from exc
        evidence_vault = EvidenceVault(self.store, self.project_root)
        for evidence_id in handoff["evidence_refs"]:
            try:
                integrity = evidence_vault.verify(evidence_id)
            except (EvidenceError, OSError) as exc:
                raise WorkflowError("Evidence artifact is missing or cannot be verified: " + evidence_id) from exc
            if not integrity["valid"]:
                raise WorkflowError("Evidence SHA-256 verification failed: " + evidence_id)
        # Artifact claims are metadata, not proof. Any artifact marked collected must
        # match a registered evidence record by engagement, path and digest.
        for artifact in handoff.get("evidence_artifacts", []):
            if artifact["collection_status"] in {"collected", "redacted_copy"}:
                if artifact.get("sha256") is None:
                    raise WorkflowError("Collected evidence artifacts require a SHA-256 digest")
                row_match = self.store.connection.execute(
                    """SELECT evidence_id FROM evidence
                       WHERE engagement_id=? AND local_path=? AND sha256=?""",
                    (row["engagement_id"], artifact["path"], artifact["sha256"]),
                ).fetchone()
                if row_match is None or row_match["evidence_id"] not in handoff["evidence_refs"]:
                    raise WorkflowError("Collected artifact must match a registered evidence reference")
                try:
                    verification = EvidenceVault(self.store, self.project_root).verify(row_match["evidence_id"])
                except (EvidenceError, OSError) as exc:
                    raise WorkflowError("Collected artifact could not be integrity-verified: " + str(exc)) from exc
                if not verification["valid"]:
                    raise WorkflowError("Collected artifact SHA-256 verification failed")
        assigned_scope = set(task_input.get("scope_subset", []))
        if any(asset not in assigned_scope for asset in handoff["scope_subset"]):
            raise WorkflowError("Handoff scope exceeds task scope")
        status = "blocked" if handoff["status"] == "partial" else handoff["status"]
        try:
            self.store.accept_task_handoff(task_id, status, handoff)
        except (ValueError, KeyError) as exc:
            raise WorkflowError(str(exc)) from exc

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
