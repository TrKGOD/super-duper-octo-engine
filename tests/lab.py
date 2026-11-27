"""Local laboratory harness shared by the broker-hardening and pipeline tests.

A ``LabEngagement`` is a throw-away project root with a migrated state database, an
*approved active* engagement scoped to one loopback HTTP server, and helpers to pin request
manifests and start broker-bound tasks exactly the way production does (``Workflow.create_plan``
→ ``start_task`` → ``ActiveHTTPExecutor``). Nothing here touches an external network.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from core.active_executor import ActiveHTTPExecutor
from core.orchestration import Workflow
from scripts.migrate import migrate

DEFAULT_CLASSES = ["http-read-only"]


class LabServer:
    """A loopback HTTP server running ``handler_class`` on an ephemeral port."""

    def __init__(self, handler_class):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)


class LabEngagement:
    def __init__(self, handler_class, *, engagement_id: str = "eng-lab", allowed_classes=None,
                 extra_rules: dict | None = None, extra_scope: dict | None = None,
                 identities: list | None = None):
        self.engagement_id = engagement_id
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.db = str(self.root / ".local" / "state.sqlite3")
        Path(self.db).parent.mkdir(parents=True)
        migrate(self.db)
        self.server = LabServer(handler_class)
        self.workflow = Workflow(self.db, project_root=self.root)
        self._allowed_classes = list(allowed_classes or DEFAULT_CLASSES)
        self._extra_rules = dict(extra_rules or {})
        self._extra_scope = dict(extra_scope or {})
        self._identities = list(identities or [])
        self._task_counter = 0
        self.executor = None

    # -- lifecycle --------------------------------------------------------------------
    def open(self, *, approve: bool = True) -> "LabEngagement":
        self.server.start()
        scope = {"allowed_domains": [], "allowed_ips": ["127.0.0.1"], "allowed_cidrs": [],
                 "allowed_http_ports": [self.server.port], "excluded_assets": [],
                 "allowed_applications": []}
        scope.update(self._extra_scope)
        rules = {"execution_enabled": False, "authorization_verified": False,
                 "allowed_test_classes": self._allowed_classes,
                 "prohibited_test_classes": ["denial-of-service", "destructive-testing", "persistence"],
                 "max_concurrency": 1, "requests_per_second": 5,
                 "human_approval_required_for_state_changes": True,
                 "authorized_identity_ids": self._identities}
        rules.update(self._extra_rules)
        self.workflow.initialize({
            "engagement_id": self.engagement_id, "authorization_reference": "AUTH-LAB-LOCAL-001",
            "scope": scope, "rules_of_engagement": rules})
        if approve:
            self.workflow.approve_engagement(
                self.engagement_id, "lab-operator", "AUTH-LAB-LOCAL-001",
                confirm_written_authorization=True, confirm_scope=True, confirm_rules=True)
        self.executor = ActiveHTTPExecutor(self.workflow, self.root)
        return self

    def close(self):
        try:
            self.workflow.close()
        finally:
            self.server.stop()
            self._tmp.cleanup()

    # -- request helpers --------------------------------------------------------------
    def manifest(self, request_id: str, path: str = "/", method: str = "GET", **extra) -> dict:
        request = {"request_id": request_id, "method": method, "url": self.server.origin + path,
                   "purpose": "Authorized lab request against the local synthetic target",
                   "timeout_seconds": 3, "max_response_bytes": 65536, "follow_redirects": True}
        request.update(extra)
        return request

    def pin(self, request: dict) -> dict:
        requests_dir = self.root / ".local" / "requests"
        requests_dir.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(request, sort_keys=True).encode()
        file_path = requests_dir / (request["request_id"] + ".json")
        file_path.write_bytes(raw)
        return {"path": ".local/requests/" + file_path.name, "sha256": hashlib.sha256(raw).hexdigest()}

    def start_task(self, requests: list, *, agent: str = "active-testing-agent",
                   skill_tags=("http-read-only",), **task_extra) -> tuple:
        """Pin ``requests``, create an active task for them and start it. Returns
        ``(task_id, [relative manifest paths])``."""
        self._task_counter += 1
        pinned = [self.pin(r) for r in requests]
        task = {"task_key": f"lab-task-{self._task_counter}", "agent": agent,
                "objective": "Execute the pinned lab requests", "completion_criteria": ["Evidence"],
                "scope_subset": ["127.0.0.1"], "domain": "web", "skill_tags": list(skill_tags),
                "active_testing": True, "request_files": pinned}
        task.update(task_extra)
        created = self.workflow.create_plan(self.engagement_id, {"tasks": [task]})
        task_id = created[0]["task_id"]
        self.workflow.start_task(task_id, model="lab-model")
        return task_id, [item["path"] for item in pinned]

    def run(self, request: dict, *, agent: str = "active-testing-agent", **task_extra) -> dict:
        task_id, paths = self.start_task([request], agent=agent, **task_extra)
        return self.executor.execute_request_file(self.engagement_id, task_id, paths[0])
