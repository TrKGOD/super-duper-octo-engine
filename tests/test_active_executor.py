import hashlib
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from core.active_executor import ActiveExecutionError, ActiveHTTPExecutor, _validate_request
from core.orchestration import Workflow, WorkflowError
from scripts.migrate import migrate


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.org/out-of-scope")
            self.end_headers()
            return
        body = b'{"ok":true,"token":"synthetic-secret"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = b'{"created":true}'
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class ActiveHTTPExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / ".local" / "state.sqlite3")
        Path(self.db).parent.mkdir(parents=True)
        migrate(self.db)
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.workflow = Workflow(self.db, project_root=self.root)
        self.engagement_id = "eng-active-test"
        self._initialize()

    def tearDown(self):
        self.workflow.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def _initialize(self, allowed_classes=None, allowed_domains=None, allowed_ips=None):
        self.workflow.initialize({
            "engagement_id": self.engagement_id,
            "authorization_reference": "AUTH-LAB-LOCAL-001",
            "scope": {
                "allowed_domains": allowed_domains or [],
                "allowed_ips": allowed_ips if allowed_ips is not None else ["127.0.0.1"],
                "allowed_cidrs": [],
                "allowed_http_ports": [self.port],
                "excluded_assets": [],
                "allowed_applications": [],
            },
            "rules_of_engagement": {
                "execution_enabled": False,
                "authorization_verified": False,
                "allowed_test_classes": allowed_classes or ["http-read-only", "state-changing-http"],
                "prohibited_test_classes": ["denial-of-service", "destructive-testing", "persistence"],
                "max_concurrency": 1,
                "requests_per_second": 1,
                "human_approval_required_for_state_changes": True,
            },
        })

    def _request(self, request_id="req-local-001", path="/", method="GET", **extra):
        request = {
            "request_id": request_id,
            "method": method,
            "url": f"http://127.0.0.1:{self.port}{path}",
            "purpose": "Verify the authorized local HTTP test endpoint",
            "timeout_seconds": 3,
            "max_response_bytes": 8192,
            "follow_redirects": True,
        }
        request.update(extra)
        return request

    def _plan_and_start(self, request, scope_subset=None):
        requests_dir = self.root / ".local" / "requests"
        requests_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = requests_dir / (request["request_id"] + ".json")
        raw = json.dumps(request, sort_keys=True).encode()
        manifest_path.write_bytes(raw)
        relative = ".local/requests/" + manifest_path.name
        created = self.workflow.create_plan(self.engagement_id, {"tasks": [{
            "task_key": "active-http-check",
            "agent": "active-testing-agent",
            "objective": "Execute the operator-reviewed local HTTP manifest",
            "completion_criteria": ["Capture authentic HTTP evidence and return a handoff"],
            "scope_subset": scope_subset or ["127.0.0.1"],
            "domain": "web",
            "active_testing": True,
            "request_files": [{
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }],
        }]})
        task_id = created[0]["task_id"]
        self.workflow.start_task(task_id, model="test-model")
        return task_id, relative

    def _approve(self):
        return self.workflow.approve_engagement(
            self.engagement_id,
            "local-test-operator",
            "AUTH-LAB-LOCAL-001",
            confirm_written_authorization=True,
            confirm_scope=True,
            confirm_rules=True,
        )

    def test_active_execution_requires_explicit_operator_approval(self):
        request = self._request()
        requests_dir = self.root / ".local" / "requests"
        requests_dir.mkdir(parents=True, exist_ok=True)
        path = requests_dir / "req-local-001.json"
        raw = json.dumps(request, sort_keys=True).encode()
        path.write_bytes(raw)
        with self.assertRaisesRegex(WorkflowError, "approved active engagement"):
            self.workflow.create_plan(self.engagement_id, {"tasks": [{
                "task_key": "active-http-check", "agent": "active-testing-agent",
                "objective": "Run a request", "completion_criteria": ["Evidence"],
                "scope_subset": ["127.0.0.1"], "active_testing": True,
                "request_files": [{"path": ".local/requests/req-local-001.json",
                                   "sha256": hashlib.sha256(raw).hexdigest()}],
            }]})

    def test_approval_requires_all_three_operator_attestations(self):
        with self.assertRaisesRegex(WorkflowError, "explicit confirmation"):
            self.workflow.approve_engagement(
                self.engagement_id, "operator", "AUTH-LAB-LOCAL-001",
                confirm_written_authorization=True, confirm_scope=False, confirm_rules=True,
            )

    def test_executes_only_pinned_in_scope_request_and_captures_evidence(self):
        self._approve()
        task_id, manifest = self._plan_and_start(self._request())
        result = ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
            self.engagement_id, task_id, manifest
        )
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(len(result["evidence_refs"]), 2)
        self.assertNotIn("synthetic-secret", result["response_excerpt"])
        for evidence_id in result["evidence_refs"]:
            self.assertTrue(ActiveHTTPExecutor(self.workflow, self.root).vault.verify(evidence_id)["valid"])
        log = self.workflow.store.connection.execute(
            "SELECT outcome,status_code FROM active_request_log WHERE request_id='req-local-001'"
        ).fetchone()
        self.assertEqual((log["outcome"], log["status_code"]), ("completed", 200))

    def test_secret_headers_are_loaded_from_environment_and_redacted_in_evidence(self):
        self._approve()
        request = self._request(secret_headers={"Authorization": "PTF_LOCAL_TEST_AUTH"})
        task_id, manifest = self._plan_and_start(request)
        with patch.dict(os.environ, {"PTF_LOCAL_TEST_AUTH": "Bearer synthetic-private-token"}):
            result = ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement_id, task_id, manifest
            )
        request_evidence = ActiveHTTPExecutor(self.workflow, self.root).vault.read(result["evidence_refs"][0])
        self.assertNotIn(b"synthetic-private-token", request_evidence)
        self.assertIn(b"[REDACTED]", request_evidence)

    def test_sensitive_headers_cannot_be_stored_as_plaintext(self):
        request = self._request(headers={"Authorization": "Bearer literal-secret"})
        with self.assertRaisesRegex(ActiveExecutionError, "must not be stored as plaintext"):
            _validate_request(request)

    def test_request_manifest_tampering_is_rejected(self):
        self._approve()
        task_id, manifest = self._plan_and_start(self._request())
        path = self.root / manifest
        path.write_text(path.read_text() + " ", encoding="utf-8")
        with self.assertRaisesRegex(ActiveExecutionError, "changed after the plan"):
            ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement_id, task_id, manifest
            )

    def test_out_of_scope_redirect_is_blocked_before_following(self):
        self._approve()
        task_id, manifest = self._plan_and_start(self._request(path="/redirect"))
        with self.assertRaisesRegex(ActiveExecutionError, "not explicitly in the engagement allowlist"):
            ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement_id, task_id, manifest
            )

    def test_private_dns_answer_requires_explicit_ip_scope(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET scope_json=? WHERE engagement_id=?",
            (json.dumps({
                "allowed_domains": ["localhost"], "allowed_ips": [], "allowed_cidrs": [],
                "allowed_http_ports": [self.port], "excluded_assets": [], "allowed_applications": [],
            }), self.engagement_id),
        )
        self.workflow.store.connection.commit()
        self._approve()
        request = self._request()
        request["url"] = f"http://localhost:{self.port}/"
        task_id, manifest = self._plan_and_start(request, scope_subset=["localhost"])
        with self.assertRaisesRegex(ActiveExecutionError, "non-public IP"):
            ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement_id, task_id, manifest
            )

    def test_post_requires_timestamped_operator_approval(self):
        request = self._request(method="POST", body="name=synthetic")
        with self.assertRaisesRegex(ActiveExecutionError, "explicit operator approval"):
            _validate_request(request)

    def test_post_requires_engagement_state_changing_class(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET rules_json=? WHERE engagement_id=?",
            (json.dumps({
                "execution_enabled": False, "authorization_verified": False,
                "allowed_test_classes": ["http-read-only"],
                "prohibited_test_classes": ["denial-of-service"],
                "max_concurrency": 1, "requests_per_second": 1,
                "human_approval_required_for_state_changes": True,
            }), self.engagement_id),
        )
        self.workflow.store.connection.commit()
        self._approve()
        request = self._request(
            method="POST", body="name=synthetic",
            operator_approval={
                "approved": True, "approved_by": "operator",
                "approved_at": datetime.now(timezone.utc).isoformat(),
                "reason": "Approved one synthetic account creation request",
            },
        )
        task_id, manifest = self._plan_and_start(request)
        with self.assertRaisesRegex(ActiveExecutionError, "not authorized by engagement rules"):
            ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement_id, task_id, manifest
            )

    def test_task_scope_subset_is_enforced_in_addition_to_engagement_scope(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET scope_json=? WHERE engagement_id=?",
            (json.dumps({
                "allowed_domains": [], "allowed_ips": ["127.0.0.1", "192.0.2.10"],
                "allowed_cidrs": [], "allowed_http_ports": [self.port],
                "excluded_assets": [], "allowed_applications": [],
            }), self.engagement_id),
        )
        self.workflow.store.connection.commit()
        self._approve()
        task_id, manifest = self._plan_and_start(self._request(), scope_subset=["192.0.2.10"])
        with self.assertRaisesRegex(ActiveExecutionError, "outside this task"):
            ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement_id, task_id, manifest
            )

    def test_operator_approved_post_executes_when_engagement_allows_it(self):
        self._approve()
        request = self._request(
            method="POST", body="name=synthetic",
            operator_approval={
                "approved": True, "approved_by": "local-test-operator",
                "approved_at": datetime.now(timezone.utc).isoformat(),
                "reason": "Approved one synthetic local test POST request",
            },
        )
        task_id, manifest = self._plan_and_start(request)
        result = ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
            self.engagement_id, task_id, manifest
        )
        self.assertEqual(result["status_code"], 201)
        self.assertEqual(len(result["evidence_refs"]), 2)

    def test_pause_killswitch_blocks_new_requests(self):
        self._approve()
        task_id, manifest = self._plan_and_start(self._request())
        self.workflow.pause_engagement(self.engagement_id, "operator", "Stop active testing")
        with self.assertRaisesRegex(ActiveExecutionError, "not explicitly approved"):
            ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement_id, task_id, manifest
            )

    def test_request_id_cannot_be_replayed(self):
        self._approve()
        task_id, manifest = self._plan_and_start(self._request())
        executor = ActiveHTTPExecutor(self.workflow, self.root)
        executor.execute_request_file(self.engagement_id, task_id, manifest)
        with self.assertRaisesRegex(ActiveExecutionError, "already been executed"):
            executor.execute_request_file(self.engagement_id, task_id, manifest)


if __name__ == "__main__":
    unittest.main()
