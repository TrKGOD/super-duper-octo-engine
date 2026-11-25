import hashlib
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from cryptography.fernet import Fernet

from core.active_executor import ActiveHTTPExecutor
from core.auth import AuthenticationManager, SessionStore
from core.orchestration import Workflow
from scripts.migrate import migrate


class AuthenticatedTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen_authorization = self.headers.get("Authorization")
        body = b'{"authenticated":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class AuthenticatedBrokerEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / ".local" / "state.sqlite")
        (self.root / ".local" / "requests").mkdir(parents=True)
        migrate(self.db)
        self.server = HTTPServer(("127.0.0.1", 0), AuthenticatedTargetHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.workflow = Workflow(self.db, project_root=self.root)
        self.engagement = "auth-executor-lab"
        self.workflow.initialize({
            "engagement_id": self.engagement,
            "authorization_reference": "AUTH-EXECUTOR-LAB-001",
            "scope": {"allowed_domains": [], "allowed_ips": ["127.0.0.1"],
                      "allowed_cidrs": [], "allowed_http_ports": [self.port],
                      "excluded_assets": [], "allowed_applications": []},
            "rules_of_engagement": {
                "execution_enabled": False, "authorization_verified": False,
                "allowed_test_classes": ["http-read-only", "authentication-http"],
                "prohibited_test_classes": ["denial-of-service"],
                "max_concurrency": 1, "requests_per_second": 5,
            },
        })
        self.workflow.approve_engagement(
            self.engagement, "lab-operator", "AUTH-EXECUTOR-LAB-001",
            confirm_written_authorization=True, confirm_scope=True, confirm_rules=True,
        )
        self.key = Fernet.generate_key()

    def tearDown(self):
        self.workflow.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_plan_identity_reaches_local_target_only_through_broker(self):
        with patch.dict(os.environ, {"HACKBOT_AUTH_VAULT_KEY": self.key.decode(),
                                     "HACKBOT_TEST_API_KEY": "synthetic-api-key"}):
            store = SessionStore(self.db)
            manager = AuthenticationManager(store, self.engagement)
            manager.register_identity("tester", "api_key", {"key_env": "HACKBOT_TEST_API_KEY"})
            session_id = manager.authenticate("tester")
            store.close()

            request = {
                "request_id": "auth-e2e-001", "method": "GET",
                "url": "http://127.0.0.1:" + str(self.port) + "/private",
                "purpose": "Verify synthetic authenticated broker request",
                "timeout_seconds": 3, "max_response_bytes": 8192,
                "follow_redirects": False,
            }
            manifest_path = self.root / ".local" / "requests" / "auth-e2e.json"
            raw = json.dumps(request, sort_keys=True).encode()
            manifest_path.write_bytes(raw)
            plan = {"tasks": [{
                "task_key": "authenticated-read", "agent": "recon-agent",
                "objective": "Read the synthetic authenticated endpoint",
                "completion_criteria": ["Receive authenticated lab response"],
                "domain": "web", "skill_tags": ["authenticated-testing"],
                "active_testing": True, "scope_subset": ["127.0.0.1"],
                "request_files": [{"path": ".local/requests/auth-e2e.json",
                                   "sha256": hashlib.sha256(raw).hexdigest()}],
                "auth_identity_id": "tester", "auth_session_id": session_id,
                "authorized_identity_ids": ["tester"],
            }]}
            created = self.workflow.create_plan(self.engagement, plan)
            task_id = created[0]["task_id"]
            self.workflow.start_task(task_id)
            result = ActiveHTTPExecutor(self.workflow, self.root).execute_request_file(
                self.engagement, task_id, ".local/requests/auth-e2e.json"
            )
            self.assertEqual(result["status_code"], 200)
            self.assertEqual(self.server.seen_authorization, "Bearer synthetic-api-key")
            self.assertEqual(len(result["evidence_refs"]), 2)


if __name__ == "__main__":
    unittest.main()
