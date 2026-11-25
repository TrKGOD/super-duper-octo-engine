import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from cryptography.fernet import Fernet

from core.auth import AuthenticationManager, SessionStore
from core.auth.broker_transport import BrokerAuthTransport
from core.orchestration import Workflow
from scripts.migrate import migrate


class AuthLabHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        if self.path != "/login" or "username=synthetic" not in body or "password=lab-password" not in body:
            self.send_response(401)
            self.end_headers()
            return
        payload = json.dumps({"session_headers": {"Cookie": "lab_session=synthetic-session"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


class AuthenticationBrokerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "state.sqlite")
        migrate(self.db)
        self.server = HTTPServer(("127.0.0.1", 0), AuthLabHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.workflow = Workflow(self.db, project_root=self.root)
        self.workflow.initialize({
            "engagement_id": "auth-lab",
            "authorization_reference": "AUTH-LAB-SYNTHETIC-001",
            "scope": {"allowed_domains": [], "allowed_ips": ["127.0.0.1"],
                      "allowed_cidrs": [], "allowed_http_ports": [self.port],
                      "excluded_assets": [], "allowed_applications": []},
            "rules_of_engagement": {
                "execution_enabled": False, "authorization_verified": False,
                "allowed_test_classes": ["http-read-only", "authentication-http"],
                "prohibited_test_classes": ["denial-of-service", "destructive-testing"],
                "max_concurrency": 1, "requests_per_second": 2,
            },
        })
        self.workflow.approve_engagement(
            "auth-lab", "lab-operator", "AUTH-LAB-SYNTHETIC-001",
            confirm_written_authorization=True, confirm_scope=True, confirm_rules=True,
        )
        self.key = Fernet.generate_key()

    def tearDown(self):
        self.workflow.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_form_login_crosses_broker_and_persists_encrypted_session(self):
        with patch.dict(os.environ, {"HACKBOT_AUTH_VAULT_KEY": self.key.decode(),
                                     "HACKBOT_LAB_PASSWORD": "lab-password"}):
            store = SessionStore(self.db)
            try:
                manager = AuthenticationManager(store, "auth-lab")
                manager.register_identity("synthetic-user", "form", {
                    "base_url": "http://127.0.0.1:" + str(self.port) + "/",
                    "login_path": "/login",
                    "fields": {"username": "synthetic"},
                    "secret_fields": {"password": "HACKBOT_LAB_PASSWORD"},
                })
                transport = BrokerAuthTransport(
                    self.workflow, "auth-lab", ["127.0.0.1"],
                    "http://127.0.0.1:" + str(self.port) + "/",
                )
                manager.transport = transport
                session_id = manager.authenticate("synthetic-user")
                self.assertTrue(session_id.startswith("sess_"))
                self.assertEqual(
                    manager.material_for_broker(session_id, "synthetic-user"),
                    {"Cookie": "lab_session=synthetic-session"},
                )
                store.close()
                reopened = SessionStore(self.db, self.key)
                try:
                    recovered = reopened.get(session_id, "auth-lab", "synthetic-user")
                    self.assertEqual(recovered["material"]["headers"]["Cookie"],
                                     "lab_session=synthetic-session")
                finally:
                    reopened.close()
                raw = Path(self.db).read_bytes()
                self.assertNotIn(b"lab-password", raw)
                self.assertNotIn(b"synthetic-session", raw)
            finally:
                try:
                    store.close()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
