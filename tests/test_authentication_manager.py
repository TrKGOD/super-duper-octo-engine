import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from core.auth.manager import AuthenticationManager, AuthError, AuthPolicy
from core.auth.session_store import SessionStore
from core.auth.adapters.oauth2 import OAuth2Adapter
from core.auth.adapters.oidc import OIDCAdapter
from core.auth.adapters.browser import BrowserAuthAdapter
from scripts.migrate import migrate


class AuthenticationManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "state.sqlite3")
        migrate(self.db)
        self.key = Fernet.generate_key()
        self.store = SessionStore(self.db, self.key)
        self.engagement = "eng-auth-test"
        self.store.db.execute("""INSERT INTO engagements
          (engagement_id,authorization_reference,status,scope_json,rules_json,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?)""", (self.engagement,"SYNTHETIC-AUTH-TEST","draft","{}","{}", "now","now"))
        self.store.db.commit()
        self.manager = AuthenticationManager(self.store, self.engagement)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_api_key_session_is_opaque_and_encrypted_at_rest(self):
        self.manager.register_identity("user-a", "api_key", {"key_env": "PTF_TEST_API_KEY"})
        with patch.dict(os.environ, {"PTF_TEST_API_KEY": "synthetic-private-key"}):
            session_id = self.manager.authenticate("user-a")
        self.assertRegex(session_id, r"^sess_[a-f0-9]{32}$")
        raw = Path(self.db).read_bytes()
        self.assertNotIn(b"synthetic-private-key", raw)
        self.assertEqual(self.manager.material_for_broker(session_id, "user-a"),
                         {"X-API-Key": "synthetic-private-key"})

    def test_session_is_bound_to_engagement_and_identity(self):
        self.manager.register_identity("user-a", "api_key", {"key_env": "PTF_TEST_API_KEY"})
        with patch.dict(os.environ, {"PTF_TEST_API_KEY": "synthetic"}):
            session_id = self.manager.authenticate("user-a")
        with self.assertRaises(Exception):
            self.store.get(session_id, "another-engagement", "user-a")
        with self.assertRaises(Exception):
            self.store.get(session_id, self.engagement, "user-b")

    def test_403_is_not_treated_as_expired_session(self):
        result = self.manager.handle_response("missing", "user-a", 403, "GET")
        self.assertFalse(result["retry"])

    def test_state_changing_401_is_never_retried(self):
        result = self.manager.handle_response("missing", "user-a", 401, "POST")
        self.assertFalse(result["retry"])
        self.assertEqual(result["reason"], "state_changing_request_never_retried")

    def test_browser_challenge_pauses_for_human(self):
        adapter = BrowserAuthAdapter(runner=lambda **_: {"mfa_required": True})
        result = adapter.authenticate({}, lambda _: "unused")
        self.assertTrue(result["challenge_required"])

    def test_oauth2_refresh_uses_injected_transport_and_rotates_tokens(self):
        adapter = OAuth2Adapter()
        calls = []
        def transport(method, path, fields, purpose):
            calls.append((method, path, fields, purpose))
            return {"access_token": "new-access", "refresh_token": "new-refresh", "expires_at": 9999999999}
        material = adapter.refresh({"refresh_token": "old-refresh"},
            {"token_path": "/oauth/token", "client_id": "synthetic-client"}, lambda _: "unused", transport)
        self.assertEqual(material["access_token"], "new-access")
        self.assertEqual(material["refresh_token"], "new-refresh")
        self.assertEqual(calls[0][0:2], ("POST", "/oauth/token"))

    def test_oidc_rejects_discovery_issuer_mismatch(self):
        adapter = OIDCAdapter()
        with self.assertRaisesRegex(RuntimeError, "issuer mismatch"):
            adapter.authenticate({"issuer": "https://issuer.example", "client_id": "client",
                "token_path": "/oauth/token", "expected_nonce": "synthetic",
                "discovery_document": {"issuer": "https://attacker.example"}},
                lambda _: "unused", lambda *args, **kwargs: {})

    def test_identity_configuration_rejects_nested_literal_secrets(self):
        with self.assertRaisesRegex(Exception, "must reference environment variables"):
            self.manager.register_identity("bad", "form", {
                "login_path": "/login", "fields": {"username": "tester", "password": "literal"}})


if __name__ == "__main__":
    unittest.main()
