"""Authentication & session-security regression tests (Phase 0 close-out + revalidation).

Covers: header-injection guards that previously compared against the wrong characters,
RFC 6749 ``expires_in`` handling, refusal to serve credentials from a parked session,
vault key rotation, ciphertext binding, cross-engagement isolation, secret non-persistence
and the browser login guards.
"""
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

from core.active_executor import ActiveExecutionError, _safe_auth_headers
from core.auth.adapters.api_key import APIKeyAdapter
from core.auth.adapters.cookie import CookieSessionAdapter
from core.auth.adapters.jwt import JWTAdapter
from core.auth.manager import AuthenticationManager, AuthError, AuthState
from core.auth.playwright_runner import PlaywrightAuthRunner
from core.auth.session_store import SessionStore, SessionStoreError
from scripts.migrate import migrate


class HeaderInjectionTests(unittest.TestCase):
    EVIL_VALUES = ("abc\r\nX-Injected: 1", "abc\nX-Injected: 1", "abc\rX", "abc\x00def")

    def test_secret_adapters_reject_real_line_breaks_and_nul(self):
        for value in self.EVIL_VALUES:
            with self.assertRaises(RuntimeError, msg=repr(value)):
                APIKeyAdapter().authenticate({"key_env": "X"}, lambda _: value)
            with self.assertRaises(RuntimeError, msg=repr(value)):
                CookieSessionAdapter().authenticate({"cookie_env": "X"}, lambda _: value)
            with self.assertRaises(RuntimeError, msg=repr(value)):
                JWTAdapter().authenticate({"token_env": "X"}, lambda _: value)

    def test_ordinary_secrets_are_still_accepted(self):
        self.assertEqual(APIKeyAdapter().authenticate({"key_env": "X"}, lambda _: "k-123")["headers"],
                         {"X-API-Key": "k-123"})
        self.assertIn("Bearer abc.def.ghi",
                      JWTAdapter().authenticate({"token_env": "X"}, lambda _: "abc.def.ghi")["headers"]["Authorization"])

    def test_api_key_header_name_cannot_be_a_framing_header_or_contain_breaks(self):
        for name in ("Host", "content-length", "Transfer-Encoding", "X-A\r\nB: c", "", "a b", "X" * 200):
            with self.assertRaises(RuntimeError, msg=repr(name)):
                APIKeyAdapter().authenticate({"key_env": "X", "header_name": name}, lambda _: "k")

    def test_broker_rejects_unsafe_authentication_material(self):
        for material in ({"Host": "evil.example"}, {"Authorization": "Bearer a\r\nX: y"},
                         {"X\r\nInjected": "v"}, {"Authorization": ""}, ["not", "a", "mapping"]):
            with self.assertRaises(ActiveExecutionError, msg=repr(material)):
                _safe_auth_headers(material)
        self.assertEqual(_safe_auth_headers({"Authorization": "Bearer ok"}), {"Authorization": "Bearer ok"})


class _AuthBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "state.sqlite3")
        migrate(self.db)
        self.key = Fernet.generate_key()
        self.store = SessionStore(self.db, self.key)
        self.engagement = "eng-auth-hardening"
        self._engagement_row(self.engagement)
        self.manager = AuthenticationManager(self.store, self.engagement)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _engagement_row(self, engagement_id):
        self.store.db.execute(
            "INSERT INTO engagements(engagement_id,authorization_reference,status,scope_json,rules_json,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (engagement_id, "SYNTHETIC-AUTH-TEST", "draft", "{}", "{}", "now", "now"))
        self.store.db.commit()

    def _session(self, secret="synthetic-api-key-value", identity="user-a"):
        self.manager.register_identity(identity, "api_key", {"key_env": "PTF_TEST_API_KEY"})
        with patch.dict(os.environ, {"PTF_TEST_API_KEY": secret}):
            return self.manager.authenticate(identity)


class TokenLifetimeTests(_AuthBase):
    def test_expires_in_is_converted_to_an_absolute_expiry(self):
        before = time.time()
        expiry = AuthenticationManager._expires_at({"expires_in": 3600})
        self.assertGreaterEqual(expiry, before + 3599)
        self.assertLessEqual(expiry, time.time() + 3601)

    def test_absolute_expiry_wins_and_garbage_is_ignored(self):
        self.assertEqual(AuthenticationManager._expires_at({"expires_at": "123456.5", "expires_in": 5}), 123456.5)
        self.assertIsNone(AuthenticationManager._expires_at({"expires_in": "soon"}))
        self.assertIsNone(AuthenticationManager._expires_at({"expires_at": "never"}))
        self.assertIsNone(AuthenticationManager._expires_at({}))

    def test_a_non_positive_lifetime_is_treated_as_already_expired(self):
        self.assertLessEqual(AuthenticationManager._expires_at({"expires_in": 0}), time.time() + 1)
        self.assertLessEqual(AuthenticationManager._expires_at({"expires_in": -50}), time.time() + 1)

    def test_oauth2_session_with_only_expires_in_is_refreshed_before_use_after_it_lapses(self):
        calls = []

        def transport(method, path, fields=None, purpose=""):
            calls.append(fields["grant_type"])
            n = len(calls)
            return {"access_token": f"access-{n}", "refresh_token": f"refresh-{n}", "expires_in": 600}

        manager = AuthenticationManager(self.store, self.engagement, transport=transport)
        manager.register_identity("svc", "oauth2", {"token_path": "/oauth/token", "client_id": "client-1"})
        session = manager.authenticate("svc")
        self.assertEqual(manager.material_for_broker(session, "svc"), {"Authorization": "Bearer access-1"})
        self.assertEqual(calls, ["client_credentials"])          # fresh: no refresh yet
        with patch("core.auth.manager.time.time", return_value=time.time() + 7200):
            headers = manager.material_for_broker(session, "svc")
        self.assertEqual(headers, {"Authorization": "Bearer access-2"})
        self.assertEqual(calls, ["client_credentials", "refresh_token"])


class SessionStateEnforcementTests(_AuthBase):
    def test_parked_sessions_never_yield_credentials(self):
        session = self._session()
        for state in (AuthState.CHALLENGE_REQUIRED, AuthState.RECOVERY_FAILED,
                      AuthState.UNAUTHENTICATED, AuthState.REVOKED):
            self.store.set_state(session, self.engagement, "user-a", state.value)
            with self.assertRaisesRegex(AuthError, "not usable", msg=state.value):
                self.manager.material_for_broker(session, "user-a")

    def test_an_authenticated_session_keeps_working(self):
        session = self._session(secret="k-live-1")
        self.assertEqual(self.manager.material_for_broker(session, "user-a"), {"X-API-Key": "k-live-1"})

    def test_a_stuck_expiring_session_is_recovered_not_trusted(self):
        session = self._session(secret="k-old")
        self.store.set_state(session, self.engagement, "user-a", AuthState.EXPIRING.value)
        with patch.dict(os.environ, {"PTF_TEST_API_KEY": "k-new"}):
            headers = self.manager.material_for_broker(session, "user-a")
        self.assertEqual(headers, {"X-API-Key": "k-new"})
        self.assertEqual(self.store.get(session, self.engagement, "user-a")["state"], "AUTHENTICATED")


class SessionVaultTests(_AuthBase):
    def test_legacy_environment_variable_is_still_honoured_and_new_one_wins(self):
        legacy, preferred = Fernet.generate_key().decode(), Fernet.generate_key().decode()
        with patch.dict(os.environ, {"HACKBOT_AUTH_VAULT_KEY": legacy}, clear=False):
            os.environ.pop("WITHERHOARD_AUTH_VAULT_KEY", None)
            SessionStore(self.db).close()                       # accepted
        with patch.dict(os.environ, {"HACKBOT_AUTH_VAULT_KEY": legacy, "WITHERHOARD_AUTH_VAULT_KEY": preferred}):
            store = SessionStore(self.db)
            self.assertIsNotNone(store._cipher)
            store.close()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(SessionStoreError, "WITHERHOARD_AUTH_VAULT_KEY"):
                SessionStore(self.db)

    def test_invalid_keys_are_rejected(self):
        for bad in ("not-a-fernet-key", ",,,", b"short"):
            with self.assertRaises(SessionStoreError, msg=repr(bad)):
                SessionStore(self.db, bad)

    def test_key_rotation_reencrypts_under_the_new_primary_key(self):
        old_key = self.key.decode()
        session = self._session(secret="rotation-secret")
        new_key = Fernet.generate_key().decode()
        # step 1: new key first, old key retained -> existing rows still readable
        rotating = SessionStore(self.db, new_key + "," + old_key)
        self.assertEqual(rotating.get(session, self.engagement, "user-a")["material"]["headers"],
                         {"X-API-Key": "rotation-secret"})
        # step 2: re-encrypt everything under the new key
        self.assertEqual(rotating.rotate_keys(), 1)
        rotating.close()
        # step 3: the old key can be retired
        only_new = SessionStore(self.db, new_key)
        self.assertEqual(only_new.get(session, self.engagement, "user-a")["material"]["headers"],
                         {"X-API-Key": "rotation-secret"})
        only_new.close()
        only_old = SessionStore(self.db, old_key)
        with self.assertRaisesRegex(SessionStoreError, "integrity"):
            only_old.get(session, self.engagement, "user-a")
        only_old.close()

    def test_ciphertext_copied_to_another_engagement_cannot_be_replayed(self):
        session = self._session(secret="bound-secret")
        other = "eng-other"
        self._engagement_row(other)
        self.store.register_identity(other, "user-a", "api_key", {"key_env": "PTF_TEST_API_KEY"})
        stolen = self.store.db.execute("SELECT encrypted_material FROM auth_sessions WHERE session_id=?",
                                       (session,)).fetchone()["encrypted_material"]
        self.store.db.execute(
            "INSERT INTO auth_sessions VALUES(?,?,?,?,?,?,?,?)",
            ("sess_replayed", other, "user-a", "AUTHENTICATED", stolen, None, 1.0, 1.0))
        self.store.db.commit()
        with self.assertRaisesRegex(SessionStoreError, "binding"):
            self.store.get("sess_replayed", other, "user-a")

    def test_a_session_id_cannot_be_overwritten_from_another_engagement(self):
        session = self._session(secret="original-secret")
        other = "eng-other-2"
        self._engagement_row(other)
        self.store.register_identity(other, "user-a", "api_key", {"key_env": "PTF_TEST_API_KEY"})
        with self.assertRaisesRegex(SessionStoreError, "already bound"):
            self.store.put(session, other, "user-a", "AUTHENTICATED", {"headers": {"X-API-Key": "attacker"}})
        self.assertEqual(self.store.get(session, self.engagement, "user-a")["material"]["headers"],
                         {"X-API-Key": "original-secret"})

    def test_sessions_are_isolated_across_engagements_and_identities(self):
        session = self._session()
        self._engagement_row("eng-b")
        self.store.register_identity("eng-b", "user-a", "api_key", {"key_env": "PTF_TEST_API_KEY"})
        for args in (("eng-b", "user-a"), (self.engagement, "user-b")):
            with self.assertRaises(SessionStoreError):
                self.store.get(session, *args)
        self.assertIsNone(self.store.latest("eng-b", "user-a"))

    def test_credential_material_never_reaches_disk_or_the_audit_trail(self):
        secret = "SYNTHETIC-MARKER-" + "7f3a9c" + "-do-not-persist"      # no secret-shaped literal in the source
        audited = []
        manager = AuthenticationManager(self.store, self.engagement,
                                        audit=lambda event, details: audited.append((event, details)))
        manager.register_identity("user-a", "api_key", {"key_env": "PTF_TEST_API_KEY"})
        with patch.dict(os.environ, {"PTF_TEST_API_KEY": secret}):
            session = manager.authenticate("user-a")
        manager.material_for_broker(session, "user-a")
        manager.revoke(session, "user-a")
        self.store.db.commit()
        for suffix in ("", "-wal", "-shm"):
            path = Path(self.db + suffix)
            if path.exists():
                self.assertNotIn(secret.encode(), path.read_bytes(), "secret found in " + path.name)
        self.assertNotIn(secret, repr(audited))
        self.assertTrue(audited, "the lifecycle was not audited at all")

    def test_identity_config_with_a_literal_secret_is_refused(self):
        for config in ({"password": "hunter2"}, {"client_secret": "abc"}, {"nested": {"api_key": "k"}}):
            with self.assertRaises(SessionStoreError, msg=repr(config)):
                self.store.register_identity(self.engagement, "bad", "form", config)

    def test_expiry_purge_and_engagement_revocation(self):
        session = self._session()
        self.store.put(session, self.engagement, "user-a", "AUTHENTICATED", {"headers": {}}, expires_at=100.0)
        self.assertEqual(self.store.purge_expired(now=1000.0), 1)
        with self.assertRaises(SessionStoreError):
            self.store.get(session, self.engagement, "user-a")
        second = self._session(identity="user-c")
        self.assertEqual(self.store.revoke_engagement(self.engagement), 1)
        with self.assertRaises(SessionStoreError):
            self.store.get(second, self.engagement, "user-c")


# ----------------------------------------------------------------------------------------
# A recording fake of the Playwright surface the runner uses (no browser involved).
class _Locator:
    def __init__(self, page, selector):
        self.page, self.selector = page, selector

    def fill(self, value, timeout=None):
        if self.page.fail_on_fill:
            raise RuntimeError(self.page.fail_on_fill.format(value=value))
        self.page.filled[self.selector] = value

    def click(self, timeout=None):
        pass

    def count(self):
        return 0


class _Page:
    def __init__(self, fail_on_fill=None):
        self.fail_on_fill, self.filled, self.urls = fail_on_fill, {}, []

    def goto(self, url, **_):
        self.urls.append(url)

    def locator(self, selector):
        return _Locator(self, selector)

    def wait_for_load_state(self, *_a, **_k):
        pass


class _Context:
    def __init__(self, page, websockets=True):
        self.page, self.routes, self.ws_routes = page, [], []
        if not websockets:
            self.route_web_socket = None
            del self.route_web_socket

    def route(self, _pattern, handler):
        self.routes.append(handler)

    def new_page(self):
        return self.page

    def cookies(self, _urls):
        return [{"name": "sid", "value": "cookie-value"}]


def _with_websocket(context):
    context.route_web_socket = lambda _pattern, handler: context.ws_routes.append(handler)
    return context


class _Browser:
    def __init__(self, page):
        self.page, self.closed, self.context = page, False, None

    def new_context(self, **_):
        self.context = _with_websocket(_Context(self.page))
        return self.context

    def close(self):
        self.closed = True


class _FakePlaywright:
    def __init__(self, page):
        self.page, self.launches, self.browsers = page, [], []
        outer = self

        class Chromium:
            def launch(self, **kwargs):
                outer.launches.append(kwargs)
                browser = _Browser(outer.page)
                outer.browsers.append(browser)
                return browser
        self.chromium = Chromium()

    def __call__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


CONFIG = {"base_url": "https://app.example.test/", "login_url": "https://app.example.test/login",
          "username_env": "U", "password_env": "P", "username_selector": "#u",
          "password_selector": "#p", "submit_selector": "#go"}
SECRETS = {"U": "alice-login", "P": "hunter2-Sup3r!"}


class _FakeRoute:
    def __init__(self, url):
        self.request = type("Request", (), {"url": url})()
        self.outcome = None

    def abort(self):
        self.outcome = "abort"

    def continue_(self):
        self.outcome = "continue"


class BrowserLoginGuardTests(unittest.TestCase):
    def _run(self, page=None, scope_guard=None, config=None):
        fake = _FakePlaywright(page or _Page())
        runner = PlaywrightAuthRunner(playwright_factory=fake, scope_guard=scope_guard)
        return fake, runner, lambda: runner(config=config or CONFIG, secret_resolver=SECRETS.__getitem__)

    def test_login_works_and_the_browser_is_always_closed(self):
        fake, _runner, call = self._run()
        self.assertEqual(call(), {"session_headers": {"Cookie": "sid=cookie-value"}})
        self.assertTrue(all(b.closed for b in fake.browsers))

    def test_out_of_scope_login_origin_is_refused_before_any_browser_starts(self):
        def deny(_url):
            raise ActiveExecutionError("Target hostname/IP is not explicitly in the engagement allowlist")
        fake, _runner, call = self._run(scope_guard=deny)
        with self.assertRaises(ActiveExecutionError):
            call()
        self.assertEqual(fake.launches, [], "a browser was launched for an out-of-scope origin")

    def test_validated_address_is_pinned_inside_chromium(self):
        fake, _runner, call = self._run(scope_guard=lambda url: "203.0.113.9")
        call()
        args = fake.launches[0]["args"]
        self.assertIn("--host-resolver-rules=MAP app.example.test 203.0.113.9,MAP * ~NOTFOUND", args)
        self.assertIn("--no-proxy-server", args)

    def test_requests_and_websockets_outside_the_login_origin_are_blocked(self):
        fake, _runner, call = self._run()
        call()
        context = fake.browsers[0].context
        for url, expected in (("https://app.example.test/static/app.js", "continue"),
                              ("https://evil.example/exfil", "abort"),
                              ("http://app.example.test/downgrade", "abort"),
                              ("https://app.example.test:8443/other-port", "abort")):
            route = _FakeRoute(url)
            context.routes[0](route)
            self.assertEqual(route.outcome, expected, url)
        closed = []
        socket = type("Socket", (), {"url": "wss://evil.example/ws",
                                     "close": lambda self, **kw: closed.append(kw),
                                     "connect_to_server": lambda self: closed.append("connected")})()
        context.ws_routes[0](socket)
        self.assertEqual(closed[0]["code"], 1008)

    def test_errors_never_carry_the_credentials_and_drop_the_cause_chain(self):
        page = _Page(fail_on_fill='Timeout. Call log:\n  - fill("{value}")')
        _fake, _runner, call = self._run(page=page)
        with self.assertRaises(RuntimeError) as raised:
            call()
        message = str(raised.exception)
        for secret in SECRETS.values():
            self.assertNotIn(secret, message)
        self.assertIn("Browser authentication failed", message)
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)

    def test_login_url_must_share_the_configured_origin(self):
        bad = dict(CONFIG, login_url="https://evil.example/login")
        _fake, _runner, call = self._run(config=bad)
        with self.assertRaisesRegex(RuntimeError, "exact configured origin"):
            call()


class RotationCommandTests(_AuthBase):
    """The operator procedure documented in docs/AUTHENTICATION_MANAGER.md, driven through the real CLI."""

    def run_cli(self, key, *argv):
        import contextlib
        import io
        import json
        from scripts import auth as auth_cli
        out = io.StringIO()
        with patch.dict(os.environ, {"WITHERHOARD_AUTH_VAULT_KEY": key}), \
                patch("sys.argv", ["auth.py", "--db", self.db, *argv]), contextlib.redirect_stdout(out):
            auth_cli.main()
        return json.loads(out.getvalue())

    def test_rotate_keys_moves_every_session_to_the_new_primary_key(self):
        old_key = self.key.decode()
        first = self._session(secret="cli-rotation-1")
        new_key = Fernet.generate_key().decode()
        self.assertEqual(self.run_cli(new_key + "," + old_key, "rotate-keys"), {"sessions_re_encrypted": 1})
        only_new = SessionStore(self.db, new_key)
        try:
            self.assertEqual(only_new.get(first, self.engagement, "user-a")["material"]["headers"],
                             {"X-API-Key": "cli-rotation-1"})
        finally:
            only_new.close()

    def test_rotation_without_the_old_key_fails_closed_and_rewrites_nothing(self):
        session = self._session(secret="cli-rotation-2")
        before = self.store.db.execute("SELECT encrypted_material FROM auth_sessions").fetchone()[0]
        with self.assertRaisesRegex(SessionStoreError, "integrity"):
            self.run_cli(Fernet.generate_key().decode(), "rotate-keys")      # the old key is missing
        after = self.store.db.execute("SELECT encrypted_material FROM auth_sessions").fetchone()[0]
        self.assertEqual(before, after)
        self.assertEqual(self.store.get(session, self.engagement, "user-a")["material"]["headers"],
                         {"X-API-Key": "cli-rotation-2"})


if __name__ == "__main__":
    unittest.main()
