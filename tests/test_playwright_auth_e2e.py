import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from core.auth.playwright_runner import PlaywrightAuthRunner
from tests.support import require_browser_or_skip


class BrowserLabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/login":
            body = b'<form method="post"><input name="user"><input name="pass" type="password"><button id="go">Login</button></form>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"authenticated"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        values = parse_qs(self.rfile.read(length).decode())
        if values.get("user") != ["synthetic"] or values.get("pass") != ["lab-password"]:
            self.send_response(401)
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("Set-Cookie", "lab_session=browser-synthetic; HttpOnly; SameSite=Lax")
        self.send_header("Location", "/home")
        self.end_headers()

    def log_message(self, *_):
        pass


class PlaywrightAuthenticationE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The pip package can be installed without a browser binary, so probe a real launch: skip where there
        # is none, fail where WITHERHOARD_REQUIRE_BROWSER=1 says there must be one (the CI `test` job).
        require_browser_or_skip()
        cls.server = HTTPServer(("127.0.0.1", 0), BrowserLabHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=2)

    def test_browser_runner_performs_local_form_login_and_returns_scoped_cookie(self):
        base = "http://127.0.0.1:" + str(self.port) + "/"
        result = PlaywrightAuthRunner()(
            config={
                "base_url": base, "login_url": base + "login",
                "username_env": "LAB_USER", "password_env": "LAB_PASSWORD",
                "username_selector": 'input[name="user"]',
                "password_selector": 'input[name="pass"]',
                "submit_selector": "#go",
            },
            secret_resolver=lambda name: {"LAB_USER": "synthetic", "LAB_PASSWORD": "lab-password"}[name],
        )
        self.assertIn("Cookie", result["session_headers"])
        self.assertIn("lab_session=browser-synthetic", result["session_headers"]["Cookie"])


if __name__ == "__main__":
    unittest.main()
