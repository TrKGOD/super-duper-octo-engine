import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from core.orchestration import Workflow
from scripts.migrate import migrate

from scripts.active_surface import (
    SurfaceParser,
    _analyse_js,
    _canonical,
    _safe_path_url,
    _same_origin,
)


class ActiveSurfaceTests(unittest.TestCase):
    def test_extracts_same_origin_links_scripts_and_form_parameters(self):
        parser = SurfaceParser()
        parser.feed("""
            <a href="/account">Account</a>
            <script src="/assets/app.js"></script>
            <form action="/search" method="GET">
              <input name="q"><input name="category">
            </form>
            <img src="/ignored.png">
        """)
        self.assertEqual(parser.links, ["/account"])
        self.assertEqual(parser.scripts, ["/assets/app.js"])
        self.assertEqual(parser.forms[0]["fields"], ["q", "category"])

    def test_same_origin_filter_rejects_external_and_non_http_links(self):
        base = "https://app.example.test/"
        self.assertEqual(_safe_path_url(base, "/api/users"), "https://app.example.test/api/users")
        self.assertIsNone(_safe_path_url(base, "https://outside.example/"))
        self.assertIsNone(_safe_path_url(base, "javascript:alert(1)"))
        self.assertIsNone(_safe_path_url(base, "/logout"))
        self.assertTrue(_same_origin(base, "https://app.example.test/next"))
        self.assertFalse(_same_origin(base, "http://app.example.test/"))

    def test_static_javascript_analysis_finds_routes_and_sinks_without_execution(self):
        source = """
          fetch('/api/v2/profile');
          const endpoint = '/graphql';
          element.innerHTML = userInput;
          eval(payload);
          window.postMessage(message, '*');
        """
        routes, indicators = _analyse_js(source)
        self.assertIn("/api/v2/profile", routes)
        self.assertIn("/graphql", routes)
        self.assertIn("dom-xss-sink", {item["type"] for item in indicators})
        self.assertIn("dynamic-code-execution", {item["type"] for item in indicators})
        self.assertIn("postmessage-wildcard", {item["type"] for item in indicators})

    def test_canonicalization_drops_fragments_and_normalizes_origin(self):
        self.assertEqual(
            _canonical("HTTPS://APP.EXAMPLE.TEST/path#fragment"),
            "https://app.example.test/path",
        )



class ActiveSurfaceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / ".local" / "state.sqlite3")
        Path(self.db).parent.mkdir(parents=True)
        migrate(self.db)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(inner):
                if inner.path == "/assets/app.js":
                    body = b"fetch('/api/v2/users'); element.innerHTML = inputValue;"
                    content_type = "application/javascript"
                elif inner.path == "/account":
                    body = b"<html><body>Public account landing</body></html>"
                    content_type = "text/html"
                else:
                    body = b"""<html><body>
                      <a href='/account'>Account</a>
                      <a href='/api/users?token=do-not-replay'>API</a>
                      <script src='/assets/app.js'></script>
                      <form action='/search' method='GET'><input name='q'></form>
                    </body></html>"""
                    content_type = "text/html"
                inner.send_response(200)
                inner.send_header("Content-Type", content_type)
                inner.send_header("Set-Cookie", "sid=synthetic; Path=/")
                origin = inner.headers.get("Origin")
                if origin:
                    inner.send_header("Access-Control-Allow-Origin", origin)
                    inner.send_header("Access-Control-Allow-Credentials", "true")
                inner.send_header("Content-Length", str(len(body)))
                inner.end_headers()
                inner.wfile.write(body)

            def do_OPTIONS(inner):
                body = b""
                inner.send_response(204)
                inner.send_header("Allow", "GET, HEAD, OPTIONS")
                inner.send_header("Content-Length", "0")
                inner.end_headers()

            def log_message(inner, *_):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.workflow = Workflow(self.db, project_root=self.root)
        self.workflow.initialize({
            "engagement_id": "eng-surface-lab",
            "authorization_reference": "AUTH-SYNTHETIC-SURFACE-LAB",
            "scope": {
                "allowed_domains": [],
                "allowed_ips": ["127.0.0.1"],
                "allowed_cidrs": [],
                "allowed_http_ports": [self.port],
                "excluded_assets": [],
                "allowed_applications": [],
            },
            "rules_of_engagement": {
                "execution_enabled": False,
                "authorization_verified": False,
                "allowed_test_classes": ["http-read-only"],
                "max_concurrency": 1,
                "requests_per_second": 1,
                "max_requests_per_engagement": 20,
            },
        })
        self.workflow.approve_engagement(
            "eng-surface-lab", "synthetic-operator", "AUTH-SYNTHETIC-SURFACE-LAB",
            confirm_written_authorization=True, confirm_scope=True, confirm_rules=True,
        )
        created = self.workflow.create_plan("eng-surface-lab", {"tasks": [{
            "task_key": "recon-lab",
            "agent": "recon-agent",
            "objective": "Discover a synthetic local web surface",
            "completion_criteria": ["Capture broker evidence and map the local test app"],
            "scope_subset": ["127.0.0.1"],
            "domain": "web",
            "skill_tags": ["passive-recon"],
            "active_testing": True,
        }]})
        self.task_id = created[0]["task_id"]
        self.workflow.start_task(self.task_id, model="synthetic-model")

    def tearDown(self):
        self.workflow.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_bounded_discovery_crawls_maps_js_and_records_broker_evidence(self):
        from scripts.active_surface import run_discovery
        with patch("scripts.active_surface.ROOT", self.root), \\
             patch("core.active_executor._acquire_slot", return_value="synthetic-lock"), \\
             patch("core.active_executor._release_slot"):
            result = run_discovery(
                self.db, "eng-surface-lab", self.task_id,
                f"http://127.0.0.1:{self.port}/", max_pages=10, max_depth=2,
            )
        self.assertEqual(result["status"], "completed")
        self.assertIn(f"http://127.0.0.1:{self.port}/account", result["observed_endpoints"])
        self.assertIn(f"http://127.0.0.1:{self.port}/api/v2/users", result["inferred_javascript_endpoints"])
        self.assertIn(f"http://127.0.0.1:{self.port}/assets/app.js", result["javascript_assets"])
        self.assertIn("dom-xss-sink", {
            indicator["type"]
            for item in result["javascript_analysis"]
            for indicator in item["indicators"]
        })
        self.assertTrue(any(item["type"] == "cors-origin-reflection-with-credentials" for item in result["observations"]))
        self.assertTrue(result["options_observation"]["status_code"] in {200, 204})
        row = self.workflow.store.connection.execute(
            "SELECT input_json FROM tasks WHERE task_id=?", (self.task_id,)
        ).fetchone()
        generated = json.loads(row["input_json"])["generated_request_files"]
        self.assertGreaterEqual(len(generated), 4)
        count = self.workflow.store.connection.execute(
            "SELECT COUNT(*) FROM active_request_log WHERE engagement_id=? AND task_id=? AND outcome='completed'",
            ("eng-surface-lab", self.task_id),
        ).fetchone()[0]
        self.assertEqual(count, len(generated))


if __name__ == "__main__":
    unittest.main()
