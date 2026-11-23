import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.active_executor import ActiveExecutionError, _validate_request
from scripts.active_surface import _parse_allowed_methods
from scripts.ingest_har import ingest_har, normalize_path
from scripts.migrate import migrate
from core.orchestration import Workflow


class HarImporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / ".local" / "state.sqlite3")
        Path(self.db).parent.mkdir(parents=True)
        migrate(self.db)
        self.workflow = Workflow(self.db, project_root=self.root)
        self.workflow.initialize({
            "engagement_id": "eng-har-lab",
            "authorization_reference": "AUTH-SYNTHETIC-HAR-LAB",
            "scope": {"allowed_domains": ["app.example.test"], "allowed_ips": [],
                      "allowed_cidrs": [], "allowed_applications": [], "excluded_assets": []},
            "rules_of_engagement": {"execution_enabled": False}
        })

    def tearDown(self):
        self.workflow.close()
        self.tmp.cleanup()

    def test_har_import_is_offline_scope_filtered_and_redacts_secret_header_values(self):
        har = self.root / "sample.har"
        har.write_text(json.dumps({"log": {"entries": [
            {"request": {"method": "GET", "url": "https://app.example.test/api/users/123?view=full&access_token=secret",
                         "headers": [{"name": "Cookie", "value": "sid=secret"}, {"name": "X-Anon-Id", "value": "anon"}]},
             "response": {"status": 200, "content": {"mimeType": "application/json",
                         "text": json.dumps({"user_id": "researcher-user-1", "email": "private@example.test"})}}},
            {"request": {"method": "GET", "url": "https://outside.example/api/private", "headers": []},
             "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}}}
        ]}}), encoding="utf-8")
        result = ingest_har(self.db, "eng-har-lab", har, project_root=self.root)
        self.assertEqual(result["endpoints"], 1)
        self.assertEqual(result["skipped_entries"], 1)
        out = self.root / ".local" / "engagements" / "eng-har-lab"
        endpoints = json.loads((out / "endpoint-inventory.json").read_text())
        self.assertEqual(endpoints["endpoints"][0]["path"], "/api/users/{id}")
        self.assertIn("cookie", endpoints["endpoints"][0]["secret_header_names"])
        self.assertNotIn("sid=secret", (out / "endpoint-inventory.json").read_text())\n        self.assertNotIn("private@example.test", (out / "endpoint-inventory.json").read_text())
        self.assertTrue((out / "id-inventory.json").is_file())

    def test_numeric_and_guid_path_segments_are_normalized(self):
        self.assertEqual(normalize_path("/api/users/123/items/550e8400-e29b-41d4-a716-446655440000"),
                         "/api/users/{id}/items/{id}")


class BrokerWriteGateTests(unittest.TestCase):
    def _request(self, method):
        return {"request_id": "write-test-001", "method": method,
                "url": "https://app.example.test/api/resource",
                "purpose": "Synthetic approved write-method validation",
                "timeout_seconds": 5, "max_response_bytes": 8192,
                "follow_redirects": False}

    def _approval(self):
        return {"approved": True, "approved_by": "synthetic-operator",
                "approved_at": datetime.now(timezone.utc).isoformat(),
                "reason": "Approved synthetic local fixture request"}

    def test_put_patch_delete_require_timestamped_approval(self):
        for method in ("PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                request = self._request(method)
                with self.assertRaises(ActiveExecutionError):
                    _validate_request(request)
                request["operator_approval"] = self._approval()
                self.assertEqual(_validate_request(request), method)

    def test_multipart_upload_requires_approval_and_has_strict_size_limit(self):
        request = self._request("POST")
        request["upload"] = {"filename": "fixture.txt", "content_type": "text/plain",
                             "content_base64": base64.b64encode(b"synthetic").decode()}
        with self.assertRaises(ActiveExecutionError):
            _validate_request(request)
        request["operator_approval"] = self._approval()
        self.assertEqual(_validate_request(request), "POST")
        request["upload"]["content_base64"] = base64.b64encode(b"x" * (262144 + 1)).decode()
        with self.assertRaisesRegex(ActiveExecutionError, "256 KiB"):
            _validate_request(request)

    def test_allow_header_is_parsed_as_method_tokens(self):
        self.assertEqual(_parse_allowed_methods("GET, HEAD, OPTIONS, PATCH"),
                         ["GET", "HEAD", "OPTIONS", "PATCH"])
        self.assertEqual(_parse_allowed_methods("GET OPTIONS"), ["GET", "OPTIONS"])


if __name__ == "__main__":
    unittest.main()
