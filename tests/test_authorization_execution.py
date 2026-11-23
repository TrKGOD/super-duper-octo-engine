import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from core.active_executor import ActiveExecutionError
from core.authorization_execution import execute_object_access_comparison


class BrokeredAuthorizationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.requests = self.root / ".local" / "requests"
        self.requests.mkdir(parents=True)
        self.executor = Mock()
        self.executor.project_root = self.root
        self.owner = {
            "request_id": "idor-owner-001",
            "method": "GET",
            "url": "https://app.example.test/api/objects/synthetic-1",
            "purpose": "Read synthetic object using its owner identity",
            "secret_headers": {"Authorization": "SYNTH_OWNER_AUTH"},
            "timeout_seconds": 5,
            "max_response_bytes": 8192,
            "follow_redirects": False,
        }
        self.other = {
            **self.owner,
            "request_id": "idor-other-001",
            "purpose": "Read synthetic object using a distinct non-owner identity",
            "secret_headers": {"Authorization": "SYNTH_OTHER_AUTH"},
        }
        # Purpose is descriptive metadata; the route and request semantics must match.
        self.other["purpose"] = self.owner["purpose"]
        self.owner_path = self._write("owner.json", self.owner)
        self.other_path = self._write("other.json", self.other)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, value):
        path = self.requests / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return ".local/requests/" + name

    def _run(self):
        return execute_object_access_comparison(
            self.executor, "eng-1", "task-1", self.owner_path, self.other_path,
            owner_identity="synthetic-owner", other_identity="synthetic-non-owner",
            object_reference="synthetic-object-1",
        )

    def test_executes_two_equivalent_requests_and_compares_broker_results(self):
        self.executor.execute_request_file.side_effect = [
            {"request_id": "idor-owner-001", "status_code": 200,
             "response_excerpt": '{"id":"synthetic-1","name":"demo"}',
             "evidence_refs": ["owner-req", "owner-resp"]},
            {"request_id": "idor-other-001", "status_code": 200,
             "response_excerpt": '{"id":"synthetic-1","name":"demo"}',
             "evidence_refs": ["other-req", "other-resp"]},
        ]
        result = self._run()
        self.assertEqual(result["status"], "comparison_completed")
        self.assertEqual(
            result["comparison"]["classification"],
            "potential_bola_same_object_representation",
        )
        self.assertEqual(self.executor.execute_request_file.call_count, 2)
        self.assertEqual(set(result["evidence_refs"]), {
            "owner-req", "owner-resp", "other-req", "other-resp"
        })

    def test_rejects_non_read_only_method_before_network(self):
        self.owner["method"] = "POST"
        self._write("owner.json", self.owner)
        with self.assertRaisesRegex(ActiveExecutionError, "only GET"):
            self._run()
        self.executor.execute_request_file.assert_not_called()

    def test_rejects_different_request_context(self):
        self.other["url"] += "?include=private"
        self._write("other.json", self.other)
        with self.assertRaisesRegex(ActiveExecutionError, "must be equivalent"):
            self._run()
        self.executor.execute_request_file.assert_not_called()

    def test_rejects_reused_secret_reference(self):
        self.other["secret_headers"] = self.owner["secret_headers"]
        self._write("other.json", self.other)
        with self.assertRaisesRegex(ActiveExecutionError, "distinct secret references"):
            self._run()
        self.executor.execute_request_file.assert_not_called()

    def test_second_request_failure_returns_partial_evidence_without_comparison(self):
        self.executor.execute_request_file.side_effect = [
            {"status_code": 200, "response_excerpt": '{"id":"synthetic-1"}',
             "evidence_refs": ["owner-evidence"]},
            ActiveExecutionError("second manifest was not pinned"),
        ]
        result = self._run()
        self.assertEqual(result["status"], "partial_execution")
        self.assertIsNone(result["other_response"])
        self.assertEqual(result["evidence_refs"], ["owner-evidence"])
        self.assertNotIn("comparison", result)

    def test_requires_distinct_identity_labels(self):
        with self.assertRaisesRegex(ActiveExecutionError, "distinct"):
            execute_object_access_comparison(
                self.executor, "eng-1", "task-1", self.owner_path, self.other_path,
                owner_identity="same", other_identity="same",
                object_reference="synthetic-object-1",
            )


if __name__ == "__main__":
    unittest.main()
