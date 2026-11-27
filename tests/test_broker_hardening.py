"""Security regression tests for the HTTP execution broker (``core/active_executor.py``).

Each test pins a defect that existed (or a boundary that must keep holding) and runs the
real broker against a loopback lab server, not a mock of the broker itself.
"""
import base64
import email
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

from core import active_executor
from core.active_executor import ActiveExecutionError, _resolve_and_authorize, _send_once, _validate_request_scope
from tests.lab import LabEngagement

APPROVAL = {"approved": True, "approved_by": "lab-operator", "approved_at": "2026-01-01T00:00:00Z",
            "reason": "Synthetic regression request approved by the lab operator"}


class _RecordingHandler(BaseHTTPRequestHandler):
    """Records raw bodies and serves a redirect for state-changing methods."""
    hits: list = []
    captured: dict = {}

    def _respond(self, status=200, body=b"{}", headers=()):
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def do_GET(self):
        self.hits.append(("GET", self.path))
        self._respond()

    def do_POST(self):
        body = self._read_body()
        self.hits.append(("POST", self.path))
        if self.path == "/upload":
            type(self).captured = {"content_type": self.headers.get("Content-Type"), "body": body}
        self._respond(201)

    def do_PUT(self):
        self._read_body()
        self.hits.append(("PUT", self.path))
        if self.path == "/redirect-me":
            self._respond(307, headers=[("Location", "/redirect-target")])
        else:
            self._respond()

    do_DELETE = do_PATCH = do_PUT

    def log_message(self, *_):
        pass


class BrokerHardeningTests(unittest.TestCase):
    def setUp(self):
        _RecordingHandler.hits = []
        _RecordingHandler.captured = {}
        self.lab = LabEngagement(
            _RecordingHandler,
            allowed_classes=["http-read-only", "state-changing-http", "upload-http"],
            extra_rules={"uploads_enabled": True}).open()

    def tearDown(self):
        self.lab.close()

    # -- multipart framing --------------------------------------------------------------
    def test_multipart_upload_is_valid_crlf_framed_multipart(self):
        # Regression: the framing used the two characters backslash+r instead of CR, so no
        # server could parse the body as multipart.
        request = self.lab.manifest(
            "upload-framing-1", "/upload", "POST", operator_approval=APPROVAL,
            upload={"filename": "fixture.txt", "content_type": "text/plain",
                    "content_base64": base64.b64encode(b"HELLO-LAB-PAYLOAD").decode()})
        self.lab.run(request, agent="active-testing-agent", skill_tags=["http-read-only"])
        captured = _RecordingHandler.captured
        self.assertTrue(captured, "the lab server never received the upload")
        self.assertNotIn(b"\\r\\n", captured["body"], "framing contains literal backslash-r/n text")
        message = email.message_from_bytes(
            b"MIME-Version: 1.0\r\nContent-Type: " + captured["content_type"].encode() + b"\r\n\r\n" + captured["body"])
        self.assertTrue(message.is_multipart())
        parts = message.get_payload()
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0].get_filename(), "fixture.txt")
        self.assertEqual(parts[0].get_payload(decode=True), b"HELLO-LAB-PAYLOAD")

    # -- state-changing requests are never re-sent --------------------------------------
    def test_state_changing_methods_never_follow_a_redirect(self):
        for method in ("PUT", "PATCH", "DELETE"):
            _RecordingHandler.hits = []
            request = self.lab.manifest(f"no-redirect-{method.lower()}", "/redirect-me", method,
                                        operator_approval=APPROVAL)
            with self.assertRaisesRegex(ActiveExecutionError, "redirects are disabled"):
                self.lab.run(request, agent="active-testing-agent", skill_tags=["http-read-only"])
            self.assertNotIn(("PUT", "/redirect-target"), _RecordingHandler.hits, method)
            self.assertEqual([h for h in _RecordingHandler.hits if h[1] == "/redirect-target"], [], method)


class DestinationValidationTests(unittest.TestCase):
    SCOPE = {"allowed_domains": ["rebind.test"], "allowed_ips": [], "allowed_cidrs": [],
             "allowed_http_ports": [], "excluded_assets": [], "allowed_applications": []}
    TASK = ["rebind.test"]

    def _answers(self, *addresses):
        return lambda host, port, type=0: [(2, 1, 6, "", (address, port)) for address in addresses]

    def test_non_canonical_ip_notation_cannot_reach_the_allow_list_logic(self):
        scope = {**self.SCOPE, "allowed_ips": ["127.0.0.1"], "allowed_domains": []}
        for host in ("2130706433", "0x7f.1", "0177.0.0.1", "127.1"):
            with self.assertRaisesRegex(ActiveExecutionError, "not permitted"):
                _validate_request_scope(f"http://{host}/", scope, ["127.0.0.1"])

    def test_split_dns_answer_with_a_private_record_is_rejected(self):
        # DNS-rebinding style answer: a public record next to a loopback record.
        with patch.object(active_executor.socket, "getaddrinfo", self._answers("93.184.216.34", "127.0.0.1")):
            with self.assertRaisesRegex(ActiveExecutionError, "non-public IP"):
                _resolve_and_authorize("http://rebind.test/", self.SCOPE, self.TASK)

    def test_metadata_address_is_rejected_even_when_a_covering_cidr_is_in_scope(self):
        scope = {**self.SCOPE, "allowed_cidrs": ["169.254.0.0/16"]}
        with patch.object(active_executor.socket, "getaddrinfo", self._answers("169.254.169.254")):
            with self.assertRaisesRegex(ActiveExecutionError, "non-public IP"):
                _resolve_and_authorize("http://rebind.test/", scope, self.TASK)

    def test_every_non_public_class_is_rejected_for_an_in_scope_hostname(self):
        for address in ("10.0.0.5", "192.168.0.1", "127.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1"):
            with patch.object(active_executor.socket, "getaddrinfo", self._answers(address)):
                with self.assertRaises(ActiveExecutionError, msg=address):
                    _resolve_and_authorize("http://rebind.test/", self.SCOPE, self.TASK)

    def test_connection_goes_to_the_validated_address_and_never_re_resolves(self):
        lookups = []

        def first_public_then_loopback(host, port, type=0):
            lookups.append(host)
            address = "93.184.216.34" if len(lookups) == 1 else "127.0.0.1"   # the rebind
            return [(2, 1, 6, "", (address, port))]

        connections = []

        def recording_connect(address, timeout=None, *a, **k):
            connections.append(address)
            raise OSError("blocked by the test; only the destination matters")

        with patch.object(active_executor.socket, "getaddrinfo", first_public_then_loopback), \
             patch.object(active_executor.socket, "create_connection", recording_connect):
            host, port, pinned_ip, _ = _resolve_and_authorize("http://rebind.test/", self.SCOPE, self.TASK)
            self.assertEqual(pinned_ip, "93.184.216.34")
            with self.assertRaises(OSError):
                _send_once("http://rebind.test/", "GET", {}, None, 3, 1024, pinned_ip)
        self.assertEqual(len(lookups), 1, "the hostname was resolved again after validation")
        self.assertEqual(connections, [("93.184.216.34", 80)])


class BrokerLedgerTests(unittest.TestCase):
    """The broker records every request as a ledger execution (state machine + evidence link)."""

    def setUp(self):
        _RecordingHandler.hits = []
        self.lab = LabEngagement(_RecordingHandler, allowed_classes=["http-read-only", "state-changing-http"]).open()
        from core.execution_ledger import ExecutionLedger
        self.ledger = ExecutionLedger(self.lab.workflow.store.connection)

    def tearDown(self):
        self.lab.close()

    def _executions(self, **filters):
        return self.ledger.list(self.lab.engagement_id, **filters)

    def test_a_successful_request_is_a_completed_execution_that_owns_its_evidence(self):
        result = self.lab.run(self.lab.manifest("ledger-ok-1", "/ok"))
        (execution,) = self._executions()
        self.assertEqual(result["execution_id"], execution["execution_id"])
        self.assertEqual(execution["status"], "COMPLETED")
        self.assertEqual(execution["kind"], "http")
        self.assertEqual(execution["exit_status"], 200)
        self.assertEqual(execution["authorization"]["decision"], "allow")
        self.assertTrue(execution["request_dispatched"])
        self.assertEqual(sorted(execution["evidence_refs"]), sorted(result["evidence_refs"]))
        rows = self.lab.workflow.store.connection.execute(
            "SELECT execution_id,task_id FROM evidence WHERE evidence_id IN (?,?)",
            tuple(result["evidence_refs"])).fetchall()
        self.assertEqual({r["execution_id"] for r in rows}, {execution["execution_id"]})
        self.assertEqual([e["to"] for e in self.ledger.events(execution["execution_id"])],
                         ["CREATED", "AUTHORIZED", "RUNNING", "COMPLETED"])

    def test_a_policy_failure_before_any_request_leaves_no_execution(self):
        # Planning already refuses out-of-scope manifests; the broker's own gate is the SHA-256
        # pin: a manifest edited after approval is refused before anything is executed.
        task_id, (manifest,) = self.lab.start_task([self.lab.manifest("ledger-deny-1", "/ok")])
        (self.lab.root / manifest).write_text('{"tampered": true}', encoding="utf-8")
        with self.assertRaisesRegex(ActiveExecutionError, "changed after the plan was approved"):
            self.lab.executor.execute_request_file(self.lab.engagement_id, task_id, manifest)
        self.assertEqual(self._executions(), [])           # nothing ran, nothing to reconcile

    def test_a_failed_read_only_request_is_failed_with_a_classified_cause(self):
        with patch.object(active_executor, "_send_once", side_effect=TimeoutError("slow target")):
            with self.assertRaises(TimeoutError):
                self.lab.run(self.lab.manifest("ledger-timeout-1", "/slow"))
        (execution,) = self._executions()
        self.assertEqual(execution["status"], "FAILED")
        self.assertEqual(execution["failure"]["class"], "timeout")

    def test_a_state_changing_request_that_errors_after_dispatch_needs_reconciliation(self):
        request = self.lab.manifest("ledger-put-1", "/ok", "PUT", operator_approval=APPROVAL)
        with patch.object(active_executor, "_send_once", side_effect=ConnectionResetError("peer reset")):
            with self.assertRaises(ConnectionResetError):
                self.lab.run(request, agent="active-testing-agent")
        (execution,) = self._executions()
        self.assertEqual(execution["status"], "RECONCILIATION_REQUIRED")
        self.assertTrue(execution["request_dispatched"])

    def test_a_crash_mid_request_is_never_automatically_repeated(self):
        task_id, (manifest,) = self.lab.start_task([self.lab.manifest("ledger-crash-1", "/ok")])
        # BaseException models a process kill: `except Exception` cleanup must not run.
        with patch.object(active_executor, "_send_once", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.lab.executor.execute_request_file(self.lab.engagement_id, task_id, manifest)
        (execution,) = self._executions()
        self.assertEqual(execution["status"], "RUNNING")      # exactly what a SIGKILL leaves behind

        from core.execution_ledger import ExecutionLedger
        survivor = ExecutionLedger(self.lab.workflow.store.connection, owner="restarted-process",
                                   clock=lambda: execution_clock + 10_000)
        execution_clock = __import__("time").time()
        moved = survivor.reconcile_stale()
        self.assertEqual(moved, [{"execution_id": execution["execution_id"], "to": "RECONCILIATION_REQUIRED"}])
        # The broker refuses to send the same request again, and nothing re-ran by itself.
        with self.assertRaisesRegex(ActiveExecutionError, "already been executed"):
            self.lab.executor.execute_request_file(self.lab.engagement_id, task_id, manifest)
        self.assertEqual([h for h in _RecordingHandler.hits if h[1] == "/ok"], [])
        # Only an explicit operator decision moves it on.
        survivor.resolve(execution["execution_id"], operator="lab-operator", resolution="failed_no_effect",
                         reason="Confirmed in the target's log that the request never arrived")
        self.assertEqual(survivor.get(execution["execution_id"])["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
