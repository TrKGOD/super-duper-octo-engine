"""Execution ledger: state machine, crash reconciliation and the no-silent-retry invariant."""
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from core.errors import FAILURE_CLASSES, classify_exception
from core.execution_ledger import ExecutionError, ExecutionLedger, NEEDS_OPERATOR, TERMINAL
from core.store import StateStore
from scripts.migrate import migrate

ALLOW = {"decision": "allow", "source": "profile-policy"}


class FakeClock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class LedgerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "state.sqlite3")
        migrate(self.db)
        self.store = StateStore(self.db)
        for engagement in ("eng-a", "eng-b"):
            self.store.create_engagement(engagement, "AUTH-LAB", {}, {}, status="active")
        self.clock = FakeClock()
        self.ledger = ExecutionLedger(self.store.connection, owner="proc-1", lease_seconds=30, clock=self.clock)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def new(self, *, risk="read_only", engagement="eng-a", ledger=None, **extra):
        ledger = ledger or self.ledger
        return ledger.create(engagement_id=engagement, kind="tool", tool_id="httpx",
                             execution_profile="safe", task_id="task-1", side_effect_risk=risk, **extra)

    def running(self, **kwargs):
        execution_id = self.new(**kwargs)
        self.ledger.authorize(execution_id, ALLOW)
        self.ledger.start(execution_id)
        return execution_id


class StateMachineTests(LedgerBase):
    def test_happy_path_records_every_step_with_actor_and_timestamps(self):
        execution_id = self.running()
        self.ledger.complete(execution_id, evidence_refs=["ev-1", "ev-1", "ev-2"], exit_status=0,
                             resource_usage={"duration_ms": 12})
        record = self.ledger.get(execution_id)
        self.assertEqual(record["status"], "COMPLETED")
        self.assertEqual(record["evidence_refs"], ["ev-1", "ev-2"])
        self.assertEqual(record["resource_usage"], {"duration_ms": 12})
        self.assertIsNotNone(record["started_at"])
        self.assertIsNotNone(record["finished_at"])
        self.assertEqual([e["to"] for e in self.ledger.events(execution_id)],
                         ["CREATED", "AUTHORIZED", "RUNNING", "COMPLETED"])

    def test_invalid_transitions_are_refused(self):
        execution_id = self.new()
        with self.assertRaises(ExecutionError):
            self.ledger.start(execution_id)                  # CREATED -> RUNNING skips authorization
        with self.assertRaises(ExecutionError):
            self.ledger.complete(execution_id)               # CREATED -> COMPLETED
        self.ledger.authorize(execution_id, ALLOW)
        with self.assertRaises(ExecutionError):
            self.ledger.authorize(execution_id, ALLOW)       # AUTHORIZED -> AUTHORIZED

    def test_terminal_states_are_final(self):
        execution_id = self.running()
        self.ledger.complete(execution_id)
        for action in (lambda: self.ledger.fail(execution_id, failure_class="tool_error", message="x"),
                       lambda: self.ledger.cancel(execution_id, reason="late"),
                       lambda: self.ledger.start(execution_id)):
            with self.assertRaises(ExecutionError):
                action()

    def test_only_an_explicit_allow_with_a_source_authorizes(self):
        for bad in ({}, {"decision": "deny", "source": "p"}, {"decision": "allow"}, None, "allow"):
            with self.assertRaises(ExecutionError, msg=repr(bad)):
                self.ledger.authorize(self.new(), bad)

    def test_failure_classes_are_validated_and_messages_redacted(self):
        execution_id = self.running()
        with self.assertRaises(ExecutionError):
            self.ledger.fail(execution_id, failure_class="because", message="x")
        status = self.ledger.fail(execution_id, failure_class="tool_error",
                                  message="login failed password=hunter2 token=abc123")
        self.assertEqual(status, "FAILED")
        failure = self.ledger.get(execution_id)["failure"]
        self.assertEqual(failure["class"], "tool_error")
        self.assertNotIn("hunter2", failure["message"])
        self.assertNotIn("abc123", failure["message"])

    def test_cancelling_a_running_execution_is_recorded(self):
        execution_id = self.running()
        self.ledger.cancel(execution_id, reason="operator stopped the run")
        self.assertEqual(self.ledger.get(execution_id)["status"], "CANCELLED")

    def test_unknown_engagement_or_kind_is_rejected(self):
        with self.assertRaises(ExecutionError):
            self.ledger.create(engagement_id="nope", kind="tool", tool_id="t", execution_profile="safe")
        with self.assertRaises(ExecutionError):
            self.ledger.create(engagement_id="eng-a", kind="shell", tool_id="t", execution_profile="safe")


class UncertainOutcomeTests(LedgerBase):
    def test_error_after_dispatch_of_a_state_changing_request_needs_reconciliation(self):
        execution_id = self.running(risk="state_changing")
        self.ledger.mark_dispatched(execution_id)
        status = self.ledger.fail(execution_id, failure_class="timeout", message="no response")
        self.assertEqual(status, "RECONCILIATION_REQUIRED")
        self.assertIn(status, NEEDS_OPERATOR)

    def test_error_before_dispatch_is_a_plain_failure(self):
        execution_id = self.running(risk="state_changing")
        self.assertEqual(self.ledger.fail(execution_id, failure_class="invalid_input", message="bad"), "FAILED")

    def test_read_only_error_after_dispatch_is_a_plain_failure(self):
        execution_id = self.running()
        self.ledger.mark_dispatched(execution_id)
        self.assertEqual(self.ledger.fail(execution_id, failure_class="timeout", message="slow"), "FAILED")

    def test_caller_can_declare_the_outcome_uncertain(self):
        execution_id = self.running()
        self.ledger.mark_dispatched(execution_id)
        self.assertEqual(self.ledger.fail(execution_id, failure_class="infrastructure", message="evidence write failed",
                                          uncertain_outcome=True), "RECONCILIATION_REQUIRED")

    def test_dispatch_can_only_be_marked_while_running(self):
        with self.assertRaises(ExecutionError):
            self.ledger.mark_dispatched(self.new())


class CrashRecoveryTests(LedgerBase):
    """Crash points from the mission: before execution, during, after the external request."""

    def test_crash_before_execution_is_interrupted_and_nothing_is_rerun(self):
        created = self.new()
        authorized = self.new()
        self.ledger.authorize(authorized, ALLOW)
        self.clock.advance(31)                                # the owner died; leases lapse
        survivor = ExecutionLedger(self.store.connection, owner="proc-2", lease_seconds=30, clock=self.clock)
        moved = survivor.reconcile_stale()
        self.assertEqual({m["execution_id"]: m["to"] for m in moved},
                         {created: "INTERRUPTED", authorized: "INTERRUPTED"})
        # nothing was re-executed: no new rows, no RUNNING rows
        self.assertEqual(len(survivor.list("eng-a")), 2)
        self.assertEqual(survivor.list("eng-a", status="RUNNING"), [])

    def test_crash_during_execution_before_dispatch_is_interrupted(self):
        execution_id = self.running()
        self.clock.advance(31)
        moved = self.ledger.reconcile_stale()
        self.assertEqual(moved, [{"execution_id": execution_id, "to": "INTERRUPTED"}])

    def test_crash_after_the_request_was_sent_requires_reconciliation(self):
        execution_id = self.running(risk="state_changing")
        self.ledger.mark_dispatched(execution_id)
        self.clock.advance(31)
        moved = self.ledger.reconcile_stale()
        self.assertEqual(moved, [{"execution_id": execution_id, "to": "RECONCILIATION_REQUIRED"}])
        self.assertEqual([e["execution_id"] for e in self.ledger.pending_reconciliation("eng-a")], [execution_id])

    def test_a_live_execution_within_its_lease_is_never_touched(self):
        execution_id = self.running()
        self.clock.advance(20)                                # < 30s lease
        self.assertEqual(self.ledger.reconcile_stale(), [])
        self.ledger.heartbeat(execution_id)
        self.clock.advance(20)                                # 40s total but renewed at 20s
        self.assertEqual(self.ledger.reconcile_stale(), [])
        self.assertEqual(self.ledger.get(execution_id)["status"], "RUNNING")

    def test_settled_executions_are_ignored_by_reconciliation(self):
        done = self.running()
        self.ledger.complete(done)
        self.clock.advance(3600)
        self.assertEqual(self.ledger.reconcile_stale(), [])

    def test_reconciliation_can_be_limited_to_one_engagement(self):
        a, b = self.running(engagement="eng-a"), self.running(engagement="eng-b")
        self.clock.advance(31)
        moved = self.ledger.reconcile_stale(engagement_id="eng-a")
        self.assertEqual([m["execution_id"] for m in moved], [a])
        self.assertEqual(self.ledger.get(b)["status"], "RUNNING")


class OperatorResolutionTests(LedgerBase):
    def _stuck(self):
        execution_id = self.running(risk="state_changing")
        self.ledger.mark_dispatched(execution_id)
        self.clock.advance(31)
        self.ledger.reconcile_stale()
        return execution_id

    def test_each_resolution_maps_to_a_terminal_state_and_is_attributed(self):
        for resolution, status in (("completed", "COMPLETED"), ("failed_no_effect", "FAILED"), ("abandoned", "CANCELLED")):
            execution_id = self._stuck()
            result = self.ledger.resolve(execution_id, operator="alice", resolution=resolution,
                                         reason="Checked the target's own request log", evidence_refs=["ev-9"])
            self.assertEqual(result, status)
            record = self.ledger.get(execution_id)
            self.assertEqual(record["reconciliation"]["decided_by"], "alice")
            self.assertIn(status, TERMINAL)
            self.assertEqual(record["evidence_refs"], ["ev-9"])

    def test_resolution_needs_a_named_operator_and_a_real_reason(self):
        execution_id = self._stuck()
        for operator, reason in (("", "a long enough reason"), ("  ", "a long enough reason"), ("alice", "short"), ("alice", "")):
            with self.assertRaises(ExecutionError, msg=(operator, reason)):
                self.ledger.resolve(execution_id, operator=operator, resolution="completed", reason=reason)
        with self.assertRaises(ExecutionError):
            self.ledger.resolve(execution_id, operator="alice", resolution="retry", reason="please run it again")
        self.assertEqual(self.ledger.get(execution_id)["status"], "RECONCILIATION_REQUIRED")

    def test_only_an_unresolved_execution_can_be_resolved(self):
        done = self.running()
        self.ledger.complete(done)
        with self.assertRaises(ExecutionError):
            self.ledger.resolve(done, operator="alice", resolution="completed", reason="not actually stuck")

    def test_resolution_cannot_cross_engagements(self):
        execution_id = self._stuck()
        with self.assertRaises(ExecutionError):
            self.ledger.resolve(execution_id, operator="mallory", resolution="completed",
                                reason="resolving someone else's execution", engagement_id="eng-b")
        self.assertEqual(self.ledger.get(execution_id)["status"], "RECONCILIATION_REQUIRED")


class IsolationAndIntegrityTests(LedgerBase):
    def test_an_execution_of_another_engagement_is_invisible(self):
        execution_id = self.new(engagement="eng-a")
        with self.assertRaises(ExecutionError):
            self.ledger.get(execution_id, "eng-b")
        with self.assertRaises(ExecutionError):
            self.ledger.events(execution_id, "eng-b")
        self.assertEqual(self.ledger.list("eng-b"), [])

    def test_evidence_can_only_reference_an_execution_of_its_own_engagement(self):
        execution_id = self.new(engagement="eng-a")
        ok = self.store.record_evidence("eng-a", "http_response", ".local/evidence/eng-a/x.json", "t",
                                        sha256="a" * 64, execution_id=execution_id, task_id="task-1")
        self.assertTrue(ok)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.record_evidence("eng-b", "http_response", ".local/evidence/eng-b/x.json", "t",
                                       sha256="b" * 64, execution_id=execution_id)

    def test_the_event_trail_is_append_only(self):
        execution_id = self.new()
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("UPDATE execution_events SET actor='x' WHERE execution_id=?", (execution_id,))
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.connection.execute("DELETE FROM execution_events WHERE execution_id=?", (execution_id,))

    def test_request_parameters_are_redacted_before_they_are_stored(self):
        execution_id = self.new(request={"url": "https://a.test/x", "password": "hunter2", "note": "token=abc999"})
        stored = repr(self.ledger.get(execution_id)["request"])
        self.assertNotIn("hunter2", stored)
        self.assertNotIn("abc999", stored)


class ConcurrencyTests(LedgerBase):
    def test_exactly_one_of_many_concurrent_completions_wins(self):
        execution_id = self.running()
        self.store.connection.commit()
        results, barrier = [], threading.Barrier(8)

        def worker():
            connection = sqlite3.connect(self.db, timeout=10)
            connection.row_factory = sqlite3.Row
            ledger = ExecutionLedger(connection, owner="t", clock=self.clock)
            barrier.wait()
            try:
                ledger.complete(execution_id)
                results.append("won")
            except ExecutionError:
                results.append("lost")
            finally:
                connection.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(results), ["lost"] * 7 + ["won"])
        self.assertEqual(self.ledger.get(execution_id)["status"], "COMPLETED")


class FailureTaxonomyTests(unittest.TestCase):
    def test_exceptions_map_to_explicit_failure_classes(self):
        from core.active_executor import ActiveExecutionError
        from core.netpolicy import DestinationDenied
        from core.pathsafe import PathSafetyError
        from core.workers.resources import ResourceError
        cases = [
            (DestinationDenied("loopback"), "security_violation"),
            (PathSafetyError("escape"), "security_violation"),
            (ActiveExecutionError("not in scope"), "authorization_denied"),
            (ResourceError("bad limit"), "invalid_input"),
            (TimeoutError("slow"), "timeout"),
            (FileNotFoundError("tool missing"), "infrastructure"),
            (ConnectionResetError("reset"), "infrastructure"),
            (ValueError("bad"), "invalid_input"),
            (TypeError("bug"), "programming_error"),
            (RuntimeError("???"), "programming_error"),
        ]
        for exc, expected in cases:
            self.assertEqual(classify_exception(exc), expected, repr(exc))
            self.assertIn(expected, FAILURE_CLASSES)


if __name__ == "__main__":
    unittest.main()
