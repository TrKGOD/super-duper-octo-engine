"""Isolated Execution Workers tests.

Exercises tool-registry argument validation (no injection), the portable subprocess
backend's bounded execution (timeout and output caps), the container backend's
hardened-by-construction command, and the manager's engagement isolation, tool
authorization, resource bounds, cancellation, cleanup and observability. Tools are the
current Python interpreter running fixed inline programs, so no external binaries are
needed.
"""
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.workers import (ContainerWorkerBackend, ResourceLimits, SubprocessWorkerBackend,
                         ToolError, ToolParam, ToolRegistry, ToolSpec, WorkerError, WorkerManager)

PY = sys.executable

ECHO = ToolSpec("echo", "echo", "1.0", "print a value", command=(PY, "-c", "import sys;print(sys.argv[1])", "{text}"),
                params=(ToolParam("text"),), timeout_seconds=15, max_output_bytes=100000)
SLEEP = ToolSpec("sleep", "sleep", "1.0", "sleep", command=(PY, "-c", "import time;time.sleep(5)"),
                 timeout_seconds=1, max_output_bytes=1000)
FLOOD = ToolSpec("flood", "flood", "1.0", "flood stdout", command=(PY, "-c", "print('A'*2000000)"),
                 timeout_seconds=15, max_output_bytes=1000)


def registry():
    reg = ToolRegistry()
    for spec in (ECHO, SLEEP, FLOOD):
        reg.register(spec)
    return reg


class ToolRegistryTests(unittest.TestCase):
    def test_unregistered_tool_is_rejected(self):
        with self.assertRaises(ToolError):
            registry().validate_invocation("nmap", {})

    def test_argument_validation_and_no_injection(self):
        reg = registry()
        with self.assertRaises(ToolError):
            reg.validate_invocation("echo", {"text": "hi", "extra": "x"})  # unknown param
        with self.assertRaises(ToolError):
            reg.validate_invocation("echo", {})  # missing required
        # A hostile value becomes exactly one argv element; it cannot add arguments.
        _, argv = reg.validate_invocation("echo", {"text": "; rm -rf / #"})
        self.assertIn("; rm -rf / #", argv)
        self.assertEqual(len(argv), 4)

    def test_typed_params(self):
        spec = ToolSpec("t", "t", "1.0", "p", command=(PY, "-c", "print(1)", "{n}", "{mode}"),
                        params=(ToolParam("n", type="int"), ToolParam("mode", type="enum", choices=("a", "b"))))
        with self.assertRaises(ToolError):
            spec.build_argv({"n": "notint", "mode": "a"})
        with self.assertRaises(ToolError):
            spec.build_argv({"n": 3, "mode": "z"})
        self.assertEqual(spec.build_argv({"n": 3, "mode": "a"})[-2:], ["3", "a"])


class SubprocessBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = self.tmp.name
        self.backend = SubprocessWorkerBackend()

    def tearDown(self):
        self.tmp.cleanup()

    def test_runs_and_captures_output(self):
        argv = ECHO.build_argv({"text": "hello-worker"})
        result = self.backend.run(argv, cwd=self.cwd, limits=ResourceLimits(wall_clock_seconds=15))
        self.assertEqual(result.exit_status, 0)
        self.assertIn(b"hello-worker", result.output)
        self.assertFalse(result.timed_out)

    def test_timeout_is_enforced(self):
        result = self.backend.run(SLEEP.build_argv({}), cwd=self.cwd,
                                  limits=ResourceLimits(wall_clock_seconds=1))
        self.assertTrue(result.timed_out)
        self.assertTrue(result.killed)

    def test_output_cap_is_enforced(self):
        result = self.backend.run(FLOOD.build_argv({}), cwd=self.cwd,
                                  limits=ResourceLimits(wall_clock_seconds=15, max_output_bytes=1000))
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.output), 1000)


class ContainerBackendTests(unittest.TestCase):
    def test_command_is_hardened_by_construction(self):
        backend = ContainerWorkerBackend("witherhoard/tool:1")
        argv = backend.build_argv(["scan", "target"], cwd="/evidence/x",
                                  limits=ResourceLimits(max_memory_mb=256, max_processes=32))
        joined = " ".join(argv)
        for flag in ("--read-only", "--cap-drop=ALL", "no-new-privileges", "--pids-limit",
                     "--memory", "--network", "--user"):
            self.assertIn(flag, joined)
        self.assertNotIn("--privileged", joined)
        self.assertNotIn("docker.sock", joined)
        self.assertIn("none", joined)  # default network none

    def test_run_delegates_to_injected_runner(self):
        captured = {}

        def fake_runner(command, *, cwd, limits, env=None):
            captured["command"] = command
            from core.workers.resources import ExecutionResult
            return ExecutionResult(0, b"ok", False, False, 1)

        backend = ContainerWorkerBackend("img:1", runner=fake_runner)
        result = backend.run(["x"], cwd="/evidence", limits=ResourceLimits())
        self.assertEqual(result.output, b"ok")
        self.assertEqual(captured["command"][:2], ["docker", "run"])


class ManagerTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "s.sqlite3")
        migrate(self.db)
        self.store = StateStore(self.db)
        for eid in ("eng-a", "eng-b"):
            self.store.create_engagement(eid, "AUTH", {}, {}, status="active")
        self.mgr = WorkerManager(self.store, self.root / "run", registry=registry())

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()


class ManagerTests(ManagerTestBase):
    def test_execute_records_observability(self):
        w = self.mgr.provision("eng-a", "task-1")
        out = self.mgr.execute(w, "echo", {"text": "visible"}, allowed_tools=["echo"])
        self.assertIn("visible", out["output"])
        obs = self.mgr.observability(w.worker_id)
        self.assertEqual(obs["engagement_id"], "eng-a")
        self.assertEqual(len(obs["tool_executions"]), 1)
        self.assertEqual(obs["tool_executions"][0]["tool_id"], "echo")
        self.assertEqual(obs["artifacts"], ["out_0_echo.log"])

    def test_unauthorized_tool_is_rejected(self):
        w = self.mgr.provision("eng-a", "task-1")
        with self.assertRaises(WorkerError):          # registered but not allowlisted
            self.mgr.execute(w, "flood", {}, allowed_tools=["echo"])
        with self.assertRaises(WorkerError):          # not registered at all
            self.mgr.execute(w, "metasploit", {}, allowed_tools=["metasploit"])

    def test_cross_engagement_artifact_isolation(self):
        wa = self.mgr.provision("eng-a", "t")
        self.mgr.execute(wa, "echo", {"text": "secret-a"}, allowed_tools=["echo"])
        wb = self.mgr.provision("eng-b", "t")
        # Worker B cannot traverse into engagement A's worker directory.
        with self.assertRaises(WorkerError):
            self.mgr.read_artifact(wb, f"../../eng-a/{wa.worker_id}/out_0_echo.log")
        # Worker A can read its own artifact.
        self.assertIn(b"secret-a", self.mgr.read_artifact(wa, "out_0_echo.log"))

    def test_invocation_budget_is_enforced(self):
        mgr = WorkerManager(self.store, self.root / "run2", registry=registry(), max_tool_invocations=1)
        w = mgr.provision("eng-a", "t")
        mgr.execute(w, "echo", {"text": "one"}, allowed_tools=["echo"])
        with self.assertRaises(WorkerError):
            mgr.execute(w, "echo", {"text": "two"}, allowed_tools=["echo"])

    def test_cancel_blocks_further_execution(self):
        w = self.mgr.provision("eng-a", "t")
        self.mgr.cancel(w)
        with self.assertRaises(WorkerError):
            self.mgr.execute(w, "echo", {"text": "x"}, allowed_tools=["echo"])
        self.assertEqual(self.mgr.observability(w.worker_id)["status"], "cancelled")

    def test_teardown_cleans_up_workdir(self):
        w = self.mgr.provision("eng-a", "t")
        self.mgr.execute(w, "echo", {"text": "x"}, allowed_tools=["echo"])
        self.assertTrue(w.workdir.exists())
        result = self.mgr.teardown(w)
        self.assertEqual(result["cleanup_status"], "cleaned")
        self.assertFalse(w.workdir.exists())
        self.assertEqual(self.mgr.observability(w.worker_id)["status"], "torn_down")

    def test_per_engagement_active_worker_limit(self):
        mgr = WorkerManager(self.store, self.root / "run3", registry=registry(),
                            max_active_workers_per_engagement=1)
        mgr.provision("eng-a", "t1")
        with self.assertRaises(WorkerError):
            mgr.provision("eng-a", "t2")


if __name__ == "__main__":
    unittest.main()
