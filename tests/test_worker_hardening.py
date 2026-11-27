"""Adversarial tests for the worker layer: lifecycle, isolation boundaries and fail-closed behaviour.

The subprocess backend is tested for what it really provides (tree termination, cancellation,
flood kill, resource limits, scrubbed environment) and is never described as a sandbox. The
container backend is driven through a *fake docker executable* so the real lifecycle code
(preflight, naming, kill, rm, orphan cleanup) runs; this proves our logic, not Docker's
isolation, which is verified separately in `tests/test_container_integration.py` when a real
runtime is available.
"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core.execution_ledger import ExecutionLedger
from core.store import StateStore
from core.workers import (CancelToken, ContainerConfigError, ContainerRuntimeUnavailable,
                          ContainerWorkerBackend, ResourceLimits, SubprocessWorkerBackend, ToolParam,
                          ToolRegistry, ToolSpec, WorkerError, WorkerManager)
from core.workers.backends import _count_user_tasks
from core.workers.tools import ToolError
from scripts.migrate import migrate
from tests.support import finalize_fake_cli, make_dir_link, pid_alive, wait_until

PY = sys.executable
GRANDCHILD = ("import subprocess, sys, time; "
              "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
              "open('grandchild.pid', 'w').write(str(p.pid)); time.sleep(120)")


def tool(tool_id, code, *, timeout=20, output=100000, params=(), network="none"):
    return ToolSpec(tool_id, tool_id, "1.0", tool_id, command=(PY, "-c", code), params=params,
                    timeout_seconds=timeout, max_output_bytes=output, network=network)


def make_registry(*specs):
    registry = ToolRegistry()
    for spec in specs:
        registry.register(spec)
    return registry


class SubprocessBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = self.tmp.name
        self.backend = SubprocessWorkerBackend()

    def tearDown(self):
        self.tmp.cleanup()

    def test_descendants_do_not_survive_a_timeout(self):
        result = self.backend.run([PY, "-c", GRANDCHILD], cwd=self.cwd,
                                  limits=ResourceLimits(wall_clock_seconds=2))
        self.assertTrue(result.timed_out)
        grandchild = int((Path(self.cwd) / "grandchild.pid").read_text())
        self.assertTrue(wait_until(lambda: not pid_alive(grandchild), 10),
                        "an orphaned grandchild process survived the timeout")

    def test_descendants_do_not_survive_a_normal_exit(self):
        code = ("import subprocess, sys; "
                "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
                "open('grandchild.pid', 'w').write(str(p.pid))")        # parent exits immediately
        result = self.backend.run([PY, "-c", code], cwd=self.cwd, limits=ResourceLimits(wall_clock_seconds=15))
        self.assertEqual(result.exit_status, 0)
        grandchild = int((Path(self.cwd) / "grandchild.pid").read_text())
        self.assertTrue(wait_until(lambda: not pid_alive(grandchild), 10),
                        "a process the tool left behind outlived the execution")

    def test_cancellation_stops_a_running_tool_promptly(self):
        token = CancelToken()
        threading.Timer(0.6, token.cancel).start()
        started = time.monotonic()
        result = self.backend.run([PY, "-c", GRANDCHILD], cwd=self.cwd,
                                  limits=ResourceLimits(wall_clock_seconds=60), cancel=token)
        self.assertTrue(result.cancelled)
        self.assertTrue(result.killed)
        self.assertFalse(result.timed_out)
        self.assertLess(time.monotonic() - started, 15)
        grandchild = int((Path(self.cwd) / "grandchild.pid").read_text())
        self.assertTrue(wait_until(lambda: not pid_alive(grandchild), 10))

    def test_an_output_flood_is_killed_long_before_the_wall_clock(self):
        flood = "import sys\nwhile True:\n    sys.stdout.write('A' * 4096)\n    sys.stdout.flush()"
        started = time.monotonic()
        result = self.backend.run([PY, "-c", flood], cwd=self.cwd,
                                  limits=ResourceLimits(wall_clock_seconds=60, max_output_bytes=10_000))
        self.assertLess(time.monotonic() - started, 20, "the flood ran until the wall clock")
        self.assertTrue(result.output_limit_exceeded)
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.output), 10_000)
        self.assertFalse(result.timed_out)

    @unittest.skipIf(sys.platform == "darwin", "RLIMIT_AS is not enforced on macOS")
    def test_a_memory_limit_is_actually_enforced(self):
        hog = "x = bytearray(700 * 1024 * 1024); print('allocated')"
        result = self.backend.run([PY, "-c", hog], cwd=self.cwd,
                                  limits=ResourceLimits(wall_clock_seconds=30, max_memory_mb=256))
        # (the traceback echoes the source line, so look for the failure, not the word)
        self.assertIn(b"MemoryError", result.output)
        self.assertNotIn("allocated", result.output.decode().splitlines())
        self.assertNotEqual(result.exit_status, 0)

    def test_the_environment_is_scrubbed_of_secrets(self):
        planted = {"PENTEST_EVIDENCE_KEY": "evidence-key-marker", "WITHERHOARD_AUTH_VAULT_KEY": "vault-key-marker",
                   "HACKBOT_AUTH_VAULT_KEY": "legacy-vault-marker", "ANTHROPIC_API_KEY": "anthropic-marker",
                   "AWS_SECRET_ACCESS_KEY": "aws-marker", "GITHUB_TOKEN": "github-marker"}
        with patch.dict(os.environ, planted):
            result = self.backend.run([PY, "-c", "import os, json; print(json.dumps(dict(os.environ)))"],
                                      cwd=self.cwd, limits=ResourceLimits(wall_clock_seconds=15))
        text = result.output.decode()
        for marker in planted.values():
            self.assertNotIn(marker, text)
        for name in planted:
            self.assertNotIn(name, text)

    def test_the_result_is_honest_that_this_is_not_a_sandbox(self):
        result = self.backend.run([PY, "-c", "print(1)"], cwd=self.cwd, limits=ResourceLimits(wall_clock_seconds=15))
        self.assertEqual(result.isolation, "process")
        self.assertFalse(result.network_enforced)


class ToolParamTests(unittest.TestCase):
    def test_a_leading_dash_is_rejected_unless_the_parameter_opts_in(self):
        param = ToolParam("target")
        for value in ("-oX", "--output=/etc/cron.d/x", "-"):
            with self.assertRaises(ToolError, msg=value):
                param.coerce(value)
        self.assertEqual(param.coerce("example.test"), "example.test")
        self.assertEqual(ToolParam("flag", allow_leading_dash=True).coerce("-v"), "-v")

    def test_control_characters_and_overlong_values_are_rejected(self):
        param = ToolParam("v", max_length=10)
        for value in ("a\nb", "a\rb", "a\x00b", "a\x1bb", "x" * 11):
            with self.assertRaises(ToolError, msg=repr(value)):
                param.coerce(value)
        self.assertEqual(param.coerce("a\tb"), "a\tb")

    def test_integer_range_is_enforced(self):
        param = ToolParam("n", type="int", min_value=1, max_value=10)
        self.assertEqual(param.coerce("5"), "5")
        for value in (0, 11, -1, "x", None):
            with self.assertRaises(ToolError, msg=repr(value)):
                param.coerce(value)

    def test_a_catalog_style_pattern_does_not_re_admit_option_injection(self):
        domain = ToolParam("domain", pattern=r"[A-Za-z0-9._-]{1,253}")
        with self.assertRaises(ToolError):
            domain.coerce("-config")                      # matches the pattern, still an option

    def test_unknown_network_mode_is_refused_at_definition_time(self):
        with self.assertRaises(ToolError):
            ToolSpec("t", "t", "1", "p", command=("x",), network="host")


class ManagerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "s.sqlite3")
        migrate(self.db)
        self.store = StateStore(self.db)
        for engagement in ("eng-a", "eng-b"):
            self.store.create_engagement(engagement, "AUTH", {}, {}, status="active")
        self.ledger = ExecutionLedger(self.store.connection)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def manager(self, registry, **kwargs):
        return WorkerManager(self.store, self.root / "run", registry=registry, **kwargs)


class ManagerLifecycleTests(ManagerBase):
    def test_a_backend_failure_frees_the_slot_and_is_recorded(self):
        missing = ToolSpec("ghost", "ghost", "1", "p", command=("definitely-not-an-installed-binary-xyz",))
        manager = self.manager(make_registry(missing), max_active_workers_per_engagement=1)
        worker = manager.provision("eng-a", "t1")
        with self.assertRaisesRegex(WorkerError, "Tool execution failed"):
            manager.execute(worker, "ghost", {}, allowed_tools=["ghost"])
        self.assertEqual(manager.observability(worker.worker_id)["status"], "failed")
        # Before the fix the worker stayed "running" and permanently consumed the only slot.
        manager.provision("eng-a", "t2")
        (execution,) = self.ledger.list("eng-a")
        self.assertEqual(execution["status"], "FAILED")
        self.assertEqual(execution["failure"]["class"], "infrastructure")

    def test_cancelling_a_worker_stops_the_tool_that_is_running(self):
        sleeper = tool("sleeper", GRANDCHILD, timeout=60)
        registry = make_registry(sleeper)
        outcome, ready = {}, threading.Event()

        def run_in_its_own_thread():
            # A manager belongs to the thread that owns its DB connection (see its docstring).
            store = StateStore(self.db)
            try:
                runner = WorkerManager(store, self.root / "run", registry=registry)
                outcome["runner"] = runner
                outcome["worker"] = runner.provision("eng-a", "t")
                ready.set()
                outcome["result"] = runner.execute(outcome["worker"], "sleeper", {}, allowed_tools=["sleeper"])
            finally:
                store.close()

        thread = threading.Thread(target=run_in_its_own_thread)
        thread.start()
        self.assertTrue(ready.wait(15))
        worker = outcome["worker"]
        self.assertTrue(wait_until((worker.workdir / "grandchild.pid").exists, 15))
        self.assertTrue(outcome["runner"].request_cancel(worker.worker_id))   # any thread, no DB access
        thread.join(timeout=20)
        self.assertFalse(thread.is_alive(), "request_cancel() did not stop the running tool")
        self.assertTrue(outcome["result"]["cancelled"])
        self.assertEqual(self.manager(registry).observability(worker.worker_id)["status"], "cancelled")
        grandchild = int((worker.workdir / "grandchild.pid").read_text())
        self.assertTrue(wait_until(lambda: not pid_alive(grandchild), 10))
        self.assertEqual(self.ledger.list("eng-a")[0]["status"], "CANCELLED")

    def test_a_timed_out_tool_is_a_classified_failure_in_the_ledger(self):
        slow = tool("slow", "import time; time.sleep(30)", timeout=1)
        manager = self.manager(make_registry(slow))
        worker = manager.provision("eng-a", "t")
        result = manager.execute(worker, "slow", {}, allowed_tools=["slow"])
        self.assertTrue(result["timed_out"])
        (execution,) = self.ledger.list("eng-a")
        self.assertEqual((execution["status"], execution["failure"]["class"]), ("FAILED", "timeout"))

    def test_each_execution_is_recorded_with_its_resource_usage(self):
        echo = tool("echo", "print('hello')")
        manager = self.manager(make_registry(echo))
        worker = manager.provision("eng-a", "task-7")
        result = manager.execute(worker, "echo", {}, allowed_tools=["echo"])
        record = self.ledger.get(result["execution_id"], "eng-a")
        self.assertEqual((record["status"], record["task_id"], record["kind"], record["tool_id"]),
                         ("COMPLETED", "task-7", "tool", "echo"))
        self.assertEqual(record["exit_status"], 0)
        self.assertIn("duration_ms", record["resource_usage"])
        self.assertEqual(record["authorization"]["decision"], "allow")

    def test_concurrent_provisioning_never_exceeds_the_engagement_limit(self):
        manager = self.manager(make_registry(), max_active_workers_per_engagement=2)
        self.store.connection.commit()
        outcomes, barrier = [], threading.Barrier(8)

        def contender():
            store = StateStore(self.db)
            try:
                contender_manager = WorkerManager(store, self.root / "run", registry=ToolRegistry(),
                                                  max_active_workers_per_engagement=2)
                barrier.wait()
                try:
                    contender_manager.provision("eng-a", "t")
                    outcomes.append("ok")
                except WorkerError:
                    outcomes.append("refused")
            finally:
                store.close()

        threads = [threading.Thread(target=contender) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertEqual(sorted(outcomes), ["ok", "ok"] + ["refused"] * 6)
        del manager

    def test_a_restarted_manager_reconciles_orphans_without_rerunning_anything(self):
        marker = self.root / "ran.txt"
        crashed = WorkerManager(self.store, self.root / "run", registry=ToolRegistry(),
                                ledger=ExecutionLedger(self.store.connection, lease_seconds=0.01),
                                max_active_workers_per_engagement=1)
        worker = crashed.provision("eng-a", "t")
        execution_id = crashed.ledger.create(engagement_id="eng-a", kind="tool", tool_id="x", execution_profile="safe",
                                             external_ref=worker.worker_id)
        crashed.ledger.authorize(execution_id, {"decision": "allow", "source": "test"})
        crashed.ledger.start(execution_id)
        crashed.ledger.mark_dispatched(execution_id)
        time.sleep(0.05)                                    # the lease lapses: the process "died"
        restarted = WorkerManager(self.store, self.root / "run", registry=ToolRegistry(),
                                  max_active_workers_per_engagement=1)
        with self.assertRaisesRegex(WorkerError, "limit"):
            restarted.provision("eng-a", "t2")              # the orphan still holds the only slot
        report = restarted.reconcile_interrupted(orphan_after_seconds=0)
        self.assertEqual(report["workers_failed"], [worker.worker_id])
        self.assertEqual(report["executions"], [{"execution_id": execution_id, "to": "RECONCILIATION_REQUIRED"}])
        self.assertFalse(marker.exists())
        restarted.provision("eng-a", "t2")                  # slot recovered


class FilesystemIsolationTests(ManagerBase):
    def setUp(self):
        super().setUp()
        self.echo = tool("echo", "print('artifact-body')")
        self.manager_ = self.manager(make_registry(self.echo))

    def test_engagement_ids_that_could_escape_the_workspace_are_refused(self):
        for bad in ("../evil", "eng-a/../../x", "..", "a b", "C:evil", "eng-a\\x", "", "x" * 300):
            with self.assertRaises(WorkerError, msg=repr(bad)):
                self.manager_.provision(bad, "t")

    def test_a_worker_cannot_read_another_workers_files_by_traversal(self):
        a = self.manager_.provision("eng-a", "t")
        self.manager_.execute(a, "echo", {}, allowed_tools=["echo"])
        b = self.manager_.provision("eng-b", "t")
        for name in (f"../../eng-a/{a.worker_id}/out_0_echo.log", f"..\\..\\eng-a\\{a.worker_id}\\out_0_echo.log",
                     str(a.workdir / "out_0_echo.log"), "/etc/passwd", "C:/Windows/win.ini", "", "."):
            with self.assertRaises(WorkerError, msg=name):
                self.manager_.read_artifact(b, name)

    def test_a_planted_symlink_or_junction_cannot_redirect_a_read(self):
        a = self.manager_.provision("eng-a", "t")
        self.manager_.execute(a, "echo", {}, allowed_tools=["echo"])
        b = self.manager_.provision("eng-b", "t")
        make_dir_link(b.workdir / "peek", a.workdir)               # what a hostile tool could create
        with self.assertRaises(WorkerError):
            self.manager_.read_artifact(b, "peek/out_0_echo.log")
        self.assertIn(b"artifact-body", self.manager_.read_artifact(a, "out_0_echo.log"))

    def test_teardown_removes_a_tool_created_link_without_following_it(self):
        a = self.manager_.provision("eng-a", "t")
        b = self.manager_.provision("eng-b", "t")
        (b.workdir / "keep.txt").write_text("must survive", encoding="utf-8")
        make_dir_link(a.workdir / "link-to-b", b.workdir)
        self.manager_.teardown(a)
        self.assertFalse(a.workdir.exists())
        self.assertTrue((b.workdir / "keep.txt").exists(), "teardown followed a link into another worker")


class IsolationPolicyTests(ManagerBase):
    def test_require_isolation_refuses_the_unsandboxed_backend(self):
        with self.assertRaisesRegex(WorkerError, "container backend"):
            self.manager(make_registry(), require_isolation=True)

    def test_a_container_backend_satisfies_require_isolation_and_reports_sandboxed(self):
        backend = ContainerWorkerBackend("img:1", runner=lambda *a, **k: None)
        manager = self.manager(make_registry(), backend=backend, require_isolation=True)
        worker = manager.provision("eng-a", "t")
        self.assertTrue(manager.observability(worker.worker_id)["sandboxed"])

    def test_the_default_manager_reports_that_it_is_not_sandboxed(self):
        manager = self.manager(make_registry())
        worker = manager.provision("eng-a", "t")
        self.assertFalse(manager.observability(worker.worker_id)["sandboxed"])


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys, time
log = os.environ.get("FAKE_DOCKER_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(sys.argv[1:]) + "\n")
command = sys.argv[1] if len(sys.argv) > 1 else ""
mode = os.environ.get("FAKE_DOCKER_MODE", "ok")
if command == "version":
    if mode == "daemon-down":
        sys.stderr.write("Cannot connect to the Docker daemon\n")
        sys.exit(1)
    print("27.0.1")
elif command == "run":
    if mode == "hang":
        time.sleep(120)
    if mode == "alloc":
        block = bytearray(200 * 1024 * 1024)
        print("client-allocated-200mb")
        sys.exit(0)
    print("tool-output-from-container")
elif command == "ps":
    print(os.environ.get("FAKE_DOCKER_PS", ""))
elif command == "image":
    print(os.environ.get("FAKE_DOCKER_IMAGE_INSPECT", "[]"))
'''
DIGEST = "sha256:" + "ab" * 32


class ContainerBackendLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        fake = self.root / "docker"
        fake.write_text(FAKE_DOCKER, encoding="utf-8")
        self.docker = finalize_fake_cli(fake)
        self.log = self.root / "docker.log"
        self.env = {"FAKE_DOCKER_LOG": str(self.log)}
        self.patcher = patch.dict(os.environ, self.env)
        self.patcher.start()
        self.workdir = self.root / "work"
        self.workdir.mkdir()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def backend(self, **kwargs):
        return ContainerWorkerBackend("witherhoard/tool:1", docker_bin=self.docker, **kwargs)

    # -- fail closed -------------------------------------------------------------------
    def test_a_missing_runtime_fails_closed_and_nothing_runs_unsandboxed(self):
        backend = ContainerWorkerBackend("img:1", docker_bin=str(self.root / "no-such-docker"))
        with self.assertRaises(ContainerRuntimeUnavailable):
            backend.preflight()
        with self.assertRaises(ContainerRuntimeUnavailable):
            backend.run(["echo", "x"], cwd=str(self.workdir), limits=ResourceLimits())

    def test_an_unreachable_daemon_fails_closed(self):
        with patch.dict(os.environ, {"FAKE_DOCKER_MODE": "daemon-down"}):
            with self.assertRaisesRegex(ContainerRuntimeUnavailable, "not reachable"):
                self.backend().preflight()

    def test_the_manager_never_falls_back_to_a_subprocess_when_the_runtime_is_missing(self):
        marker = self.root / "tool-ran.txt"
        code = f"open({str(marker)!r}, 'w').write('ran')"
        db = str(self.root / "s.sqlite3")
        migrate(db)
        store = StateStore(db)
        try:
            store.create_engagement("eng-a", "AUTH", {}, {}, status="active")
            backend = ContainerWorkerBackend("img:1", docker_bin=str(self.root / "no-such-docker"))
            manager = WorkerManager(store, self.root / "run", backend=backend, require_isolation=True,
                                    registry=make_registry(tool("writer", code)))
            worker = manager.provision("eng-a", "t")
            with self.assertRaisesRegex(WorkerError, "Tool execution failed"):
                manager.execute(worker, "writer", {}, allowed_tools=["writer"])
            self.assertFalse(marker.exists(), "the tool ran on the host despite the container requirement")
            self.assertEqual(manager.observability(worker.worker_id)["status"], "failed")
        finally:
            store.close()

    # -- hardening of the constructed command ---------------------------------------------
    def test_the_command_carries_every_required_hardening_flag(self):
        argv = self.backend().build_argv(["scan", "target"], cwd=str(self.workdir),
                                         limits=ResourceLimits(max_memory_mb=256, max_processes=32, max_cpus=0.5))
        image_at = argv.index("witherhoard/tool:1")
        head = argv[:image_at]
        joined = " ".join(head)
        for required in ("--read-only", "--cap-drop=ALL", "no-new-privileges", "--pids-limit 32",
                         "--memory 256m", "--memory-swap 256m", "--cpus 0.5", "--network none",
                         "--user 65534:65534", "--pull never", "--init", "--ipc none", "--rm",
                         "--label witherhoard.managed=true", ",dst=/evidence,ro"):
            self.assertIn(required, joined)
        self.assertEqual(argv[image_at + 1:], ["scan", "target"])
        for forbidden in ("--privileged", "docker.sock", "--cap-add", "--network host", "--net=host",
                          "--pid host", "--device", "unconfined", "--volumes-from"):
            self.assertNotIn(forbidden, joined)

    def test_container_names_are_unique_and_the_image_never_starts_with_a_dash(self):
        backend = self.backend()
        names = {backend.build_argv(["x"], cwd=str(self.workdir), limits=ResourceLimits())[
            backend.build_argv(["x"], cwd=str(self.workdir), limits=ResourceLimits()).index("--name") + 1]
            for _ in range(5)}
        self.assertEqual(len(names), 5)
        for bad in ("--privileged", "img with space", "img;rm", "", "-v", "a" * 400):
            with self.assertRaises(ContainerConfigError, msg=bad):
                ContainerWorkerBackend(bad)

    def test_a_mount_source_that_could_append_mount_options_is_refused(self):
        backend = self.backend()
        for hostile in ("/runs/eng,src=/etc,dst=/x", '/runs/"quoted"', "/runs/a\nb"):
            with self.assertRaises(ContainerConfigError, msg=hostile):
                backend.build_argv(["x"], cwd=hostile, limits=ResourceLimits())

    def test_root_is_refused_and_digest_pinning_can_be_required(self):
        for user in ("0:0", "root:root", "0"):
            with self.assertRaises(ContainerConfigError, msg=user):
                ContainerWorkerBackend("img:1", run_as=user)
        with self.assertRaises(ContainerConfigError):
            ContainerWorkerBackend("witherhoard/tool:1", require_pinned_image=True)
        pinned = ContainerWorkerBackend("witherhoard/tool@" + DIGEST, require_pinned_image=True)
        self.assertTrue(pinned.describe()["image_pinned"])

    def test_the_pinned_digest_must_actually_be_present_in_the_runtime(self):
        backend = ContainerWorkerBackend("witherhoard/tool@" + DIGEST, docker_bin=self.docker, require_pinned_image=True)
        with patch.dict(os.environ, {"FAKE_DOCKER_IMAGE_INSPECT": json.dumps(["witherhoard/tool@" + DIGEST])}):
            self.assertTrue(backend.verify_image())
        with patch.dict(os.environ, {"FAKE_DOCKER_IMAGE_INSPECT": json.dumps(["witherhoard/tool@sha256:" + "cd" * 32])}):
            with self.assertRaises(ContainerConfigError):
                backend.verify_image()

    # -- network -------------------------------------------------------------------------
    def test_network_access_requires_an_operator_provisioned_network_never_the_default_bridge(self):
        with self.assertRaisesRegex(ContainerConfigError, "egress network"):
            self.backend().build_argv(["x"], cwd=str(self.workdir), limits=ResourceLimits(), network="egress_allowlist")
        configured = self.backend(egress_network="witherhoard-egress", dns_servers=("10.9.0.2",))
        argv = configured.build_argv(["x"], cwd=str(self.workdir), limits=ResourceLimits(), network="egress_allowlist")
        joined = " ".join(argv)
        self.assertIn("--network witherhoard-egress", joined)
        self.assertIn("--dns 10.9.0.2", joined)
        self.assertNotIn("bridge", joined)
        with self.assertRaises(ContainerConfigError):
            configured.build_argv(["x"], cwd=str(self.workdir), limits=ResourceLimits(), network="host")

    # -- lifecycle against the fake runtime -------------------------------------------------
    def test_a_normal_run_removes_its_container_and_reports_container_isolation(self):
        result = self.backend().run(["scan"], cwd=str(self.workdir), limits=ResourceLimits(wall_clock_seconds=20),
                                    env=self.env)
        self.assertIn(b"tool-output-from-container", result.output)
        self.assertEqual((result.isolation, result.network_enforced), ("container", True))
        verbs = [call[0] for call in self.calls()]
        self.assertEqual(verbs[0], "version")
        self.assertIn("run", verbs)
        self.assertEqual(verbs[-1], "rm")
        name = result.detail["container"]
        self.assertEqual(self.calls()[-1], ["rm", "-f", name])

    def test_the_docker_client_is_not_held_to_the_tools_resource_limits(self):
        """The cgroup limits the tool *inside* the container. The same address-space / process limit on
        the local ``docker`` client (a Go binary that reserves address space and spawns threads) would
        crash it, so the client is bounded by wall clock and output only. The container still gets them."""
        env = {**self.env, "FAKE_DOCKER_MODE": "alloc"}
        with patch.dict(os.environ, {"FAKE_DOCKER_MODE": "alloc"}):
            result = self.backend().run(["scan"], cwd=str(self.workdir),
                                        limits=ResourceLimits(wall_clock_seconds=20, max_memory_mb=64,
                                                              max_processes=16), env=env)
        self.assertEqual(result.exit_status, 0, result.output)
        self.assertIn(b"client-allocated-200mb", result.output)
        (run_call,) = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(run_call[run_call.index("--memory") + 1], "64m")
        self.assertEqual(run_call[run_call.index("--pids-limit") + 1], "16")

    def test_the_tools_own_subprocess_backend_still_enforces_its_memory_limit(self):
        """Counterpart: the *subprocess* backend has no container, so there the limit stays on the process."""
        code = "b = bytearray(200 * 1024 * 1024); print('ALLOC-' + 'OK')"      # marker is not contiguous in the source
        result = SubprocessWorkerBackend().run([PY, "-c", code], cwd=str(self.workdir),
                                               limits=ResourceLimits(wall_clock_seconds=20, max_memory_mb=64))
        self.assertNotEqual(result.exit_status, 0)
        self.assertNotIn(b"ALLOC-OK", result.output)

    def test_a_timeout_kills_and_removes_the_container_not_just_the_client(self):
        env = {**self.env, "FAKE_DOCKER_MODE": "hang"}
        with patch.dict(os.environ, {"FAKE_DOCKER_MODE": "hang"}):
            result = self.backend().run(["scan"], cwd=str(self.workdir),
                                        limits=ResourceLimits(wall_clock_seconds=1), env=env)
        self.assertTrue(result.timed_out)
        name = result.detail["container"]
        calls = self.calls()
        self.assertIn(["kill", name], calls, "the container kept running after its client was killed")
        self.assertLess(calls.index(["kill", name]), calls.index(["rm", "-f", name]))

    def test_cancellation_kills_the_container(self):
        token = CancelToken()
        threading.Timer(0.8, token.cancel).start()
        env = {**self.env, "FAKE_DOCKER_MODE": "hang"}
        with patch.dict(os.environ, {"FAKE_DOCKER_MODE": "hang"}):
            result = self.backend().run(["scan"], cwd=str(self.workdir),
                                        limits=ResourceLimits(wall_clock_seconds=60), env=env, cancel=token)
        self.assertTrue(result.cancelled)
        self.assertIn(["kill", result.detail["container"]], self.calls())

    def test_orphaned_containers_are_found_by_label_and_removed(self):
        with patch.dict(os.environ, {"FAKE_DOCKER_PS": "abc123\ndef456"}):
            self.assertEqual(self.backend().cleanup_orphans(), 2)
        calls = self.calls()
        self.assertIn(["ps", "-aq", "--filter", "label=witherhoard.managed=true"], calls)
        self.assertIn(["rm", "-f", "abc123"], calls)
        self.assertIn(["rm", "-f", "def456"], calls)

    def test_lifecycle_is_audited(self):
        events = []
        self.backend(audit=lambda event, details: events.append(event)).run(
            ["scan"], cwd=str(self.workdir), limits=ResourceLimits(wall_clock_seconds=20), env=self.env)
        self.assertEqual(events, ["container.starting", "container.removed"])


class _FakeResource:
    """Stands in for the POSIX ``resource`` module so the limit arithmetic is testable on any platform."""
    RLIMIT_CPU, RLIMIT_AS, RLIMIT_NPROC, RLIMIT_FSIZE = 0, 9, 6, 1

    def __init__(self):
        self.calls = []

    def setrlimit(self, which, values):
        self.calls.append((which, values))


class ProcessLimitTests(unittest.TestCase):
    """``RLIMIT_NPROC`` is compared by the kernel with every task of the same user on the host. An absolute
    value below that count makes fork and thread creation fail for the tool (EAGAIN), so on a busy host or
    CI runner a Go tool could not even start. The limit is therefore relative: baseline + max_processes."""

    def proc_tree(self, layout):
        """layout: {pid: (uid, thread_count)} -> a fake /proc and a stat function reporting those owners."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        owners = {}
        for pid, (uid, threads) in layout.items():
            (root / str(pid) / "task").mkdir(parents=True)
            for tid in range(threads):
                (root / str(pid) / "task" / str(pid + tid)).mkdir()
            owners[str(root / str(pid)).replace("\\", "/")] = uid
        (root / "self").mkdir()                                   # non-numeric entries are not processes
        (root / "cpuinfo").write_text("x", encoding="utf-8")

        def fake_stat(path):
            normalized = str(path).replace("\\", "/")
            if normalized not in owners:
                raise FileNotFoundError(path)
            return type("Stat", (), {"st_uid": owners[normalized]})()
        return str(root), fake_stat

    def test_the_count_includes_threads_and_only_the_users_own_tasks(self):
        root, fake_stat = self.proc_tree({1: (0, 3), 100: (1000, 4), 101: (1000, 1), 200: (2000, 9)})
        self.assertEqual(_count_user_tasks(root, 1000, stat=fake_stat), 5)
        self.assertEqual(_count_user_tasks(root, 0, stat=fake_stat), 3)
        self.assertEqual(_count_user_tasks(root, 4242, stat=fake_stat), 0)

    def test_a_process_that_exits_while_being_counted_is_ignored(self):
        root, fake_stat = self.proc_tree({100: (1000, 2), 101: (1000, 2)})

        def flaky_stat(path):
            if str(path).replace("\\", "/").endswith("/101"):
                raise FileNotFoundError(path)
            return fake_stat(path)
        self.assertEqual(_count_user_tasks(root, 1000, stat=flaky_stat), 2)

    def test_without_proc_there_is_no_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(_count_user_tasks(str(Path(directory) / "absent"), 1000))

    def test_the_process_limit_is_the_baseline_plus_what_the_tool_may_add(self):
        fake = _FakeResource()
        limits = ResourceLimits(wall_clock_seconds=10, max_memory_mb=256, max_processes=64, max_output_bytes=1000)
        with patch("core.workers.backends._posix_resource", fake):
            apply = SubprocessWorkerBackend()._preexec(limits, task_baseline=100)
            apply()
        applied = dict(fake.calls)
        self.assertEqual(applied[fake.RLIMIT_NPROC], (164, 164))
        self.assertEqual(applied[fake.RLIMIT_AS], (256 * 1024 * 1024,) * 2)
        self.assertEqual(applied[fake.RLIMIT_CPU], (11, 11))
        self.assertEqual(applied[fake.RLIMIT_FSIZE], (4000, 4000))

    def test_without_a_baseline_no_absolute_process_limit_is_imposed(self):
        fake = _FakeResource()
        with patch("core.workers.backends._posix_resource", fake):
            SubprocessWorkerBackend()._preexec(ResourceLimits(max_processes=64), task_baseline=None)()
        self.assertNotIn(fake.RLIMIT_NPROC, dict(fake.calls))
        self.assertIn(fake.RLIMIT_AS, dict(fake.calls), "the other limits must still be applied")

    def test_a_refused_process_limit_does_not_abort_the_launch(self):
        class Refusing(_FakeResource):
            def setrlimit(self, which, values):
                if which == self.RLIMIT_NPROC:
                    raise ValueError("current limit exceeds maximum limit")
                super().setrlimit(which, values)
        fake = Refusing()
        with patch("core.workers.backends._posix_resource", fake):
            SubprocessWorkerBackend()._preexec(ResourceLimits(), task_baseline=10)()
        self.assertIn(fake.RLIMIT_FSIZE, dict(fake.calls))

    def test_there_are_no_posix_limits_where_the_module_is_missing(self):
        with patch("core.workers.backends._posix_resource", None):
            self.assertIsNone(SubprocessWorkerBackend()._preexec(ResourceLimits(), task_baseline=10))

    def test_the_result_reports_the_process_limit_only_when_it_was_really_applied(self):
        if os.name == "nt":
            self.skipTest("the Windows Job Object path reports its own limits")
        with patch("core.workers.backends._count_user_tasks", return_value=None):
            with tempfile.TemporaryDirectory() as directory:
                result = SubprocessWorkerBackend().run([PY, "-c", "print(1)"], cwd=directory,
                                                       limits=ResourceLimits(wall_clock_seconds=15))
        self.assertFalse(result.detail["limits_enforced"]["processes"])


if __name__ == "__main__":
    unittest.main()
