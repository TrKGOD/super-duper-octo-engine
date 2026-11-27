"""Verify, against a REAL container runtime, the isolation the container backend claims.

``tests/test_worker_hardening.py`` drives the container backend through a fake ``docker`` so our own
lifecycle code (preflight, naming, kill, rm, orphan cleanup, fail-closed) is tested everywhere. That
proves our logic, not Docker's isolation. The tests here check what the *kernel and runtime* actually
did: non-root user, no capabilities, read-only root, read-only evidence mount, no network interface
but loopback, cgroup limits, kill-and-remove on timeout and cancel, and that nothing is pulled.

Gate
----
``WITHERHOARD_CONTAINER_TESTS=1`` turns the class on.

* gate unset -> every test is skipped with an explicit reason (a default run needs no runtime);
* gate set   -> a missing runtime or image is a hard FAILURE, never a skip. The dedicated
  ``container-isolation`` CI job sets the gate, so "the isolation was not verified" can never be
  reported as green.

Prerequisites: a Docker-compatible runtime and the image ``WITHERHOARD_CONTAINER_TEST_IMAGE``
(default ``busybox:1.36``) already present locally — the backend runs with ``--pull never`` by design.

``test_orphan_cleanup_*`` removes every container labelled ``witherhoard.managed=true``; it refuses to
run when such containers already exist (they may belong to a real assessment).
"""
import os
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from core.workers import (CancelToken, ContainerConfigError, ContainerRuntimeUnavailable,
                          ContainerWorkerBackend, ResourceLimits)
from tests.support import wait_until

GATE = "WITHERHOARD_CONTAINER_TESTS"
DEDICATED = "WITHERHOARD_CONTAINER_TESTS_DEDICATED_RUNTIME"     # set by CI: nothing else runs on this runtime
IMAGE = os.environ.get("WITHERHOARD_CONTAINER_TEST_IMAGE", "busybox:1.36")
ENABLED = os.environ.get(GATE) == "1"
LABEL = "witherhoard.managed=true"


def require_runtime(backend: ContainerWorkerBackend, image: str) -> dict:
    """Fail loudly (never skip) when the gate is on but the runtime or image is not usable."""
    try:
        info = backend.preflight()
    except ContainerRuntimeUnavailable as exc:
        raise AssertionError(f"{GATE}=1 but no usable container runtime: {exc}") from exc
    if backend._docker("image", "inspect", image).returncode != 0:
        raise AssertionError(f"{GATE}=1 but image '{image}' is not present locally and the backend never "
                             f"pulls. Provision it first: docker pull {image}")
    return info


# Scripts executed *inside* the container with `sh -c`. They only read the container's own view of
# itself (identity, capability bits, mounts, interfaces, cgroup limits) or try an operation that the
# isolation must refuse. None of them touches the host network.
SCRIPT_IDENTITY = "echo UID=$(id -u); echo GID=$(id -g)"
SCRIPT_KERNEL_STATE = (
    "grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status | tr '\\t' '_'")
SCRIPT_ROOT_FS = "if touch /probe 2>/dev/null; then echo ROOT=WRITABLE; else echo ROOT=READONLY; fi"
SCRIPT_EVIDENCE = (
    "cat /evidence/seed.txt; "
    "if touch /evidence/planted 2>/dev/null; then echo EVIDENCE=WRITABLE; else echo EVIDENCE=READONLY; fi")
SCRIPT_NETWORK = "for n in $(ls /sys/class/net); do echo IFACE=$n; done"
SCRIPT_NOEXEC = (          # the copy keeps the name "busybox" so that, if executed, it really runs the applet
    "cp /bin/busybox /tmp/busybox && if /tmp/busybox true 2>/dev/null; then echo TMPEXEC=ALLOWED; "
    "else echo TMPEXEC=DENIED; fi")
SCRIPT_HOST_VIEW = (
    "echo PROCS=$(ls /proc | grep -c '^[0-9][0-9]*$'); "
    "if [ -e /var/run/docker.sock ]; then echo SOCKET=PRESENT; else echo SOCKET=ABSENT; fi; "
    "echo SECRETS=$(env | grep -c WITHERHOARD_TEST_SECRET)")
SCRIPT_CGROUP = (
    "for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do "
    "if [ -r \"$f\" ]; then echo MEMORY=$(cat \"$f\"); break; fi; done; "
    "for f in /sys/fs/cgroup/pids.max /sys/fs/cgroup/pids/pids.max; do "
    "if [ -r \"$f\" ]; then echo PIDS=$(cat \"$f\"); break; fi; done")


def parse(output: bytes) -> dict:
    """KEY=VALUE lines of a script's output (docker warnings and other lines are ignored)."""
    values: dict = {}
    for line in output.decode("utf-8", "replace").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.isupper():
            values.setdefault(key, []).append(value)
    return values


class GateSemanticsTests(unittest.TestCase):
    """Run everywhere: the gate must fail closed, not skip, when asked to verify without a runtime."""

    def test_a_missing_runtime_is_a_failure_not_a_skip_when_the_gate_is_on(self):
        backend = ContainerWorkerBackend(IMAGE, docker_bin="definitely-not-a-container-runtime")
        with self.assertRaisesRegex(AssertionError, "no usable container runtime"):
            require_runtime(backend, IMAGE)

    def test_the_scripts_are_plain_posix_sh(self):
        import shutil
        import subprocess
        shell = shutil.which("sh") or shutil.which("bash")
        if shell is None:
            self.skipTest("no POSIX shell on this host to syntax-check the in-container scripts")
        for name, script in [(n, v) for n, v in globals().items() if n.startswith("SCRIPT_")]:
            check = subprocess.run([shell, "-n", "-c", script], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, f"{name}: {check.stderr}")


@unittest.skipUnless(ENABLED, f"set {GATE}=1 to verify isolation against a real container runtime")
class ContainerIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = ContainerWorkerBackend(IMAGE)
        cls.info = require_runtime(cls.backend, IMAGE)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.evidence = Path(self._tmp.name)
        os.chmod(self.evidence, 0o755)                           # the container runs as 65534, not as us
        seed = self.evidence / "seed.txt"
        seed.write_text("evidence-seed\n", encoding="utf-8")
        os.chmod(seed, 0o644)
        self.containers = []                                     # names to force-remove afterwards
        self.addCleanup(self._remove_leftovers)

    def _remove_leftovers(self):
        for name in filter(None, self.containers):
            self.backend._docker("rm", "-f", name, timeout=30)

    # -- helpers ------------------------------------------------------------------------
    def sh(self, script, *, seconds=30, limits=None, cancel=None, backend=None):
        limits = limits or ResourceLimits(wall_clock_seconds=seconds, max_memory_mb=128, max_processes=32)
        result = (backend or self.backend).run(["sh", "-c", script], cwd=str(self.evidence),
                                               limits=limits, cancel=cancel)
        self.containers.append(result.detail.get("container", ""))
        return result

    def exists(self, name) -> bool:
        listing = self.backend._docker("ps", "-aq", "--filter", f"name=^{name}$")
        return bool(listing.stdout.strip())

    def assert_removed(self, name, why):
        self.assertTrue(wait_until(lambda: not self.exists(name), timeout=15, interval=0.5), why)

    # -- who and with what privileges ---------------------------------------------------------
    def test_the_tool_runs_unprivileged_in_a_normal_run(self):
        result = self.sh(SCRIPT_IDENTITY)
        self.assertEqual(result.exit_status, 0, result.output)
        values = parse(result.output)
        self.assertEqual(values.get("UID"), ["65534"], result.output)
        self.assertEqual(values.get("GID"), ["65534"], result.output)
        self.assertEqual((result.isolation, result.network_enforced), ("container", True))
        self.assertFalse(result.timed_out)

    def test_every_capability_is_dropped_and_privilege_escalation_is_blocked(self):
        result = self.sh(SCRIPT_KERNEL_STATE)
        text = result.output.decode("utf-8", "replace")
        self.assertIn("CapEff:_0000000000000000", text, text)
        self.assertIn("CapBnd:_0000000000000000", text, text)
        self.assertIn("NoNewPrivs:_1", text, text)
        self.assertIn("Seccomp:_2", text, "the runtime's default seccomp filter is not active: " + text)

    # -- filesystem ---------------------------------------------------------------------------
    def test_the_root_filesystem_is_read_only(self):
        result = self.sh(SCRIPT_ROOT_FS)
        self.assertEqual(parse(result.output).get("ROOT"), ["READONLY"], result.output)

    def test_the_evidence_mount_is_readable_but_not_writable_and_the_host_is_untouched(self):
        result = self.sh(SCRIPT_EVIDENCE)
        text = result.output.decode("utf-8", "replace")
        self.assertIn("evidence-seed", text, text)
        self.assertEqual(parse(result.output).get("EVIDENCE"), ["READONLY"], text)
        self.assertEqual(sorted(path.name for path in self.evidence.iterdir()), ["seed.txt"])

    def test_scratch_space_cannot_execute_binaries(self):
        result = self.sh(SCRIPT_NOEXEC)
        self.assertEqual(parse(result.output).get("TMPEXEC"), ["DENIED"], result.output)

    # -- network and host visibility ------------------------------------------------------------
    def test_there_is_no_network_interface_except_loopback(self):
        result = self.sh(SCRIPT_NETWORK)
        self.assertEqual(sorted(parse(result.output).get("IFACE", [])), ["lo"], result.output)

    def test_the_host_is_not_visible_from_inside(self):
        with patch.dict(os.environ, {"WITHERHOARD_TEST_SECRET": "must-not-leak"}):
            result = self.sh(SCRIPT_HOST_VIEW)
        values = parse(result.output)
        self.assertEqual(values.get("SOCKET"), ["ABSENT"], result.output)
        self.assertEqual(values.get("SECRETS"), ["0"], "a host environment variable reached the tool")
        self.assertLess(int(values.get("PROCS", ["999"])[0]), 12,
                        "the tool can see host processes (PID namespace shared?)")

    # -- resource limits --------------------------------------------------------------------------
    def test_memory_and_process_limits_are_applied_by_the_runtime_cgroup(self):
        limits = ResourceLimits(wall_clock_seconds=30, max_memory_mb=96, max_processes=24)
        values = parse(self.sh(SCRIPT_CGROUP, limits=limits).output)
        self.assertEqual(values.get("MEMORY"), [str(96 * 1024 * 1024)],
                         "the runtime did not apply --memory (rootless without cgroup delegation?)")
        self.assertEqual(values.get("PIDS"), ["24"], "the runtime did not apply --pids-limit")

    # -- lifecycle ----------------------------------------------------------------------------
    def test_a_finished_container_is_removed(self):
        result = self.sh("echo done")
        self.assertEqual(result.exit_status, 0, result.output)
        self.assert_removed(result.detail["container"], "a finished container was left behind")

    def test_a_timeout_kills_the_container_and_removes_it(self):
        started = time.monotonic()
        result = self.sh("sleep 120", seconds=8)                 # long enough for a cold start to be running
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 40, "the container outlived its timeout")
        self.assert_removed(result.detail["container"], "container still present after timeout")

    def test_cancellation_kills_the_container_and_removes_it(self):
        token = CancelToken()

        def cancel_once_running():
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                running = self.backend._docker("ps", "-q", "--filter", "label=" + LABEL, "--filter", "status=running")
                if running.stdout.strip():
                    token.cancel()
                    return
                time.sleep(0.2)
            token.cancel()                                       # never became visible: still end the test

        threading.Thread(target=cancel_once_running, daemon=True).start()
        started = time.monotonic()
        result = self.sh("sleep 120", seconds=90, cancel=token)
        self.assertTrue(result.cancelled)
        self.assertLess(time.monotonic() - started, 60)
        self.assert_removed(result.detail["container"], "container still present after cancel")

    def test_orphan_cleanup_removes_framework_containers_and_nothing_else(self):
        existing = self.backend._docker("ps", "-aq", "--filter", "label=" + LABEL).stdout.strip()
        if existing and os.environ.get(DEDICATED) != "1":
            self.skipTest("labelled containers already exist on this runtime and it is not declared dedicated "
                          f"({DEDICATED}=1); refusing to sweep what may be a real assessment")
        suffix = uuid.uuid4().hex[:8]
        ours, other = f"wh-it-orphan-{suffix}", f"other-it-{suffix}"
        self.containers += [ours, other]
        common = ["--network", "none", "--read-only", "--cap-drop=ALL"]
        for name, extra in ((ours, ["--label", LABEL]), (other, [])):
            started = self.backend._docker("run", "-d", "--name", name, *extra, *common, IMAGE, "sleep", "120",
                                           timeout=60)
            self.assertEqual(started.returncode, 0, started.stderr)
        self.assertGreaterEqual(self.backend.cleanup_orphans(), 1)
        self.assertFalse(self.exists(ours), "the framework container survived orphan cleanup")
        self.assertTrue(self.exists(other), "orphan cleanup removed a container that is not ours")

    # -- images ------------------------------------------------------------------------------
    def test_a_missing_image_is_never_pulled(self):
        ghost = f"witherhoard-test.invalid/never-pulled-{uuid.uuid4().hex[:8]}:0"
        result = self.sh("echo should-not-run", backend=ContainerWorkerBackend(ghost))
        self.assertNotEqual(result.exit_status, 0)
        self.assertNotIn(b"should-not-run", result.output)
        self.assertNotEqual(self.backend._docker("image", "inspect", ghost).returncode, 0)

    def test_digest_pinning_verifies_the_local_image(self):
        listing = self.backend._docker("image", "inspect", "--format", "{{index .RepoDigests 0}}", IMAGE)
        digest_ref = listing.stdout.strip()
        if listing.returncode != 0 or "@sha256:" not in digest_ref:
            self.skipTest("the test image has no registry digest (it was built locally, not pulled)")
        pinned = ContainerWorkerBackend(digest_ref, require_pinned_image=True)
        self.assertTrue(pinned.verify_image())
        self.assertEqual(self.sh("echo pinned", backend=pinned).exit_status, 0)
        with self.assertRaises(ContainerConfigError):
            ContainerWorkerBackend(f"{digest_ref.split('@')[0]}@sha256:{'0' * 64}",
                                   require_pinned_image=True).verify_image()


if __name__ == "__main__":
    unittest.main()
