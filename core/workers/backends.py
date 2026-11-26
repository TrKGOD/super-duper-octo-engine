"""Worker execution backends.

Two backends share one interface. The **subprocess** backend is portable and always
enforces a wall-clock timeout and an output ceiling (via pipe backpressure plus a draining
reader), runs with no shell, an isolated working directory and a scrubbed environment, and
on POSIX also applies CPU/memory/process rlimits. It is **not** a security sandbox: it does
not isolate the filesystem or network from the host. The **container** backend is the real
isolation boundary; it builds a hardened `docker run` invocation (read-only root, dropped
capabilities, no-new-privileges, pids/memory/cpu limits, no host network by default, no
privileged mode, no docker socket) and is the backend to use for untrusted tools. See
docs/ISOLATED_EXECUTION.md for the threat model and residual risks.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time

from core.workers.resources import ExecutionResult, ResourceLimits

try:  # POSIX-only resource limits
    import resource as _posix_resource
except ImportError:  # pragma: no cover - Windows
    _posix_resource = None


def _scrubbed_env(workdir: str, extra: dict | None = None) -> dict:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": workdir, "TMPDIR": workdir, "TEMP": workdir, "TMP": workdir,
        "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
    }
    # Preserve only OS-essential variables so an interpreter can start; never inherit
    # secrets or the broader environment.
    for key in ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "PATHEXT", "NUMBER_OF_PROCESSORS", "COMSPEC"):
        if key in os.environ:
            env[key] = os.environ[key]
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


class WorkerBackend:
    name = "abstract"

    def run(self, argv, *, cwd, limits: ResourceLimits, env=None) -> ExecutionResult:  # pragma: no cover
        raise NotImplementedError


class SubprocessWorkerBackend(WorkerBackend):
    """Portable bounded execution. Resource-bounded, not a security sandbox."""
    name = "subprocess"

    def _preexec(self, limits: ResourceLimits):
        if _posix_resource is None:
            return None

        def apply():  # pragma: no cover - POSIX only, exercised in CI not on Windows
            os.setsid()
            cpu = max(1, int(limits.wall_clock_seconds) + 1)
            _posix_resource.setrlimit(_posix_resource.RLIMIT_CPU, (cpu, cpu))
            mem = limits.max_memory_mb * 1024 * 1024
            _posix_resource.setrlimit(_posix_resource.RLIMIT_AS, (mem, mem))
            try:
                _posix_resource.setrlimit(_posix_resource.RLIMIT_NPROC,
                                          (limits.max_processes, limits.max_processes))
            except (ValueError, OSError):
                pass
            _posix_resource.setrlimit(_posix_resource.RLIMIT_FSIZE,
                                      (limits.max_output_bytes * 4, limits.max_output_bytes * 4))
        return apply

    def run(self, argv, *, cwd, limits: ResourceLimits, env=None) -> ExecutionResult:
        limits.validate()
        argv = [str(token) for token in argv]
        started = time.monotonic()
        proc = subprocess.Popen(
            argv, cwd=cwd, env=_scrubbed_env(cwd, env), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False,
            preexec_fn=self._preexec(limits) if _posix_resource is not None else None,
        )
        kept = bytearray()
        truncated = {"value": False}

        def drain():
            while True:
                chunk = proc.stdout.read(8192)
                if not chunk:
                    break
                remaining = limits.max_output_bytes - len(kept)
                if remaining > 0:
                    kept.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated["value"] = True
                else:
                    truncated["value"] = True  # keep draining so the process can finish

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()

        timed_out = False
        try:
            try:
                proc.wait(timeout=limits.wall_clock_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill(proc)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            reader.join(timeout=5)
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
        duration_ms = int((time.monotonic() - started) * 1000)
        return ExecutionResult(
            exit_status=proc.returncode, output=bytes(kept), truncated=truncated["value"],
            timed_out=timed_out, duration_ms=duration_ms, killed=timed_out)

    @staticmethod
    def _kill(proc):
        try:
            if _posix_resource is not None:
                os.killpg(os.getpgid(proc.pid), 9)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass


_HARDENING_FLAGS = (
    "--rm", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
    "--network", "none",
)


class ContainerWorkerBackend(WorkerBackend):
    """Hardened container execution — the real isolation boundary.

    ``build_argv`` produces a ``docker run`` command with mandatory hardening; ``run``
    delegates to an injected executor (default: the subprocess backend's bounded runner), so
    the hardened command construction is testable without Docker. Using it requires a
    container runtime; where none is present, ``run`` raises.
    """
    name = "container"

    def __init__(self, image: str, *, runner=None, docker_bin: str = "docker"):
        self.image = image
        self.docker_bin = docker_bin
        self._runner = runner

    def build_argv(self, argv, *, cwd, limits: ResourceLimits, network: str = "none") -> list:
        limits.validate()
        net = "none" if network == "none" else "bridge"  # egress is further constrained by the host firewall
        command = [
            self.docker_bin, "run", "--rm", "--read-only",
            "--cap-drop=ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(limits.max_processes),
            "--memory", f"{limits.max_memory_mb}m", "--memory-swap", f"{limits.max_memory_mb}m",
            "--cpus", "1.0", "--network", net,
            "--tmpfs", "/work:rw,noexec,nosuid,size=64m", "--workdir", "/work",
            "--user", "65534:65534", "--mount", f"type=bind,src={cwd},dst=/evidence,ro",
            self.image, *[str(token) for token in argv],
        ]
        # Defensive: never allow privilege escalation or host-control mounts.
        joined = " ".join(command)
        for forbidden in ("--privileged", "/var/run/docker.sock", "--cap-add"):
            if forbidden in joined:
                raise RuntimeError("Container command must never contain " + forbidden)
        return command

    def run(self, argv, *, cwd, limits: ResourceLimits, env=None, network: str = "none") -> ExecutionResult:
        command = self.build_argv(argv, cwd=cwd, limits=limits, network=network)
        runner = self._runner or SubprocessWorkerBackend().run
        return runner(command, cwd=cwd, limits=limits, env=env)
