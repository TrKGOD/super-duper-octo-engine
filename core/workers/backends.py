"""Worker execution backends.

Two backends share one interface and **neither is hidden behind the other**:

``SubprocessWorkerBackend`` (``isolation = "process"``)
    Portable and bounded, but **not a security sandbox**. It enforces a wall-clock timeout,
    an output ceiling (a flood is *killed*, not merely discarded), cooperative cancellation and
    process-**tree** termination (POSIX session + ``killpg``; Windows Job Object). It runs with
    no shell, a scrubbed environment and a private working directory, and applies resource
    limits (POSIX ``rlimit``; Windows Job Object memory/process limits). It does **not** isolate
    the filesystem or the network from the host.

``ContainerWorkerBackend`` (``isolation = "container"``)
    The isolation boundary for untrusted tools: read-only root, all capabilities dropped,
    ``no-new-privileges``, pid/memory/cpu limits, non-root user, no network unless an
    operator-provisioned egress network is configured, no privileged mode, no docker socket,
    no implicit image pull. It **fails closed**: if the runtime is unavailable it raises
    ``ContainerRuntimeUnavailable`` — it never degrades to unrestricted subprocess execution.
    Containers are named and labelled so a timeout, a cancel or a crash can always find and
    remove them (killing the local ``docker run`` client does *not* stop the container).

See docs/ISOLATED_EXECUTION.md for the threat model and the deployment prerequisites.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
import uuid

from core.runtime import CHILD_TEXT_ENCODING, resolve_executable
from core.workers.resources import CancelToken, ExecutionResult, ResourceLimits

try:  # POSIX-only resource limits
    import resource as _posix_resource
except ImportError:  # pragma: no cover - Windows
    _posix_resource = None


class WorkerBackendError(RuntimeError):
    pass


class ContainerRuntimeUnavailable(WorkerBackendError):
    """The container runtime is missing or unreachable. Never degrade to subprocess execution."""


class ContainerConfigError(WorkerBackendError):
    """The requested container configuration cannot be made safe."""


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


def _count_user_tasks(proc_root: str = "/proc", uid: int | None = None, *, stat=os.stat,
                      listdir=os.listdir) -> int | None:
    """Tasks (processes **and threads**) currently owned by ``uid``; ``None`` where ``/proc`` is unavailable.

    ``RLIMIT_NPROC`` is not a per-tool limit: the kernel compares it with *every task of the same user*
    on the host, so an absolute value below that count makes ``fork()`` and thread creation fail for the
    tool outright (``EAGAIN``) — on a busy workstation or CI runner, a Go tool cannot even start. Measuring
    the baseline lets the limit mean what ``ResourceLimits.max_processes`` says: how many tasks the tool
    may *add*.
    """
    if uid is None:
        if not hasattr(os, "getuid"):
            return None
        uid = os.getuid()
    try:
        entries = listdir(proc_root)
    except OSError:
        return None
    total = 0
    for name in entries:
        if not name.isdigit():
            continue
        path = f"{proc_root}/{name}"
        try:
            if stat(path).st_uid != uid:
                continue
            total += len(listdir(path + "/task"))
        except OSError:                       # the process exited while it was being looked at
            continue
    return total


# ------------------------------------------------------------------------------------------
# Windows Job Object: the only reliable way to bound and kill a whole process tree there.
if os.name == "nt":  # pragma: no cover - exercised on Windows only
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _BasicLimits(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]

    _LIMIT_ACTIVE_PROCESS, _LIMIT_PROCESS_MEMORY, _LIMIT_KILL_ON_CLOSE = 0x8, 0x100, 0x2000
    _JOB_EXTENDED_LIMIT_INFORMATION = 9

    class _WindowsJob:
        """Kill-on-close job with a per-process memory limit and an active-process limit."""

        def __init__(self, limits: ResourceLimits, enforce_limits: bool = True):
            handle = _k32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObject failed")
            self.handle = handle
            info = _ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = _LIMIT_KILL_ON_CLOSE      # always: tree termination
            if enforce_limits:
                info.BasicLimitInformation.LimitFlags |= _LIMIT_PROCESS_MEMORY | _LIMIT_ACTIVE_PROCESS
                info.BasicLimitInformation.ActiveProcessLimit = limits.max_processes
                info.ProcessMemoryLimit = limits.max_memory_mb * 1024 * 1024
            if not _k32.SetInformationJobObject(handle, _JOB_EXTENDED_LIMIT_INFORMATION,
                                                ctypes.byref(info), ctypes.sizeof(info)):
                error = ctypes.get_last_error()
                _k32.CloseHandle(handle)
                raise OSError(error, "SetInformationJobObject failed")

        def assign(self, proc) -> bool:
            return bool(_k32.AssignProcessToJobObject(self.handle, int(proc._handle)))

        def terminate(self) -> None:
            _k32.TerminateJobObject(self.handle, 1)

        def close(self) -> None:
            if self.handle:
                _k32.CloseHandle(self.handle)
                self.handle = None
else:  # pragma: no cover - POSIX
    _WindowsJob = None


class WorkerBackend:
    name = "abstract"
    isolation = "none"

    def run(self, argv, *, cwd, limits: ResourceLimits, env=None, network: str = "none",
            cancel: CancelToken | None = None) -> ExecutionResult:  # pragma: no cover
        raise NotImplementedError

    def cleanup_orphans(self) -> int:
        return 0


class SubprocessWorkerBackend(WorkerBackend):
    """Portable bounded execution. Resource-bounded and tree-killed, **not a security sandbox**."""
    name = "subprocess"
    isolation = "process"

    def _preexec(self, limits: ResourceLimits, task_baseline: int | None = None):
        """Return the function that applies POSIX rlimits in the child (``None`` where there are none).

        ``task_baseline`` is the number of tasks the user already owns (measured in the parent before the
        fork). The process limit is ``baseline + max_processes``; without a baseline (no ``/proc``) it is
        **not applied**, because an absolute value would break any tool on a host busier than the limit.
        """
        if _posix_resource is None:
            return None

        def apply():  # runs in the forked child; POSIX only
            cpu = max(1, int(limits.wall_clock_seconds) + 1)
            _posix_resource.setrlimit(_posix_resource.RLIMIT_CPU, (cpu, cpu))
            mem = limits.max_memory_mb * 1024 * 1024
            _posix_resource.setrlimit(_posix_resource.RLIMIT_AS, (mem, mem))
            if task_baseline is not None:
                ceiling = task_baseline + limits.max_processes
                try:
                    _posix_resource.setrlimit(_posix_resource.RLIMIT_NPROC, (ceiling, ceiling))
                except (ValueError, OSError):
                    pass
            _posix_resource.setrlimit(_posix_resource.RLIMIT_FSIZE,
                                      (limits.max_output_bytes * 4, limits.max_output_bytes * 4))
        return apply

    # -- tree termination -----------------------------------------------------------
    @staticmethod
    def _kill_tree(proc, job):
        """Terminate ``proc`` and every descendant. Best effort, never raises."""
        try:
            if os.name == "nt":
                if job is not None:
                    job.terminate()
                else:  # no job object available: fall back to the tree walk
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                   capture_output=True, timeout=10, check=False)
            else:
                os.killpg(proc.pid, signal.SIGKILL)      # proc.pid is the session/group leader
        except (ProcessLookupError, PermissionError, OSError, subprocess.SubprocessError):
            pass
        try:
            proc.kill()
        except OSError:
            pass

    def run(self, argv, *, cwd, limits: ResourceLimits, env=None, network: str = "none",
            cancel: CancelToken | None = None, apply_resource_limits: bool = True) -> ExecutionResult:
        """Run ``argv`` bounded by wall clock, output size, cancellation and tree termination.

        ``apply_resource_limits=False`` skips the per-process memory / process-count / CPU limits and
        keeps everything else. It exists for exactly one caller: the container backend, whose
        *client* process (``docker run``) must not inherit limits meant for the tool inside the
        container — those are enforced there by the runtime's cgroup, and an address-space or
        process-count limit on a Go binary crashes it.
        """
        limits.validate()
        argv = [str(token) for token in argv]
        started = time.monotonic()
        job, kwargs, task_baseline = None, {}, None
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            try:
                job = _WindowsJob(limits, enforce_limits=apply_resource_limits)
            except OSError:
                job = None
        else:
            kwargs["start_new_session"] = True                       # own session => own process group
            if _posix_resource is not None and apply_resource_limits:
                task_baseline = _count_user_tasks()                  # measured before the fork (see its docstring)
                kwargs["preexec_fn"] = self._preexec(limits, task_baseline)
        proc = subprocess.Popen(
            argv, cwd=cwd, env=_scrubbed_env(cwd, env), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False, **kwargs)
        job_assigned = False
        if job is not None:
            try:
                job_assigned = job.assign(proc)
            except OSError:
                job_assigned = False
            if not job_assigned:                                     # e.g. already inside a non-nestable job
                job.close()
                job = None

        kept = bytearray()
        state = {"truncated": False, "overflow": False}

        def drain():
            while True:
                chunk = proc.stdout.read(8192)
                if not chunk:
                    break
                room = limits.max_output_bytes - len(kept)
                if room > 0:
                    kept.extend(chunk[:room])
                if len(chunk) > room:
                    state["truncated"] = True
                    state["overflow"] = True      # a flood is a fault: stop the process, do not wait for the clock

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()

        timed_out = cancelled = False
        try:
            while True:
                try:
                    proc.wait(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break
                if time.monotonic() - started > limits.wall_clock_seconds:
                    timed_out = True
                    break
                if state["overflow"]:
                    break
            overflow = state["overflow"]
            if proc.poll() is None or timed_out or cancelled or overflow:
                self._kill_tree(proc, job)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            else:
                # Normal exit: reap any descendant the tool left running *before* waiting for the
                # reader, because a survivor can hold the output pipe open indefinitely.
                self._reap_descendants(proc, job)
            reader.join(timeout=5)
        finally:
            if job is not None:
                job.terminate()
            if proc.stdout is not None:
                # close() can block while another thread is parked in read(); never let it hang us
                closer = threading.Thread(target=proc.stdout.close, daemon=True)
                closer.start()
                closer.join(timeout=2)
            if job is not None:
                job.close()
        duration_ms = int((time.monotonic() - started) * 1000)
        killed = timed_out or cancelled or state["overflow"]
        return ExecutionResult(
            exit_status=proc.returncode, output=bytes(kept), truncated=state["truncated"],
            timed_out=timed_out, duration_ms=duration_ms, killed=killed, cancelled=cancelled,
            output_limit_exceeded=state["overflow"], isolation="process", network_enforced=False,
            detail={"tree_kill": ("job_object" if job_assigned else "taskkill") if os.name == "nt" else "process_group",
                    "limits_enforced": {
                        "memory": apply_resource_limits and (bool(job_assigned) if os.name == "nt" else _posix_resource is not None),
                        # POSIX: only when the user's current task count could be measured (see _count_user_tasks)
                        "processes": apply_resource_limits and (
                            bool(job_assigned) if os.name == "nt"
                            else _posix_resource is not None and task_baseline is not None)}})

    @staticmethod
    def _reap_descendants(proc, job):
        if os.name == "nt":
            if job is not None:
                job.terminate()
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass


_HARDENING_FLAGS = (
    "--rm", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
    "--network", "none",
)
_PINNED_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}")
_SAFE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}")
_FORBIDDEN_FLAGS = ("--privileged", "docker.sock", "--cap-add", "--network=host", "--net=host",
                    "--pid=host", "--ipc=host", "--userns=host", "--uts=host", "--device",
                    "seccomp=unconfined", "apparmor=unconfined", "--volumes-from", "--cgroupns=host")
_LABEL = "witherhoard.managed=true"


class ContainerWorkerBackend(WorkerBackend):
    """Hardened container execution — the real isolation boundary.

    ``build_argv`` produces a ``docker run`` command with mandatory hardening and a unique
    container name; ``run`` executes it, kills and removes the container on timeout / cancel /
    error, and **fails closed** when the runtime is unavailable. An injected ``runner`` (used by
    tests) replaces only the process execution, never the hardening.
    """
    name = "container"
    isolation = "container"

    def __init__(self, image: str, *, runner=None, docker_bin: str = "docker",
                 require_pinned_image: bool = False, egress_network: str | None = None,
                 dns_servers: tuple = (), audit=None, run_as: str = "65534:65534"):
        if not isinstance(image, str) or not _SAFE_IMAGE.fullmatch(image) or image.startswith("-"):
            raise ContainerConfigError("Invalid container image reference")
        if require_pinned_image and not _PINNED_IMAGE.fullmatch(image):
            raise ContainerConfigError("A digest-pinned image (name@sha256:<64 hex>) is required")
        if run_as.split(":")[0] in ("0", "root", ""):
            raise ContainerConfigError("Containers must not run as root")
        self.image = image
        self.docker_bin = docker_bin
        self.require_pinned_image = require_pinned_image
        self.egress_network = egress_network
        self.dns_servers = tuple(dns_servers)
        self.run_as = run_as
        self.audit = audit or (lambda event, details: None)
        self._runner = runner
        self._preflight_ok = False
        self.runtime_version: str | None = None

    # -- runtime control --------------------------------------------------------------
    def _docker(self, *args, timeout: float = 20):
        try:
            return subprocess.run([self.docker_bin, *args], capture_output=True, text=True,
                                  timeout=timeout, check=False, **CHILD_TEXT_ENCODING)
        except (FileNotFoundError, PermissionError) as exc:
            raise ContainerRuntimeUnavailable(f"container runtime '{self.docker_bin}' cannot be executed") from exc
        except subprocess.TimeoutExpired as exc:
            raise ContainerRuntimeUnavailable("container runtime did not answer in time") from exc

    def preflight(self) -> dict:
        """Verify the runtime is present and reachable. Raises instead of degrading."""
        if resolve_executable(self.docker_bin) is None:
            raise ContainerRuntimeUnavailable(
                f"container runtime '{self.docker_bin}' was not found. The container backend fails closed: "
                "it never falls back to unrestricted subprocess execution.")
        probe = self._docker("version", "--format", "{{.Server.Version}}")
        if probe.returncode != 0 or not probe.stdout.strip():
            raise ContainerRuntimeUnavailable("container runtime daemon is not reachable")
        self.runtime_version = probe.stdout.strip()
        self._preflight_ok = True
        return {"runtime": self.docker_bin, "version": self.runtime_version, "image": self.image,
                "image_pinned": bool(_PINNED_IMAGE.fullmatch(self.image))}

    def verify_image(self) -> bool:
        """For a digest-pinned image, confirm the local runtime holds exactly that digest."""
        match = re.search(r"@(sha256:[0-9a-f]{64})$", self.image)
        if not match:
            raise ContainerConfigError("Only a digest-pinned image can be verified")
        inspect = self._docker("image", "inspect", "--format", "{{json .RepoDigests}}", self.image)
        if inspect.returncode != 0 or match.group(1) not in inspect.stdout:
            raise ContainerConfigError("The runtime does not hold the pinned image digest; provision it first (--pull never)")
        return True

    def describe(self) -> dict:
        return {"backend": "container", "image": self.image,
                "image_pinned": bool(_PINNED_IMAGE.fullmatch(self.image)),
                "user": self.run_as, "read_only_root": True, "capabilities": "none",
                "no_new_privileges": True, "privileged": False, "docker_socket": False,
                "network_default": "none", "egress_network": self.egress_network,
                "image_pull": "never"}

    # -- command construction ---------------------------------------------------------
    def build_argv(self, argv, *, cwd, limits: ResourceLimits, network: str = "none",
                   name: str | None = None) -> list:
        limits.validate()
        cwd = str(cwd)
        if any(ch in cwd for ch in (",", '"', "'", "\n", "\r", "\x00")):
            # --mount takes comma-separated key=value pairs: a comma in the path would let a
            # crafted engagement/worker id append mount options (e.g. a read-write host path).
            raise ContainerConfigError("Mount source contains characters that are unsafe in --mount")
        if network == "none":
            net_args = ["--network", "none"]
        elif network == "egress_allowlist":
            if not self.egress_network:
                raise ContainerConfigError(
                    "Network egress was requested but no operator-provisioned egress network is configured. "
                    "Default bridge networking is unrestricted and is never used (deployment prerequisite).")
            net_args = ["--network", self.egress_network]
            for server in self.dns_servers:
                net_args += ["--dns", str(server)]
        else:
            raise ContainerConfigError("Unknown network mode: " + str(network))
        name = name or "wh-" + uuid.uuid4().hex[:16]
        prefix = [
            self.docker_bin, "run", "--rm", "--init", "--pull", "never",
            "--name", name, "--label", _LABEL, "--label", "witherhoard.container=" + name,
            "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
            "--ipc", "none",
            "--pids-limit", str(limits.max_processes),
            "--memory", f"{limits.max_memory_mb}m", "--memory-swap", f"{limits.max_memory_mb}m",
            "--cpus", str(limits.max_cpus), "--ulimit", "nofile=1024:1024",
            *net_args,
            "--tmpfs", "/work:rw,noexec,nosuid,nodev,size=64m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m", "--workdir", "/work",
            "--user", self.run_as, "--mount", f"type=bind,src={cwd},dst=/evidence,ro",
        ]
        # Defensive: the part *we* build must never contain privilege escalation or host-control
        # options. (Tool arguments follow the image and are data, so they are not scanned.)
        joined = " ".join(prefix)
        for forbidden in _FORBIDDEN_FLAGS:
            if forbidden in joined:
                raise ContainerConfigError("Container command must never contain " + forbidden)
        return prefix + [self.image, *[str(token) for token in argv]]

    # -- execution --------------------------------------------------------------------
    @staticmethod
    def _container_name(command) -> str:
        return command[command.index("--name") + 1]

    def run(self, argv, *, cwd, limits: ResourceLimits, env=None, network: str = "none",
            cancel: CancelToken | None = None) -> ExecutionResult:
        if self._runner is None and not self._preflight_ok:
            self.preflight()
        command = self.build_argv(argv, cwd=cwd, limits=limits, network=network)
        name = self._container_name(command)
        self.audit("container.starting", {"container": name, "image": self.image, "network": network})
        try:
            if self._runner is not None:
                result = self._runner(command, cwd=cwd, limits=limits, env=env)
            else:
                try:
                    # The tool's memory / process limits are enforced *inside* the container (cgroup,
                    # --memory / --pids-limit above). The local docker client is bounded by wall clock,
                    # output and cancellation only: an RLIMIT_AS / RLIMIT_NPROC / job-memory limit meant
                    # for the tool would crash a Go client or starve its threads.
                    result = SubprocessWorkerBackend().run(command, cwd=cwd, limits=limits, env=env, cancel=cancel,
                                                           apply_resource_limits=False)
                except FileNotFoundError as exc:
                    raise ContainerRuntimeUnavailable("container runtime disappeared during execution") from exc
                if result.timed_out or result.cancelled or result.output_limit_exceeded:
                    # Killing the local client does NOT stop the container: do it explicitly.
                    self._docker("kill", name, timeout=15)
                    self.audit("container.killed", {"container": name, "timed_out": result.timed_out,
                                                    "cancelled": result.cancelled})
        finally:
            if self._runner is None:
                self._docker("rm", "-f", name, timeout=15)       # idempotent; --rm may not have fired
                self.audit("container.removed", {"container": name})
        result.isolation = "container"
        result.network_enforced = True
        # Not "enforced": we asked the runtime (--memory/--pids-limit/--cpus); whether the host honours
        # the cgroup limits is what tests/test_container_integration.py verifies on a real runtime.
        result.detail = {**result.detail, "container": name, "image": self.image, "network": network,
                         "limits_enforced": {"memory": False, "processes": False},
                         "limits_requested_from_runtime": {"memory_mb": limits.max_memory_mb,
                                                           "processes": limits.max_processes, "cpus": limits.max_cpus},
                         "client_resource_limits_applied": False}
        return result

    def cleanup_orphans(self) -> int:
        """Remove every container this framework started that is still around (after a crash)."""
        if self._runner is not None:
            return 0
        listing = self._docker("ps", "-aq", "--filter", "label=" + _LABEL)
        if listing.returncode != 0:
            return 0
        ids = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
        for container_id in ids:
            self._docker("rm", "-f", container_id, timeout=15)
            self.audit("container.orphan_removed", {"container": container_id})
        return len(ids)
