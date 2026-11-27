"""Resource limits and the result of a bounded execution."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


class ResourceError(ValueError):
    pass


class CancelToken:
    """Cooperative cancellation shared between the manager and a running backend."""

    def __init__(self):
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()


@dataclass(frozen=True)
class ResourceLimits:
    wall_clock_seconds: float = 30.0
    max_output_bytes: int = 1_000_000
    max_memory_mb: int = 512          # RLIMIT_AS on POSIX, job-object limit on Windows, cgroup in a container
    max_processes: int = 64           # RLIMIT_NPROC on POSIX, job-object active-process limit on Windows
    max_cpus: float = 1.0             # container only (--cpus); CPU time is bounded by the wall clock elsewhere

    def validate(self) -> "ResourceLimits":
        if not 0 < self.wall_clock_seconds <= 600:
            raise ResourceError("wall_clock_seconds must be in (0, 600]")
        if not 0 < self.max_output_bytes <= 64_000_000:
            raise ResourceError("max_output_bytes must be in (0, 64MB]")
        if not 0 < self.max_memory_mb <= 8192:
            raise ResourceError("max_memory_mb must be in (0, 8192]")
        if not 0 < self.max_processes <= 4096:
            raise ResourceError("max_processes must be in (0, 4096]")
        if not 0 < self.max_cpus <= 16:
            raise ResourceError("max_cpus must be in (0, 16]")
        return self


@dataclass
class ExecutionResult:
    exit_status: int | None
    output: bytes
    truncated: bool
    timed_out: bool
    duration_ms: int
    killed: bool = False
    cancelled: bool = False
    output_limit_exceeded: bool = False
    isolation: str = "process"            # "process" (NOT a sandbox) | "container"
    network_enforced: bool = False        # True only when the backend itself restricts the network
    detail: dict = field(default_factory=dict)

    def to_metadata(self) -> dict:
        return {
            "exit_status": self.exit_status, "output_bytes": len(self.output),
            "truncated": self.truncated, "timed_out": self.timed_out,
            "duration_ms": self.duration_ms, "killed": self.killed, "cancelled": self.cancelled,
            "output_limit_exceeded": self.output_limit_exceeded, "isolation": self.isolation,
            "network_enforced": self.network_enforced, "detail": self.detail,
        }
