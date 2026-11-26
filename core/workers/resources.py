"""Resource limits and the result of a bounded execution."""
from __future__ import annotations

from dataclasses import dataclass


class ResourceError(ValueError):
    pass


@dataclass(frozen=True)
class ResourceLimits:
    wall_clock_seconds: float = 30.0
    max_output_bytes: int = 1_000_000
    max_memory_mb: int = 512          # applied via rlimits on POSIX; advisory elsewhere
    max_processes: int = 64           # applied via rlimits on POSIX; advisory elsewhere

    def validate(self) -> "ResourceLimits":
        if not 0 < self.wall_clock_seconds <= 600:
            raise ResourceError("wall_clock_seconds must be in (0, 600]")
        if not 0 < self.max_output_bytes <= 64_000_000:
            raise ResourceError("max_output_bytes must be in (0, 64MB]")
        if not 0 < self.max_memory_mb <= 8192:
            raise ResourceError("max_memory_mb must be in (0, 8192]")
        if not 0 < self.max_processes <= 4096:
            raise ResourceError("max_processes must be in (0, 4096]")
        return self


@dataclass
class ExecutionResult:
    exit_status: int | None
    output: bytes
    truncated: bool
    timed_out: bool
    duration_ms: int
    killed: bool = False

    def to_metadata(self) -> dict:
        return {
            "exit_status": self.exit_status, "output_bytes": len(self.output),
            "truncated": self.truncated, "timed_out": self.timed_out,
            "duration_ms": self.duration_ms, "killed": self.killed,
        }
