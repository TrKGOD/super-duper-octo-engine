"""Isolated Execution Workers.

Separates agent reasoning from tool execution. The manager provisions a per-(engagement,
task) worker with an engagement-namespaced working directory, runs only registered,
allowlisted tools with validated arguments, caps and sanitizes their output, bounds
resources, isolates artifacts per engagement, records full observability, and cleans up.

Isolation strength depends on the backend:
- ``SubprocessWorkerBackend`` is portable and bounds resources/output/time but is **not** a
  security sandbox (no filesystem/network isolation on its own).
- ``ContainerWorkerBackend`` is the real isolation boundary: a hardened ``docker run``
  (read-only root, dropped caps, no-new-privileges, pids/memory/cpu limits, no host network
  by default, never privileged, no docker socket). See docs/ISOLATED_EXECUTION.md for the
  threat model and residual risks.
"""
from core.workers.backends import (ContainerWorkerBackend, SubprocessWorkerBackend, WorkerBackend)
from core.workers.manager import Worker, WorkerError, WorkerManager
from core.workers.resources import ExecutionResult, ResourceError, ResourceLimits
from core.workers.tools import ToolError, ToolParam, ToolRegistry, ToolSpec

__all__ = [
    "WorkerManager", "Worker", "WorkerError", "WorkerBackend", "SubprocessWorkerBackend",
    "ContainerWorkerBackend", "ResourceLimits", "ExecutionResult", "ResourceError",
    "ToolRegistry", "ToolSpec", "ToolParam", "ToolError",
]
