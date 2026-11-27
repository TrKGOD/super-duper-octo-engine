"""Worker manager: lifecycle, isolation, bounded tool execution and observability.

A worker is provisioned per (engagement, task) with its own working directory namespaced by
engagement, so one engagement's worker cannot read another's artifacts. Only tools that are
both registered and in the engagement's allowlist may run; their output is capped and
sanitized; and every lifecycle event, tool execution, resource figure and cleanup status is
recorded. Each tool run is also an execution in the unified ledger
(``core/execution_ledger.py``): state machine, evidence association, crash reconciliation.

This is the orchestration layer; the isolation strength comes from the chosen backend (see
``backends.py`` and ``docs/ISOLATED_EXECUTION.md``). The default subprocess backend is **not**
a sandbox, so construct the manager with ``require_isolation=True`` to refuse to run on
anything but a container backend — there is deliberately no silent fallback in either
direction.
"""
from __future__ import annotations

import calendar
import json
import os
import shutil
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.errors import classify_exception
from core.execution_ledger import ExecutionLedger
from core.pathsafe import PathSafetyError, is_link_like, resolve_within, safe_component
from core.redaction import redact
from core.store import utc_now
from core.workers.backends import SubprocessWorkerBackend, WorkerBackend
from core.workers.resources import CancelToken, ResourceLimits
from core.workers.tools import ToolError, ToolRegistry


class WorkerError(RuntimeError):
    pass


@dataclass
class Worker:
    worker_id: str
    engagement_id: str
    task_id: str
    workdir: Path
    backend: str
    image: str | None = None


def _rmtree(path: Path) -> None:
    def make_writable_and_retry(function, target, _error):
        os.chmod(target, stat.S_IWRITE)
        function(target)
    if sys.version_info >= (3, 12):          # ``onerror`` is deprecated since 3.12 in favour of ``onexc``
        shutil.rmtree(path, onexc=make_writable_and_retry)
    else:
        shutil.rmtree(path, onerror=make_writable_and_retry)


class WorkerManager:
    """Thread contract: a manager (like the ``StateStore`` it wraps) belongs to the thread that
    owns its database connection. Control from another thread is limited to
    :meth:`request_cancel`, which touches no database state; the owning thread records the
    outcome when the interrupted execution returns."""

    def __init__(self, store, root, *, backend: WorkerBackend | None = None,
                 registry: ToolRegistry | None = None, audit=None,
                 max_tool_invocations: int = 20, max_active_workers_per_engagement: int = 2,
                 require_isolation: bool = False, ledger: ExecutionLedger | None = None):
        self.store = store
        self.root = Path(root)
        self.base = self.root / "workers"
        self.backend = backend or SubprocessWorkerBackend()
        if require_isolation and getattr(self.backend, "isolation", "none") != "container":
            raise WorkerError(
                "require_isolation=True needs a container backend; refusing to fall back to "
                "unsandboxed subprocess execution")
        self.require_isolation = require_isolation
        self.registry = registry or ToolRegistry()
        self.audit = audit or (lambda event, details: None)
        self.max_tool_invocations = max_tool_invocations
        self.max_active = max_active_workers_per_engagement
        self.ledger = ledger or ExecutionLedger(store.connection)
        self._cancel_tokens: dict[str, CancelToken] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._live: set[str] = set()
        self._guard = threading.Lock()

    # -- persistence helpers ----------------------------------------------
    def _row(self, worker_id):
        return self.store.connection.execute(
            "SELECT * FROM worker_executions WHERE worker_id=?", (worker_id,)).fetchone()

    def _update(self, worker_id, **fields):
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        with self.store.connection:
            self.store.connection.execute(
                f"UPDATE worker_executions SET {sets} WHERE worker_id=?",
                (*fields.values(), worker_id))

    # -- lifecycle --------------------------------------------------------
    def provision(self, engagement_id: str, task_id: str, *, image: str | None = None) -> Worker:
        try:
            engagement_id = safe_component(engagement_id, "engagement_id")
        except PathSafetyError as exc:
            raise WorkerError("Invalid engagement identifier for a worker workspace") from exc
        worker_id = "wrk_" + uuid.uuid4().hex[:16]
        connection = self.store.connection
        nested = connection.in_transaction
        # The slot check and the insert must be one atomic step: otherwise two concurrent
        # provisioners both see "1 < 2 active" and the per-engagement bound is exceeded.
        if not nested:
            connection.execute("BEGIN IMMEDIATE")
        try:
            if connection.execute("SELECT 1 FROM engagements WHERE engagement_id=?",
                                  (engagement_id,)).fetchone() is None:
                raise WorkerError("Unknown engagement: " + str(engagement_id))
            active = connection.execute(
                "SELECT COUNT(*) c FROM worker_executions WHERE engagement_id=? AND status IN ('provisioned','running')",
                (engagement_id,)).fetchone()["c"]
            if active >= self.max_active:
                raise WorkerError("Per-engagement active worker limit reached")
            connection.execute(
                "INSERT INTO worker_executions(worker_id,engagement_id,task_id,backend,image,status,"
                "started_at,cleanup_status) VALUES(?,?,?,?,?,'provisioned',?,'pending')",
                (worker_id, engagement_id, task_id, self.backend.name, image, utc_now()))
            if not nested:
                connection.commit()
        except Exception:
            if not nested:
                connection.rollback()
            raise
        try:
            if is_link_like(self.base):
                raise PathSafetyError("worker root is a symlink or junction")
            workdir = resolve_within(self.base, engagement_id, worker_id)
            workdir.mkdir(parents=True, exist_ok=False)
            try:
                os.chmod(workdir.parent, 0o700)
                os.chmod(workdir, 0o700)
            except OSError:
                pass
        except (OSError, PathSafetyError) as exc:
            self._update(worker_id, status="failed", finished_at=utc_now())
            raise WorkerError("Worker workspace could not be created safely") from exc
        with self._guard:
            self._live.add(worker_id)
            self._locks[worker_id] = threading.Lock()
        isolation = getattr(self.backend, "isolation", "none")
        self.audit("worker.provisioned", {"worker_id": worker_id, "engagement_id": engagement_id,
                                          "task_id": task_id, "backend": self.backend.name,
                                          "isolation": isolation, "sandboxed": isolation == "container"})
        return Worker(worker_id, engagement_id, task_id, workdir, self.backend.name, image)

    def execute(self, worker: Worker, tool_id: str, params: dict, *, allowed_tools) -> dict:
        row = self._row(worker.worker_id)
        if row is None:
            raise WorkerError("Unknown worker")
        if row["status"] in ("cancelled", "torn_down", "failed"):
            raise WorkerError("Worker is not runnable (status: " + row["status"] + ")")
        if tool_id not in set(allowed_tools):
            raise WorkerError("Tool is not authorized for this engagement: " + str(tool_id))
        try:
            spec, argv = self.registry.validate_invocation(tool_id, params)
        except ToolError as exc:
            raise WorkerError(str(exc)) from exc
        lock = self._locks.setdefault(worker.worker_id, threading.Lock())
        with lock:                                   # one tool at a time per worker
            return self._execute_locked(worker, spec, argv, tool_id, allowed_tools)

    def _execute_locked(self, worker, spec, argv, tool_id, allowed_tools) -> dict:
        row = self._row(worker.worker_id)
        prior = json.loads(row["tool_executions_json"])
        if len(prior) >= self.max_tool_invocations:
            raise WorkerError("Per-worker tool invocation budget exhausted")
        limits = ResourceLimits(wall_clock_seconds=spec.timeout_seconds,
                                max_output_bytes=spec.max_output_bytes).validate()

        execution_id = self.ledger.create(
            engagement_id=worker.engagement_id, kind="tool", tool_id=tool_id,
            execution_profile="safe" if spec.network == "none" else "active_controlled",
            task_id=worker.task_id, request={"argv": argv, "worker_id": worker.worker_id,
                                             "network": spec.network},
            side_effect_risk="read_only", external_ref=worker.worker_id, actor="worker_manager")
        self.ledger.authorize(execution_id, {
            "decision": "allow", "source": "worker_manager.engagement_allowlist",
            "allowed_tools": sorted(set(allowed_tools)), "network": spec.network}, actor="worker_manager")
        self._update(worker.worker_id, status="running")
        self.ledger.start(execution_id, actor="worker_manager")
        token = CancelToken()
        self._cancel_tokens[worker.worker_id] = token
        try:
            self.ledger.mark_dispatched(execution_id)
            result = self.backend.run(argv, cwd=str(worker.workdir), limits=limits,
                                      network=spec.network, cancel=token)
        except Exception as exc:
            # A backend that cannot run (missing binary, runtime down, config refused) used to
            # leave this worker "running" forever, permanently consuming one of the
            # engagement's worker slots. It is now an explicit, classified failure.
            self.ledger.fail(execution_id, failure_class=classify_exception(exc), message=str(exc),
                             actor="worker_manager")
            self._update(worker.worker_id, status="failed", finished_at=utc_now())
            self.audit("worker.execution_failed", {"worker_id": worker.worker_id, "tool_id": tool_id,
                                                   "execution_id": execution_id,
                                                   "failure_class": classify_exception(exc)})
            raise WorkerError("Tool execution failed: " + redact(str(exc))[:300]) from exc
        finally:
            self._cancel_tokens.pop(worker.worker_id, None)

        text = redact(result.output.decode("utf-8", "replace"))
        artifact_name = f"out_{len(prior)}_{tool_id}.log"
        (worker.workdir / artifact_name).write_text(text, encoding="utf-8")

        meta = {"tool_id": tool_id, "tool_version": spec.version, "argv": argv,
                "artifact": artifact_name, "execution_id": execution_id, **result.to_metadata()}
        prior.append(meta)
        row = self._row(worker.worker_id)
        artifacts = json.loads(row["artifacts_json"]) + [artifact_name]
        usage = json.loads(row["resource_usage_json"])
        usage["total_duration_ms"] = usage.get("total_duration_ms", 0) + result.duration_ms
        usage["invocations"] = len(prior)
        current_status = row["status"]               # a concurrent cancel() must not be undone
        if result.cancelled and current_status != "cancelled":
            current_status = "cancelled"             # cancelled from another thread via request_cancel()
            self._update(worker.worker_id, finished_at=utc_now())
            self.audit("worker.cancelled", {"worker_id": worker.worker_id})
        self._update(worker.worker_id, status="cancelled" if current_status == "cancelled" else "running",
                     tool_executions_json=json.dumps(prior), artifacts_json=json.dumps(artifacts),
                     resource_usage_json=json.dumps(usage))
        usage_report = {"duration_ms": result.duration_ms, "output_bytes": len(result.output),
                        "isolation": result.isolation}
        if result.cancelled:
            self.ledger.cancel(execution_id, reason="cancelled by the worker manager", actor="worker_manager")
        elif result.timed_out:
            self.ledger.fail(execution_id, failure_class="timeout", message="tool exceeded its wall-clock limit",
                             actor="worker_manager")
        else:
            self.ledger.complete(execution_id, exit_status=result.exit_status, resource_usage=usage_report,
                                 partial=bool(result.output_limit_exceeded), actor="worker_manager")
        self.audit("worker.tool_executed", {"worker_id": worker.worker_id, "tool_id": tool_id,
                                            "execution_id": execution_id, "timed_out": result.timed_out,
                                            "truncated": result.truncated, "cancelled": result.cancelled})
        return {"tool_id": tool_id, "artifact": artifact_name, "output": text,
                "execution_id": execution_id, **result.to_metadata()}

    def read_artifact(self, worker: Worker, name: str) -> bytes:
        """Read a file strictly within the worker's own directory (isolation boundary)."""
        if not isinstance(name, str) or not name:
            raise WorkerError("Artifact name is required")
        parts = name.replace("\\", "/").split("/")
        try:
            target = resolve_within(worker.workdir, *parts)
        except PathSafetyError as exc:
            raise WorkerError("Artifact path escapes the worker directory") from exc
        if not target.is_file():
            raise WorkerError("Artifact not found: " + str(name))
        return target.read_bytes()

    def request_cancel(self, worker_id: str) -> bool:
        """Thread-safe: stop the tool currently running in ``worker_id``, if any.

        Pure in-memory signal (no database access), so it may be called from any thread. The
        thread running ``execute`` observes it, kills the process tree and records the
        cancellation.
        """
        token = self._cancel_tokens.get(worker_id)
        if token is None:
            return False
        token.cancel()
        return True

    def cancel(self, worker: Worker) -> None:
        row = self._row(worker.worker_id)
        if row is None or row["status"] in ("torn_down", "completed"):
            return
        self.request_cancel(worker.worker_id)        # stops a tool that is running right now
        self._update(worker.worker_id, status="cancelled", finished_at=utc_now())
        self.audit("worker.cancelled", {"worker_id": worker.worker_id})

    def complete(self, worker: Worker) -> None:
        self._update(worker.worker_id, status="completed", finished_at=utc_now())

    def teardown(self, worker: Worker) -> dict:
        cleanup = "cleaned"
        try:
            if worker.workdir.exists():
                _rmtree(worker.workdir)
        except OSError:
            cleanup = "failed"
        row = self._row(worker.worker_id)
        finished = row["finished_at"] if row and row["finished_at"] else utc_now()
        self._update(worker.worker_id, status="torn_down", finished_at=finished, cleanup_status=cleanup)
        with self._guard:
            self._live.discard(worker.worker_id)
            self._locks.pop(worker.worker_id, None)
        self.audit("worker.torn_down", {"worker_id": worker.worker_id, "cleanup": cleanup})
        return {"worker_id": worker.worker_id, "cleanup_status": cleanup}

    # -- crash recovery ---------------------------------------------------
    def reconcile_interrupted(self, *, engagement_id: str | None = None,
                              orphan_after_seconds: float = 3600.0) -> dict:
        """After a crash/restart: fail orphaned workers, settle stale executions, remove containers.

        Nothing is re-run. A worker row left ``provisioned``/``running`` by a process that no
        longer exists permanently consumed a per-engagement slot; its executions become
        ``INTERRUPTED``/``RECONCILIATION_REQUIRED`` for an operator to resolve.
        """
        cutoff = time.time() - orphan_after_seconds
        rows = self.store.connection.execute(
            "SELECT worker_id,engagement_id,started_at FROM worker_executions WHERE status IN ('provisioned','running')"
            + (" AND engagement_id=?" if engagement_id else ""),
            (engagement_id,) if engagement_id else ()).fetchall()
        failed = []
        for row in rows:
            if row["worker_id"] in self._live:
                continue
            try:
                started = calendar.timegm(time.strptime(row["started_at"], "%Y-%m-%dT%H:%M:%SZ"))
            except ValueError:
                started = 0.0
            if started <= cutoff:
                self._update(row["worker_id"], status="failed", finished_at=utc_now())
                self.audit("worker.orphan_failed", {"worker_id": row["worker_id"]})
                failed.append(row["worker_id"])
        moved = self.ledger.reconcile_stale(engagement_id=engagement_id)
        containers = self.backend.cleanup_orphans()
        return {"workers_failed": failed, "executions": moved, "containers_removed": containers}

    def observability(self, worker_id: str) -> dict | None:
        row = self._row(worker_id)
        if row is None:
            return None
        isolation = getattr(self.backend, "isolation", "none")
        return {
            "worker_id": row["worker_id"], "engagement_id": row["engagement_id"],
            "task_id": row["task_id"], "backend": row["backend"], "image": row["image"],
            "isolation": isolation, "sandboxed": isolation == "container",
            "status": row["status"], "started_at": row["started_at"], "finished_at": row["finished_at"],
            "tool_executions": json.loads(row["tool_executions_json"]),
            "resource_usage": json.loads(row["resource_usage_json"]),
            "artifacts": json.loads(row["artifacts_json"]), "cleanup_status": row["cleanup_status"],
        }
