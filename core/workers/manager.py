"""Worker manager: lifecycle, isolation, bounded tool execution and observability.

A worker is provisioned per (engagement, task) with its own working directory namespaced by
engagement, so one engagement's worker cannot read another's artifacts. Only tools that are
both registered and in the engagement's allowlist may run; their output is capped and
sanitized; and every lifecycle event, tool execution, resource figure and cleanup status is
recorded (directive §10.5). This is the orchestration layer; the isolation strength comes
from the chosen backend (see backends.py / docs/ISOLATED_EXECUTION.md).
"""
from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.active_executor import _redact_text
from core.store import utc_now
from core.workers.backends import SubprocessWorkerBackend, WorkerBackend
from core.workers.resources import ResourceLimits
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


class WorkerManager:
    def __init__(self, store, root, *, backend: WorkerBackend | None = None,
                 registry: ToolRegistry | None = None, audit=None,
                 max_tool_invocations: int = 20, max_active_workers_per_engagement: int = 2):
        self.store = store
        self.root = Path(root)
        self.base = self.root / "workers"
        self.backend = backend or SubprocessWorkerBackend()
        self.registry = registry or ToolRegistry()
        self.audit = audit or (lambda event, details: None)
        self.max_tool_invocations = max_tool_invocations
        self.max_active = max_active_workers_per_engagement

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
        if self.store.connection.execute(
                "SELECT 1 FROM engagements WHERE engagement_id=?", (engagement_id,)).fetchone() is None:
            raise WorkerError("Unknown engagement: " + str(engagement_id))
        active = self.store.connection.execute(
            "SELECT COUNT(*) c FROM worker_executions WHERE engagement_id=? AND status IN ('provisioned','running')",
            (engagement_id,)).fetchone()["c"]
        if active >= self.max_active:
            raise WorkerError("Per-engagement active worker limit reached")
        worker_id = "wrk_" + uuid.uuid4().hex[:16]
        workdir = (self.base / engagement_id / worker_id)
        workdir.mkdir(parents=True, exist_ok=False)
        with self.store.connection:
            self.store.connection.execute(
                "INSERT INTO worker_executions(worker_id,engagement_id,task_id,backend,image,status,"
                "started_at,cleanup_status) VALUES(?,?,?,?,?,'provisioned',?,'pending')",
                (worker_id, engagement_id, task_id, self.backend.name, image, utc_now()))
        self.audit("worker.provisioned", {"worker_id": worker_id, "engagement_id": engagement_id, "task_id": task_id})
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

        prior = json.loads(row["tool_executions_json"])
        if len(prior) >= self.max_tool_invocations:
            raise WorkerError("Per-worker tool invocation budget exhausted")

        limits = ResourceLimits(wall_clock_seconds=spec.timeout_seconds,
                                max_output_bytes=spec.max_output_bytes).validate()
        self._update(worker.worker_id, status="running")
        result = self.backend.run(argv, cwd=str(worker.workdir), limits=limits)

        text = _redact_text(result.output.decode("utf-8", "replace"))
        artifact_name = f"out_{len(prior)}_{tool_id}.log"
        (worker.workdir / artifact_name).write_text(text, encoding="utf-8")

        meta = {"tool_id": tool_id, "tool_version": spec.version, "argv": argv,
                "artifact": artifact_name, **result.to_metadata()}
        prior.append(meta)
        artifacts = json.loads(row["artifacts_json"]) + [artifact_name]
        usage = json.loads(row["resource_usage_json"])
        usage["total_duration_ms"] = usage.get("total_duration_ms", 0) + result.duration_ms
        usage["invocations"] = len(prior)
        self._update(worker.worker_id, status="running",
                     tool_executions_json=json.dumps(prior), artifacts_json=json.dumps(artifacts),
                     resource_usage_json=json.dumps(usage))
        self.audit("worker.tool_executed", {"worker_id": worker.worker_id, "tool_id": tool_id,
                                            "timed_out": result.timed_out, "truncated": result.truncated})
        return {"tool_id": tool_id, "artifact": artifact_name, "output": text, **result.to_metadata()}

    def read_artifact(self, worker: Worker, name: str) -> bytes:
        """Read a file strictly within the worker's own directory (isolation boundary)."""
        base = worker.workdir.resolve()
        target = (worker.workdir / name).resolve()
        if not (target == base or target.is_relative_to(base)):
            raise WorkerError("Artifact path escapes the worker directory")
        if not target.is_file():
            raise WorkerError("Artifact not found: " + str(name))
        return target.read_bytes()

    def cancel(self, worker: Worker) -> None:
        row = self._row(worker.worker_id)
        if row is None or row["status"] in ("torn_down", "completed"):
            return
        self._update(worker.worker_id, status="cancelled", finished_at=utc_now())
        self.audit("worker.cancelled", {"worker_id": worker.worker_id})

    def complete(self, worker: Worker) -> None:
        self._update(worker.worker_id, status="completed", finished_at=utc_now())

    def teardown(self, worker: Worker) -> dict:
        cleanup = "cleaned"
        try:
            if worker.workdir.exists():
                shutil.rmtree(worker.workdir)
        except OSError:
            cleanup = "failed"
        row = self._row(worker.worker_id)
        finished = row["finished_at"] if row and row["finished_at"] else utc_now()
        self._update(worker.worker_id, status="torn_down", finished_at=finished, cleanup_status=cleanup)
        self.audit("worker.torn_down", {"worker_id": worker.worker_id, "cleanup": cleanup})
        return {"worker_id": worker.worker_id, "cleanup_status": cleanup}

    def observability(self, worker_id: str) -> dict | None:
        row = self._row(worker_id)
        if row is None:
            return None
        return {
            "worker_id": row["worker_id"], "engagement_id": row["engagement_id"],
            "task_id": row["task_id"], "backend": row["backend"], "image": row["image"],
            "status": row["status"], "started_at": row["started_at"], "finished_at": row["finished_at"],
            "tool_executions": json.loads(row["tool_executions_json"]),
            "resource_usage": json.loads(row["resource_usage_json"]),
            "artifacts": json.loads(row["artifacts_json"]), "cleanup_status": row["cleanup_status"],
        }
