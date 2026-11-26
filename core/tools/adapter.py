"""Tool adapter contract and the default brokered adapter.

An adapter is the only thing that runs a tool, and it runs it **through the Phase 5 worker
broker** (`WorkerManager.execute`) — which enforces the registered-tool allowlist, the
injection-safe argv, the isolated workdir and the resource/output bounds. There is no raw
shell and no path around the broker. The adapter lifecycle (directive §5.2): authorize the
execution profile, validate input, execute through the broker, capture and parse output,
return a structured result with observations.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.tools.profiles import ProfilePolicy
from core.tools.registry import ToolDefinition


class AdapterError(RuntimeError):
    pass


@dataclass
class ToolResult:
    tool_id: str
    profile: str
    exit_status: int | None = None
    duration_ms: int | None = None
    timed_out: bool = False
    truncated: bool = False
    artifact: str | None = None
    observations: list = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id, "profile": self.profile, "exit_status": self.exit_status,
            "duration_ms": self.duration_ms, "timed_out": self.timed_out, "truncated": self.truncated,
            "artifact": self.artifact, "observations": self.observations, "error": self.error,
        }


class ToolAdapter:
    adapter_id = "abstract"

    def validate_input(self, definition: ToolDefinition, params: dict) -> list:
        # Reuse the worker ToolSpec's injection-safe argv validation.
        return definition.spec.build_argv(params)

    def parse(self, definition: ToolDefinition, raw_output: str) -> list:  # pragma: no cover - overridden
        raise NotImplementedError

    def execute(self, worker_manager, worker, definition: ToolDefinition, params: dict, *,
                allowed_tools, policy: ProfilePolicy | None = None, auto_selected: bool = True,
                operator_approved: bool = False) -> ToolResult:
        policy = policy or ProfilePolicy()
        allowed, reason = policy.authorize(
            tool_id=definition.tool_id, profile=definition.execution_profile,
            state_changing=definition.state_changing, auto_selected=auto_selected,
            operator_approved=operator_approved)
        if not allowed:
            raise AdapterError("Tool execution not authorized: " + str(reason))

        self.validate_input(definition, params)
        # The tool's worker spec must be known to the broker's registry before execution.
        if definition.spec.tool_id not in worker_manager.registry:
            worker_manager.registry.register(definition.spec)

        result = worker_manager.execute(worker, definition.spec.tool_id, params, allowed_tools=allowed_tools)
        observations = self.parse(definition, result.get("output", ""))
        return ToolResult(
            tool_id=definition.tool_id, profile=definition.execution_profile,
            exit_status=result.get("exit_status"), duration_ms=result.get("duration_ms"),
            timed_out=result.get("timed_out", False), truncated=result.get("truncated", False),
            artifact=result.get("artifact"), observations=observations)


class BrokeredCommandAdapter(ToolAdapter):
    """Default adapter: runs the tool's worker spec through the broker and parses its output
    with an injected parser (defaults to a bounded passthrough)."""
    adapter_id = "brokered-command"

    def __init__(self, parser=None):
        self._parser = parser

    def parse(self, definition: ToolDefinition, raw_output: str) -> list:
        if self._parser is not None:
            return list(self._parser(raw_output))
        text = str(raw_output or "")
        return [{"type": "raw_output", "text": text[:1000], "truncated": len(text) > 1000}]
