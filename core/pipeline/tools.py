"""Built-in, broker-mediated tool definitions.

The CLI catalog (subfinder, httpx, ...) runs through the worker broker. The pipeline's
authorization comparison runs through the *HTTP* broker (``ActiveHTTPExecutor``), which already
enforces scope, DNS pinning, rate limits, request pinning and evidence capture. It is registered
in the same :class:`ToolRegistry` so tool selection, execution-profile policy, honest availability
and redundancy control apply to it exactly as they do to an external binary — one selection
architecture, two execution backends.
"""
from __future__ import annotations

from core.tools.catalog import build_default_catalog
from core.tools.registry import ToolDefinition, ToolRegistry
from core.workers.tools import ToolSpec

BROKER_AUTHZ_COMPARE = "broker-authz-compare"


def broker_tool_definitions() -> list[ToolDefinition]:
    spec = ToolSpec(
        BROKER_AUTHZ_COMPARE, "Brokered authorization comparison", "1",
        "Paired read-only requests as two approved identities through the scope-enforcing HTTP broker",
        command=("<in-process:ActiveHTTPExecutor>",), network="egress_allowlist", risk="medium",
        timeout_seconds=120, max_output_bytes=1_000_000)
    return [ToolDefinition(
        tool_id=BROKER_AUTHZ_COMPARE, name="Brokered authorization comparison", category="validation",
        version="1", spec=spec, capabilities=("authorization_comparison",),
        vulnerability_classes=("object_authorization", "function_authorization"),
        execution_profile="active_controlled", state_changing=False, risk="medium",
        network="egress_allowlist", binary=None, adapter="broker-http", parser="passthrough",
        status="lab_tested", requires=("http_broker",),
        description="Read-only GET comparison across identities; judged by the validation engine on vault evidence.")]


def build_pipeline_registry(*, include_catalog: bool = True) -> ToolRegistry:
    registry = build_default_catalog() if include_catalog else ToolRegistry()
    for definition in broker_tool_definitions():
        registry.register(definition)
    return registry
