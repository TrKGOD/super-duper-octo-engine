"""Extended Tool Registry.

Builds on the Phase 5 worker tool contract (`core/workers/tools.ToolSpec`, which already
gives injection-safe argv and resource bounds) with the richer metadata the Intelligence
Layer needs: category, capabilities, vulnerability classes, execution profile, adapter,
parser, and honest availability status. A registry entry is **not** proof a tool is
installed — `check_availability` says so truthfully. Execution always goes through the
Phase 5 worker broker (see `adapter.py`); the registry never runs anything itself.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field

from core.tools.profiles import ProfilePolicy, validate_profile
from core.workers.tools import ToolSpec

# Honest integration status (directive §12).
STATUSES = ("planned", "registered", "adapter_implemented", "lab_tested", "integrated",
            "available", "disabled", "requires_operator_configuration")


class ToolRegistryError(ValueError):
    pass


@dataclass
class ToolDefinition:
    tool_id: str
    name: str
    category: str
    version: str
    spec: ToolSpec                      # Phase 5 execution contract (argv/params/limits)
    capabilities: tuple = ()
    vulnerability_classes: tuple = ()
    execution_profile: str = "safe"
    state_changing: bool = False
    risk: str = "low"
    network: str = "none"               # none | egress_allowlist
    supported_os: tuple = ("linux", "darwin", "windows")
    binary: str | None = None           # executable checked for availability; None = built-in
    adapter: str = "brokered-command"
    parser: str = "passthrough"
    status: str = "registered"
    documentation: str | None = None
    description: str = ""

    def validate(self) -> "ToolDefinition":
        if not self.tool_id or not isinstance(self.spec, ToolSpec):
            raise ToolRegistryError("A tool_id and a worker ToolSpec are required")
        if self.spec.tool_id != self.tool_id:
            raise ToolRegistryError("ToolDefinition.tool_id must match its spec.tool_id")
        validate_profile(self.execution_profile)
        if self.network not in ("none", "egress_allowlist"):
            raise ToolRegistryError("network must be 'none' or 'egress_allowlist'")
        if self.status not in STATUSES:
            raise ToolRegistryError("Unknown status: " + str(self.status))
        return self

    def to_dict(self) -> dict:
        return {"tool_id": self.tool_id, "name": self.name, "category": self.category,
                "version": self.version, "capabilities": list(self.capabilities),
                "vulnerability_classes": list(self.vulnerability_classes),
                "execution_profile": self.execution_profile, "state_changing": self.state_changing,
                "risk": self.risk, "network": self.network, "adapter": self.adapter,
                "parser": self.parser, "status": self.status}


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, definition: ToolDefinition) -> None:
        self._tools[definition.validate().tool_id] = definition

    def unregister(self, tool_id: str) -> None:
        self._tools.pop(tool_id, None)

    def update(self, tool_id: str, **fields) -> ToolDefinition:
        definition = self.get(tool_id)
        for key, value in fields.items():
            if not hasattr(definition, key):
                raise ToolRegistryError("Unknown field: " + key)
            setattr(definition, key, value)
        return definition.validate()

    def get(self, tool_id: str) -> ToolDefinition:
        definition = self._tools.get(tool_id)
        if definition is None:
            raise ToolRegistryError("Unregistered tool: " + str(tool_id))
        return definition

    def __contains__(self, tool_id: str) -> bool:
        return tool_id in self._tools

    def list(self, *, category: str | None = None) -> list[ToolDefinition]:
        tools = [t for t in self._tools.values() if category is None or t.category == category]
        return sorted(tools, key=lambda t: t.tool_id)

    def search(self, text: str) -> list[ToolDefinition]:
        text = str(text).lower()
        return sorted(
            (t for t in self._tools.values()
             if text in t.tool_id.lower() or text in t.name.lower()
             or any(text in c.lower() for c in t.capabilities)
             or any(text in v.lower() for v in t.vulnerability_classes)),
            key=lambda t: t.tool_id)

    def by_capability(self, capability: str) -> list[ToolDefinition]:
        return sorted((t for t in self._tools.values() if capability in t.capabilities),
                      key=lambda t: t.tool_id)

    def by_vulnerability_class(self, vulnerability_class: str) -> list[ToolDefinition]:
        return sorted((t for t in self._tools.values() if vulnerability_class in t.vulnerability_classes),
                      key=lambda t: t.tool_id)

    def check_availability(self, tool_id: str) -> str:
        """Truthful availability: a built-in tool is available; a binary tool is available only
        if its executable is on PATH, otherwise it requires operator configuration."""
        definition = self.get(tool_id)
        if definition.status == "disabled":
            return "disabled"
        if definition.binary is None:
            return "available"
        return "available" if shutil.which(definition.binary) else "requires_operator_configuration"

    def check_version(self, tool_id: str) -> dict:
        definition = self.get(tool_id)
        return {"tool_id": tool_id, "declared_version": definition.version,
                "detected_version": None,
                "note": "Runtime version detection runs the tool through the broker; not performed here."}

    def select_tools(self, *, capability: str | None = None, vulnerability_class: str | None = None,
                     policy: ProfilePolicy | None = None, auto_selected: bool = True,
                     operator_approved: bool = False) -> dict:
        """Deterministic baseline selection: available tools matching the request whose profile
        is authorized. RESTRICTED tools are never returned for an auto-selection."""
        candidates = list(self._tools.values())
        if capability is not None:
            candidates = [t for t in candidates if capability in t.capabilities]
        if vulnerability_class is not None:
            candidates = [t for t in candidates if vulnerability_class in t.vulnerability_classes]
        policy = policy or ProfilePolicy()
        selected, rejected = [], []
        for definition in sorted(candidates, key=lambda t: t.tool_id):
            availability = self.check_availability(definition.tool_id)
            if availability != "available":
                rejected.append({"tool_id": definition.tool_id, "reason": availability})
                continue
            allowed, reason = policy.authorize(
                tool_id=definition.tool_id, profile=definition.execution_profile,
                state_changing=definition.state_changing, auto_selected=auto_selected,
                operator_approved=operator_approved)
            (selected if allowed else rejected).append(
                definition if allowed else {"tool_id": definition.tool_id, "reason": reason})
        return {"selected": [t.to_dict() for t in selected], "rejected": rejected}
