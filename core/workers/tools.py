"""Tool registry for worker execution.

Only registered tools may run in a worker, and only with validated parameters substituted
into fixed argv slots — a parameter value becomes exactly one argv element and can never
introduce new arguments, so there is no argument injection. Each tool declares its
permissions, network needs, risk, timeout and output ceiling (directive §12.4).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


class ToolError(ValueError):
    pass


@dataclass(frozen=True)
class ToolParam:
    name: str
    type: str = "string"            # string | int | enum
    required: bool = True
    choices: tuple = ()
    pattern: str | None = None

    def coerce(self, value):
        if self.type == "int":
            if isinstance(value, bool) or not isinstance(value, int):
                try:
                    value = int(value)
                except (TypeError, ValueError) as exc:
                    raise ToolError(f"Parameter '{self.name}' must be an integer") from exc
            return str(value)
        if self.type == "enum":
            if value not in self.choices:
                raise ToolError(f"Parameter '{self.name}' must be one of {list(self.choices)}")
            return str(value)
        text = str(value)
        if self.pattern is not None and not re.fullmatch(self.pattern, text):
            raise ToolError(f"Parameter '{self.name}' does not match the allowed pattern")
        if "\x00" in text:
            raise ToolError(f"Parameter '{self.name}' contains a NUL byte")
        return text


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    name: str
    version: str
    purpose: str
    command: tuple                  # argv tokens; a token "{param}" is replaced by a value
    params: tuple = ()
    required_permissions: tuple = ()
    network: str = "none"           # none | egress_allowlist
    risk: str = "low"
    timeout_seconds: int = 30
    max_output_bytes: int = 1_000_000

    def build_argv(self, values: dict) -> list:
        values = dict(values or {})
        by_name = {param.name: param for param in self.params}
        unknown = set(values) - set(by_name)
        if unknown:
            raise ToolError("Unknown parameters: " + ", ".join(sorted(unknown)))
        resolved = {}
        for param in self.params:
            if param.name not in values:
                if param.required:
                    raise ToolError("Missing required parameter: " + param.name)
                continue
            resolved[param.name] = param.coerce(values[param.name])
        argv = []
        for token in self.command:
            if isinstance(token, str) and token.startswith("{") and token.endswith("}"):
                key = token[1:-1]
                if key not in resolved:
                    if key in by_name and not by_name[key].required:
                        continue
                    raise ToolError("Unfilled command placeholder: " + key)
                argv.append(resolved[key])   # exactly one argv element; no splitting/injection
            else:
                argv.append(token)
        return argv


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if not isinstance(spec, ToolSpec) or not spec.tool_id:
            raise ToolError("A ToolSpec with a tool_id is required")
        self._tools[spec.tool_id] = spec

    def get(self, tool_id: str) -> ToolSpec:
        spec = self._tools.get(tool_id)
        if spec is None:
            raise ToolError("Unregistered tool: " + str(tool_id))
        return spec

    def __contains__(self, tool_id: str) -> bool:
        return tool_id in self._tools

    def ids(self) -> set:
        return set(self._tools)

    def validate_invocation(self, tool_id: str, values: dict) -> tuple[ToolSpec, list]:
        spec = self.get(tool_id)
        return spec, spec.build_argv(values)
