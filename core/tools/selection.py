"""Agent-to-tool capability requests and deterministic tool selection (directive §6).

An agent requests a *capability* (and optionally a vulnerability class and a profile cap),
not a binary. The selector resolves it to authorized, available tools via the registry +
profile policy, and avoids redundant coverage: a tool whose capabilities are already covered
by prior results is deferred (with a reason), not run again without cause. The selection is
deterministic; an LLM may propose, but this layer decides what may run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.tools.profiles import ProfilePolicy, rank, validate_profile
from core.tools.registry import ToolRegistry


@dataclass
class CapabilityRequest:
    capability: str | None = None
    vulnerability_class: str | None = None
    max_profile: str | None = None            # the agent's requested ceiling (e.g. "safe")
    covered_capabilities: tuple = ()           # capabilities already satisfied by prior work
    auto_selected: bool = True
    operator_approved: bool = False

    def __post_init__(self):
        if self.max_profile is not None:
            validate_profile(self.max_profile)


class ToolSelector:
    def __init__(self, registry: ToolRegistry, policy: ProfilePolicy | None = None):
        self.registry = registry
        self.policy = policy or ProfilePolicy()

    def select(self, request: CapabilityRequest) -> dict:
        base = self.registry.select_tools(
            capability=request.capability, vulnerability_class=request.vulnerability_class,
            policy=self.policy, auto_selected=request.auto_selected,
            operator_approved=request.operator_approved)
        selected, deferred = [], []
        covered = set(request.covered_capabilities or ())
        for tool in base["selected"]:
            if request.max_profile is not None and rank(tool["execution_profile"]) > rank(request.max_profile):
                deferred.append({"tool_id": tool["tool_id"], "reason": "exceeds_requested_profile_cap"})
                continue
            caps = set(tool["capabilities"])
            if covered and caps and caps.issubset(covered):
                deferred.append({"tool_id": tool["tool_id"], "reason": "capability_already_covered"})
                continue
            selected.append(tool)
        return {
            "capability": request.capability, "vulnerability_class": request.vulnerability_class,
            "selected": selected, "deferred": deferred, "rejected": base["rejected"],
            "note": "Deterministic selection: authorized, available, non-redundant tools. "
                    "A selected tool's output is a candidate, not a confirmed finding.",
        }
