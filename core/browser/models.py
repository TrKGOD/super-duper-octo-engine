"""Normalized value records for browser-observed application surface.

Every field here originates from untrusted page content or network metadata. These
records deliberately carry *structure and metadata only*. Request/response bodies,
cookie values and secret-bearing header values are never represented.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def _as_list(value) -> list:
    return list(value) if isinstance(value, (tuple, set, list)) else []


@dataclass(frozen=True)
class NormalizedRoute:
    template: str
    methods: tuple = ()
    kinds: tuple = ()
    sources: tuple = ()
    param_names: tuple = ()
    dynamic: bool = False
    observations: int = 0

    def to_dict(self) -> dict:
        return {
            "template": self.template,
            "methods": _as_list(self.methods),
            "kinds": _as_list(self.kinds),
            "sources": _as_list(self.sources),
            "param_names": _as_list(self.param_names),
            "dynamic": bool(self.dynamic),
            "observations": int(self.observations),
        }


@dataclass(frozen=True)
class NetworkObservation:
    method: str
    url: str
    origin: str
    path_template: str
    status: int | None = None
    resource_type: str | None = None
    content_type: str | None = None
    initiator: str | None = None
    query_param_names: tuple = ()
    header_names: tuple = ()
    request_action: str | None = None
    identity: str | None = None
    timing_ms: float | None = None
    blocked: bool = False
    block_reason: str | None = None

    @property
    def endpoint_key(self) -> tuple:
        return (self.method, self.path_template, self.origin)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "origin": self.origin,
            "path_template": self.path_template,
            "status": self.status,
            "resource_type": self.resource_type,
            "content_type": self.content_type,
            "initiator": self.initiator,
            "query_param_names": _as_list(self.query_param_names),
            "header_names": _as_list(self.header_names),
            "request_action": self.request_action,
            "identity": self.identity,
            "timing_ms": self.timing_ms,
            "blocked": bool(self.blocked),
            "block_reason": self.block_reason,
        }


@dataclass(frozen=True)
class WorkflowStep:
    action: str
    route: str
    kind: str = "navigate"  # navigate | submit | click | request

    def to_dict(self) -> dict:
        return {"action": self.action, "route": self.route, "kind": self.kind}


@dataclass(frozen=True)
class Workflow:
    name: str
    steps: tuple = ()
    identity: str | None = None
    mutating: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "identity": self.identity,
            "mutating": bool(self.mutating),
            "steps": [step.to_dict() for step in self.steps],
        }
