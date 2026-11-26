"""Deterministic route/path normalization and deduplication.

The goal is to collapse equivalent resources so that ``/users/1``, ``/users/2`` and the
client-router pattern ``/users/:id`` are recognized as one route ``/users/{id}`` instead
of three distinct endpoints. A single generic ``{id}`` placeholder is used for every
dynamic segment on purpose: it guarantees correct deduplication regardless of the
identifier's concrete type, which is what the surface map needs. Concrete sample values
are never kept in the template.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, parse_qsl

from core.browser.models import NormalizedRoute

_PLACEHOLDER = "{id}"

# Router-style dynamic markers: ":id", "{id}", "*", "[slug]".
_ROUTER_PARAM = re.compile(r"^(?::.+|\{.+\}|\[.+\]|\*+)$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INT = re.compile(r"^-?\d+$")
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# A long opaque token/slug that contains at least one digit (ids, hashes, base64-ish).
_OPAQUE = re.compile(r"^(?=.*\d)[A-Za-z0-9._~-]{12,}$")


def _is_dynamic_segment(segment: str) -> bool:
    if not segment:
        return False
    if _ROUTER_PARAM.match(segment):
        return True
    if _UUID.match(segment) or _INT.match(segment) or _DATE.match(segment):
        return True
    if _HEX.match(segment):
        return True
    if _OPAQUE.match(segment):
        return True
    return False


def _route_path(raw: str) -> str:
    """Extract the routing path from a URL, hash route or bare path.

    Hash-based SPA routes (``#/users/1`` or ``http://app/#/users/1``) route on the
    fragment, so the fragment path is preferred when the real path is empty or root.
    """
    text = str(raw).strip()
    if not text:
        return "/"
    parsed = urlsplit(text)
    path = parsed.path or ""
    fragment = parsed.fragment or ""
    if fragment.startswith("/") and path in ("", "/"):
        path = fragment
    elif text.startswith("#") and text[1:2] == "/":
        path = text[1:]
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def normalize_route(raw: str) -> tuple[str, tuple[str, ...]]:
    """Return ``(template, query_param_names)`` for a URL, hash route or path pattern.

    The template is the path with every dynamic segment replaced by ``{id}`` and a single
    trailing slash removed (except for the root). Query parameter *names* are returned
    separately (sorted, de-duplicated); values are never included.
    """
    parsed = urlsplit(str(raw).strip())
    path = _route_path(raw)
    segments = path.split("/")
    normalized = [_PLACEHOLDER if _is_dynamic_segment(seg) else seg for seg in segments]
    template = "/".join(normalized)
    if len(template) > 1 and template.endswith("/"):
        template = template[:-1]
    if not template:
        template = "/"
    param_names = tuple(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name}))
    return template, param_names


def routes_equivalent(left: str, right: str) -> bool:
    return normalize_route(left)[0] == normalize_route(right)[0]


class RouteSet:
    """Accumulates observed routes and emits a deduplicated, normalized set."""

    def __init__(self) -> None:
        self._routes: dict[str, dict] = {}

    def add(self, raw: str, *, methods=(), kind: str = "navigation",
            source: str = "browser", param_names=()) -> str:
        template, query_params = normalize_route(raw)
        params = set(query_params) | set(param_names or ())
        entry = self._routes.setdefault(
            template,
            {"template": template, "methods": set(), "kinds": set(),
             "sources": set(), "param_names": set(), "samples": 0},
        )
        entry["methods"].update(m.upper() for m in methods if m)
        entry["kinds"].add(kind)
        entry["sources"].add(source)
        entry["param_names"].update(params)
        entry["samples"] += 1
        return template

    def __contains__(self, raw: str) -> bool:
        return normalize_route(raw)[0] in self._routes

    def __len__(self) -> int:
        return len(self._routes)

    def templates(self) -> set[str]:
        return set(self._routes)

    def normalized(self) -> list[dict]:
        result = []
        for entry in self._routes.values():
            dynamic = _PLACEHOLDER in entry["template"]
            route = NormalizedRoute(
                template=entry["template"],
                methods=tuple(sorted(entry["methods"])),
                kinds=tuple(sorted(entry["kinds"])),
                sources=tuple(sorted(entry["sources"])),
                param_names=tuple(sorted(entry["param_names"])),
                dynamic=dynamic,
                observations=entry["samples"],
            )
            result.append(route.to_dict())
        return sorted(result, key=lambda item: item["template"])
