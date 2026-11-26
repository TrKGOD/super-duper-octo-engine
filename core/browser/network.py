"""Network request intelligence captured from the browser.

Ingests per-request *metadata* only and deduplicates by (method, normalized path,
origin). Sensitive query values are stripped via the broker's existing redaction helper,
header *names* are kept but values are discarded, and bodies are never represented.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from core.active_executor import _is_sensitive_name, _strip_sensitive_query
from core.browser.models import NetworkObservation
from core.browser.routes import normalize_route
from core.browser.scope import _origin


def _header_names(headers) -> tuple:
    if isinstance(headers, dict):
        names = headers.keys()
    elif isinstance(headers, (list, tuple, set)):
        names = [item[0] if isinstance(item, (list, tuple)) and item else item for item in headers]
    else:
        names = []
    return tuple(sorted({str(name).lower() for name in names if name}))


def _content_type(raw: dict, header_map) -> str | None:
    explicit = raw.get("content_type")
    if explicit:
        return str(explicit).split(";")[0].strip().lower()
    if isinstance(header_map, dict):
        for key, value in header_map.items():
            if str(key).lower() == "content-type":
                return str(value).split(";")[0].strip().lower()
    return None


class NetworkIntelligence:
    """Deduplicating sink for browser-generated request metadata."""

    def __init__(self) -> None:
        self._observations: dict[tuple, NetworkObservation] = {}

    def ingest(self, raw: dict, *, action=None, identity=None,
               blocked: bool = False, block_reason: str | None = None) -> NetworkObservation | None:
        if not isinstance(raw, dict):
            return None
        url = raw.get("url")
        if not url:
            return None
        parsed = urlsplit(str(url))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        method = str(raw.get("method", "GET")).upper()
        template, _ = normalize_route(url)
        # Keep non-secret query parameter names for intelligence; drop sensitive ones entirely.
        query_param_names = tuple(sorted({
            name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
            if name and not _is_sensitive_name(name)
        }))
        header_map = raw.get("headers")
        observation = NetworkObservation(
            method=method,
            url=_strip_sensitive_query(str(url)),
            origin=_origin(url),
            path_template=template,
            status=raw.get("status"),
            resource_type=(str(raw["resource_type"]).lower() if raw.get("resource_type") else None),
            content_type=_content_type(raw, header_map),
            initiator=(str(raw["initiator"]) if raw.get("initiator") else None),
            query_param_names=query_param_names,
            header_names=_header_names(header_map),
            request_action=action,
            identity=identity,
            timing_ms=raw.get("timing_ms"),
            blocked=bool(blocked),
            block_reason=block_reason,
        )
        key = observation.endpoint_key + (bool(blocked),)
        existing = self._observations.get(key)
        # Prefer a non-blocked, status-bearing observation when deduplicating.
        if existing is None or (existing.status is None and observation.status is not None):
            self._observations[key] = observation
        return observation

    def observations(self) -> list[dict]:
        return sorted((obs.to_dict() for obs in self._observations.values()),
                      key=lambda item: (item["origin"], item["path_template"], item["method"], item["blocked"]))

    def endpoints(self) -> list[dict]:
        """Distinct in-application endpoints (method + normalized path + origin), excluding blocked."""
        seen = {}
        for obs in self._observations.values():
            if obs.blocked:
                continue
            seen.setdefault(obs.endpoint_key, {
                "method": obs.method, "path_template": obs.path_template, "origin": obs.origin,
                "content_types": set(), "query_param_names": set(),
            })
            if obs.content_type:
                seen[obs.endpoint_key]["content_types"].add(obs.content_type)
            seen[obs.endpoint_key]["query_param_names"].update(obs.query_param_names)
        result = []
        for entry in seen.values():
            entry["content_types"] = sorted(entry["content_types"])
            entry["query_param_names"] = sorted(entry["query_param_names"])
            result.append(entry)
        return sorted(result, key=lambda item: (item["origin"], item["path_template"], item["method"]))
