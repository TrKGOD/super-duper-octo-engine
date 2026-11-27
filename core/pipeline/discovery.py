"""Observation stage: project a discovery report into the engagement graph as *observed* structure.

The report comes from the guarded same-origin discovery runner (``scripts/active_surface.py``),
which already fetches only through the scope-enforcing broker. Everything projected here is
``observed`` (or ``inferred`` for endpoints that were only mentioned in JavaScript) with
provenance ``discovery`` and a confidence below the operator's own declarations. Discovery can
add structure, but it cannot create an identity, a role or an authorization edge: the graph's
trust boundary refuses those below control-plane trust, and nothing here attempts them.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from core.browser.routes import normalize_route


def _origin_of(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def project_discovery(ingestor, report: dict, *, origin: str) -> dict:
    """Fold ``report`` into the graph; returns counts. Cross-origin URLs are ignored."""
    graph = ingestor.graph
    created = {"endpoints": 0, "parameters": 0, "skipped_cross_origin": 0}
    nodes: dict = {}

    def endpoint(method: str, url: str, trust: str):
        if _origin_of(url) != origin:
            created["skipped_cross_origin"] += 1
            return None
        template, _query = normalize_route(urlsplit(url).path or "/")
        key = (method.upper(), template)
        if key not in nodes:
            nodes[key] = ingestor.register_endpoint(method, origin, template, trust=trust, provenance="discovery")
            created["endpoints"] += 1
        return nodes[key]

    def parameter(node_id: str, method: str, template: str, name: str):
        key = f"{method.upper()} {origin}{template}?{name}"
        param = graph.upsert_node("parameter", key, label=name, trust="observed",
                                  provenance=[{"source": "discovery"}], confidence=0.5)
        graph.upsert_edge(node_id, "ACCEPTS", param, trust="observed",
                          provenance=[{"source": "discovery"}], confidence=0.5)
        created["parameters"] += 1

    for url in report.get("observed_endpoints", []):
        endpoint("GET", url, "observed")
    for url in report.get("inferred_javascript_endpoints", []):
        endpoint("GET", url, "inferred")
    for operation in report.get("api_operations", []):
        node = endpoint(operation.get("method", "GET"), operation.get("url", ""), "observed")
        if node is None:
            continue
        template, _ = normalize_route(urlsplit(operation["url"]).path or "/")
        for item in operation.get("parameters", []):
            if item.get("name"):
                parameter(node, operation.get("method", "GET"), template, str(item["name"]))
    for observation in report.get("observations", []):
        if observation.get("type") != "form-observed":
            continue
        node = endpoint(observation.get("method", "GET"), observation.get("url", ""), "observed")
        if node is None:
            continue
        template, _ = normalize_route(urlsplit(observation["url"]).path or "/")
        for name in observation.get("parameter_names", []):
            parameter(node, observation.get("method", "GET"), template, str(name))
    return created
