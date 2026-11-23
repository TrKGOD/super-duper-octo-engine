#!/usr/bin/env python3
"""Bounded same-origin Web/API discovery through the engagement HTTP broker.

This command is available only to a running, explicitly approved specialist task.
It never invokes a general scanner or arbitrary shell command.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.active_executor import ActiveExecutionError, ActiveHTTPExecutor, _resolve_and_authorize
from core.orchestration import Workflow


class SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.scripts = []
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        values = {str(k).lower(): v for k, v in attrs if k}
        if tag.lower() in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        if tag.lower() == "script" and values.get("src"):
            self.scripts.append(values["src"])
        if tag.lower() == "form":
            self.current_form = {"action": values.get("action", ""), "method": values.get("method", "GET").upper(), "fields": []}
            self.forms.append(self.current_form)
        if self.current_form is not None and tag.lower() in {"input", "select", "textarea", "button"}:
            name = values.get("name")
            if name:
                self.current_form["fields"].append(name)

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self.current_form = None


ROUTE_PATTERNS = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|open)\s*\(\s*['"`]([^'"`]{1,500})""", re.I),
    re.compile(r"""(?:url|endpoint|baseURL|path)\s*[:=]\s*['"`]([^'"`]{1,500})""", re.I),
    re.compile(r"""['"`]((?:/api/|/graphql\b|/v[0-9]+/)[^'"`\s]{0,300})['"`]""", re.I),
]
SINK_PATTERNS = {
    "dom-xss-sink": re.compile(r"\b(?:innerHTML|outerHTML|document\.write)\b", re.I),
    "dynamic-code-execution": re.compile(r"\b(?:eval|new Function)\s*\(", re.I),
    "postmessage-wildcard": re.compile(r"""postMessage\s*\([^;]{0,300},\s*['"]\*['"]""", re.I),
    "unsafe-url-navigation": re.compile(r"\b(?:location\.href|window\.open)\s*=", re.I),
}
SECURITY_HEADERS = {
    "strict-transport-security": "missing-hsts",
    "content-security-policy": "missing-csp",
    "x-content-type-options": "missing-nosniff",
    "referrer-policy": "missing-referrer-policy",
    "permissions-policy": "missing-permissions-policy",
}


def _origin(url):
    p = urlsplit(url)
    return p.scheme.lower(), (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80)


def _canonical(url):
    p = urlsplit(url)
    path = p.path or "/"
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, "", ""))


def _same_origin(base, candidate):
    return _origin(base) == _origin(candidate)


def _safe_path_url(base, value):
    candidate = urljoin(base, value.strip())
    p = urlsplit(candidate)
    if p.scheme not in {"http", "https"} or not p.hostname or not _same_origin(base, candidate):
        return None
    if p.username or p.password or p.fragment:
        return None
    if any(x in p.path.lower() for x in ("/logout", "/signout", "/delete", "/remove", "/checkout", "/purchase")):
        return None
    # Never replay query values discovered in links; endpoint inventory records paths only.
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", ""))


def _is_crawlable_page(url):
    path = urlsplit(url).path.lower()
    blocked = (
        "/api/", "/graphql", "/v1/", "/v2/", "/users/", "/account",
        "/profile", "/orders", "/billing", "/settings", "/admin",
        "/download", "/export", "/upload", "/import", "/logout", "/signout",
        "/unsubscribe", "/reset", "/activate", "/confirm", "/cancel",
        "/invite", "/subscribe", "/follow", "/like", "/payment", "/transfer",
        "/transaction", "/submit", "/execute", "/action", "/approve",
        "/accept", "/decline", "/session", "/password", "/token",
    )
    return not any(token in path for token in blocked) and not path.lower().endswith(
        (".json", ".xml", ".pdf", ".zip", ".csv")
    )


def _headers_map(headers):
    return {str(k).lower(): str(v) for k, v in headers.items()}

def _parse_allowed_methods(value):
    """Parse Allow/CORS method lists as tokens, never individual characters."""
    return sorted({item.upper() for item in re.split(r"[,\s]+", str(value or "")) if item})



def _request(executor, engagement_id, task_id, target, purpose, headers=None, method="GET", secret_headers=None):
    if method not in {"GET", "OPTIONS"}:
        raise ActiveExecutionError("Surface discovery supports only GET and OPTIONS")
    task = executor.workflow.store.connection.execute(
        "SELECT input_json FROM tasks WHERE task_id=? AND engagement_id=?",
        (task_id, engagement_id),
    ).fetchone()
    if task is None:
        raise ActiveExecutionError("Unknown active discovery task")
    task_data = json.loads(task["input_json"])
    if task_data.get("active_testing") is not True:
        raise ActiveExecutionError("Discovery requires an active_testing task")
    request_id = "surf-" + uuid.uuid4().hex[:20]
    manifest = {
        "request_id": request_id,
        "method": method,
        "url": target,
        "purpose": purpose[:490],
        "headers": headers or {},
        "secret_headers": secret_headers or {},
        "timeout_seconds": 8,
        "max_response_bytes": 65536,
        "follow_redirects": True,
    }
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    request_dir = ROOT / ".local" / "requests"
    request_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if request_dir.is_symlink():
        raise ActiveExecutionError(".local/requests must not be a symlink")
    rel = ".local/requests/" + request_id + ".json"
    path = ROOT / rel
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    generated = list(task_data.get("generated_request_files", []))
    generated.append({"path": rel, "sha256": hashlib.sha256(raw).hexdigest()})
    task_data["generated_request_files"] = generated
    with executor.workflow.store.connection:
        executor.workflow.store.connection.execute(
            "UPDATE tasks SET input_json=? WHERE task_id=?",
            (json.dumps(task_data, sort_keys=True), task_id),
        )
        executor.workflow.store.append_audit(
            engagement_id, "active-surface-discovery", "surface.request_manifest_generated",
            {"task_id": task_id, "request_id": request_id, "path": rel,
             "sha256": hashlib.sha256(raw).hexdigest(), "target": urlsplit(target).hostname,
             "method": "GET"},
        )
    return executor.execute_request_file(engagement_id, task_id, rel)


def _analyse_js(text):
    routes, indicators = set(), []
    for pattern in ROUTE_PATTERNS:
        for match in pattern.findall(text):
            value = match.strip()
            if value and not value.startswith(("data:", "javascript:", "#")):
                routes.add(value)
    for name, pattern in SINK_PATTERNS.items():
        count = len(pattern.findall(text))
        if count:
            indicators.append({"type": name, "occurrences": count, "status": "static_indicator_not_a_finding"})
    return sorted(routes), indicators


def run_discovery(db, engagement_id, task_id, target_url, max_pages=50, max_depth=3, secret_headers=None, user_agent=None):
    if not 1 <= max_pages <= 100 or not 0 <= max_depth <= 4:
        raise ActiveExecutionError("Bounds are max_pages 1..100 and max_depth 0..4")
    target_url = _canonical(target_url)
    with Workflow(db, project_root=ROOT) as workflow:
        row = workflow.store.connection.execute(
            """SELECT t.agent,t.status,t.input_json,e.status AS engagement_status,e.scope_json,e.rules_json,
                      e.authorization_reference
               FROM tasks t JOIN engagements e ON e.engagement_id=t.engagement_id
               WHERE t.task_id=? AND t.engagement_id=?""", (task_id, engagement_id)
        ).fetchone()
        if row is None or row["status"] != "running" or row["agent"] not in {
            "recon-agent", "enumeration-agent", "vulnerability-agent", "active-testing-agent"
        }:
            raise ActiveExecutionError("Discovery requires a running authorized discovery specialist task")
        rules = json.loads(row["rules_json"])
        if row["engagement_status"] != "active" or rules.get("execution_enabled") is not True or rules.get("authorization_verified") is not True:
            raise ActiveExecutionError("Engagement authorization is not active and verified")
        task = json.loads(row["input_json"])
        if task.get("active_testing") is not True or not task.get("scope_subset"):
            raise ActiveExecutionError("Task must be active_testing and have a non-empty exact scope subset")
        scope = json.loads(row["scope_json"])
        _resolve_and_authorize(target_url, scope, task["scope_subset"])
        executor = ActiveHTTPExecutor(workflow, ROOT)
        # Optional authenticated mode uses only environment-backed secret header references.\n        auth_headers = dict(secret_headers or {})\n        base_headers = {"User-Agent": user_agent} if user_agent else {}\n        # Small fixed metadata set: useful discovery, not directory brute force.
        metadata_paths = (
            "/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json",
            "/api-docs", "/.well-known/openid-configuration",
        )
        queue = deque([(target_url, 0)])
        for metadata_path in metadata_paths:
            candidate = _safe_path_url(target_url, metadata_path)
            if candidate and candidate != target_url:
                queue.append((candidate, 1))
        visited, endpoints, inferred_endpoints, js_assets, findings, tech = set(), set(), set(), set(), [], {}
        api_operations, identity_metadata = [], {}
        evidence_refs = []
        page_count = 0
        blocked_requests = 0
        while queue and page_count < max_pages:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            try:
                result = _request(executor, engagement_id, task_id, current, "Same-origin page discovery and endpoint mapping", base_headers, secret_headers=auth_headers)
            except ActiveExecutionError as exc:
                blocked_requests += 1
                findings.append({"type": "discovery-blocked", "url": current, "reason": str(exc)})
                continue
            page_count += 1
            evidence_refs.extend(result.get("evidence_refs", []))
            headers = _headers_map(result.get("response_headers") or {})
            if result.get("status_code") is not None:
                tech.setdefault("http_statuses", set()).add(result["status_code"])
            for header in ("server", "x-powered-by", "via", "content-type"):
                if headers.get(header):
                    tech[header] = headers[header][:200]
            body = result.get("response_excerpt") or ""
            content_type = headers.get("content-type", "")
            current_path = urlsplit(current).path.lower()
            if current_path.endswith("/robots.txt") or current_path == "/robots.txt":
                for line in body.splitlines():
                    key, sep, value = line.partition(":")
                    if not sep:
                        continue
                    if key.strip().lower() == "sitemap":
                        sitemap = _safe_path_url(target_url, value.strip())
                        if sitemap:
                            endpoints.add(sitemap)
                            if sitemap not in visited:
                                queue.append((sitemap, 1))
                    elif key.strip().lower() in {"allow", "disallow"} and value.strip().startswith("/"):
                        path_url = _safe_path_url(target_url, value.strip())
                        if path_url:
                            endpoints.add(path_url)
                continue
            if current_path.endswith("/sitemap.xml") or current_path == "/sitemap.xml":
                for location in re.findall(r"<loc>\s*(.*?)\s*</loc>", body, re.I | re.S):
                    sitemap_url = _safe_path_url(target_url, location)
                    if sitemap_url:
                        endpoints.add(sitemap_url)
                        if _is_crawlable_page(sitemap_url) and sitemap_url not in visited and len(visited) + len(queue) < max_pages:
                            queue.append((sitemap_url, 1))
                continue
            if current_path.endswith(("/openapi.json", "/swagger.json", "/api-docs")) or "openapi" in content_type or "swagger" in content_type:
                try:
                    spec = json.loads(body)
                    for api_path, operations in spec.get("paths", {}).items():
                        resolved_api = _safe_path_url(target_url, api_path)
                        if not resolved_api:
                            continue
                        endpoints.add(resolved_api)
                        for method_name, operation in operations.items():
                            if method_name.lower() in {"get", "head", "post", "put", "patch", "delete", "options"} and isinstance(operation, dict):
                                api_operations.append({
                                    "url": resolved_api, "method": method_name.upper(),
                                    "operation_id": operation.get("operationId"),
                                    "parameters": [
                                        {"name": p.get("name"), "in": p.get("in")}
                                        for p in operation.get("parameters", []) if isinstance(p, dict)
                                    ],
                                    "status": "documented_operation_not_executed",
                                })
                except (ValueError, TypeError):
                    findings.append({"type": "api-spec-parse-failed", "url": current, "status": "observation"})
                continue
            if current_path.endswith("/.well-known/openid-configuration"):
                try:
                    identity_metadata = {
                        key: value for key, value in json.loads(body).items()
                        if key in {"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                                   "jwks_uri", "end_session_endpoint", "registration_endpoint",
                                   "response_types_supported", "grant_types_supported", "scopes_supported"}
                    }
                except (ValueError, TypeError):
                    findings.append({"type": "oidc-discovery-parse-failed", "url": current, "status": "observation"})
                continue
            if "javascript" in content_type or current.lower().endswith(".js"):
                routes, indicators = _analyse_js(body)
                for route in routes:
                    resolved = _safe_path_url(target_url, route)
                    if resolved:
                        endpoints.add(resolved)
                        inferred_endpoints.add(resolved)
                if indicators:
                    findings.extend([{"url": current, **item} for item in indicators])
                if "sourceMappingURL=" in body:
                    map_ref = body.split("sourceMappingURL=", 1)[1].splitlines()[0].strip().split()[0]
                    mapped = _safe_path_url(current, map_ref)
                    if mapped:
                        endpoints.add(mapped)
                        js_assets.add(mapped)
                continue
            if "html" not in content_type and not current.endswith("/"):
                continue
            parser = SurfaceParser()
            try:
                parser.feed(body)
            except Exception:
                continue
            for link in parser.links:
                resolved = _safe_path_url(current, link)
                if resolved:
                    endpoints.add(resolved)
                    if depth < max_depth and _is_crawlable_page(resolved) and len(visited) + len(queue) < max_pages:
                        queue.append((resolved, depth + 1))
            for script in parser.scripts:
                resolved = _safe_path_url(current, script)
                if resolved:
                    js_assets.add(resolved)
                    endpoints.add(resolved)
            for form in parser.forms:
                action = _safe_path_url(current, form.get("action") or current)
                if action:
                    endpoints.add(action)
                    findings.append({
                        "type": "form-observed", "url": action, "method": form["method"],
                        "parameter_names": sorted(set(form["fields"])),
                        "status": "surface_observation_not_a_finding",
                    })
            for header, label in SECURITY_HEADERS.items():
                if header == "strict-transport-security" and urlsplit(current).scheme != "https":
                    continue
                if not headers.get(header):
                    findings.append({"type": label, "url": current, "status": "configuration_observation"})
            for cookie_index, flags in enumerate(result.get("cookie_security_flags", [])):
                for flag in ("secure", "httponly"):
                    if flag not in flags:
                        findings.append({"type": "cookie-missing-" + flag, "url": current,
                                         "cookie_index": cookie_index, "status": "configuration_observation"})
                if not any(flag.startswith("samesite=") for flag in flags):
                    findings.append({"type": "cookie-missing-samesite", "url": current,
                                     "cookie_index": cookie_index, "status": "configuration_observation"})
        # Fetch only same-origin JavaScript assets already observed in HTML.
        js_results = []
        for script_url in sorted(js_assets)[:min(10, max_pages - page_count)]:
            try:
                js_result = _request(executor, engagement_id, task_id, script_url, "Static JavaScript endpoint and sink analysis", headers=base_headers, secret_headers=auth_headers)
                evidence_refs.extend(js_result.get("evidence_refs", []))
                js_body = js_result.get("response_excerpt") or ""
                routes, indicators = _analyse_js(js_body)
                for route in routes:
                    resolved = _safe_path_url(target_url, route)
                    if resolved:
                        endpoints.add(resolved)
                        inferred_endpoints.add(resolved)
                js_results.append({"url": script_url, "status_code": js_result.get("status_code"), "route_count": len(routes), "indicators": indicators, "evidence_refs": js_result.get("evidence_refs", [])})
            except ActiveExecutionError as exc:
                blocked_requests += 1
                js_results.append({"url": script_url, "blocked": str(exc)})
        # One harmless CORS observation, never credentials or state changes.
        cors = None
        options = None
        try:
            cors = _request(executor, engagement_id, task_id, target_url,
                            "Read-only CORS policy observation using a non-credentialed synthetic Origin",
                            {"Origin": "https://pentest-agent.invalid"})
        except ActiveExecutionError as exc:
            blocked_requests += 1
            cors = {"blocked": str(exc)}
        if cors and isinstance(cors, dict):
            evidence_refs.extend(cors.get("evidence_refs", []))
        try:
            options = _request(executor, engagement_id, task_id, target_url,
                               "Read-only HTTP OPTIONS capability observation", headers=base_headers, method="OPTIONS", secret_headers=auth_headers)
        except ActiveExecutionError as exc:
            blocked_requests += 1
            options = {"blocked": str(exc)}
        if options and isinstance(options, dict):
            evidence_refs.extend(options.get("evidence_refs", []))
        if options and options.get("status_code"):
            option_headers = _headers_map(options.get("response_headers") or {})
            allowed_methods = option_headers.get("allow") or option_headers.get("access-control-allow-methods")
            if allowed_methods:
                findings.append({"type": "http-options-methods-observed", "url": target_url,
                                 "methods": _parse_allowed_methods(allowed_methods),
                                 "status": "capability_observation_not_a_vulnerability"})
        if cors and cors.get("status_code"):
            response_headers = _headers_map(cors.get("response_headers") or {})
            allowed_origin = response_headers.get("access-control-allow-origin", "")
            allow_credentials = response_headers.get("access-control-allow-credentials", "").lower() == "true"
            if allowed_origin == "https://pentest-agent.invalid" and allow_credentials:
                findings.append({"type": "cors-origin-reflection-with-credentials", "url": target_url, "status": "requires_independent_validation"})
            elif allowed_origin == "*":
                findings.append({"type": "cors-wildcard-origin", "url": target_url, "status": "configuration_observation_not_proof"})
        return {
            "status": "completed" if page_count and not blocked_requests else "partial",
            "blocked_requests": blocked_requests,
            "target": target_url,
            "pages_fetched": page_count,
            "pages_seen": len(visited),
            "observed_endpoints": sorted(endpoints - inferred_endpoints),
            "inferred_javascript_endpoints": sorted(inferred_endpoints),
            "endpoints": sorted(endpoints),
            "javascript_assets": sorted(js_assets),
            "javascript_analysis": js_results,
            "api_operations": api_operations,
            "identity_metadata": identity_metadata,
            "technology_indicators": {k: sorted(v) if isinstance(v, set) else v for k, v in tech.items()},
            "observations": findings,
            "evidence_refs": list(dict.fromkeys(evidence_refs)),
            "cors_observation": cors,
            "options_observation": options,
            "limits": {"max_pages": max_pages, "max_depth": max_depth, "same_origin_only": True, "authenticated_mode": bool(auth_headers), "methods": ["GET", "OPTIONS"]},
            "note": "Static indicators and configuration observations are candidates, not confirmed vulnerabilities. All HTTP requests were GET/OPTIONS-only and broker-recorded.",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--max-depth", type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(run_discovery(args.db, args.engagement_id, args.task_id, args.target_url,
                                   args.max_pages, args.max_depth), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ActiveExecutionError, ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
