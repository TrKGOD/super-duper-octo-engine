"""Evidence-led operational helpers for SSRF, authentication and cache analysis.

All active HTTP traffic is delegated to ActiveHTTPExecutor. This module never
opens sockets, sends raw HTTP, performs concurrent requests or bypasses scope.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from core.active_executor import ActiveExecutionError

READ_ONLY = {"GET", "HEAD", "OPTIONS"}


def _load_manifest(executor, relative_path: str) -> dict[str, Any]:
    path = Path(relative_path)
    if path.is_absolute() or ".." in path.parts or path.parts[:2] != (".local", "requests"):
        raise ActiveExecutionError("Security-test manifests must be confined to .local/requests/")
    candidate = executor.project_root / path
    if candidate.is_symlink():
        raise ActiveExecutionError("Security-test manifest must not be a symlink")
    resolved = candidate.resolve(strict=True)
    root = (executor.project_root / ".local" / "requests").resolve(strict=True)
    if not resolved.is_file() or not resolved.is_relative_to(root) or resolved.stat().st_size > 65536:
        raise ActiveExecutionError("Security-test manifest is outside the requests directory or too large")
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveExecutionError("Security-test manifest must be UTF-8 JSON") from exc
    if not isinstance(data, dict):
        raise ActiveExecutionError("Security-test manifest must be a JSON object")
    return data


def _validate_readonly_pair(left: dict, right: dict, identity_mode: str) -> None:
    for item in (left, right):
        if str(item.get("method", "")).upper() not in READ_ONLY:
            raise ActiveExecutionError("Security comparison allows only GET, HEAD and OPTIONS")
        if item.get("body") not in (None, "") or item.get("operator_approval") is not None:
            raise ActiveExecutionError("Security comparison cannot contain a body or state-change approval")
    if not left.get("request_id") or left.get("request_id") == right.get("request_id"):
        raise ActiveExecutionError("Paired requests require distinct request IDs")
    a = {k: v for k, v in left.items() if k not in {"request_id", "secret_headers"}}
    b = {k: v for k, v in right.items() if k not in {"request_id", "secret_headers"}}
    if a != b:
        raise ActiveExecutionError("Paired requests must be equivalent; only request_id and secret_headers may differ")
    left_secrets = left.get("secret_headers") or {}
    right_secrets = right.get("secret_headers") or {}
    if not isinstance(left_secrets, dict) or not isinstance(right_secrets, dict):
        raise ActiveExecutionError("secret_headers must be objects of environment-variable references")
    if identity_mode == "two_identities":
        if not left_secrets or set(left_secrets) != set(right_secrets):
            raise ActiveExecutionError("Both identities must use the same secret header names")
        if set(left_secrets.values()) & set(right_secrets.values()):
            raise ActiveExecutionError("Identity pairs require distinct secret references")
    elif identity_mode == "authenticated_vs_anonymous":
        if bool(left_secrets) == bool(right_secrets):
            raise ActiveExecutionError("Authentication comparison requires one authenticated and one anonymous manifest")
        if left_secrets and not right_secrets:
            return
        if right_secrets and not left_secrets:
            return
    else:
        raise ActiveExecutionError("Unsupported identity comparison mode")


def execute_readonly_pair(executor, engagement_id: str, task_id: str,
                          first_file: str, second_file: str, *, identity_mode: str,
                          first_label: str, second_label: str) -> dict[str, Any]:
    if not first_label.strip() or not second_label.strip() or first_label == second_label:
        raise ActiveExecutionError("Two distinct non-empty identity labels are required")
    first = _load_manifest(executor, first_file)
    second = _load_manifest(executor, second_file)
    _validate_readonly_pair(first, second, identity_mode)
    first_result = executor.execute_request_file(engagement_id, task_id, first_file)
    try:
        second_result = executor.execute_request_file(engagement_id, task_id, second_file)
    except Exception as exc:
        return {
            "status": "partial_execution", "first_label": first_label, "second_label": second_label,
            "first_response": first_result, "second_response": None,
            "evidence_refs": list(first_result.get("evidence_refs") or []),
            "error": str(exc)[:300],
            "limitations": ["Only the first brokered request completed; no comparison was performed."],
        }
    refs = list(dict.fromkeys(
        list(first_result.get("evidence_refs") or []) + list(second_result.get("evidence_refs") or [])
    ))
    return {
        "status": "comparison_completed", "first_label": first_label, "second_label": second_label,
        "first_response": first_result, "second_response": second_result, "evidence_refs": refs,
    }


def _header_map(result: dict) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (result.get("response_headers") or {}).items()}


def analyze_authentication_pair(pair: dict, *, authenticated_label: str,
                                anonymous_label: str, protected_resource: str) -> dict:
    if pair.get("status") != "comparison_completed":
        return {"status": pair.get("status", "inconclusive"), "test_type": "authentication_boundary",
                "evidence_refs": pair.get("evidence_refs", []), "limitations": ["A complete brokered pair is required."]}
    first, second = pair["first_response"], pair["second_response"]
    # Labels identify which manifest was authenticated; caller passes them explicitly.
    if pair["first_label"] == authenticated_label:
        auth, anon = first, second
    elif pair["second_label"] == authenticated_label:
        auth, anon = second, first
    else:
        raise ValueError("authenticated_label must match one of the pair labels")
    auth_ok = isinstance(auth.get("status_code"), int) and 200 <= auth["status_code"] < 300
    anon_ok = isinstance(anon.get("status_code"), int) and 200 <= anon["status_code"] < 300
    if auth_ok and anon_ok:
        classification = "potential_authentication_boundary_gap"
        rationale = "Both authenticated and anonymous identities received successful responses; confirm the resource is not intentionally public."
        status = "candidate_only"
    elif auth_ok and anon.get("status_code") in {401, 403, 404}:
        classification, rationale, status = "anonymous_access_denied", "The anonymous request received an authorization-style denial.", "observation"
    else:
        classification, rationale, status = "inconclusive_authentication_pair", "The response pair does not establish the expected authentication boundary.", "observation"
    cookie_flags = auth.get("cookie_security_flags") or []
    flattened = {str(flag).lower() for group in cookie_flags if isinstance(group, list) for flag in group}
    cookie_findings = []
    if cookie_flags:
        for flag in ("secure", "httponly"):
            if flag not in flattened:
                cookie_findings.append("missing_" + flag)
        if not any(item.startswith("samesite=") for item in flattened):
            cookie_findings.append("missing_samesite")
    return {
        "test_type": "authentication_boundary", "status": status, "classification": classification,
        "protected_resource": protected_resource, "authenticated_status": auth.get("status_code"),
        "anonymous_status": anon.get("status_code"), "session_cookie_flags": sorted(flattened),
        "cookie_flag_observations": cookie_findings, "evidence_refs": pair.get("evidence_refs", []),
        "rationale": rationale,
        "limitations": [
            "A successful anonymous response may be intentional for a public resource; verify the documented access policy.",
            "Cookie attributes are only assessed when a Set-Cookie response was captured; absence of a cookie is not itself a flaw.",
            "This check does not test login, MFA bypass, OTP replay, recovery abuse or credential guessing.",
        ],
    }


def _body_fingerprint(body: Any) -> str | None:
    if not isinstance(body, str) or not body:
        return None
    return hashlib.sha256(re.sub(r"\s+", " ", body).strip().encode()).hexdigest()


def analyze_cache_pair(pair: dict, *, first_private_marker: str,
                       second_private_marker: str) -> dict:
    if pair.get("status") != "comparison_completed":
        return {"status": pair.get("status", "inconclusive"), "test_type": "cache_isolation",
                "evidence_refs": pair.get("evidence_refs", []), "limitations": ["A complete brokered pair is required."]}
    if not first_private_marker or not second_private_marker or first_private_marker == second_private_marker:
        raise ValueError("Two distinct synthetic private markers are required")
    first, second = pair["first_response"], pair["second_response"]
    first_body = first.get("response_excerpt") or ""
    second_body = second.get("response_excerpt") or ""
    first_headers, second_headers = _header_map(first), _header_map(second)
    cache_directives = (first_headers.get("cache-control", "") + "," + second_headers.get("cache-control", "")).lower()
    shared_cache_signals = []
    for name in ("age", "x-cache", "cf-cache-status", "via"):
        values = [v for v in (first_headers.get(name), second_headers.get(name)) if v]
        if values:
            shared_cache_signals.append({"header": name, "values": values})
    leaked_first = first_private_marker in second_body
    leaked_second = second_private_marker in first_body
    sensitive_cacheable = any(token in cache_directives for token in ("public", "s-maxage", "max-age")) and not any(
        token in cache_directives for token in ("private", "no-store")
    )
    if leaked_first or leaked_second:
        classification, status = "potential_cross_identity_cache_disclosure", "candidate_only"
        rationale = "A synthetic identity-specific marker appeared in the other identity's response."
    elif sensitive_cacheable:
        classification, status = "potential_sensitive_response_cacheability", "candidate_only"
        rationale = "Cache directives indicate potentially shared caching; verify whether the response contains identity-specific data and whether the cache key varies by identity."
    else:
        classification, status = "no_cache_leak_signal_observed", "observation"
        rationale = "No cross-identity synthetic marker or clearly shared-cacheable response signal was observed."
    return {
        "test_type": "cache_isolation", "status": status, "classification": classification,
        "first_status": first.get("status_code"), "second_status": second.get("status_code"),
        "cross_identity_marker_leak": leaked_first or leaked_second,
        "cache_control": cache_directives, "vary_headers": [
            first_headers.get("vary"), second_headers.get("vary")
        ], "shared_cache_signals": shared_cache_signals,
        "response_fingerprints": [_body_fingerprint(first_body), _body_fingerprint(second_body)],
        "evidence_refs": pair.get("evidence_refs", []), "rationale": rationale,
        "limitations": [
            "This is a sequential, read-only cache-isolation check; it does not poison caches.",
            "A cache header alone does not prove cross-user disclosure.",
            "Use distinct synthetic records with unique markers and confirm CDN/proxy cache behavior independently.",
        ],
    }


def analyze_ssrf_probe(response: dict, *, marker: str, callback_events: list[dict] | None = None) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,96}", marker or ""):
        raise ValueError("SSRF marker must be a unique non-secret token")
    events = callback_events or []
    matched = [event for event in events if isinstance(event, dict) and event.get("marker") == marker]
    response_text = str(response.get("response_excerpt") or "")
    reflected = marker in response_text
    if matched:
        classification, status = "potential_ssrf_callback_observed", "candidate_only"
        rationale = "Operator-supplied callback evidence contains the unique marker; independently verify callback provenance and target-side URL-fetch behavior."
    elif reflected:
        classification, status = "marker_reflected_without_callback", "observation"
        rationale = "The marker was reflected in the application response, but no callback evidence was supplied."
    else:
        classification, status = "ssrf_inconclusive", "observation"
        rationale = "No matching callback event or response reflection was observed; this does not rule out blind or asynchronous SSRF."
    return {
        "test_type": "ssrf_canary_validation", "status": status, "classification": classification,
        "marker": marker, "callback_event_count": len(matched), "marker_reflected": reflected,
        "http_status": response.get("status_code"), "evidence_refs": list(response.get("evidence_refs") or []),
        "rationale": rationale,
        "limitations": [
            "The callback log is operator-supplied and its provenance must be independently verified.",
            "No internal, loopback, link-local, metadata or third-party destination is probed.",
            "Absence of a callback does not disprove SSRF when the feature is asynchronous or egress-filtered.",
        ],
    }


def validate_scoped_callback_url(callback_url: str, scope: dict) -> str:
    parsed = urlsplit(callback_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ActiveExecutionError("SSRF callback must be an HTTPS URL without userinfo or fragment")
    host = parsed.hostname.lower().rstrip(".")
    def matches(entry):
        entry = str(entry).lower().rstrip(".")
        return host == entry or (entry.startswith("*.") and host.endswith("." + entry[2:]) and host != entry[2:])
    allowed = any(matches(item) for item in scope.get("allowed_domains", []))
    if not allowed:
        raise ActiveExecutionError("SSRF callback host must be explicitly listed in engagement allowed_domains")
    if any(matches(item) for item in scope.get("excluded_assets", [])):
        raise ActiveExecutionError("SSRF callback host is excluded by engagement scope")
    return host



def analyze_race_capture(events: list[dict]) -> dict:
    """Review operator-supplied isolated-lab timing/state captures; performs no requests."""
    from datetime import datetime
    if not isinstance(events, list) or not 2 <= len(events) <= 100:
        raise ValueError("Race capture must contain between 2 and 100 events")
    parsed = []
    seen_ids = set()
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Every race event must be an object")
        request_id = event.get("request_id")
        if not isinstance(request_id, str) or not request_id or request_id in seen_ids:
            raise ValueError("Race events require unique request_id values")
        seen_ids.add(request_id)
        if not event.get("object_reference") or not str(event["object_reference"]).startswith("synthetic-"):
            raise ValueError("Race analysis is restricted to explicitly synthetic object references")
        try:
            start = datetime.fromisoformat(str(event["started_at"]).replace("Z", "+00:00"))
            finish = datetime.fromisoformat(str(event["finished_at"]).replace("Z", "+00:00"))
        except (KeyError, ValueError) as exc:
            raise ValueError("Race event timestamps must be ISO-8601") from exc
        if start.tzinfo is None or finish.tzinfo is None or finish < start:
            raise ValueError("Race event timestamps must be timezone-aware and ordered")
        parsed.append((event, start, finish))
    references = {item[0]["object_reference"] for item in parsed}
    if len(references) != 1:
        raise ValueError("Race capture events must refer to one synthetic object")
    overlaps = []
    for index, (left, left_start, left_end) in enumerate(parsed):
        for right, right_start, right_end in parsed[index + 1:]:
            if max(left_start, right_start) < min(left_end, right_end):
                overlaps.append([left["request_id"], right["request_id"]])
    invariant_violations = [item[0]["request_id"] for item in parsed
                            if item[0].get("invariant_violation") is True]
    if overlaps and invariant_violations:
        classification, status = "potential_race_condition", "candidate_only"
        rationale = "Overlapping synthetic operations coincide with an operator-recorded invariant violation; independently reproduce in the isolated lab."
    elif overlaps:
        classification, status = "overlap_without_invariant_violation", "observation"
        rationale = "Operations overlapped, but no explicit invariant violation was recorded."
    else:
        classification, status = "no_overlap_observed", "observation"
        rationale = "No overlapping operation intervals were present in the supplied capture."
    return {
        "test_type": "passive_race_capture_analysis", "status": status,
        "classification": classification, "overlapping_pairs": overlaps,
        "invariant_violation_request_ids": invariant_violations,
        "synthetic_object_reference": next(iter(references)), "event_count": len(parsed),
        "rationale": rationale,
        "limitations": [
            "This analyzes operator-supplied isolated-lab logs only; it does not create concurrent traffic.",
            "Clock skew, instrumentation gaps and application retries can distort overlap analysis.",
            "A candidate requires repeatable reproduction and proof of the violated business/security invariant.",
        ],
    }


def analyze_http_framing(request: dict) -> dict:
    """Passive-only framing review for supplied request headers; never sends them."""
    headers = request.get("headers") or []
    if isinstance(headers, dict):
        headers = [{"name": key, "value": value} for key, value in headers.items()]
    normalized = [(str(item.get("name", "")).lower(), str(item.get("value", "")).strip())
                  for item in headers if isinstance(item, dict)]
    transfer = [value for name, value in normalized if name == "transfer-encoding"]
    lengths = [value for name, value in normalized if name == "content-length"]
    findings = []
    if transfer and lengths:
        findings.append("transfer_encoding_and_content_length_present")
    if len(lengths) > 1:
        findings.append("duplicate_content_length_headers")
    if len(transfer) > 1:
        findings.append("duplicate_transfer_encoding_headers")
    if len(lengths) > 1 and len(set(lengths)) > 1:
        findings.append("conflicting_content_length_values")
    if len(transfer) > 1 and len(set(transfer)) > 1:
        findings.append("conflicting_transfer_encoding_values")
    if transfer and any("chunked" in value.lower() for value in transfer) and any(
        value != value.strip() for value in transfer
    ):
        findings.append("noncanonical_transfer_encoding_whitespace")
    return {
        "test_type": "passive_http_framing_review",
        "status": "observation" if findings else "no_framing_anomaly_observed",
        "findings": sorted(set(findings)),
        "limitations": [
            "Header patterns are indicators only and do not prove request smuggling.",
            "No ambiguous framing is transmitted; active desynchronization testing requires an isolated lab and a dedicated approved harness.",
        ],
    }
