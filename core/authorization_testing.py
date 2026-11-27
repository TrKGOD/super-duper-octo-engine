"""Evidence-based comparison helpers for object-level authorization testing.

This module does not perform network requests. It analyzes responses already
returned by the scope-enforcing HTTP broker, keeping transport and policy
enforcement in ActiveHTTPExecutor.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


_VOLATILE_KEYS = {
    "requestid", "traceid", "correlationid", "timestamp", "createdat",
    "updatedat", "nonce", "csrf", "csrf_token", "token", "access_token",
}
_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "authorization", "cookie", "session", "api_key", "apikey",
}


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9_]", "", str(value).lower())


def _normalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize_json(item)
            for key, item in sorted(value.items())
            if _normalized_key(key) not in _VOLATILE_KEYS
            and _normalized_key(key) not in _SENSITIVE_KEYS
        }
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"\s+", " ", value).strip()
    return value


def _response_fingerprint(body: str | None) -> str | None:
    if not isinstance(body, str) or not body.strip():
        return None
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        normalized = re.sub(r"\s+", " ", body).strip()
        if not normalized:
            return None
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    normalized = json.dumps(
        _normalize_json(parsed), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


response_fingerprint = _response_fingerprint   # public name used by the validation engine


def _is_success(status: Any) -> bool:
    return isinstance(status, int) and 200 <= status < 300


def compare_object_access(
    owner_response: Mapping[str, Any],
    other_response: Mapping[str, Any],
    *,
    owner_identity: str,
    other_identity: str,
    object_reference: str,
) -> dict[str, Any]:
    """Compare the same read-only object request under two approved identities.

    A matching 2xx response is only a candidate signal. It is not proof that
    the object belongs exclusively to the owner identity; callers must verify
    ownership and object sensitivity using synthetic test data.
    """
    if not owner_identity.strip() or not other_identity.strip():
        raise ValueError("Both identity labels are required")
    if owner_identity == other_identity:
        raise ValueError("Authorization comparison requires two distinct identities")
    if not object_reference.strip():
        raise ValueError("A stable object reference is required")

    owner_status = owner_response.get("status_code")
    other_status = other_response.get("status_code")
    owner_body = owner_response.get("response_excerpt")
    other_body = other_response.get("response_excerpt")
    owner_truncated = owner_response.get("response_body_truncated") is True
    other_truncated = other_response.get("response_body_truncated") is True

    owner_fp = _response_fingerprint(owner_body)
    other_fp = _response_fingerprint(other_body)
    same_representation = bool(owner_fp and other_fp and owner_fp == other_fp)
    owner_allowed = _is_success(owner_status)
    other_allowed = _is_success(other_status)

    if owner_truncated or other_truncated:
        classification = "inconclusive_truncated_response"
        rationale = "At least one response was truncated; compare complete bounded evidence before drawing conclusions."
    elif not owner_allowed:
        classification = "invalid_owner_baseline"
        rationale = "The designated owner identity did not receive a successful baseline response."
    elif other_allowed and same_representation:
        classification = "potential_bola_same_object_representation"
        rationale = "A distinct identity received a successful response with the same normalized representation as the owner."
    elif other_allowed:
        classification = "potential_bola_access_granted"
        rationale = "A distinct identity received a successful response; determine whether the returned object is actually owned by the other identity or public."
    elif other_status in {401, 403, 404}:
        classification = "access_denial_observed"
        rationale = "The non-owner identity received an authorization-style denial; this single comparison does not prove complete coverage."
    else:
        classification = "inconclusive_response_difference"
        rationale = "The responses differ, but the status pattern does not establish an authorization decision."

    return {
        "test_type": "object_level_authorization_comparison",
        "classification": classification,
        "status": "candidate_only" if classification.startswith("potential_bola") else "observation",
        "owner_identity": owner_identity,
        "other_identity": other_identity,
        "object_reference": object_reference,
        "owner_status": owner_status,
        "other_status": other_status,
        "same_normalized_representation": same_representation,
        "owner_response_fingerprint": owner_fp,
        "other_response_fingerprint": other_fp,
        "evidence_refs": list(dict.fromkeys(
            list(owner_response.get("evidence_refs") or [])
            + list(other_response.get("evidence_refs") or [])
        )),
        "rationale": rationale,
        "required_follow_up": [
            "Confirm the object is synthetic and belongs to the owner identity.",
            "Confirm the second identity is not authorized to access the object.",
            "Repeat with a second known synthetic object or identity pair where safe.",
            "Have an independent validation agent review both broker evidence records.",
        ],
        "limitations": [
            "HTTP status and response similarity alone do not prove a vulnerability.",
            "Public objects, shared tenant access, caching, and application-specific policy may explain the result.",
            "No state-changing request or bulk object enumeration is performed by this analyzer.",
        ],
    }


def compare_function_access(
    baseline_response: Mapping[str, Any],
    lower_privilege_response: Mapping[str, Any],
    *,
    baseline_role: str,
    comparison_role: str,
    function_reference: str,
) -> dict[str, Any]:
    """Compare read-only access to the same function across approved roles."""
    if not baseline_role.strip() or not comparison_role.strip() or baseline_role == comparison_role:
        raise ValueError("Two distinct, non-empty role labels are required")
    if not function_reference.strip():
        raise ValueError("A function reference is required")

    baseline_status = baseline_response.get("status_code")
    comparison_status = lower_privilege_response.get("status_code")
    allowed = _is_success(baseline_status) and _is_success(comparison_status)
    denied = comparison_status in {401, 403, 404}
    if allowed:
        classification = "potential_function_level_authorization_gap"
        status = "candidate_only"
        rationale = "The lower-privilege identity received a successful response from the same read-only function."
    elif denied:
        classification = "access_denial_observed"
        status = "observation"
        rationale = "The lower-privilege identity received an authorization-style denial."
    else:
        classification = "inconclusive"
        status = "observation"
        rationale = "The response pair does not establish a role-based authorization decision."

    return {
        "test_type": "function_level_authorization_comparison",
        "classification": classification,
        "status": status,
        "baseline_role": baseline_role,
        "comparison_role": comparison_role,
        "function_reference": function_reference,
        "baseline_status": baseline_status,
        "comparison_status": comparison_status,
        "evidence_refs": list(dict.fromkeys(
            list(baseline_response.get("evidence_refs") or [])
            + list(lower_privilege_response.get("evidence_refs") or [])
        )),
        "rationale": rationale,
        "limitations": [
            "Successful access may be intentional for shared or public functions.",
            "The comparison must use equivalent requests and approved synthetic identities.",
            "A candidate requires independent validation against the documented role policy.",
        ],
    }
