"""Deterministic validation oracles, one per vulnerability class.

Each oracle maps observed evidence to a disposition using a deterministic rule, not the
proposer's claim and not "the payload was accepted". Where a sound analyzer already exists
it is reused (object/function authorization, SQLi differential); reflected-input and
security-header oracles are added here. Every oracle returns
``{"disposition", "explanation", "comparison"}``.
"""
from __future__ import annotations

import html
import re

from core.authorization_testing import compare_function_access, compare_object_access
from core.protocol_testing import analyze_sqli_pair
from core.validation_engine.records import INCONCLUSIVE, REFUTED, SUPPORTED


class OracleError(ValueError):
    pass


def object_authorization(request: dict) -> dict:
    """BOLA/IDOR: reuse the object-access comparison; access by a non-owner confirms it."""
    comparison = compare_object_access(
        request["owner_response"], request["other_response"],
        owner_identity=request["owner_identity"], other_identity=request["other_identity"],
        object_reference=request["object_reference"])
    classification = comparison["classification"]
    ownership_confirmed = bool(request.get("ownership_confirmed"))
    if classification == "potential_bola_same_object_representation":
        disposition = SUPPORTED
        explanation = ("A non-owner identity received the owner's exact normalized object "
                       "representation — broken object-level authorization.")
    elif classification == "potential_bola_access_granted" and ownership_confirmed:
        disposition = SUPPORTED
        explanation = ("A non-owner identity received a successful response for an object "
                       "confirmed to belong to another identity.")
    elif classification == "potential_bola_access_granted":
        disposition = INCONCLUSIVE
        explanation = ("A non-owner received a success response, but object ownership was not "
                       "confirmed (could be public or shared); confirm ownership to validate.")
    elif classification == "access_denial_observed":
        disposition = REFUTED
        explanation = "The non-owner identity was denied; object-level authorization held."
    else:
        disposition = INCONCLUSIVE
        explanation = comparison.get("rationale", "The comparison did not establish an authorization decision.")
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison}


def function_authorization(request: dict) -> dict:
    """BFLA: reuse the function-access comparison across approved roles."""
    comparison = compare_function_access(
        request["baseline_response"], request["lower_privilege_response"],
        baseline_role=request["baseline_role"], comparison_role=request["comparison_role"],
        function_reference=request["function_reference"])
    classification = comparison["classification"]
    policy_confirms_restriction = bool(request.get("role_restriction_confirmed"))
    if classification == "potential_function_level_authorization_gap" and policy_confirms_restriction:
        disposition = SUPPORTED
        explanation = ("A lower-privilege role invoked a function documented as restricted — "
                       "broken function-level authorization.")
    elif classification == "potential_function_level_authorization_gap":
        disposition = INCONCLUSIVE
        explanation = ("A lower-privilege role received success, but the function's role "
                       "restriction was not confirmed; confirm the policy to validate.")
    elif classification == "access_denial_observed":
        disposition = REFUTED
        explanation = "The lower-privilege role was denied; function-level authorization held."
    else:
        disposition = INCONCLUSIVE
        explanation = comparison.get("rationale", "The role comparison was inconclusive.")
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison}


def sqli(request: dict) -> dict:
    """SQL injection: reuse the differential analyzer; a boolean differential validates."""
    comparison = analyze_sqli_pair(request["samples"])
    if comparison["boolean_pair_differs"]:
        disposition = SUPPORTED
        explanation = ("True/false payloads produced a reproducible, controlled response "
                       "difference consistent with SQL injection (no data extracted).")
    elif comparison["findings"]:
        disposition = INCONCLUSIVE
        explanation = ("A SQL signal was observed (error string or timing) but no reproducible "
                       "boolean differential; gather controlled samples before confirming.")
    else:
        disposition = REFUTED
        explanation = "No SQL-injection signal was established across the samples."
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison}


_EXECUTABLE_CONTEXTS = {"html_body", "html_attribute", "script", "unknown"}


def reflected_input(request: dict) -> dict:
    """Reflected XSS: a unique marker must appear UN-encoded in an executable context."""
    marker = str(request.get("marker", "")).strip()
    body = str(request.get("response_body", ""))
    context = str(request.get("context", "unknown"))
    if not marker:
        raise OracleError("reflected_input requires a unique marker")
    present = marker in body
    encoded_present = (html.escape(marker) in body) or (re.sub(r"[<>\"'&]", "", marker) in body and not present)
    comparison = {"marker_present_raw": present, "encoded_form_present": encoded_present, "context": context}
    if present and context in _EXECUTABLE_CONTEXTS:
        disposition = SUPPORTED
        explanation = f"The marker was reflected unencoded in an executable context ({context})."
    elif not present and encoded_present:
        disposition = REFUTED
        explanation = "The marker was reflected only in an encoded/escaped form; output is sanitized."
    elif not present:
        disposition = REFUTED
        explanation = "The marker was not reflected in the response."
    else:
        disposition = INCONCLUSIVE
        explanation = "The marker was reflected but the sink context does not establish execution."
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison}


_SECURITY_HEADERS = {
    "content-security-policy", "strict-transport-security", "x-content-type-options",
    "referrer-policy", "permissions-policy", "x-frame-options",
}


def security_header(request: dict) -> dict:
    """Security misconfiguration: a required header is absent (deterministic, low severity)."""
    headers = {str(k).lower() for k in (request.get("response_headers") or {})}
    required = str(request.get("required_header", "")).lower()
    if required not in _SECURITY_HEADERS:
        raise OracleError("security_header requires a known required_header")
    comparison = {"required_header": required, "present": required in headers,
                  "observed_security_headers": sorted(headers & _SECURITY_HEADERS)}
    if required in headers:
        disposition = REFUTED
        explanation = f"The required security header '{required}' is present."
    else:
        disposition = SUPPORTED
        explanation = f"The required security header '{required}' is absent (misconfiguration)."
    return {"disposition": disposition, "explanation": explanation, "comparison": comparison}


ORACLES = {
    "object_authorization": object_authorization,
    "function_authorization": function_authorization,
    "sqli": sqli,
    "reflected_input": reflected_input,
    "security_header": security_header,
}
