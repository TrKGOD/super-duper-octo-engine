"""Offline OAuth/OIDC/JWT and SQL-injection evidence analyzers.

These routines inspect operator-supplied artifacts only. They do not fetch
discovery documents, verify JWT signatures, mint tokens, alter flows, or send
HTTP requests. Any security conclusion remains a candidate for independent
validation against the identity provider's documented policy.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import statistics
import sys
from pathlib import Path
from typing import Any


def _decode_segment(segment: str) -> dict[str, Any]:
    if not isinstance(segment, str) or len(segment) > 32768:
        raise ValueError("JWT segment is missing or too large")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("JWT segment is not valid base64url JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("JWT segment must decode to a JSON object")
    return value


def inspect_jwt(token: str, *, expected_issuer: str | None = None,
                expected_audience: str | None = None, jwks: dict | None = None,
                now: int | None = None) -> dict[str, Any]:
    """Inspect JWT structure and claims; deliberately does not verify signatures."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise ValueError("Expected compact signed JWT with three segments")
    header, claims = _decode_segment(parts[0]), _decode_segment(parts[1])
    findings: list[str] = []
    alg = header.get("alg")
    if alg == "none":
        findings.append("unsigned_algorithm")
    if not isinstance(alg, str) or not alg:
        findings.append("missing_algorithm")
    if header.get("crit"):
        findings.append("critical_header_requires_profile_review")
    if header.get("jku") or header.get("x5u"):
        findings.append("remote_key_reference_requires_policy_review")
    if expected_issuer and claims.get("iss") != expected_issuer:
        findings.append("issuer_mismatch")
    if expected_audience:
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if expected_audience not in audiences:
            findings.append("audience_mismatch")
    if now is not None:
        if isinstance(claims.get("exp"), (int, float)) and claims["exp"] <= now:
            findings.append("token_expired")
        if isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] > now:
            findings.append("token_not_yet_valid")
        if isinstance(claims.get("iat"), (int, float)) and claims["iat"] > now:
            findings.append("issued_in_future")
    if "exp" not in claims:
        findings.append("missing_expiration")
    if jwks is not None:
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
        kid = header.get("kid")
        matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
        if kid and len(matches) == 0:
            findings.append("kid_not_found_in_supplied_jwks")
        elif kid and len(matches) > 1:
            findings.append("ambiguous_duplicate_kid_in_supplied_jwks")
        elif not kid:
            findings.append("missing_kid_requires_key_selection_review")
        if matches and matches[0].get("use") not in (None, "sig"):
            findings.append("jwks_key_not_marked_for_signatures")
        if matches and matches[0].get("alg") and alg and matches[0]["alg"] != alg:
            findings.append("jwks_algorithm_mismatch")
    return {
        "status": "candidate_only" if findings else "observation",
        "header": {k: header.get(k) for k in ("alg", "typ", "kid", "crit", "jku", "x5u") if k in header},
        "claims": {k: claims.get(k) for k in ("iss", "sub", "aud", "exp", "nbf", "iat", "azp", "scope", "nonce") if k in claims},
        "findings": findings,
        "limitations": [
            "JWT signature and cryptographic key validity were NOT verified.",
            "A finding is a policy-review candidate, not proof of exploitability.",
            "Do not log or include raw tokens in reports; retain redacted evidence references only.",
        ],
    }


def analyze_oidc_discovery(metadata: dict, *, expected_issuer: str | None = None) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise ValueError("OIDC discovery artifact must be a JSON object")
    findings = []
    issuer = metadata.get("issuer")
    if not isinstance(issuer, str) or not issuer.startswith("https://"):
        findings.append("issuer_missing_or_not_https")
    if expected_issuer and issuer != expected_issuer:
        findings.append("issuer_mismatch")
    endpoints = ("authorization_endpoint", "token_endpoint", "jwks_uri")
    for endpoint in endpoints:
        value = metadata.get(endpoint)
        if not isinstance(value, str) or not value.startswith("https://"):
            findings.append(endpoint + "_missing_or_not_https")
    algorithms = metadata.get("id_token_signing_alg_values_supported")
    if isinstance(algorithms, list) and algorithms and set(algorithms) <= {"none"}:
        findings.append("only_unsigned_id_token_algorithm_advertised")
    return {
        "status": "candidate_only" if findings else "observation",
        "issuer": issuer, "endpoints_present": {key: bool(metadata.get(key)) for key in endpoints},
        "findings": findings,
        "limitations": ["Metadata is descriptive; endpoint behavior and cryptographic validation require separate evidence."],
    }


def analyze_oauth_flow(flow: dict) -> dict[str, Any]:
    """Review a normalized, redacted flow record supplied by the operator."""
    if not isinstance(flow, dict):
        raise ValueError("OAuth flow artifact must be a JSON object")
    request = flow.get("authorization_request") or {}
    callback = flow.get("callback") or {}
    token = flow.get("token_response") or {}
    findings = []
    expected_redirect = flow.get("registered_redirect_uri")
    requested_redirect = request.get("redirect_uri")
    returned_state = callback.get("state")
    sent_state = request.get("state")
    if not sent_state:
        findings.append("authorization_request_missing_state")
    elif returned_state != sent_state:
        findings.append("state_missing_or_mismatch")
    if expected_redirect and requested_redirect != expected_redirect:
        findings.append("redirect_uri_differs_from_registered_value")
    challenge = request.get("code_challenge")
    method = request.get("code_challenge_method")
    if flow.get("public_client") is True and (not challenge or method != "S256"):
        findings.append("public_client_missing_pkce_s256")
    expected_nonce = request.get("nonce")
    actual_nonce = (flow.get("id_token_claims") or {}).get("nonce")
    if expected_nonce and actual_nonce != expected_nonce:
        findings.append("oidc_nonce_missing_or_mismatch")
    if token and token.get("token_type") and str(token["token_type"]).lower() != "bearer":
        findings.append("unexpected_token_type_review")
    return {
        "status": "candidate_only" if findings else "observation",
        "findings": findings,
        "evidence_refs": flow.get("evidence_refs", []),
        "limitations": [
            "Flow checks require accurate redacted captures and the provider's registered-client configuration.",
            "This analyzer does not redeem authorization codes, replay tokens, or validate PKCE cryptographically.",
            "Missing fields may reflect an incomplete capture; distinguish absent evidence from absent controls.",
        ],
    }


_SQL_ERROR = re.compile(
    r"(?:SQL syntax.*MySQL|Warning: mysql_|PostgreSQL.*ERROR|ORA-\\d{4,5}|"
    r"SQLite\\/JDBC|ODBC SQL Server Driver|Unclosed quotation mark|"
    r"SQLSTATE\\[[0-9A-Z]+\\])", re.IGNORECASE
)


def analyze_sqli_pair(pair: dict) -> dict[str, Any]:
    """Compare operator-captured baseline/true/false samples without issuing probes."""
    if not isinstance(pair, dict):
        raise ValueError("SQLi evidence must be a JSON object")
    baseline = pair.get("baseline") or {}
    true_case = pair.get("true_case") or {}
    false_case = pair.get("false_case") or {}
    samples = [baseline, true_case, false_case]
    if not all(isinstance(item, dict) for item in samples):
        raise ValueError("SQLi samples must be JSON objects")
    findings = []
    errors = []
    for label, sample in zip(("baseline", "true_case", "false_case"), samples):
        body = str(sample.get("body_excerpt") or "")
        if _SQL_ERROR.search(body):
            errors.append(label)
    if errors:
        findings.append("database_error_signature_observed")
    statuses = [item.get("status_code") for item in samples]
    fingerprints = [item.get("normalized_fingerprint") for item in samples]
    boolean_diff = (
        true_case.get("status_code") == false_case.get("status_code")
        and fingerprints[1] is not None and fingerprints[2] is not None
        and fingerprints[1] != fingerprints[2]
    )
    if boolean_diff:
        findings.append("boolean_pair_response_difference")
    timing = pair.get("timing_samples_ms") or {}
    true_times, false_times = timing.get("true_case"), timing.get("false_case")
    timing_signal = False
    if (isinstance(true_times, list) and isinstance(false_times, list)
            and len(true_times) >= 3 and len(false_times) >= 3
            and all(isinstance(x, (int, float)) and x >= 0 for x in true_times + false_times)):
        true_med, false_med = statistics.median(true_times), statistics.median(false_times)
        threshold = max(1000.0, statistics.median(true_times + false_times) * 0.5)
        timing_signal = abs(true_med - false_med) >= threshold
        if timing_signal:
            findings.append("repeatable_timing_difference_candidate")
    return {
        "status": "candidate_only" if findings else "observation",
        "classification": "potential_sqli_signal" if findings else "no_sqli_signal_established",
        "findings": findings, "error_sample_labels": errors,
        "status_codes": statuses, "boolean_pair_differs": boolean_diff,
        "timing_signal": timing_signal, "evidence_refs": pair.get("evidence_refs", []),
        "limitations": [
            "Response differences and error strings are leads, not proof of SQL injection.",
            "Timing signals require repeated controlled samples and network/server-load confounder review.",
            "No database contents are extracted and no write, stacked, out-of-band, or destructive query is tested.",
            "This analyzer does not generate payloads or send requests; use only approved synthetic test data.",
        ],
    }


def _load_local_json(path_text: str) -> dict:
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts or path.parts[0] != ".local":
        raise ValueError("Input must be a relative file under .local/")
    root = Path(".local")
    if root.is_symlink() or path.is_symlink():
        raise ValueError("Symlinked local evidence is not accepted")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve(strict=True)) or not resolved.is_file() or resolved.stat().st_size > 262144:
        raise ValueError("Evidence file escapes .local or exceeds 256 KiB")
    data = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Evidence file must contain a JSON object")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("oidc-discovery", "oauth-flow", "jwt", "sqli-pair"))
    parser.add_argument("--input", required=True, help="Operator-supplied JSON under .local/")
    parser.add_argument("--expected-issuer")
    parser.add_argument("--expected-audience")
    parser.add_argument("--now", type=int)
    args = parser.parse_args(argv)
    try:
        data = _load_local_json(args.input)
        if args.kind == "oidc-discovery":
            result = analyze_oidc_discovery(data, expected_issuer=args.expected_issuer)
        elif args.kind == "oauth-flow":
            result = analyze_oauth_flow(data)
        elif args.kind == "sqli-pair":
            result = analyze_sqli_pair(data)
        else:
            result = inspect_jwt(data.get("token", ""), expected_issuer=args.expected_issuer,
                expected_audience=args.expected_audience, jwks=data.get("jwks"), now=args.now)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"analysis error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
