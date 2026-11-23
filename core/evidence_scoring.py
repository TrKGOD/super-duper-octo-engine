"""Evidence-readiness scoring; never a substitute for independent validation."""
def score_finding(finding, evidence, integrity):
    refs = finding.get("evidence_refs") or []
    by_id = {item["evidence_id"]: item for item in evidence}
    verified = [ref for ref in refs if integrity.get(ref) is True and ref in by_id]
    request = any(by_id[ref].get("evidence_type") in {"http_request", "burp_request", "curl_command"} for ref in verified)
    response = any(by_id[ref].get("evidence_type") == "http_response" for ref in verified)
    reproduction = any(by_id[ref].get("evidence_type") == "reproduction_notes" for ref in verified)
    screenshot = any(by_id[ref].get("evidence_type") == "screenshot" for ref in verified)
    independent = bool(
        finding.get("validated_by")
        and finding.get("validated_by") != finding.get("proposed_by")
        and finding.get("status") in {"validated", "reported"}
    )
    metadata = all(finding.get(key) for key in ("asset", "method", "description"))
    components = {
        "integrity": 25 if refs and len(verified) == len(refs) else 0,
        "request_response_pair": 20 if request and response else (10 if request or response else 0),
        "independent_validation": 20 if independent else 0,
        "reproduction_notes": 15 if reproduction else 0,
        "screenshot": 10 if screenshot else 0,
        "finding_metadata": 10 if metadata else 0,
    }
    return {
        "score": sum(components.values()),
        "components": components,
        "verified_evidence_count": len(verified),
        "total_evidence_count": len(refs),
        "label": "evidence_readiness_only",
        "warning": "This score does not prove exploitability, impact, authorization, or finding validity.",
    }
