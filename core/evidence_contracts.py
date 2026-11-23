"""Evidence contracts for source-backed security hypotheses.

Contracts describe what would support or refute a claim. They never promote a
finding to validated; independent validation remains a separate lifecycle step.
"""
from __future__ import annotations

class EvidenceContractError(ValueError):
    pass

CLASS_REQUIREMENTS = {
    "sqli": {"http_request", "http_response", "reproduction_notes"},
    "xss": {"http_request", "http_response", "reproduction_notes"},
    "ssrf": {"http_request", "http_response", "reproduction_notes"},
    "idor": {"http_request", "http_response", "reproduction_notes"},
    "bola": {"http_request", "http_response", "reproduction_notes"},
    "authentication": {"http_request", "http_response", "reproduction_notes"},
    "authorization": {"http_request", "http_response", "reproduction_notes"},
    "source_code": {"source_excerpt", "reproduction_notes"},
    "sast": {"source_excerpt", "call_graph"},
    "dast": {"http_request", "http_response", "reproduction_notes"},
}

def validate_evidence_contract(contract, evidence_items, integrity):
    if not isinstance(contract, dict):
        raise EvidenceContractError("evidence_contract must be an object")
    claims = contract.get("claims")
    if not isinstance(claims, list) or not claims:
        raise EvidenceContractError("At least one explicit claim is required")
    by_id = {item.get("evidence_id"): item for item in evidence_items}
    seen = set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise EvidenceContractError("Each claim must be an object")
        claim_id = claim.get("claim_id")
        if not isinstance(claim_id, str) or not claim_id.strip() or claim_id in seen:
            raise EvidenceContractError("Claim IDs must be unique non-empty strings")
        seen.add(claim_id)
        if not isinstance(claim.get("assertion"), str) or not claim["assertion"].strip():
            raise EvidenceContractError(f"Claim {claim_id} has no assertion")
        refs = claim.get("supporting_refs", [])
        if not isinstance(refs, list) or not refs:
            raise EvidenceContractError(f"Claim {claim_id} has no supporting evidence")
        for ref in refs + claim.get("refuting_refs", []):
            if ref not in by_id or integrity.get(ref) is not True:
                raise EvidenceContractError(f"Claim {claim_id} references missing or unverified evidence: {ref}")
    vuln_class = str(contract.get("vulnerability_class", "")).lower()
    required = CLASS_REQUIREMENTS.get(vuln_class, set())
    present = {by_id[ref].get("evidence_type") for claim in claims
               for ref in claim.get("supporting_refs", [])}
    missing = sorted(required - present)
    return {"claim_count": len(claims), "verified_refs": sum(
        len(claim.get("supporting_refs", [])) + len(claim.get("refuting_refs", []))
        for claim in claims), "missing_artifact_types": missing,
        "ready_for_independent_review": not missing,
        "warning": "Evidence readiness is not a finding-validity or exploitability decision."}
