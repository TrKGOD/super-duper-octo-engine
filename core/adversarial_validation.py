"""Structured, bounded adversarial review for independent finding validation."""
from __future__ import annotations

class AdversarialReviewError(ValueError):
    pass

DISPOSITIONS = {"supported", "refuted", "inconclusive"}

def build_challenge(finding, max_claims=12):
    contract = finding.get("evidence_contract") or {}
    claims = contract.get("claims") or []
    if not claims:
        raise AdversarialReviewError("Cannot challenge a finding without explicit evidence claims")
    if len(claims) > max_claims:
        raise AdversarialReviewError("Claim count exceeds the review budget")
    return {"finding_id": finding.get("finding_id"),
            "proposer": finding.get("proposed_by"),
            "reviewer_must_differ_from": finding.get("proposed_by"),
            "claims": [{"claim_id": c["claim_id"], "assertion": c["assertion"],
                        "counter_hypotheses": c.get("alternative_explanations", []),
                        "evidence_to_inspect": c.get("supporting_refs", [])}
                       for c in claims],
            "instruction": "Attempt to disprove each claim. Do not infer impossibility from missing evidence; mark inconclusive and request a concrete next check."}

def evaluate_review(finding, review, max_rounds=3):
    if not isinstance(review, dict):
        raise AdversarialReviewError("Review must be an object")
    reviewer = review.get("reviewer")
    if not isinstance(reviewer, str) or not reviewer.strip() or reviewer == finding.get("proposed_by"):
        raise AdversarialReviewError("Reviewer must be distinct from the proposing agent")
    rounds = review.get("rounds", 1)
    if not isinstance(rounds, int) or rounds < 1 or rounds > max_rounds:
        raise AdversarialReviewError("Adversarial review exceeded its bounded round limit")
    expected = {c.get("claim_id") for c in (finding.get("evidence_contract") or {}).get("claims", [])}
    results = review.get("claim_results")
    if not isinstance(results, list) or {r.get("claim_id") for r in results} != expected:
        raise AdversarialReviewError("Every claim must receive exactly one disposition")
    if any(r.get("disposition") not in DISPOSITIONS for r in results):
        raise AdversarialReviewError("Unsupported claim disposition")
    if any(not isinstance(r.get("rationale"), str) or not r["rationale"].strip() for r in results):
        raise AdversarialReviewError("Each disposition requires an evidence-based rationale")
    refuted = [r["claim_id"] for r in results if r["disposition"] == "refuted"]
    inconclusive = [r["claim_id"] for r in results if r["disposition"] == "inconclusive"]
    supported = [r["claim_id"] for r in results if r["disposition"] == "supported"]
    if refuted:
        decision = "rejected"
    elif inconclusive:
        decision = "needs_more_evidence"
    else:
        decision = "eligible_for_independent_validation"
    return {"decision": decision, "supported_claims": supported,
            "refuted_claims": refuted, "inconclusive_claims": inconclusive,
            "reviewer": reviewer, "rounds": rounds}
