"""Evidence-verified adversarial finding review and lifecycle integration."""
from __future__ import annotations
import json
from core.adversarial_validation import evaluate_review, AdversarialReviewError
from core.evidence_contracts import validate_evidence_contract, EvidenceContractError
from core.evidence import EvidenceError

class FindingReviewError(ValueError):
    pass

def review_finding(store, vault, finding_id, review):
    row = store.connection.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
    if row is None:
        raise FindingReviewError("Unknown finding: " + finding_id)
    finding = dict(row)
    refs = json.loads(row["evidence_refs_json"])
    contract = review.get("evidence_contract") or finding.get("evidence_contract")
    if not contract:
        raise FindingReviewError("Finding requires an evidence_contract before adversarial review")
    if row["status"] not in {"validation_pending", "needs_more_evidence"}:
        raise FindingReviewError("Finding must be validation_pending or needs_more_evidence for adversarial review")
    evidence = []
    integrity = {}
    for ref in refs:
        item = store.connection.execute(
            "SELECT evidence_id,evidence_type FROM evidence WHERE evidence_id=? AND engagement_id=?",
            (ref, row["engagement_id"]),
        ).fetchone()
        if item is None:
            raise FindingReviewError("Evidence reference is missing or belongs to another engagement: " + ref)
        try:
            integrity[ref] = vault.verify(ref)["valid"]
        except (EvidenceError, OSError) as exc:
            raise FindingReviewError("Evidence integrity check failed: " + ref) from exc
        evidence.append(dict(item))
    verified_refs = {ref for ref, valid in integrity.items() if valid}
    for claim_result in review.get("claim_results", []):
        cited = set(claim_result.get("evidence_refs", []))
        if not cited or not cited <= verified_refs:
            raise FindingReviewError("Each review disposition must cite evidence verified for this engagement")
    try:
        readiness = validate_evidence_contract(contract, evidence, integrity)
        decision = evaluate_review({**finding, "evidence_contract": contract}, review)
    except (EvidenceContractError, AdversarialReviewError) as exc:
        raise FindingReviewError(str(exc)) from exc
    if not readiness["ready_for_independent_review"]:
        decision["decision"] = "needs_more_evidence"
        decision["missing_artifact_types"] = readiness["missing_artifact_types"]
    decision["evidence_readiness"] = readiness
    store.record_finding_review(finding_id, review["reviewer"], decision, review)
    current = row["status"]
    if decision["decision"] == "rejected":
        store.transition_finding(finding_id, "rejected", review["reviewer"],
            validation_notes="Adversarial review refuted claims: " + ", ".join(decision["refuted_claims"]))
    elif decision["decision"] == "needs_more_evidence":
        if current == "validation_pending":
            store.transition_finding(finding_id, "needs_more_evidence", review["reviewer"],
                validation_notes="Adversarial review inconclusive or evidence contract incomplete.")
    else:
        store.transition_finding(finding_id, "validated", review["reviewer"],
            validation_notes="Independent adversarial review addressed every claim; evidence integrity verified.")
    return decision
