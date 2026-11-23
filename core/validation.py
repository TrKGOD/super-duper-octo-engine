"""Deterministic validation rules for security findings."""

class FindingValidationError(ValueError):
    pass


def validate_finding(finding):
    required = ("finding_id", "engagement_id", "title", "status", "asset", "description", "proposed_by")
    missing = [key for key in required if not finding.get(key)]
    if missing:
        raise FindingValidationError("Missing required fields: " + ", ".join(missing))
    allowed = {"observation", "hypothesis", "validation_pending", "validated", "rejected", "needs_more_evidence", "reported", "retest_pending", "resolved"}
    if finding["status"] not in allowed:
        raise FindingValidationError("Unsupported finding status: " + str(finding["status"]))
    evidence = finding.get("evidence_refs") or []
    if not isinstance(evidence, list) or any(not isinstance(x, str) or not x.strip() for x in evidence):
        raise FindingValidationError("evidence_refs must be a list of non-empty strings")
    if finding["status"] in {"validated", "reported"}:
        validator = finding.get("validated_by")
        if not isinstance(validator, str) or not validator.strip():
            raise FindingValidationError("A validated/reported finding requires validated_by")
        if validator.strip() == finding["proposed_by"].strip():
            raise FindingValidationError("The proposing agent cannot validate its own finding")
        if not evidence:
            raise FindingValidationError("A validated/reported finding requires at least one evidence reference")
    if finding["status"] == "rejected" and not finding.get("validation_notes"):
        raise FindingValidationError("A rejected finding requires validation_notes")


FINDING_TRANSITIONS = {
    "observation": {"hypothesis", "rejected", "needs_more_evidence"},
    "hypothesis": {"validation_pending", "rejected", "needs_more_evidence"},
    "validation_pending": {"validated", "rejected", "needs_more_evidence"},
    "needs_more_evidence": {"validation_pending", "rejected"},
    "validated": {"reported", "retest_pending", "resolved"},
    "reported": {"retest_pending", "resolved"},
    "retest_pending": {"validated", "needs_more_evidence", "resolved"},
    "rejected": set(),
    "resolved": set(),
}


def validate_finding_transition(current_status, next_status):
    """Reject lifecycle transitions not explicitly allowed by the finding state machine."""
    if current_status not in FINDING_TRANSITIONS:
        raise FindingValidationError("Unsupported current finding status: " + str(current_status))
    if next_status not in FINDING_TRANSITIONS[current_status]:
        raise FindingValidationError(
            "Invalid finding status transition: " + current_status + " -> " + str(next_status)
        )
