"""Finding lifecycle integration and safe retesting.

Drives the *existing* finding state machine (`core.store.transition_finding` /
`FINDING_TRANSITIONS`) from the engine's disposition rather than duplicating it, and
reuses the existing independence gate: a finding can only reach ``validated`` through an
eligible independent review by someone other than the proposer. Retesting after
remediation compares fresh evidence through the same oracle and never auto-repeats a
state-changing test.

Lifecycle mapping (directive §9.5 adapted to existing statuses):
DISCOVERED→`observation`/`hypothesis`, VALIDATION_PENDING→`validation_pending`,
CONFIRMED→`validated`, REFUTED→`rejected`, INCONCLUSIVE→`needs_more_evidence`,
REPORTED→`reported`, RETEST_PENDING→`retest_pending`, FIX_VERIFIED→`resolved`,
STILL_PRESENT→re-`validated`.
"""
from __future__ import annotations

from core.validation_engine.engine import ExploitValidationEngine, ValidationError
from core.validation_engine.records import INCONCLUSIVE, REFUTED, SUPPORTED, ValidationRecordStore


class FindingValidator:
    def __init__(self, store, *, validator_id: str = "exploit-validation-engine", version: str = "1.0"):
        self.store = store
        self.validator_id = validator_id
        self.version = version

    def _finding(self, finding_id: str):
        row = self.store.connection.execute(
            "SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if row is None:
            raise ValidationError("Unknown finding: " + str(finding_id))
        return row

    def _engine(self, engagement_id: str) -> ExploitValidationEngine:
        return ExploitValidationEngine(
            engagement_id, record_store=ValidationRecordStore(self.store.connection, engagement_id),
            validator_id=self.validator_id, version=self.version)

    def validate_finding(self, finding_id: str, request: dict, validator: str) -> dict:
        finding = self._finding(finding_id)
        if finding["status"] != "validation_pending":
            raise ValidationError("Finding must be in validation_pending to validate (is: "
                                  + finding["status"] + ")")
        if validator.strip() == finding["proposed_by"]:
            raise ValidationError("The proposing agent cannot validate its own finding")
        record = self._engine(finding["engagement_id"]).validate({**request, "finding_id": finding_id})

        if record.disposition == SUPPORTED:
            self.store.record_finding_review(finding_id, validator, {
                "decision": "eligible_for_independent_validation",
                "supported_claims": [record.record_id], "refuted_claims": [], "inconclusive_claims": []},
                record.to_dict())
            status = self.store.transition_finding(finding_id, "validated", validator,
                                                   validation_notes=record.explanation)
        elif record.disposition == REFUTED:
            status = self.store.transition_finding(finding_id, "rejected", validator,
                                                   validation_notes=record.explanation)
        else:
            status = self.store.transition_finding(finding_id, "needs_more_evidence", validator,
                                                   validation_notes=record.explanation)
        return {"disposition": record.disposition, "record_id": record.record_id, "finding_status": status}

    def retest_finding(self, finding_id: str, request: dict, validator: str) -> dict:
        finding = self._finding(finding_id)
        if finding["status"] not in ("validated", "reported"):
            raise ValidationError("Only a validated or reported finding can be retested")
        if request.get("state_changing") and not request.get("approved_state_change"):
            raise ValidationError("A state-changing retest requires explicit operator approval")
        if validator.strip() == finding["proposed_by"]:
            raise ValidationError("The proposing agent cannot retest its own finding")

        self.store.transition_finding(finding_id, "retest_pending", validator,
                                      validation_notes="Retest after remediation.")
        record = self._engine(finding["engagement_id"]).validate({**request, "finding_id": finding_id})

        if record.disposition == REFUTED:
            status = self.store.transition_finding(finding_id, "resolved", validator,
                                                   validation_notes="FIX_VERIFIED: " + record.explanation)
            outcome = "FIX_VERIFIED"
        elif record.disposition == SUPPORTED:
            self.store.record_finding_review(finding_id, validator, {
                "decision": "eligible_for_independent_validation",
                "supported_claims": [record.record_id], "refuted_claims": [], "inconclusive_claims": []},
                record.to_dict())
            status = self.store.transition_finding(finding_id, "validated", validator,
                                                   validation_notes="STILL_PRESENT: " + record.explanation)
            outcome = "STILL_PRESENT"
        else:
            status = self.store.transition_finding(finding_id, "needs_more_evidence", validator,
                                                   validation_notes="Retest inconclusive: " + record.explanation)
            outcome = "INCONCLUSIVE"
        return {"disposition": record.disposition, "outcome": outcome,
                "record_id": record.record_id, "finding_status": status}
