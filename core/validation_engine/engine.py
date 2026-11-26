"""Independent exploit-validation engine.

Given a validation request (a vulnerability class plus the observed evidence), the engine
runs the matching deterministic oracle and returns a :class:`ValidationRecord` with the
disposition SUPPORTED / REFUTED / INCONCLUSIVE. It is **independent of the proposer**: it
derives the disposition only from the supplied evidence and deliberately ignores any
claimed conclusion in the request. It never upgrades INCONCLUSIVE to a confirmation.
"""
from __future__ import annotations

from core.validation_engine.oracles import ORACLES, OracleError
from core.validation_engine.records import (DISPOSITIONS, ValidationRecord,
                                            ValidationRecordStore)


class ValidationError(ValueError):
    pass


class ExploitValidationEngine:
    def __init__(self, engagement_id: str, *, record_store: ValidationRecordStore | None = None,
                 validator_id: str = "exploit-validation-engine", version: str = "1.0"):
        self.engagement_id = engagement_id
        self.record_store = record_store
        self.validator_id = validator_id
        self.version = version

    def validate(self, request: dict) -> ValidationRecord:
        vclass = request.get("vulnerability_class")
        oracle = ORACLES.get(vclass)
        if oracle is None:
            raise ValidationError("No validation oracle for vulnerability class: " + str(vclass))
        try:
            outcome = oracle(request)
        except OracleError as exc:
            raise ValidationError(str(exc)) from exc
        disposition = outcome["disposition"]
        if disposition not in DISPOSITIONS:
            raise ValidationError("Oracle returned an invalid disposition: " + str(disposition))

        record = ValidationRecord(
            engagement_id=self.engagement_id, vulnerability_class=vclass, oracle=oracle.__name__,
            disposition=disposition, explanation=outcome["explanation"], comparison=outcome.get("comparison", {}),
            validator_id=self.validator_id, validator_version=self.version,
            finding_id=request.get("finding_id"), hypothesis_id=request.get("hypothesis_id"),
            request_refs=list(request.get("request_refs", [])),
            response_refs=list(request.get("response_refs", [])),
            baseline_refs=list(request.get("baseline_refs", [])),
        )
        if self.record_store is not None:
            self.record_store.persist(record)
        return record
