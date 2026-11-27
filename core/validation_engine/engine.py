"""Independent exploit-validation engine.

Given a validation request (a vulnerability class plus the observed evidence), the engine
runs the matching deterministic oracle and returns a :class:`ValidationRecord` with the
disposition SUPPORTED / REFUTED / INCONCLUSIVE. It is **independent of the proposer**: it
derives the disposition only from the supplied evidence and deliberately ignores any
claimed conclusion in the request. It never upgrades INCONCLUSIVE to a confirmation.

Two modes, and the record says which one produced it (``evidence_verified``):

* **Resolved** (an :class:`EvidenceResolver` is configured): the request carries *references*;
  the engine loads each artifact from the vault, verifies its SHA-256 and engagement
  ownership, rebuilds the oracle input from those bytes, takes policy facts from the control
  plane (``facts``), and records which bytes it used. Only such records can drive a finding's
  lifecycle.
* **Offline** (no resolver): the oracle runs on data embedded in the request. Useful for
  analysing captured samples, but the result is explicitly *unverified* and cannot confirm
  anything.
"""
from __future__ import annotations

from core.validation_engine.errors import EvidenceResolutionError, ValidationError  # noqa: F401 - re-exported
from core.validation_engine.oracles import ORACLES, OracleError
from core.validation_engine.records import (DISPOSITIONS, ValidationRecord,
                                            ValidationRecordStore)


class ExploitValidationEngine:
    def __init__(self, engagement_id: str, *, record_store: ValidationRecordStore | None = None,
                 resolver=None, facts=None, validator_id: str = "exploit-validation-engine",
                 version: str = "1.0"):
        self.engagement_id = engagement_id
        self.record_store = record_store
        self.resolver = resolver
        self.facts = facts
        self.validator_id = validator_id
        self.version = version

    def validate(self, request: dict) -> ValidationRecord:
        vclass = request.get("vulnerability_class")
        oracle = ORACLES.get(vclass)
        if oracle is None:
            raise ValidationError("No validation oracle for vulnerability class: " + str(vclass))

        descriptors: list = []
        if self.resolver is not None:
            oracle_request, descriptors = self.resolver.materialize(vclass, request, self.facts)
            verified = True
        else:
            oracle_request, verified = request, False
        try:
            outcome = oracle(oracle_request)
        except OracleError as exc:
            raise ValidationError(str(exc)) from exc
        disposition = outcome["disposition"]
        if disposition not in DISPOSITIONS:
            raise ValidationError("Oracle returned an invalid disposition: " + str(disposition))

        if verified:
            # The references recorded are the ones actually loaded and hashed, not the caller's list.
            request_refs = [d["evidence_id"] for d in descriptors if d["evidence_type"] == "http_request"]
            response_refs = [d["evidence_id"] for d in descriptors if d["evidence_type"] == "http_response"]
            baseline_refs: list = []
        else:
            request_refs = list(request.get("request_refs", []))
            response_refs = list(request.get("response_refs", []))
            baseline_refs = list(request.get("baseline_refs", []))
        record = ValidationRecord(
            engagement_id=self.engagement_id, vulnerability_class=vclass, oracle=oracle.__name__,
            disposition=disposition, explanation=outcome["explanation"], comparison=outcome.get("comparison", {}),
            validator_id=self.validator_id, validator_version=self.version,
            finding_id=request.get("finding_id"), hypothesis_id=request.get("hypothesis_id"),
            request_refs=request_refs, response_refs=response_refs, baseline_refs=baseline_refs,
            evidence_verified=verified, evidence_hashes=descriptors,
            evidence_requests=list(outcome.get("evidence_requests", [])),
        )
        if self.record_store is not None:
            self.record_store.persist(record)
        return record
