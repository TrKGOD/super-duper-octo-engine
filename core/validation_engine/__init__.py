"""Exploit Validation Engine.

Makes validation evidence-first and independent of discovery. Deterministic oracles map
observed evidence to a disposition (SUPPORTED / REFUTED / INCONCLUSIVE); the engine records
each run as a tamper-evident :class:`ValidationRecord`; the finding lifecycle is driven
through the existing state machine and its proposer≠validator gate; and findings can be
safely retested after remediation. A hypothesis is not a finding, an accepted payload is
not impact, and an INCONCLUSIVE result can never become a confirmation.
"""
from core.validation_engine.engine import ExploitValidationEngine, ValidationError
from core.validation_engine.lifecycle import FindingValidator
from core.validation_engine.oracles import ORACLES, OracleError
from core.validation_engine.records import (DISPOSITIONS, INCONCLUSIVE, REFUTED, SUPPORTED,
                                            ValidationRecord, ValidationRecordStore)
from core.validation_engine.report import ReportError, build_finding_report

__all__ = [
    "ExploitValidationEngine", "ValidationError", "FindingValidator", "ORACLES", "OracleError",
    "ValidationRecord", "ValidationRecordStore", "DISPOSITIONS", "SUPPORTED", "REFUTED",
    "INCONCLUSIVE", "build_finding_report", "ReportError",
]
