"""Exploit Validation Engine.

Makes validation evidence-first and independent of discovery. Deterministic oracles map
observed evidence to a disposition (SUPPORTED / REFUTED / INCONCLUSIVE); the engine records
each run as a tamper-evident :class:`ValidationRecord`; the finding lifecycle is driven
through the existing state machine and its proposer≠validator gate; and findings can be
safely retested after remediation. A hypothesis is not a finding, an accepted payload is
not impact, and an INCONCLUSIVE result can never become a confirmation.

Validation receives *evidence references*, not conclusions or embedded bodies: the
:class:`EvidenceResolver` loads and integrity-checks each artifact from the vault, and only
records computed that way (``evidence_verified``) may move a finding through its lifecycle.
"""
from core.validation_engine.engine import ExploitValidationEngine
from core.validation_engine.errors import EvidenceResolutionError, ValidationError
from core.validation_engine.facts import GraphFacts
from core.validation_engine.lifecycle import FindingValidator
from core.validation_engine.oracles import ORACLES, OracleError
from core.validation_engine.records import (DISPOSITIONS, INCONCLUSIVE, REFUTED, SUPPORTED,
                                            ValidationRecord, ValidationRecordStore)
from core.validation_engine.report import ReportError, build_finding_report
from core.validation_engine.resolver import EvidenceResolver

__all__ = [
    "ExploitValidationEngine", "ValidationError", "EvidenceResolutionError", "FindingValidator",
    "EvidenceResolver", "GraphFacts", "ORACLES", "OracleError",
    "ValidationRecord", "ValidationRecordStore", "DISPOSITIONS", "SUPPORTED", "REFUTED",
    "INCONCLUSIVE", "build_finding_report", "ReportError",
]
