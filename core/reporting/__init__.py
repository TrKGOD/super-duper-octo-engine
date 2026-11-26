"""Reporting engine (Component G).

Generates technical, executive, attack-surface, tool-execution and evidence-package reports
in Markdown / HTML / JSON / SARIF from persisted state. Reuses the existing validated-findings
gate and evidence vault: only independently validated, integrity-verified findings appear in
confirmed sections; unvalidated findings and scanner candidates are kept separate and never
presented as confirmed.
"""
from core.reporting.context import ReportContext
from core.reporting.engine import FORMATS, ReportingEngine, ReportingError
from core.reporting.templates import BUILDERS, TEMPLATE_VERSION

__all__ = ["ReportingEngine", "ReportingError", "ReportContext", "FORMATS", "BUILDERS",
           "TEMPLATE_VERSION"]
