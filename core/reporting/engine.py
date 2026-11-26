"""Reporting engine: build a structured report, then render it to a chosen format.

Consumes normalized findings, evidence, attack surface and tool-execution data via
`ReportContext`, applies a versioned template, and renders Markdown / HTML / JSON / SARIF.
PDF is not bundled — operators print the HTML to PDF — so it is not offered as a format here
rather than pretending to produce one.
"""
from __future__ import annotations

import json

from core.reporting import render as _render
from core.reporting.context import ReportContext
from core.reporting.templates import BUILDERS

FORMATS = ("json", "markdown", "html", "sarif")


class ReportingError(ValueError):
    pass


class ReportingEngine:
    def __init__(self, store, project_root="."):
        self.store = store
        self.project_root = project_root

    def report_types(self) -> list[str]:
        return sorted(BUILDERS)

    def build(self, report_type: str, engagement_id: str) -> dict:
        if report_type not in BUILDERS:
            raise ReportingError("Unknown report type: " + str(report_type))
        ctx = ReportContext(self.store, engagement_id, project_root=self.project_root)
        return BUILDERS[report_type](ctx)

    def render(self, structured: dict, fmt: str = "markdown") -> str:
        if fmt == "json":
            return _render.to_json(structured)
        if fmt == "markdown":
            return _render.to_markdown(structured)
        if fmt == "html":
            return _render.to_html(structured)
        if fmt == "sarif":
            return json.dumps(_render.to_sarif(structured), indent=2, sort_keys=True)
        raise ReportingError("Unknown format: " + str(fmt) + " (supported: " + ", ".join(FORMATS)
                             + "; PDF is produced by printing the HTML)")

    def generate(self, report_type: str, engagement_id: str, fmt: str = "markdown") -> str:
        return self.render(self.build(report_type, engagement_id), fmt)
