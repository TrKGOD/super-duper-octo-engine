"""Browser Intelligence Engine.

Controlled, scope-bounded browser interaction that turns a modern web application's
observable behavior into a normalized, deduplicated attack surface: routes, network
endpoints, forms, workflows and coverage.

Design rules (enforced by the modules below and their tests):

- All page-derived content is **untrusted data**. It never changes scope, policy or
  agent behavior; page text is never interpreted as an instruction.
- Scope is enforced with the **same deterministic allowlists** as the HTTP broker
  (``core.active_executor``). There is no second, browser-specific policy engine.
- Request/response **bodies, cookie values and secret-bearing header values are never
  stored**; only structure and metadata are kept, with sensitive query values stripped.
- Browser I/O is isolated behind an injectable ``BrowserDriver`` so the engine is fully
  testable without a real browser. The real Playwright-backed driver is an optional
  dependency and its real-browser path is exercised only by an optional E2E test.
- The engine **discovers**; it never auto-submits state-changing or destructive forms.
"""
from core.browser.coverage import BrowserCoverage
from core.browser.forms import DiscoveredForm, FormCatalog, parse_forms_from_html
from core.browser.models import NetworkObservation, NormalizedRoute, Workflow, WorkflowStep
from core.browser.network import NetworkIntelligence
from core.browser.routes import RouteSet, normalize_route
from core.browser.runner import (BrowserBudget, BrowserIntelligenceRunner, ChallengeRequired,
                                  PageObservation, compare_identity_surfaces, merge_surface_sources)
from core.browser.scope import OriginScope

__all__ = [
    "BrowserCoverage", "BrowserBudget", "BrowserIntelligenceRunner", "ChallengeRequired",
    "DiscoveredForm", "FormCatalog", "NetworkIntelligence", "NetworkObservation",
    "NormalizedRoute", "OriginScope", "PageObservation", "RouteSet", "Workflow",
    "WorkflowStep", "compare_identity_surfaces", "merge_surface_sources",
    "normalize_route", "parse_forms_from_html",
]
