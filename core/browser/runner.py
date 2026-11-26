"""Bounded, scope-enforced browser exploration orchestrator.

The runner drives an injectable :class:`BrowserDriver` over a bounded set of in-scope
routes, folding every observation into normalized routes, network endpoints, forms and
coverage. It enforces scope on both navigation targets and captured requests using the
shared :class:`~core.browser.scope.OriginScope`, treats all page content as untrusted
data, pauses on human-verification challenges, and never auto-submits forms.

Browser I/O lives entirely behind the driver, so the engine is exercised in CI with a
scripted fake driver. The real Playwright driver (``core.browser.playwright_driver``) is
an optional dependency validated only by an optional end-to-end test.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from core.browser.coverage import BrowserCoverage
from core.browser.forms import FormCatalog, parse_forms_from_html
from core.browser.models import Workflow, WorkflowStep
from core.browser.network import NetworkIntelligence
from core.browser.routes import RouteSet, normalize_route
from core.browser.scope import OriginScope
from core.store import utc_now

_UNTRUSTED_NOTE = (
    "All routes, endpoints and forms are derived from untrusted page content and are "
    "candidates for assessment, not confirmed findings. Page content never alters scope "
    "or policy. Discovery did not submit forms or perform state-changing actions."
)


@dataclass
class PageObservation:
    """What a driver reports after visiting one route. All fields are untrusted."""
    url: str
    status: int | None = None
    html: str = ""
    links: tuple = ()          # raw anchor hrefs
    client_routes: tuple = ()  # router-exposed route patterns/links
    network: tuple = ()        # raw per-request metadata dicts
    actions: tuple = ()        # labels of observable actions on the page (for workflows)
    challenge: bool = False
    error: str | None = None


class BrowserDriver:
    """Interface a concrete browser backend must implement."""

    def navigate(self, url: str) -> PageObservation:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        return None


@dataclass
class BrowserBudget:
    max_pages: int = 25
    max_requests: int = 400
    max_failures: int = 10

    def validate(self) -> "BrowserBudget":
        if not 1 <= self.max_pages <= 500:
            raise ValueError("max_pages must be between 1 and 500")
        if not 1 <= self.max_requests <= 5000:
            raise ValueError("max_requests must be between 1 and 5000")
        if not 1 <= self.max_failures <= 100:
            raise ValueError("max_failures must be between 1 and 100")
        return self


class ChallengeRequired(RuntimeError):
    """Raised to pause exploration when a human-verification challenge is detected."""

    def __init__(self, route: str, identity: str | None):
        super().__init__("Human verification challenge detected; browser exploration paused")
        self.route = route
        self.identity = identity


def _pattern_marker(path: str) -> bool:
    return any(marker in path for marker in (":", "{", "}", "*"))


def _strip_fragment(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


class BrowserIntelligenceRunner:
    def __init__(self, driver: BrowserDriver, origin_scope: OriginScope, *,
                 budget: BrowserBudget | None = None, identity: str | None = None,
                 challenge_pause: bool = True, audit=None) -> None:
        self.driver = driver
        self.scope = origin_scope
        self.budget = (budget or BrowserBudget()).validate()
        self.identity = identity
        self.challenge_pause = challenge_pause
        self.audit = audit or (lambda event, details: None)
        self.routes = RouteSet()
        self.network = NetworkIntelligence()
        self.forms = FormCatalog()
        self.coverage = BrowserCoverage()
        self.workflows: list[Workflow] = []
        self._requests_captured = 0
        self._failures = 0

    # -- queue helpers -----------------------------------------------------
    def _enqueue(self, queue, queued_templates, visited_templates, raw_url, base, kind):
        absolute = urljoin(base, str(raw_url))
        parsed = urlsplit(absolute)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return
        path_and_fragment = (parsed.path or "") + (("#" + parsed.fragment) if parsed.fragment else "")
        template, _ = normalize_route(absolute)
        allowed, reason = self.scope.check(absolute)
        if not allowed:
            self.coverage.record_blocked(_strip_fragment(absolute), reason or "out_of_scope")
            return
        # Record the route as discovered regardless of whether it is a navigable concrete URL.
        self.routes.add(absolute, kind=kind, source="browser")
        self.coverage.record_discovered(template, self.identity)
        if _pattern_marker(path_and_fragment):
            return  # unresolved route pattern: discovered, but not navigable
        if template in visited_templates or template in queued_templates:
            return
        queued_templates.add(template)
        queue.append(absolute)

    # -- network -----------------------------------------------------------
    def _ingest_network(self, page: PageObservation):
        for raw in page.network or ():
            if self._requests_captured >= self.budget.max_requests:
                return
            if not isinstance(raw, dict) or not raw.get("url"):
                continue
            url = str(raw["url"])
            allowed, reason = self.scope.check(url)
            if not allowed:
                # The real driver aborts cross-origin requests; record the blocked attempt.
                self.network.ingest(raw, action="aborted", identity=self.identity,
                                    blocked=True, block_reason=reason or "out_of_scope")
                self.coverage.record_blocked(_strip_fragment(url), reason or "out_of_scope_request")
                continue
            observation = self.network.ingest(raw, action=raw.get("action"), identity=self.identity)
            if observation is None:
                continue
            self._requests_captured += 1
            self.coverage.record_request()
            self.coverage.record_endpoint(observation.endpoint_key)
            self.routes.add(url, methods=(observation.method,), kind="api", source="network")

    # -- forms -------------------------------------------------------------
    def _ingest_forms(self, page: PageObservation, final_url: str, template: str):
        for form in parse_forms_from_html(page.html, final_url, source_route=template):
            # Record forms whose action stays within scope; never submit anything. The
            # form's resolved origin (not its path template, which drops the host) is what
            # must be checked, so a cross-origin action target is correctly rejected.
            if not self.scope.allows(form.origin + "/"):
                self.coverage.record_blocked(form.action_template, "form_action_out_of_scope")
                continue
            self.forms.add(form)
            self.coverage.record_form(form.action_template)

    # -- workflows ---------------------------------------------------------
    def _record_workflow(self, page: PageObservation, template: str):
        if not page.actions:
            return
        steps = tuple(WorkflowStep(action=str(label), route=template, kind="click")
                      for label in page.actions if label)
        if not steps:
            return
        name = f"{template}::" + "|".join(step.action for step in steps)
        self.workflows.append(Workflow(name=name, steps=steps, identity=self.identity, mutating=False))
        self.coverage.record_workflow(name)

    # -- main loop ---------------------------------------------------------
    def explore(self, seeds) -> dict:
        queue: list[str] = []
        queued_templates: set[str] = set()
        visited_templates: set[str] = set()
        for seed in seeds or ():
            self._enqueue(queue, queued_templates, visited_templates, seed, str(seed), "navigation")

        challenge_hit = False
        pages_visited = 0
        while queue and pages_visited < self.budget.max_pages:
            if self._failures >= self.budget.max_failures:
                self.audit("browser.exploration_aborted", {"reason": "failure_budget_exhausted"})
                break
            url = queue.pop(0)
            template, _ = normalize_route(url)
            if template in visited_templates:
                continue
            visited_templates.add(template)

            allowed, reason = self.scope.check(url)
            if not allowed:
                self.coverage.record_blocked(_strip_fragment(url), reason or "out_of_scope")
                continue

            try:
                page = self.driver.navigate(url)
            except Exception as exc:  # a driver failure must not crash the engine
                self._failures += 1
                self.coverage.record_failure(template, "driver_error: " + type(exc).__name__)
                continue
            pages_visited += 1

            if page.error:
                self._failures += 1
                self.coverage.record_failure(template, str(page.error))
                continue

            final_url = page.url or url
            final_allowed, final_reason = self.scope.check(final_url)
            if not final_allowed:
                # Navigation left scope (e.g., cross-origin redirect): record and skip ingestion.
                self.coverage.record_blocked(_strip_fragment(final_url), final_reason or "redirect_out_of_scope")
                continue
            final_template, _ = normalize_route(final_url)
            visited_templates.add(final_template)
            self.routes.add(final_url, kind="navigation", source="browser")
            self.coverage.record_visit(final_template, self.identity)

            if page.challenge:
                self.audit("browser.challenge_required", {"route": final_template, "identity": self.identity})
                challenge_hit = True
                if self.challenge_pause:
                    raise ChallengeRequired(final_template, self.identity)
                self.coverage.record_blocked(_strip_fragment(final_url), "challenge_required")
                continue

            self._ingest_network(page)
            self._ingest_forms(page, final_url, final_template)
            self._record_workflow(page, final_template)

            for raw_link in list(page.links or ()) + list(page.client_routes or ()):
                kind = "navigation" if raw_link in (page.links or ()) else "client_route"
                self._enqueue(queue, queued_templates, visited_templates, raw_link, final_url, kind)

        return self._report(list(seeds or ()), pages_visited, challenge_hit)

    def _report(self, seeds, pages_visited, challenge_hit) -> dict:
        return {
            "identity": self.identity,
            "seeds": seeds,
            "pages_visited": pages_visited,
            "routes": self.routes.normalized(),
            "network_observations": self.network.observations(),
            "network_endpoints": self.network.endpoints(),
            "forms": self.forms.normalized(),
            "workflows": [workflow.to_dict() for workflow in self.workflows],
            "coverage": self.coverage.report(),
            "challenge_required": challenge_hit,
            "budget": {"max_pages": self.budget.max_pages, "max_requests": self.budget.max_requests,
                       "max_failures": self.budget.max_failures},
            "generated_at": utc_now(),
            "note": _UNTRUSTED_NOTE,
        }


def compare_identity_surfaces(report_a: dict, report_b: dict) -> dict:
    """Compare two identities' observed routes/endpoints (observation, not an authz claim).

    This reports *observed reachability differences* between two authorized identities. It
    is evidence for later access-control analysis; it does not by itself prove a finding,
    and accessibility is never inferred from hidden UI elements.
    """
    def templates(report):
        return {route["template"] for route in report.get("routes", [])}

    def endpoints(report):
        return {(e["method"], e["path_template"], e["origin"]) for e in report.get("network_endpoints", [])}

    routes_a, routes_b = templates(report_a), templates(report_b)
    ep_a, ep_b = endpoints(report_a), endpoints(report_b)
    return {
        "identity_a": report_a.get("identity"),
        "identity_b": report_b.get("identity"),
        "routes_only_a": sorted(routes_a - routes_b),
        "routes_only_b": sorted(routes_b - routes_a),
        "routes_shared": sorted(routes_a & routes_b),
        "endpoints_only_a": sorted(list(ep) for ep in (ep_a - ep_b)),
        "endpoints_only_b": sorted(list(ep) for ep in (ep_b - ep_a)),
        "note": "Reachability differences are observations for access-control analysis, "
                "not confirmed authorization findings.",
    }


def merge_surface_sources(browser_report: dict, *other_sources: dict) -> dict:
    """Union browser routes with other discovery sources (HAR/OpenAPI/active_surface).

    Each ``other`` source may provide an ``endpoints`` list of path strings and/or a
    ``routes`` list of templates; every value is normalized before merging so equivalent
    resources collapse across sources.
    """
    merged = RouteSet()
    for route in browser_report.get("routes", []):
        merged.add(route["template"], kind="navigation", source="browser")
    for source in other_sources:
        label = source.get("source", "import") if isinstance(source, dict) else "import"
        for template in (source.get("routes", []) if isinstance(source, dict) else []):
            key = template["template"] if isinstance(template, dict) else template
            merged.add(str(key), kind="client_route", source=label)
        for endpoint in (source.get("endpoints", []) if isinstance(source, dict) else []):
            merged.add(str(endpoint), kind="api", source=label)
    routes = merged.normalized()
    return {"routes": routes, "route_count": len(routes),
            "sources": ["browser"] + [s.get("source", "import") for s in other_sources if isinstance(s, dict)]}
