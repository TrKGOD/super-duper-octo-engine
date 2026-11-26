"""Coverage accounting for a browser-intelligence run.

Coverage distinguishes *discovered* (seen as a link/route), *visited* (actually
navigated), *captured* (network endpoints observed), forms, workflows, and *blocked*
actions (refused by scope). It is progress accounting, not proof that any endpoint was
security-tested — validation is a separate stage.
"""
from __future__ import annotations


class BrowserCoverage:
    def __init__(self) -> None:
        self.discovered_routes: set[str] = set()
        self.visited_routes: set[str] = set()
        self.endpoints: set[tuple] = set()
        self.form_actions: set[str] = set()
        self.workflows: set[str] = set()
        self.captured_requests = 0
        self.authenticated: dict[str, set[str]] = {}
        self.failed_navigations: list[dict] = []
        self.blocked_actions: list[dict] = []

    def record_discovered(self, template: str, identity: str | None = None) -> None:
        self.discovered_routes.add(template)
        if identity:
            self.authenticated.setdefault(identity, set())

    def record_visit(self, template: str, identity: str | None = None) -> None:
        self.discovered_routes.add(template)
        self.visited_routes.add(template)
        if identity:
            self.authenticated.setdefault(identity, set()).add(template)

    def record_endpoint(self, endpoint_key: tuple) -> None:
        self.endpoints.add(endpoint_key)

    def record_request(self) -> None:
        self.captured_requests += 1

    def record_form(self, action_template: str) -> None:
        self.form_actions.add(action_template)

    def record_workflow(self, name: str) -> None:
        self.workflows.add(name)

    def record_failure(self, route: str, error: str) -> None:
        self.failed_navigations.append({"route": route, "error": error})

    def record_blocked(self, url: str, reason: str) -> None:
        self.blocked_actions.append({"url": url, "reason": reason})

    def report(self) -> dict:
        discovered = len(self.discovered_routes)
        visited = len(self.visited_routes)
        unexplored = sorted(self.discovered_routes - self.visited_routes)
        percent = round(100 * visited / discovered, 1) if discovered else 0.0
        return {
            "routes_discovered": discovered,
            "routes_visited": visited,
            "routes_unexplored": unexplored,
            "navigation_coverage_percent": percent,
            "endpoints_captured": len(self.endpoints),
            "requests_captured": self.captured_requests,
            "forms_discovered": len(self.form_actions),
            "workflows_discovered": len(self.workflows),
            "authenticated_identities": sorted(self.authenticated),
            "authenticated_coverage": {
                identity: sorted(routes) for identity, routes in sorted(self.authenticated.items())
            },
            "failed_navigations": list(self.failed_navigations),
            "blocked_actions": list(self.blocked_actions),
            "warning": "Navigation coverage is discovery progress, not proof that any "
                       "endpoint was security-tested; validation is a separate stage.",
        }
