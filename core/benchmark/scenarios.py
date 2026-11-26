"""Synthetic benchmark scenarios.

A scenario seeds the real attack graph for a synthetic engagement and declares the
ground-truth vulnerabilities as ``(planner_category, endpoint_path)`` pairs. All targets are
in-memory synthetic data; nothing contacts a live host and no model is called. A
``DetectorProfile`` can inject false positives/negatives to exercise the metrics themselves.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable

ORIGIN = "https://app.local:443"

# Planner hypothesis category -> validation-engine oracle class.
CATEGORY_TO_CLASS = {
    "idor_bola": "object_authorization",
    "bfla": "function_authorization",
    "sqli": "sqli",
    "xss": "reflected_input",
}

ALLOWED_TEST_CLASSES = ("web-authorization-idor", "web-authorization-bac", "web-sqli",
                        "web-xss", "web-ssrf")


@dataclass(frozen=True)
class DetectorProfile:
    false_positives: frozenset = frozenset()
    false_negatives: frozenset = frozenset()

    def should_detect(self, key: tuple, is_true_vuln: bool) -> bool:
        if key in self.false_negatives:
            return False
        if key in self.false_positives:
            return True
        return is_true_vuln


PERFECT = DetectorProfile()


@dataclass(frozen=True)
class Scenario:
    name: str
    version: str
    seed: Callable          # (ingestor, graph) -> None
    ground_truth: frozenset  # of (category, endpoint_path)
    detector: DetectorProfile = PERFECT

    def hash(self) -> str:
        material = self.name + "|" + self.version + "|" + "|".join(
            sorted(f"{c}:{t}" for c, t in self.ground_truth))
        return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# -- seed helpers ---------------------------------------------------------
def _endpoint_with_param(ing, graph, method, path, param):
    eid = ing.register_endpoint(method, ORIGIN, path)
    node = graph.upsert_node("parameter", f"{method} {ORIGIN}{path}?{param}", label=param, trust="observed")
    graph.upsert_edge(eid, "ACCEPTS", node, trust="observed")
    return eid


def _seed_bola(ing, graph):
    ing.register_identity("alice")
    ing.register_identity("bob")
    eid = ing.register_endpoint("GET", ORIGIN, "/api/orders/{id}")
    obj = graph.upsert_node("object", "order-7", trust="control_plane")
    graph.upsert_edge(eid, "REFERENCES", obj, trust="observed")
    ing.declare_object_owner("order-7", "bob")
    ing.observe_access("alice", eid, evidence_refs=["bola-ev"])


def _seed_bfla(ing, graph):
    ing.register_identity("carol")
    eid = ing.register_endpoint("GET", ORIGIN, "/admin/report")
    ing.authorize_role_access("admin", eid)        # restricted to admin
    ing.observe_access("carol", eid, evidence_refs=["bfla-ev"])  # carol lacks admin


def _seed_sqli(ing, graph):
    ing.register_identity("alice")
    eid = _endpoint_with_param(ing, graph, "GET", "/search", "q")
    ing.observe_access("alice", eid)


def _seed_clean(ing, graph):
    ing.register_identity("alice")
    eid = _endpoint_with_param(ing, graph, "GET", "/profile", "name")
    ing.observe_access("alice", eid)


def _seed_mixed(ing, graph):
    _seed_bola(ing, graph)
    _seed_sqli(ing, graph)
    _seed_clean(ing, graph)


def build_default_scenarios() -> list[Scenario]:
    return [
        Scenario("web-bola-basic", "1.0", _seed_bola,
                 frozenset({("idor_bola", "/api/orders/{id}")})),
        Scenario("api-bfla-basic", "1.0", _seed_bfla,
                 frozenset({("bfla", "/admin/report")})),
        Scenario("web-sqli-basic", "1.0", _seed_sqli,
                 frozenset({("sqli", "/search")})),
        Scenario("clean-negative", "1.0", _seed_clean, frozenset()),
        Scenario("mixed-web-api", "1.0", _seed_mixed,
                 frozenset({("idor_bola", "/api/orders/{id}"), ("sqli", "/search")})),
    ]
