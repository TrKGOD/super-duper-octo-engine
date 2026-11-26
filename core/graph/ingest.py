"""Trusted ingestion layer for the attack graph.

Separates three provenance classes and never lets a weaker one assert a stronger fact:

- **Control plane** (operator facts): identities, roles, permissions, authorized access,
  object ownership, trust boundaries. These are the only writers of authorization edges.
- **Observations** (trusted pipeline, values derived from real traffic): structure and
  `OBSERVED_ACCESS` with evidence. Never authorization grants.
- **Proposals** (untrusted agent/target-derived hypotheses): structure and hypotheses
  only. Refused if they try to assert authorization relationships or invent identities.
"""
from __future__ import annotations

from core.graph.schema import AUTHORIZATION_EDGE_TYPES, EDGE_TYPES, GraphError
from core.graph.store import AttackGraph

# Node types that represent principals/policy and may only be created by the control plane.
CONTROL_PLANE_NODE_TYPES = frozenset({"identity", "user", "role", "permission", "trust_boundary"})
# Edges an untrusted proposal may never assert (authorization, plus observation-of-fact).
PROPOSAL_FORBIDDEN_EDGES = AUTHORIZATION_EDGE_TYPES | frozenset({"OBSERVED_ACCESS"})


class IngestError(GraphError):
    pass


def _prov(source: str, extra=None) -> list:
    entry = {"source": source}
    if extra:
        entry.update(extra)
    return [entry]


def _endpoint_key(method: str, origin: str, path: str) -> str:
    return f"{str(method).upper()} {origin}{path}"


class GraphIngestor:
    def __init__(self, graph: AttackGraph, audit=None):
        self.graph = graph
        self.audit = audit or (lambda event, details: None)

    # -- control plane (operator-authorized facts) -------------------------
    def register_identity(self, identity_key: str, *, label=None, user=False, provenance="operator") -> str:
        node_type = "user" if user else "identity"
        return self.graph.upsert_node(node_type, identity_key, label=label, trust="control_plane",
                                      provenance=_prov(provenance), confidence=1.0)

    def register_role(self, role_key: str, *, permissions=()) -> str:
        rid = self.graph.upsert_node("role", role_key, trust="control_plane",
                                     provenance=_prov("operator"), confidence=1.0)
        for permission in permissions:
            self.grant_permission(role_key, permission)
        return rid

    def grant_role(self, identity_key: str, role_key: str, *, user=False) -> str:
        iid = self.register_identity(identity_key, user=user)
        rid = self.graph.upsert_node("role", role_key, trust="control_plane",
                                     provenance=_prov("operator"), confidence=1.0)
        return self.graph.upsert_edge(iid, "HAS_ROLE", rid, trust="control_plane",
                                      provenance=_prov("operator"), confidence=1.0)

    def grant_permission(self, role_key: str, permission_key: str) -> str:
        rid = self.graph.upsert_node("role", role_key, trust="control_plane",
                                     provenance=_prov("operator"), confidence=1.0)
        pid = self.graph.upsert_node("permission", permission_key, trust="control_plane",
                                     provenance=_prov("operator"), confidence=1.0)
        return self.graph.upsert_edge(rid, "HAS_PERMISSION", pid, trust="control_plane",
                                      provenance=_prov("operator"), confidence=1.0)

    def authorize_access(self, identity_key: str, endpoint_node_id: str, *, user=False) -> str:
        iid = self.register_identity(identity_key, user=user)
        return self.graph.upsert_edge(iid, "CAN_ACCESS", endpoint_node_id, trust="control_plane",
                                      provenance=_prov("operator"), confidence=1.0)

    def authorize_role_access(self, role_key: str, endpoint_node_id: str) -> str:
        rid = self.graph.upsert_node("role", role_key, trust="control_plane",
                                     provenance=_prov("operator"), confidence=1.0)
        return self.graph.upsert_edge(rid, "CAN_ACCESS", endpoint_node_id, trust="control_plane",
                                      provenance=_prov("operator"), confidence=1.0)

    def declare_object_owner(self, object_key: str, owner_identity_key: str, *, user=False) -> str:
        oid = self.graph.upsert_node("object", object_key, trust="control_plane",
                                     provenance=_prov("operator"), confidence=1.0)
        owner = self.register_identity(owner_identity_key, user=user)
        return self.graph.upsert_edge(oid, "BELONGS_TO", owner, trust="control_plane",
                                      provenance=_prov("operator"), confidence=1.0)

    def register_endpoint(self, method: str, origin: str, path: str, *, attributes=None,
                          trust="control_plane") -> str:
        key = _endpoint_key(method, origin, path)
        attrs = {"method": str(method).upper(), "origin": origin, "path": path}
        attrs.update(attributes or {})
        return self.graph.upsert_node("endpoint", key, label=path, attributes=attrs,
                                      trust=trust, provenance=_prov("operator"), confidence=1.0)

    # -- observations (trusted pipeline) -----------------------------------
    def observe_access(self, identity_key: str, endpoint_node_id: str, *, evidence_refs=(),
                       source="observation", user=False) -> str:
        node_type = "user" if user else "identity"
        iid = self.graph.node_id(node_type, identity_key)
        if self.graph.get_node_by_id(iid) is None:
            raise IngestError("Observed access must reference a registered, authorized identity")
        return self.graph.upsert_edge(iid, "OBSERVED_ACCESS", endpoint_node_id, trust="observed",
                                      provenance=_prov(source), evidence_refs=list(evidence_refs),
                                      confidence=0.6)

    def ingest_browser_report(self, report: dict, *, source="browser", identity_key=None,
                              user=False, evidence_refs=()) -> dict:
        """Fold a Browser Intelligence report into the graph as observed structure."""
        if identity_key is not None:
            node_type = "user" if user else "identity"
            if self.graph.get_node_by_id(self.graph.node_id(node_type, identity_key)) is None:
                raise IngestError("Browser observations must attach to a registered identity")
        created = {"endpoints": 0, "parameters": 0, "routes": 0, "workflows": 0, "observed_access": 0}
        prov = _prov(source, {"identity": identity_key} if identity_key else None)

        endpoint_ids: dict[str, str] = {}
        for endpoint in report.get("network_endpoints", []):
            method, origin, path = endpoint.get("method", "GET"), endpoint.get("origin", ""), endpoint.get("path_template", "/")
            key = _endpoint_key(method, origin, path)
            attrs = {"method": str(method).upper(), "origin": origin, "path": path,
                     "content_types": endpoint.get("content_types", [])}
            eid = self.graph.upsert_node("endpoint", key, label=path, attributes=attrs,
                                         trust="observed", provenance=prov, confidence=0.6)
            endpoint_ids[key] = eid
            created["endpoints"] += 1
            for param in endpoint.get("query_param_names", []):
                pid = self.graph.upsert_node("parameter", f"{key}?{param}", label=param,
                                             attributes={"name": param, "location": "query"},
                                             trust="observed", provenance=prov, confidence=0.6)
                self.graph.upsert_edge(eid, "ACCEPTS", pid, trust="observed", provenance=prov, confidence=0.6)
                created["parameters"] += 1

        for form in report.get("forms", []):
            method, origin, path = form.get("method", "GET"), form.get("origin", ""), form.get("action_template", "/")
            key = _endpoint_key(method, origin, path)
            eid = self.graph.upsert_node("endpoint", key, label=path,
                                         attributes={"method": str(method).upper(), "origin": origin, "path": path,
                                                     "form": True, "state_changing": form.get("state_changing"),
                                                     "destructive": form.get("destructive")},
                                         trust="observed", provenance=prov, confidence=0.6)
            endpoint_ids[key] = eid
            for field in form.get("fields", []):
                name = field.get("name")
                if not name:
                    continue
                pid = self.graph.upsert_node("parameter", f"{key}#{name}", label=name,
                                             attributes={"name": name, "location": "form", "type": field.get("type")},
                                             trust="observed", provenance=prov, confidence=0.6)
                self.graph.upsert_edge(eid, "ACCEPTS", pid, trust="observed", provenance=prov, confidence=0.6)
                created["parameters"] += 1

        route_ids: dict[str, str] = {}
        for route in report.get("routes", []):
            template = route.get("template")
            if not template:
                continue
            rid = self.graph.upsert_node("route", template, label=template,
                                         attributes={"methods": route.get("methods", []),
                                                     "dynamic": route.get("dynamic")},
                                         trust="observed", provenance=prov, confidence=0.5)
            route_ids[template] = rid
            created["routes"] += 1

        for workflow in report.get("workflows", []):
            name = workflow.get("name")
            if not name:
                continue
            wid = self.graph.upsert_node("workflow", name, label=name, trust="observed",
                                         provenance=prov, confidence=0.5)
            created["workflows"] += 1
            for step in workflow.get("steps", []):
                template = step.get("route")
                if template in route_ids:
                    self.graph.upsert_edge(wid, "INVOKES", route_ids[template], trust="observed",
                                           provenance=prov, confidence=0.5)

        if identity_key is not None:
            for eid in endpoint_ids.values():
                self.observe_access(identity_key, eid, evidence_refs=evidence_refs,
                                    source=source, user=user)
                created["observed_access"] += 1

        self.audit("graph.browser_report_ingested", {"source": source, "identity": identity_key, **created})
        return created

    # -- untrusted agent proposals -----------------------------------------
    def propose(self, proposals, *, source: str) -> dict:
        """Persist agent-proposed nodes/edges as inferred hypotheses.

        Refuses to create principal/policy nodes or assert authorization/observation-of-fact
        edges, so untrusted content can never mutate authorization relationships or invent
        identities. Returns counts of what was accepted.
        """
        accepted = {"nodes": 0, "edges": 0}
        prov = _prov("agent_proposal", {"origin": source})
        for proposal in proposals:
            kind = proposal.get("kind")
            if kind == "node":
                node_type = proposal.get("node_type")
                if node_type in CONTROL_PLANE_NODE_TYPES:
                    raise IngestError(
                        f"Untrusted proposal cannot create control-plane node type '{node_type}'")
                self.graph.upsert_node(node_type, proposal["key"], label=proposal.get("label"),
                                       attributes=proposal.get("attributes"), trust="inferred",
                                       provenance=prov, confidence=float(proposal.get("confidence", 0.2)))
                accepted["nodes"] += 1
            elif kind == "edge":
                edge_type = proposal.get("edge_type")
                if edge_type in PROPOSAL_FORBIDDEN_EDGES:
                    raise IngestError(
                        f"Untrusted proposal cannot assert relationship '{edge_type}' "
                        f"(authorization/observation edges require a trusted source)")
                if edge_type not in EDGE_TYPES:
                    raise IngestError("Unknown proposed edge type: " + str(edge_type))
                src = self._resolve_proposed_endpoint(proposal["src"])
                dst = self._resolve_proposed_endpoint(proposal["dst"])
                self.graph.upsert_edge(src, edge_type, dst, trust="inferred", provenance=prov,
                                       confidence=float(proposal.get("confidence", 0.2)))
                accepted["edges"] += 1
            else:
                raise IngestError("Proposal must have kind 'node' or 'edge'")
        self.audit("graph.proposals_ingested", {"source": source, **accepted})
        return accepted

    def _resolve_proposed_endpoint(self, ref: dict) -> str:
        node_type = ref.get("node_type")
        if node_type in CONTROL_PLANE_NODE_TYPES:
            raise IngestError(f"Untrusted proposal cannot reference-create node type '{node_type}'")
        return self.graph.upsert_node(node_type, ref["key"], label=ref.get("label"),
                                      trust="inferred", provenance=_prov("agent_proposal"),
                                      confidence=0.2)
