"""Engagement-scoped attack-graph persistence over SQLite.

Nodes and edges deduplicate on their natural key, accumulate provenance, keep the highest
confidence seen, and upgrade to the strongest trust asserted. Every read and write is
constrained to a single engagement, so one engagement's graph can never read or mutate
another's. Authorization/policy edges are refused below control-plane trust here, at the
lowest level, independent of the ingestion API.
"""
from __future__ import annotations

import hashlib
import json

from core.graph.schema import (GraphError, ensure_authorization_trust, stronger_trust,
                               validate_edge, validate_node_type)
from core.store import utc_now


def _digest(prefix: str, *parts: str) -> str:
    raw = "\x00".join(parts).encode("utf-8")
    return prefix + hashlib.sha256(raw).hexdigest()[:24]


def _merge_provenance(existing: list, additions: list) -> list:
    merged = list(existing)
    seen = {json.dumps(item, sort_keys=True) for item in merged}
    for item in additions:
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            merged.append(item)
            seen.add(key)
    return merged


class AttackGraph:
    def __init__(self, connection, engagement_id: str):
        self.connection = connection
        self.engagement_id = engagement_id

    # -- ids ---------------------------------------------------------------
    def node_id(self, node_type: str, key: str) -> str:
        return _digest("gn_", self.engagement_id, node_type, key)

    def _edge_id(self, src_id: str, edge_type: str, dst_id: str) -> str:
        return _digest("ge_", self.engagement_id, src_id, edge_type, dst_id)

    # -- nodes -------------------------------------------------------------
    def upsert_node(self, node_type: str, key: str, *, label: str | None = None,
                    attributes: dict | None = None, trust: str = "inferred",
                    provenance=None, confidence: float = 0.0) -> str:
        validate_node_type(node_type)
        if not isinstance(key, str) or not key.strip():
            raise GraphError("Node key must be a non-empty string")
        node_id = self.node_id(node_type, key)
        attributes = dict(attributes or {})
        provenance = list(provenance or [])
        now = utc_now()
        with self.connection:
            row = self.connection.execute(
                "SELECT attributes_json,provenance_json,trust,confidence,created_at,label "
                "FROM graph_nodes WHERE node_id=? AND engagement_id=?",
                (node_id, self.engagement_id),
            ).fetchone()
            if row is None:
                self.connection.execute(
                    "INSERT INTO graph_nodes(node_id,engagement_id,node_type,node_key,label,"
                    "attributes_json,trust,provenance_json,confidence,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (node_id, self.engagement_id, node_type, key, label,
                     json.dumps(attributes, sort_keys=True), trust,
                     json.dumps(provenance), float(confidence), now, now),
                )
            else:
                merged_attrs = {**json.loads(row["attributes_json"]), **attributes}
                merged_prov = _merge_provenance(json.loads(row["provenance_json"]), provenance)
                self.connection.execute(
                    "UPDATE graph_nodes SET label=?,attributes_json=?,trust=?,provenance_json=?,"
                    "confidence=?,updated_at=? WHERE node_id=? AND engagement_id=?",
                    (label or row["label"], json.dumps(merged_attrs, sort_keys=True),
                     stronger_trust(trust, row["trust"]), json.dumps(merged_prov),
                     max(float(confidence), float(row["confidence"])), now,
                     node_id, self.engagement_id),
                )
        return node_id

    # -- edges -------------------------------------------------------------
    def upsert_edge(self, src_id: str, edge_type: str, dst_id: str, *, trust: str = "inferred",
                    attributes: dict | None = None, provenance=None, confidence: float = 0.0,
                    evidence_refs=None) -> str:
        src = self._node_row(src_id)
        dst = self._node_row(dst_id)
        if src is None or dst is None:
            raise GraphError("Both edge endpoints must be existing nodes in this engagement")
        validate_edge(edge_type, src["node_type"], dst["node_type"])
        ensure_authorization_trust(edge_type, trust)
        edge_id = self._edge_id(src_id, edge_type, dst_id)
        attributes = dict(attributes or {})
        provenance = list(provenance or [])
        evidence_refs = list(evidence_refs or [])
        now = utc_now()
        with self.connection:
            row = self.connection.execute(
                "SELECT attributes_json,provenance_json,evidence_refs_json,trust,confidence,created_at "
                "FROM graph_edges WHERE edge_id=? AND engagement_id=?",
                (edge_id, self.engagement_id),
            ).fetchone()
            if row is None:
                self.connection.execute(
                    "INSERT INTO graph_edges(edge_id,engagement_id,src_node_id,dst_node_id,edge_type,"
                    "trust,attributes_json,provenance_json,evidence_refs_json,confidence,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (edge_id, self.engagement_id, src_id, dst_id, edge_type, trust,
                     json.dumps(attributes, sort_keys=True), json.dumps(provenance),
                     json.dumps(evidence_refs), float(confidence), now, now),
                )
            else:
                merged_attrs = {**json.loads(row["attributes_json"]), **attributes}
                merged_prov = _merge_provenance(json.loads(row["provenance_json"]), provenance)
                merged_ev = _merge_provenance(json.loads(row["evidence_refs_json"]), evidence_refs)
                self.connection.execute(
                    "UPDATE graph_edges SET attributes_json=?,trust=?,provenance_json=?,evidence_refs_json=?,"
                    "confidence=?,updated_at=? WHERE edge_id=? AND engagement_id=?",
                    (json.dumps(merged_attrs, sort_keys=True), stronger_trust(trust, row["trust"]),
                     json.dumps(merged_prov), json.dumps(merged_ev),
                     max(float(confidence), float(row["confidence"])), now, edge_id, self.engagement_id),
                )
        return edge_id

    # -- reads -------------------------------------------------------------
    def _node_row(self, node_id: str):
        return self.connection.execute(
            "SELECT * FROM graph_nodes WHERE node_id=? AND engagement_id=?",
            (node_id, self.engagement_id),
        ).fetchone()

    @staticmethod
    def _node_dict(row) -> dict:
        return {
            "node_id": row["node_id"], "node_type": row["node_type"], "key": row["node_key"],
            "label": row["label"], "attributes": json.loads(row["attributes_json"]),
            "trust": row["trust"], "provenance": json.loads(row["provenance_json"]),
            "confidence": row["confidence"],
        }

    @staticmethod
    def _edge_dict(row) -> dict:
        return {
            "edge_id": row["edge_id"], "src": row["src_node_id"], "dst": row["dst_node_id"],
            "edge_type": row["edge_type"], "trust": row["trust"],
            "attributes": json.loads(row["attributes_json"]),
            "provenance": json.loads(row["provenance_json"]),
            "evidence_refs": json.loads(row["evidence_refs_json"]), "confidence": row["confidence"],
        }

    def get_node(self, node_type: str, key: str):
        row = self._node_row(self.node_id(node_type, key))
        return self._node_dict(row) if row else None

    def get_node_by_id(self, node_id: str):
        row = self._node_row(node_id)
        return self._node_dict(row) if row else None

    def nodes(self, node_type: str | None = None) -> list[dict]:
        if node_type is None:
            rows = self.connection.execute(
                "SELECT * FROM graph_nodes WHERE engagement_id=? ORDER BY node_type,node_key",
                (self.engagement_id,)).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM graph_nodes WHERE engagement_id=? AND node_type=? ORDER BY node_key",
                (self.engagement_id, node_type)).fetchall()
        return [self._node_dict(row) for row in rows]

    def edges(self, edge_type: str | None = None, *, src_id: str | None = None,
              dst_id: str | None = None) -> list[dict]:
        clauses = ["engagement_id=?"]
        params: list = [self.engagement_id]
        if edge_type is not None:
            clauses.append("edge_type=?"); params.append(edge_type)
        if src_id is not None:
            clauses.append("src_node_id=?"); params.append(src_id)
        if dst_id is not None:
            clauses.append("dst_node_id=?"); params.append(dst_id)
        rows = self.connection.execute(
            "SELECT * FROM graph_edges WHERE " + " AND ".join(clauses) + " ORDER BY edge_type",
            params).fetchall()
        return [self._edge_dict(row) for row in rows]

    def neighbors(self, node_id: str, edge_type: str | None = None, direction: str = "out") -> list[dict]:
        """Return [{edge, node}] for adjacent nodes. direction: out | in | both."""
        result = []
        if direction in ("out", "both"):
            for edge in self.edges(edge_type, src_id=node_id):
                node = self.get_node_by_id(edge["dst"])
                if node:
                    result.append({"edge": edge, "node": node, "direction": "out"})
        if direction in ("in", "both"):
            for edge in self.edges(edge_type, dst_id=node_id):
                node = self.get_node_by_id(edge["src"])
                if node:
                    result.append({"edge": edge, "node": node, "direction": "in"})
        return result

    def counts(self) -> dict:
        n = self.connection.execute(
            "SELECT COUNT(*) c FROM graph_nodes WHERE engagement_id=?", (self.engagement_id,)).fetchone()["c"]
        e = self.connection.execute(
            "SELECT COUNT(*) c FROM graph_edges WHERE engagement_id=?", (self.engagement_id,)).fetchone()["c"]
        return {"nodes": n, "edges": e}
