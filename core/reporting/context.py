"""Normalized report inputs.

Gathers everything a report needs from persisted state: engagement metadata, **confirmed**
findings (validated/reported/resolved) whose evidence integrity is re-verified at report
time, the unvalidated/candidate material kept strictly separate, the discovered attack
surface, and tool-execution records. Reuses the existing validated-findings gate and
evidence vault. Secrets (the authorization reference) are not exposed.
"""
from __future__ import annotations

import json

from core.evidence import EvidenceError, EvidenceVault
from core.validation_engine import ValidationRecordStore
from core.tools.observations import ObservationStore

_CONFIRMED = ("validated", "reported", "resolved")
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


class ReportContext:
    def __init__(self, store, engagement_id: str, *, project_root="."):
        self.store = store
        self.engagement_id = engagement_id
        self.project_root = project_root
        self.vault = EvidenceVault(store, project_root)
        row = store.connection.execute(
            "SELECT engagement_id,status,scope_json,rules_json FROM engagements WHERE engagement_id=?",
            (engagement_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown engagement: " + str(engagement_id))
        self._engagement = row

    def engagement(self) -> dict:
        return {"engagement_id": self.engagement_id, "status": self._engagement["status"],
                "scope": json.loads(self._engagement["scope_json"]),
                "authorization_reference": "[REDACTED]"}

    def _validation_class(self, finding_id: str):
        records = ValidationRecordStore(self.store.connection, self.engagement_id).for_finding(finding_id)
        supported = [r for r in records if r["disposition"] == "SUPPORTED"]
        return (supported[-1]["vulnerability_class"] if supported else None,
                [r["record_id"] for r in records],
                all(ValidationRecordStore(self.store.connection, self.engagement_id).verify(r["record_id"])
                    for r in records) if records else True)

    def confirmed_findings(self) -> tuple[list, list]:
        rows = self.store.connection.execute(
            "SELECT * FROM findings WHERE engagement_id=? AND status IN ('validated','reported','resolved') "
            "ORDER BY finding_id", (self.engagement_id,)).fetchall()
        included, excluded = [], []
        for row in sorted(rows, key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 5), r["finding_id"])):
            refs = json.loads(row["evidence_refs_json"])
            evidence = self.store.finding_evidence(row["finding_id"])
            integrity = {}
            for evidence_id in refs:
                try:
                    integrity[evidence_id] = self.vault.verify(evidence_id)["valid"]
                except (EvidenceError, OSError):
                    integrity[evidence_id] = False
            if not refs or not all(integrity.values()):
                excluded.append({"finding_id": row["finding_id"],
                                 "reason": "missing or failed evidence integrity verification"})
                continue
            vclass, record_ids, records_ok = self._validation_class(row["finding_id"])
            supporting = [r for r in ValidationRecordStore(self.store.connection, self.engagement_id)
                          .for_finding(row["finding_id"]) if r["disposition"] == "SUPPORTED"]
            verified = bool(supporting) and all(r["evidence_verified"] for r in supporting)
            included.append({
                "finding_id": row["finding_id"], "title": row["title"], "status": row["status"],
                "severity": row["severity"], "asset": row["asset"], "method": row["method"],
                "parameter": row["parameter"], "vulnerability_class": vclass,
                "description": row["description"], "impact": row["impact"],
                "preconditions": json.loads(row["preconditions_json"] or "[]"),
                "validated_by": row["validated_by"], "validation_notes": row["validation_notes"],
                "validation_records": record_ids, "validation_records_integrity_ok": records_ok,
                "validation_evidence_verified": verified,
                "evidence": [{"evidence_id": e["evidence_id"], "type": e["evidence_type"],
                              "sha256": e["sha256"], "redacted": bool(e["redacted"]),
                              "integrity_verified": True} for e in evidence],
            })
        return included, excluded

    def unvalidated(self) -> dict:
        rows = self.store.connection.execute(
            "SELECT finding_id,title,status,severity,asset FROM findings WHERE engagement_id=? "
            "AND status IN ('observation','hypothesis','validation_pending','needs_more_evidence') "
            "ORDER BY finding_id", (self.engagement_id,)).fetchall()
        candidates = ObservationStore(self.store.connection, self.engagement_id).candidates()
        return {
            "unvalidated_findings": [dict(r) for r in rows],
            "candidate_observations": [{"tool_id": c["tool_id"], "observation_type": c["observation_type"],
                                        "vulnerability_class": c["vulnerability_class"],
                                        "severity_candidate": c["severity_candidate"],
                                        "target": c["target_reference"], "disposition": c["disposition"]}
                                       for c in candidates],
            "note": "Unvalidated findings and scanner candidates are NOT confirmed vulnerabilities.",
        }

    def investigation(self) -> dict:
        """What was investigated, what is still open, and what was never tested."""
        rows = self.store.connection.execute(
            "SELECT * FROM planner_hypotheses WHERE engagement_id=? ORDER BY score DESC,hypothesis_id",
            (self.engagement_id,)).fetchall()
        by_class: dict = {}
        unresolved = []
        no_executor = 0
        for row in rows:
            bucket = by_class.setdefault(row["test_class"], {
                "hypotheses": 0, "executed": 0, "supported": 0, "refuted": 0, "inconclusive": 0, "blocked": 0})
            bucket["hypotheses"] += 1
            bucket["executed"] += 1 if row["executed"] else 0
            key = {"SUPPORTED": "supported", "REFUTED": "refuted", "INCONCLUSIVE": "inconclusive",
                   "BLOCKED": "blocked"}.get(row["status"])
            if key:
                bucket[key] += 1
            if row["status"] not in ("SUPPORTED", "REFUTED"):
                unresolved.append({
                    "hypothesis_id": row["hypothesis_id"], "category": row["category"],
                    "test_class": row["test_class"], "target": row["target_label"], "status": row["status"],
                    "reason": row["status_reason"], "executed": bool(row["executed"]),
                    "evidence_requests": json.loads(row["evidence_requests_json"] or "[]")})
            if str(row["status_reason"] or "").startswith("no_automated_executor"):
                no_executor += 1
        tested = {e["dst_node_id"] for e in self.store.connection.execute(
            "SELECT dst_node_id FROM graph_edges WHERE engagement_id=? AND edge_type='TARGETS'",
            (self.engagement_id,)).fetchall()}
        endpoints = self.store.connection.execute(
            "SELECT node_id,node_key FROM graph_nodes WHERE engagement_id=? AND node_type='endpoint' "
            "ORDER BY node_key", (self.engagement_id,)).fetchall()
        return {
            "hypotheses_total": len(rows), "coverage_by_test_class": by_class,
            "unresolved_hypotheses": unresolved,
            "untested_endpoints": [e["node_key"] for e in endpoints if e["node_id"] not in tested],
            "hypotheses_without_automated_executor": no_executor,
        }

    def execution_summary(self) -> dict:
        """Execution-ledger view: what ran, what failed and what an operator still has to settle."""
        rows = self.store.connection.execute(
            "SELECT kind,status,COUNT(*) c FROM executions WHERE engagement_id=? GROUP BY kind,status",
            (self.engagement_id,)).fetchall()
        pending = self.store.connection.execute(
            "SELECT execution_id,tool_id,status FROM executions WHERE engagement_id=? "
            "AND status IN ('INTERRUPTED','RECONCILIATION_REQUIRED') ORDER BY created_at",
            (self.engagement_id,)).fetchall()
        return {"by_kind_and_status": [{"kind": r["kind"], "status": r["status"], "count": r["c"]} for r in rows],
                "awaiting_operator_reconciliation": [dict(p) for p in pending]}

    def attack_surface(self) -> dict:
        def nodes(node_type):
            rows = self.store.connection.execute(
                "SELECT node_key,label,attributes_json,trust FROM graph_nodes WHERE engagement_id=? AND node_type=? "
                "ORDER BY node_key", (self.engagement_id, node_type)).fetchall()
            return [{"key": r["node_key"], "label": r["label"], "trust": r["trust"],
                     "attributes": json.loads(r["attributes_json"])} for r in rows]
        observations = ObservationStore(self.store.connection, self.engagement_id)
        detected = observations.list(disposition="DETECTED")
        return {
            "hosts": nodes("host"), "services": nodes("service"), "endpoints": nodes("endpoint"),
            "routes": nodes("route"), "parameters": nodes("parameter"), "technologies": nodes("technology"),
            "detected_observations": len(detected),
            "coverage_note": "Discovery is not asserted to be complete; unexplored areas may remain.",
        }

    def tool_execution(self) -> dict:
        workers = self.store.connection.execute(
            "SELECT worker_id,task_id,backend,status,started_at,finished_at,tool_executions_json,cleanup_status "
            "FROM worker_executions WHERE engagement_id=? ORDER BY started_at", (self.engagement_id,)).fetchall()
        by_tool = {}
        for obs in ObservationStore(self.store.connection, self.engagement_id).list():
            bucket = by_tool.setdefault(obs["tool_id"], {"detected": 0, "candidates": 0, "errors": 0})
            key = {"DETECTED": "detected", "CANDIDATE": "candidates", "ERROR": "errors"}.get(obs["disposition"])
            if key:
                bucket[key] += 1
        return {
            "workers": [{"worker_id": w["worker_id"], "task_id": w["task_id"], "backend": w["backend"],
                         "status": w["status"], "cleanup_status": w["cleanup_status"],
                         "tool_executions": json.loads(w["tool_executions_json"])} for w in workers],
            "by_tool": by_tool,
        }
