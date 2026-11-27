"""Normalized tool observations and graph correlation (directive §7).

Every tool adapter result is normalized into `tool_observations` rows with an explicit
disposition, traceable to its tool/task/engagement/execution. Structure is `DETECTED`,
scanner leads are `CANDIDATE`, validation outcomes are `SUPPORTED`/`REFUTED`/`INCONCLUSIVE`,
and failures are `ERROR`. A `DETECTED`/`CANDIDATE` observation is never a confirmed finding —
confirmation is the validation engine's job. Values are redacted; raw output stays an
artifact reference.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from core.active_executor import _strip_sensitive_query
from core.redaction import redact_value
from core.graph.store import AttackGraph
from core.store import new_id, utc_now

DISPOSITIONS = ("DETECTED", "CANDIDATE", "SUPPORTED", "REFUTED", "INCONCLUSIVE", "ERROR")

_DISPOSITION_BY_TYPE = {
    "subdomain": "DETECTED", "dns_record": "DETECTED", "http_service": "DETECTED",
    "route": "DETECTED", "content": "DETECTED", "raw_output": "DETECTED",
    "vulnerability_candidate": "CANDIDATE", "xss_candidate": "CANDIDATE", "error": "ERROR",
}


_redact_value = redact_value  # key-aware: {"password": "x"} is redacted, not just string leaves


@dataclass
class Observation:
    engagement_id: str
    tool_id: str
    observation_type: str
    disposition: str
    task_id: str | None = None
    execution_id: str | None = None
    tool_version: str | None = None
    target_reference: str | None = None
    asset_reference: str | None = None
    endpoint_reference: str | None = None
    vulnerability_class: str | None = None
    severity_candidate: str | None = None
    confidence: float = 0.0
    execution_profile: str | None = None
    raw_artifact_reference: str | None = None
    evidence_references: list = field(default_factory=list)
    source_provenance: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)
    observation_id: str = field(default_factory=lambda: new_id("obs"))


class ObservationStore:
    def __init__(self, connection, engagement_id: str):
        self.connection = connection
        self.engagement_id = engagement_id

    def add(self, observation: Observation) -> str:
        with self.connection:
            self.connection.execute(
                "INSERT INTO tool_observations(observation_id,engagement_id,task_id,execution_id,tool_id,"
                "tool_version,observation_type,disposition,target_reference,asset_reference,"
                "endpoint_reference,vulnerability_class,severity_candidate,confidence,execution_profile,"
                "raw_artifact_reference,evidence_references_json,source_provenance_json,data_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (observation.observation_id, self.engagement_id, observation.task_id,
                 observation.execution_id, observation.tool_id, observation.tool_version,
                 observation.observation_type, observation.disposition, observation.target_reference,
                 observation.asset_reference, observation.endpoint_reference, observation.vulnerability_class,
                 observation.severity_candidate, float(observation.confidence), observation.execution_profile,
                 observation.raw_artifact_reference, json.dumps(observation.evidence_references),
                 json.dumps(observation.source_provenance, sort_keys=True),
                 json.dumps(_redact_value(observation.data), sort_keys=True), utc_now()))
        return observation.observation_id

    def list(self, *, disposition: str | None = None) -> list[dict]:
        if disposition is None:
            rows = self.connection.execute(
                "SELECT * FROM tool_observations WHERE engagement_id=? ORDER BY created_at",
                (self.engagement_id,)).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM tool_observations WHERE engagement_id=? AND disposition=? ORDER BY created_at",
                (self.engagement_id, disposition)).fetchall()
        return [self._row(r) for r in rows]

    def candidates(self) -> list[dict]:
        return self.list(disposition="CANDIDATE")

    @staticmethod
    def _row(row) -> dict:
        return {
            "observation_id": row["observation_id"], "task_id": row["task_id"],
            "execution_id": row["execution_id"], "tool_id": row["tool_id"],
            "tool_version": row["tool_version"], "observation_type": row["observation_type"],
            "disposition": row["disposition"], "target_reference": row["target_reference"],
            "asset_reference": row["asset_reference"], "endpoint_reference": row["endpoint_reference"],
            "vulnerability_class": row["vulnerability_class"], "severity_candidate": row["severity_candidate"],
            "confidence": row["confidence"], "execution_profile": row["execution_profile"],
            "raw_artifact_reference": row["raw_artifact_reference"],
            "evidence_references": json.loads(row["evidence_references_json"]),
            "source_provenance": json.loads(row["source_provenance_json"]),
            "data": json.loads(row["data_json"]), "created_at": row["created_at"],
        }


def normalize_tool_result(store: ObservationStore, definition, tool_result, *, task_id=None,
                          execution_id=None, asset=None) -> list[str]:
    """Normalize a Component E ToolResult's parsed observations into stored records."""
    ids = []
    for parsed in getattr(tool_result, "observations", []) or []:
        otype = parsed.get("type", "raw_output")
        disposition = _DISPOSITION_BY_TYPE.get(otype, "DETECTED")

        def _clean(value):
            return _strip_sensitive_query(value) if isinstance(value, str) and "://" in value else value

        url = _clean(parsed.get("url") or parsed.get("matched_at"))
        target = url or _clean(parsed.get("host")) or _clean(parsed.get("poc")) or asset
        endpoint = url if disposition in ("DETECTED", "CANDIDATE") else None
        vuln_class = None
        if disposition == "CANDIDATE":
            vuln_class = (definition.vulnerability_classes[0] if definition.vulnerability_classes else None)
        observation = Observation(
            engagement_id=store.engagement_id, tool_id=definition.tool_id,
            tool_version=definition.version, observation_type=otype, disposition=disposition,
            task_id=task_id, execution_id=execution_id,
            target_reference=target, asset_reference=asset, endpoint_reference=endpoint,
            vulnerability_class=vuln_class, severity_candidate=parsed.get("severity"),
            confidence=0.5 if disposition == "DETECTED" else (0.3 if disposition == "CANDIDATE" else 0.0),
            execution_profile=definition.execution_profile,
            raw_artifact_reference=getattr(tool_result, "artifact", None),
            source_provenance={"tool_id": definition.tool_id, "profile": definition.execution_profile,
                               "parser": definition.parser},
            data=parsed)
        ids.append(store.add(observation))
    return ids


def correlate_to_graph(graph: AttackGraph, observations) -> dict:
    """Project DETECTED structure observations into the graph as observed nodes.

    Only structure is projected (hosts/routes), with `observed` trust and provenance.
    CANDIDATE observations are **not** projected as structure — they are leads for the
    planner/validation engine, never confirmed facts or authorization.
    """
    created = {"hosts": 0, "routes": 0, "skipped_candidates": 0}
    for obs in observations:
        if obs.get("disposition") != "DETECTED":
            if obs.get("disposition") == "CANDIDATE":
                created["skipped_candidates"] += 1
            continue
        prov = [{"source": "tool:" + str(obs.get("tool_id")), "observation_id": obs.get("observation_id")}]
        otype = obs.get("observation_type")
        if otype == "subdomain" and obs.get("target_reference"):
            graph.upsert_node("host", obs["target_reference"], trust="observed", provenance=prov, confidence=0.5)
            created["hosts"] += 1
        elif otype in ("http_service", "route") and obs.get("endpoint_reference"):
            graph.upsert_node("route", obs["endpoint_reference"], label=obs["endpoint_reference"],
                              trust="observed", provenance=prov, confidence=0.5)
            created["routes"] += 1
    return created
