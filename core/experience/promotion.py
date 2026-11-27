"""Promotion gate: validated findings → experience memory.

The only path into Validated Experience Memory. It refuses anything that is not an
**independently validated** finding backed by a SUPPORTED validation record (Phase 4). A
hypothesis, a refuted or inconclusive test, or a scanner candidate can never become a
reusable experience. The promoted record is sanitized by the store; evidence is referenced
by id, never copied.
"""
from __future__ import annotations

import json

from core.experience.store import _MINT_KEY, ExperienceRecord, ExperienceStore, PromotionTicket
from core.validation_engine import ValidationRecordStore

# Finding statuses that represent an independently confirmed finding.
_CONFIRMED = {"validated", "reported", "resolved"}


class PromotionError(ValueError):
    pass


def promote_finding(experience_store: ExperienceStore, state_store, finding_id: str, *,
                    technology: str | None = None, required_identity: str | None = None,
                    knowledge_patterns=(), related_graph_entities=(),
                    promoted_by: str = "validation-agent") -> str:
    finding = state_store.connection.execute(
        "SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
    if finding is None:
        raise PromotionError("Unknown finding: " + str(finding_id))
    if finding["status"] not in _CONFIRMED:
        raise PromotionError(
            "Only an independently validated finding can be promoted to experience "
            "(status is '" + finding["status"] + "')")

    records = ValidationRecordStore(state_store.connection, finding["engagement_id"]).for_finding(finding_id)
    supported = [r for r in records if r["disposition"] == "SUPPORTED" and r["evidence_verified"]]
    if not supported:
        # Experience is reused across engagements, so the bar is higher than for the finding itself:
        # the confirming validation must have been computed on vault-verified evidence.
        raise PromotionError("A SUPPORTED validation record computed on vault-verified evidence "
                             "is required before promotion")
    vrec = supported[-1]
    characteristics = {"method": finding["method"], "parameter": finding["parameter"]}
    if vrec.get("hypothesis_id"):
        hypothesis = state_store.connection.execute(
            "SELECT category,target_label FROM planner_hypotheses WHERE hypothesis_id=? AND engagement_id=?",
            (vrec["hypothesis_id"], finding["engagement_id"])).fetchone()
        if hypothesis is not None:             # lets a later engagement match the lead to its own endpoints
            characteristics["path_template"] = hypothesis["target_label"]
            characteristics["hypothesis_category"] = hypothesis["category"]

    evidence_refs = json.loads(finding["evidence_refs_json"])
    graph_entities = list(related_graph_entities)
    if vrec.get("hypothesis_id"):
        graph_entities.append(vrec["hypothesis_id"])

    record = ExperienceRecord(
        vulnerability_category=vrec["vulnerability_class"],
        source_engagement_id=finding["engagement_id"],
        attack_surface=finding["asset"],
        technology=technology,
        required_identity=required_identity,
        prerequisites=json.loads(finding["preconditions_json"]) if finding["preconditions_json"] else [],
        endpoint_characteristics=characteristics,
        tooling=[vrec["oracle"]],
        execution_methodology=finding["description"],
        validation_methodology=finding["validation_notes"] or vrec["explanation"],
        evidence_reference_ids=evidence_refs,
        expected_behavior=vrec["explanation"],
        actual_behavior=finding["impact"],
        related_graph_entities=graph_entities,
        related_knowledge_patterns=list(knowledge_patterns),
        confidence=0.7,
    )
    ticket = PromotionTicket(finding_id, vrec["record_id"], finding["engagement_id"], _key=_MINT_KEY)
    return experience_store.add(record, ticket=ticket, promoted_by=promoted_by)
