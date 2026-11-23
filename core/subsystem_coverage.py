"""Subsystem inventory and coverage accounting for breadth-oriented assessment."""
from __future__ import annotations

class CoverageError(ValueError):
    pass

STATUSES = {"not_assessed", "in_progress", "assessed", "blocked", "not_applicable"}

def validate_inventory(inventory):
    if not isinstance(inventory, list) or not inventory:
        raise CoverageError("Subsystem inventory must be a non-empty list")
    ids = set()
    for item in inventory:
        if not isinstance(item, dict):
            raise CoverageError("Subsystem entries must be objects")
        sid = item.get("subsystem_id")
        if not isinstance(sid, str) or not sid.strip() or sid in ids:
            raise CoverageError("Subsystem IDs must be unique non-empty strings")
        ids.add(sid)
        if not isinstance(item.get("name"), str) or not item["name"].strip():
            raise CoverageError(f"Subsystem {sid} requires a name")
        if item.get("status", "not_assessed") not in STATUSES:
            raise CoverageError(f"Subsystem {sid} has an unsupported status")
        if not isinstance(item.get("surfaces", []), list):
            raise CoverageError(f"Subsystem {sid} surfaces must be a list")
    return True

def summarize_coverage(inventory):
    validate_inventory(inventory)
    counts = {status: 0 for status in STATUSES}
    for item in inventory:
        counts[item.get("status", "not_assessed")] += 1
    denominator = len(inventory) - counts["not_applicable"]
    assessed = counts["assessed"]
    return {"total": len(inventory), "applicable": denominator, "counts": counts,
            "coverage_percent": round(100 * assessed / denominator, 1) if denominator else 100.0,
            "unassessed": [i["subsystem_id"] for i in inventory
                           if i.get("status", "not_assessed") in {"not_assessed", "in_progress"}],
            "blocked": [i["subsystem_id"] for i in inventory if i.get("status") == "blocked"],
            "warning": "Coverage measures inventory status, not proof that every vulnerability class was tested."}

def apply_updates(inventory, updates):
    """Apply evidence-linked updates to a validated inventory without inventing coverage."""
    validate_inventory(inventory)
    known = {item["subsystem_id"] for item in inventory}
    result = [dict(item) for item in inventory]
    by_id = {item["subsystem_id"]: item for item in result}
    for update in updates:
        if update.get("subsystem_id") not in known:
            raise CoverageError("Update references an unknown subsystem")
        if update.get("status") not in {"in_progress", "assessed", "blocked", "not_applicable"}:
            raise CoverageError("Unsupported subsystem update status")
        if update.get("status") == "assessed" and not update.get("evidence_refs"):
            raise CoverageError("An assessed subsystem requires evidence references")
        by_id[update["subsystem_id"]]["status"] = update["status"]
        by_id[update["subsystem_id"]]["last_evidence_refs"] = list(update.get("evidence_refs", []))
        if update.get("notes"):
            by_id[update["subsystem_id"]]["assessment_notes"] = update["notes"]
    return result


def summarize_engagement_coverage(store, engagement_id, inventory):
    """Fold the latest audited subsystem updates over an operator-supplied inventory."""
    rows = store.connection.execute(
        "SELECT details_json FROM audit_events WHERE engagement_id=? AND event_type='subsystem.coverage_updated' ORDER BY event_id",
        (engagement_id,),
    ).fetchall()
    current = [dict(item) for item in inventory]
    for row in rows:
        import json
        details = json.loads(row["details_json"])
        current = apply_updates(current, details.get("updates", []))
    return {"inventory": current, **summarize_coverage(current)}
