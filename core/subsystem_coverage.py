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
