"""Validated Experience Memory (Component C).

A dedicated, reusable store of independently validated security experience. Only
validation-engine-confirmed findings are promoted here (never a hypothesis, refuted or
inconclusive test); records hold no secrets (evidence is referenced by id); retrieval is
similarity-based and advisory — a past success is never evidence a new target is vulnerable
and never authorization to act on a different engagement.
"""
import sqlite3
from pathlib import Path

from core.experience.promotion import PromotionError, promote_finding
from core.experience.proposals import CATEGORY_MAP, LEAD_CONFIDENCE_CAP, propose_from_experience
from core.experience.store import (ExperienceError, ExperienceRecord, ExperienceStore, PromotionTicket,
                                   STATUSES)


def open_experience_store(path) -> ExperienceStore:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    return ExperienceStore(connection)


__all__ = [
    "ExperienceStore", "ExperienceRecord", "ExperienceError", "STATUSES",
    "promote_finding", "PromotionError", "open_experience_store", "PromotionTicket",
    "propose_from_experience", "CATEGORY_MAP", "LEAD_CONFIDENCE_CAP",
]
