#!/usr/bin/env python3
"""Find possible duplicate findings without merging or changing lifecycle state."""
import argparse
import json
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.store import StateStore


def normalize(value):
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def find_duplicates(store, engagement_id, threshold=0.72):
    rows = store.connection.execute(
        """SELECT finding_id,title,status,asset,method,parameter,description
           FROM findings WHERE engagement_id=? ORDER BY finding_id""",
        (engagement_id,),
    ).fetchall()
    candidates = []
    for index, left in enumerate(rows):
        for right in rows[index + 1:]:
            if normalize(left["asset"]) != normalize(right["asset"]):
                continue
            if normalize(left["method"]) != normalize(right["method"]):
                continue
            if normalize(left["parameter"]) != normalize(right["parameter"]):
                continue
            title_similarity = SequenceMatcher(
                None, normalize(left["title"]), normalize(right["title"])
            ).ratio()
            description_similarity = SequenceMatcher(
                None, normalize(left["description"]), normalize(right["description"])
            ).ratio()
            similarity = round(0.6 * title_similarity + 0.4 * description_similarity, 4)
            if similarity >= threshold:
                candidates.append({
                    "finding_ids": [left["finding_id"], right["finding_id"]],
                    "similarity": similarity,
                    "title_similarity": round(title_similarity, 4),
                    "description_similarity": round(description_similarity, 4),
                    "asset": left["asset"],
                    "method": left["method"],
                    "parameter": left["parameter"],
                    "statuses": [left["status"], right["status"]],
                    "requires_operator_review": True,
                })
    return candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/state.sqlite3")
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--threshold", type=float, default=0.72)
    parser.add_argument("--json-out")
    args = parser.parse_args()
    if not 0.5 <= args.threshold <= 1:
        parser.error("--threshold must be between 0.5 and 1")
    with StateStore(args.db) as store:
        candidates = find_duplicates(store, args.engagement_id, args.threshold)
    result = {
        "engagement_id": args.engagement_id,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "warning": "Similarity is triage only. No findings were merged, deleted, or changed.",
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_out:
        target = Path(args.json_out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print("duplicate detection failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
