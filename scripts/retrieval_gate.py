#!/usr/bin/env python3
"""Run deterministic skill-retrieval and agent-capability contract gates.

These gates validate routing and evidence contracts, not model reasoning quality.
Use the agent benchmark runner for model-produced predictions.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.skill_registry import load_registry, select_skills

DEFAULT_CASES = ROOT / "benchmarks" / "retrieval-gate-cases.json"


def run_gates(cases_path=DEFAULT_CASES):
    cases = json.loads(Path(cases_path).read_text(encoding="utf-8"))
    registry = load_registry()
    results = []
    for case in cases["retrieval_cases"]:
        selected = select_skills(
            registry, domain=case["domain"], agent=case["agent"], tags=case["tags"]
        )
        ids = {item["id"] for item in selected}
        results.append({
            "case_id": case["case_id"],
            "expected_skill": case["expected_skill"],
            "retrieved": case["expected_skill"] in ids,
            "selected_skill_ids": sorted(ids),
            "required_tags": case["tags"],
        })

    handoff = json.loads((ROOT / "templates" / "handoff.schema.json").read_text())
    finding = json.loads((ROOT / "templates" / "finding.schema.json").read_text())
    vuln_agent = (ROOT / ".claude/agents/vulnerability-agent.md").read_text()
    exploit_agent = (ROOT / ".claude/agents/exploitation-agent.md").read_text()
    validator_agent = (ROOT / ".claude/agents/validation-agent.md").read_text()
    reporting_agent = (ROOT / ".claude/agents/reporting-agent.md").read_text()
    capability = {
        "handoff_requires_evidence_refs": "evidence_refs" in handoff.get("required", []),
        "handoff_requires_limitations": "limitations" in handoff.get("required", []),
        "validated_finding_requires_validator": any("validated_by" in item.get("then", {}).get("required", []) for item in finding.get("allOf", [])),
        "validated_finding_requires_evidence": finding.get("allOf", [{}])[0].get("then", {}).get("properties", {}).get("evidence_refs", {}).get("minItems", 0) >= 1,
        "vulnerability_agent_separates_observations_and_hypotheses": "observed facts" in vuln_agent.lower() and "hypotheses" in vuln_agent.lower(),
        "exploitation_agent_requires_reviewed_manifests": "SHA-256-pinned" in exploit_agent,
        "validation_agent_requires_independent_proposal": "different agent" in validator_agent,
        "reporting_agent_requires_evidence": "evidence" in reporting_agent.lower(),
    }
    passed_retrieval = sum(item["retrieved"] for item in results)
    passed_capability = sum(capability.values())
    return {
        "retrieval_case_count": len(results),
        "retrieval_passed": passed_retrieval,
        "retrieval_failed": [item["case_id"] for item in results if not item["retrieved"]],
        "capability_gate_count": len(capability),
        "capability_passed": passed_capability,
        "capability_failed": [key for key, value in capability.items() if not value],
        "retrieval_results": results,
        "capability_results": capability,
        "limitations": "Deterministic registry and contract checks only; not a model-quality, exploitability, or real-world coverage claim."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    try:
        result = run_gates(args.cases)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not result["retrieval_failed"] and not result["capability_failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
