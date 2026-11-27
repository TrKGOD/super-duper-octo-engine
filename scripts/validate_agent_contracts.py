#!/usr/bin/env python3
"""Validate the agent contract registry against the code it describes, and render its documentation.

``config/agent-contracts.json`` states, for every agent, its responsibility, allowed inputs,
output contract, handoff conditions, failure behaviour, evidence requirements, tool permissions,
prohibited actions and escalation rules. A contract that disagrees with the implementation is a
documentation claim the software does not back, so this check fails CI when:

* an agent file has no contract, or a contract has no agent file;
* the contract's ``tools`` differ from the agent's frontmatter;
* the dispatch allowlist (``core.orchestration.ALLOWED_AGENTS``) and the contracts disagree;
* a handoff status is not in ``templates/handoff.schema.json``;
* a deterministic gate named by a contract does not exist;
* an agent both proposes and validates findings, or two agents claim the same responsibility;
* a skill is declared compatible with an agent that has no contract.

``--render`` regenerates ``docs/AGENT_CONTRACTS.md``; ``--check-docs`` fails if it is stale.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.validate_agent_tools import AGENTS, parse_frontmatter  # noqa: E402

CONTRACTS = ROOT / "config" / "agent-contracts.json"
DOC = ROOT / "docs" / "AGENT_CONTRACTS.md"
REQUIRED = ("role_kind", "responsibility", "distinct_from", "allowed_inputs", "handoff_statuses",
            "handoff_to", "failure_behavior", "evidence_requirements", "tools", "proposes_findings",
            "validates_findings", "prohibited", "escalation", "deterministic_gates")
ROLE_KINDS = {"coordinator", "gatekeeper", "recon", "enumeration", "analysis", "executor", "validator", "synthesis"}


def _handoff_statuses(root: Path) -> set:
    schema = json.loads((root / "templates" / "handoff.schema.json").read_text(encoding="utf-8"))
    return set(schema["properties"]["status"]["enum"])


def validate(contracts_path: Path = CONTRACTS, agents_dir: Path = AGENTS, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    data = json.loads(contracts_path.read_text(encoding="utf-8"))
    contracts = data["agents"]
    statuses = _handoff_statuses(root)

    frontmatter = {}
    for path in sorted(agents_dir.glob("*.md")):                 # top level only: model-1 is a frozen baseline
        name, tools = parse_frontmatter(path)
        frontmatter[name] = tools
    for name in sorted(set(frontmatter) - set(contracts)):
        errors.append(f"agent '{name}' has no contract in {contracts_path.name}")
    for name in sorted(set(contracts) - set(frontmatter)):
        errors.append(f"contract '{name}' has no agent definition file")

    from core.orchestration import ALLOWED_AGENTS
    dispatchable = set(contracts) - {"pentest-orchestrator"}
    if dispatchable != set(ALLOWED_AGENTS):
        errors.append("contracts and core.orchestration.ALLOWED_AGENTS disagree: "
                      f"only in contracts {sorted(dispatchable - set(ALLOWED_AGENTS))}, "
                      f"only in dispatch {sorted(set(ALLOWED_AGENTS) - dispatchable)}")

    seen_responsibilities: dict = {}
    for name, contract in contracts.items():
        missing = [key for key in REQUIRED if key not in contract or contract[key] in ("", [], {}, None)
                   and key not in ("proposes_findings", "validates_findings")]
        if missing:
            errors.append(f"{name}: contract is missing or empty: {missing}")
            continue
        if contract["role_kind"] not in ROLE_KINDS:
            errors.append(f"{name}: unknown role_kind '{contract['role_kind']}'")
        if name in frontmatter and set(contract["tools"]) != frontmatter[name]:
            errors.append(f"{name}: contract tools {sorted(contract['tools'])} differ from the agent file "
                          f"{sorted(frontmatter[name])}")
        bad_status = set(contract["handoff_statuses"]) - statuses
        if bad_status:
            errors.append(f"{name}: handoff statuses not in the handoff schema: {sorted(bad_status)}")
        for other in contract["distinct_from"]:
            if other not in contracts:
                errors.append(f"{name}: distinct_from names unknown agent '{other}'")
        for gate in contract["deterministic_gates"]:
            if not (root / gate).exists():
                errors.append(f"{name}: deterministic gate does not exist: {gate}")
        if contract["proposes_findings"] and contract["validates_findings"]:
            errors.append(f"{name}: an agent must not both propose and validate findings")
        key = contract["responsibility"].strip().lower()
        if key in seen_responsibilities:
            errors.append(f"{name} and {seen_responsibilities[key]} claim an identical responsibility")
        seen_responsibilities[key] = name
    if not any(c.get("validates_findings") for c in contracts.values()):
        errors.append("no agent is defined as an independent validator")
    if not data.get("baseline_prohibited"):
        errors.append("baseline_prohibited must not be empty")

    registry = json.loads((root / ".claude" / "skills" / "registry.json").read_text(encoding="utf-8"))
    known = set(contracts) | {path.stem for path in agents_dir.glob("*.md")}
    for skill in registry["skills"]:
        unknown = set(skill["compatible_agents"]) - known
        if unknown:
            errors.append(f"skill {skill['id']} is compatible with agents that have no contract: {sorted(unknown)}")
    return errors


def render(contracts_path: Path = CONTRACTS) -> str:
    data = json.loads(contracts_path.read_text(encoding="utf-8"))
    lines = ["# Agent Contracts", "",
             "<!-- GENERATED from config/agent-contracts.json by scripts/validate_agent_contracts.py --render. "
             "Do not edit by hand. -->", "",
             "Every agent's responsibility, inputs, outputs, handoff, failure behaviour, evidence requirements, tools, "
             "prohibitions and escalation rules. `scripts/validate_agent_contracts.py` fails CI when a contract disagrees "
             "with the agent file, the dispatch allowlist, the handoff schema or the skill registry.", "",
             "## Baseline prohibitions (every agent)", ""]
    lines += [f"- {item}" for item in data["baseline_prohibited"]]
    lines += ["", f"Output contract for every agent: `{data['handoff_contract']}`.", "",
              "## Summary", "", "| Agent | Role | Tools | Proposes | Validates | Hands off to |", "|---|---|---|---|---|---|"]
    for name, c in data["agents"].items():
        lines.append(f"| {name} | {c['role_kind']} | {', '.join(c['tools'])} | "
                     f"{'yes' if c['proposes_findings'] else 'no'} | {'yes' if c['validates_findings'] else 'no'} | "
                     f"{', '.join(c['handoff_to'])} |")
    for name, c in data["agents"].items():
        lines += ["", f"## {name}", "", f"**Responsibility.** {c['responsibility']}", "",
                  "**Distinct from**", ""]
        lines += [f"- `{other}`: {why}" for other, why in c["distinct_from"].items()]
        for title, key in (("Allowed inputs", "allowed_inputs"), ("Prohibited (beyond the baseline)", "prohibited"),
                           ("Escalation", "escalation"), ("Deterministic gates", "deterministic_gates")):
            lines += ["", f"**{title}**", ""] + [f"- {item}" for item in c[key]]
        lines += ["", f"**Handoff statuses.** {', '.join(c['handoff_statuses'])}", "",
                  f"**Failure behaviour.** {c['failure_behavior']}", "",
                  f"**Evidence requirements.** {c['evidence_requirements']}"]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", action="store_true", help="rewrite docs/AGENT_CONTRACTS.md")
    parser.add_argument("--check-docs", action="store_true", help="fail if docs/AGENT_CONTRACTS.md is stale")
    args = parser.parse_args(argv)
    errors = validate()
    if args.render:
        DOC.write_text(render(), encoding="utf-8", newline="\n")
        print("wrote", DOC.relative_to(ROOT))
    if args.check_docs and (not DOC.exists() or DOC.read_text(encoding="utf-8").replace("\r\n", "\n") != render()):
        errors.append("docs/AGENT_CONTRACTS.md is stale; run: python scripts/validate_agent_contracts.py --render")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Agent contracts valid: {len(json.loads(CONTRACTS.read_text(encoding='utf-8'))['agents'])} agents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
