#!/usr/bin/env python3
"""Statically validate least-privilege tool declarations in Claude Code agents.

This checks repository frontmatter only. It is not a runtime permission boundary.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / ".claude" / "agents"
PRIVILEGED_TOOLS = {"Bash", "Task", "Write", "Edit", "WebFetch", "WebSearch"}
ORCHESTRATOR_TOOLS = {"Read", "Grep", "Glob", "Bash", "Task", "Write"}


def parse_frontmatter(path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"Missing YAML frontmatter: {path.relative_to(ROOT)}")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError(f"Unterminated YAML frontmatter: {path.relative_to(ROOT)}")
    frontmatter = text[4:end]
    name = re.search(r"(?m)^name:\s*(.+?)\s*$", frontmatter)
    tools = re.search(r"(?m)^tools:\s*(.*?)\s*$", frontmatter)
    if not name or not tools:
        raise ValueError(f"Agent requires name and tools frontmatter: {path.relative_to(ROOT)}")
    declared = [item.strip() for item in tools.group(1).split(",") if item.strip()]
    if len(declared) != len(set(declared)):
        raise ValueError(f"Duplicate tool declaration: {path.relative_to(ROOT)}")
    return name.group(1), set(declared)


def validate_agents(root=AGENTS):
    errors = []
    paths = sorted(root.rglob("*.md"))
    if not paths:
        return ["No agent Markdown files found"]
    for path in paths:
        try:
            name, tools = parse_frontmatter(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        scoped_bash_agents = {"active-testing-agent", "recon-agent", "enumeration-agent", "vulnerability-agent", "exploitation-agent"}
        if name in scoped_bash_agents:
            expected = {"Bash"}
            if tools != expected:
                errors.append(f"{path.relative_to(ROOT)}: {name} tools must be exactly {sorted(expected)}")
        elif name == "validation-agent":
            expected = {"Bash", "Read"}
            if tools != expected:
                errors.append(f"{path.relative_to(ROOT)}: validation-agent tools must be exactly {sorted(expected)}")
        elif name == "pentest-orchestrator":
            unexpected = tools - ORCHESTRATOR_TOOLS
            missing = {"Task"} - tools
            if unexpected:
                errors.append(f"{path.relative_to(ROOT)}: unexpected orchestrator tools {sorted(unexpected)}")
            if missing:
                errors.append(f"{path.relative_to(ROOT)}: missing required orchestrator tools {sorted(missing)}")
        else:
            dangerous = tools & PRIVILEGED_TOOLS
            if dangerous:
                errors.append(f"{path.relative_to(ROOT)}: privileged tools forbidden for specialist {name}: {sorted(dangerous)}")
    return errors


def main():
    errors = validate_agents()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Agent tool declarations valid: {len(list(AGENTS.rglob('*.md')))} agents")
    print("Static metadata check only; Claude Code runtime permissions must be verified separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
