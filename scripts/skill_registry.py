#!/usr/bin/env python3
"""Validate and query the repository's declarative Claude Code Skill Registry."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / ".claude" / "skills" / "registry.json"
RISK_CLASSES = {"passive_analysis", "controlled_validation_guidance", "controlled_read_only_http", "research_context"}
VALIDATION_STATUSES = {"catalogued_unverified", "implemented_unverified", "runtime_verified", "deprecated"}
DOMAINS = {"web", "api", "mobile", "cloud", "active_directory"}


class RegistryError(ValueError):
    """Raised when registry metadata is incomplete or inconsistent."""


def _frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", text, re.DOTALL)
    if not match:
        raise RegistryError(f"Missing YAML frontmatter: {path.relative_to(ROOT)}")
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if not line.strip():
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise RegistryError(f"Malformed frontmatter line in {path}: {line}")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_registry(path: Path = DEFAULT_REGISTRY) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Cannot read registry {path}: {exc}") from exc
    if data.get("schema_version") != 1 or data.get("registry_status") != "runtime_context_selection":
        raise RegistryError("Unsupported schema_version or registry_status")
    if not isinstance(data.get("skills"), list) or not data["skills"]:
        raise RegistryError("Registry must contain a non-empty skills array")

    ids: set[str] = set()
    names: set[str] = set()
    for item in data["skills"]:
        required = ("id", "name", "path", "domains", "tags", "compatible_agents",
                    "prerequisites", "risk_class", "validation_status")
        missing = [key for key in required if key not in item]
        if missing:
            raise RegistryError(f"Skill entry missing fields {missing}: {item.get('id', '<unknown>')}")
        if item["id"] in ids or item["name"] in names:
            raise RegistryError(f"Duplicate skill id or name: {item['id']}")
        ids.add(item["id"])
        names.add(item["name"])
        if item["risk_class"] not in RISK_CLASSES:
            raise RegistryError(f"Invalid risk_class for {item['id']}")
        if item["validation_status"] not in VALIDATION_STATUSES:
            raise RegistryError(f"Invalid validation_status for {item['id']}")
        if not item["domains"] or not set(item["domains"]) <= DOMAINS:
            raise RegistryError(f"Invalid or empty domains for {item['id']}")
        for key in ("tags", "compatible_agents", "prerequisites"):
            if not isinstance(item[key], list) or not item[key] or any(
                not isinstance(value, str) or not value.strip() for value in item[key]
            ):
                raise RegistryError(f"{key} must be a non-empty string list for {item['id']}")

        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or not item["path"].startswith(".claude/skills/"):
            raise RegistryError(f"Skill path escapes the project skill directory: {item['path']}")
        skill_path = ROOT / relative
        if not skill_path.is_file():
            raise RegistryError(f"Skill file does not exist: {item['path']}")
        frontmatter = _frontmatter(skill_path)
        if frontmatter.get("name") != item["name"]:
            raise RegistryError(f"Registry name does not match SKILL.md frontmatter: {item['id']}")
        if not frontmatter.get("description"):
            raise RegistryError(f"Skill description is empty: {item['id']}")

    # Enforce catalogue completeness in both directions: no orphan SKILL.md.
    registered_paths = {item["path"] for item in data["skills"]}
    discovered_paths = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / ".claude" / "skills").rglob("SKILL.md")
    }
    unregistered = discovered_paths - registered_paths
    if unregistered:
        raise RegistryError(f"Unregistered Skill file(s): {sorted(unregistered)}")

    agent_dir = ROOT / ".claude" / "agents"
    available_agents = {
        path.stem for path in agent_dir.glob("*.md")
    }
    for item in data["skills"]:
        unknown = set(item["compatible_agents"]) - available_agents
        if unknown:
            raise RegistryError(f"Unknown compatible agent(s) for {item['id']}: {sorted(unknown)}")
    return data


def select_skills(data: dict, domain: str | None = None, agent: str | None = None,
                  tags: list[str] | None = None) -> list[dict]:
    wanted_tags = {tag.lower() for tag in (tags or [])}
    matches = []
    for item in data["skills"]:
        if domain and domain not in item["domains"]:
            continue
        if agent and agent not in item["compatible_agents"]:
            continue
        if wanted_tags and not wanted_tags.intersection(tag.lower() for tag in item["tags"]):
            continue
        matches.append(item)
    return sorted(matches, key=lambda entry: entry["id"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "list", "select"))
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--domain", choices=sorted(DOMAINS))
    parser.add_argument("--agent")
    parser.add_argument("--tag", action="append", default=[])
    args = parser.parse_args(argv)

    try:
        data = load_registry(args.registry)
        if args.command == "validate":
            print(f"Skill Registry valid: {len(data['skills'])} skills")
            return 0
        selected = data["skills"] if args.command == "list" else select_skills(
            data, domain=args.domain, agent=args.agent, tags=args.tag
        )
        for item in selected:
            print(f"{item['id']}\t{item['name']}\t{item['path']}\t{item['risk_class']}\t{item['validation_status']}")
        return 0
    except RegistryError as exc:
        print(f"Skill Registry error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
