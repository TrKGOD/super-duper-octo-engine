import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import skill_registry


class SkillRegistryTests(unittest.TestCase):
    def test_repository_registry_is_valid(self):
        registry = skill_registry.load_registry()
        self.assertEqual(len(registry["skills"]), 24)

    def test_select_by_domain_and_agent(self):
        registry = skill_registry.load_registry()
        selected = skill_registry.select_skills(
            registry, domain="web", agent="vulnerability-agent"
        )
        ids = {item["id"] for item in selected}
        self.assertIn("web-xss", ids)
        self.assertIn("web-oauth-jwt", ids)
        self.assertNotIn("active-directory", ids)

    def test_scope_and_active_http_skills_are_selectable(self):
        registry = skill_registry.load_registry()
        scope = skill_registry.select_skills(
            registry, domain="web", agent="scope-analyst", tags=["authorization"]
        )
        active = skill_registry.select_skills(
            registry, domain="web", agent="active-testing-agent", tags=["http-read-only"]
        )
        self.assertEqual([item["id"] for item in scope], ["engagement-scope"])
        self.assertEqual([item["id"] for item in active], ["active-http-testing"])

    def test_active_web_api_discovery_skill_is_selectable_for_surface_agents(self):
        registry = skill_registry.load_registry()
        for agent, tag in (
            ("recon-agent", "active-recon"),
            ("enumeration-agent", "routes"),
            ("vulnerability-agent", "javascript-analysis"),
        ):
            selected = skill_registry.select_skills(
                registry, domain="web", agent=agent, tags=[tag]
            )
            self.assertIn("active-web-api-discovery", {item["id"] for item in selected})

    def test_tag_filter_uses_any_requested_tag(self):
        registry = skill_registry.load_registry()
        selected = skill_registry.select_skills(registry, tags=["ssrf"])
        self.assertEqual([item["id"] for item in selected], ["web-ssrf", "web-ssrf-advanced"])

    def test_rejects_path_traversal(self):
        registry = skill_registry.load_registry()
        registry["skills"][0]["path"] = ".claude/skills/../../CLAUDE.md"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with patch.object(skill_registry, "ROOT", Path(directory)):
                with self.assertRaisesRegex(skill_registry.RegistryError, "escapes"):
                    skill_registry.load_registry(path)

    def test_rejects_skill_file_missing_from_catalogue(self):
        registry = skill_registry.load_registry()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for item in registry["skills"]:
                destination = root / item["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    (skill_registry.ROOT / item["path"]).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            agents = root / ".claude" / "agents"
            agents.mkdir(parents=True)
            for agent in (skill_registry.ROOT / ".claude" / "agents").glob("*.md"):
                (agents / agent.name).write_text(agent.read_text(encoding="utf-8"), encoding="utf-8")
            orphan = root / ".claude" / "skills" / "forgotten-skill" / "SKILL.md"
            orphan.parent.mkdir(parents=True)
            orphan.write_text("---\\nname: forgotten-skill\\ndescription: Unregistered test skill\\n---\\n", encoding="utf-8")
            registry_path = root / "registry.json"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            with patch.object(skill_registry, "ROOT", root):
                with self.assertRaisesRegex(skill_registry.RegistryError, "Unregistered Skill"):
                    skill_registry.load_registry(registry_path)

    def test_rejects_unknown_agent(self):
        registry = skill_registry.load_registry()
        registry["skills"][0]["compatible_agents"].append("agent-that-does-not-exist")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with patch.object(skill_registry, "ROOT", skill_registry.ROOT):
                with self.assertRaisesRegex(skill_registry.RegistryError, "Unknown compatible"):
                    skill_registry.load_registry(path)


if __name__ == "__main__":
    unittest.main()
