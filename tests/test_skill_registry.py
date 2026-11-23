import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import skill_registry


class SkillRegistryTests(unittest.TestCase):
    def test_repository_registry_is_valid(self):
        registry = skill_registry.load_registry()
        self.assertEqual(len(registry["skills"]), 14)

    def test_select_by_domain_and_agent(self):
        registry = skill_registry.load_registry()
        selected = skill_registry.select_skills(
            registry, domain="web", agent="vulnerability-agent"
        )
        ids = {item["id"] for item in selected}
        self.assertIn("web-xss", ids)
        self.assertIn("web-oauth-jwt", ids)
        self.assertNotIn("active-directory", ids)

    def test_tag_filter_uses_any_requested_tag(self):
        registry = skill_registry.load_registry()
        selected = skill_registry.select_skills(registry, tags=["ssrf"])
        self.assertEqual([item["id"] for item in selected], ["web-ssrf"])

    def test_rejects_path_traversal(self):
        registry = skill_registry.load_registry()
        registry["skills"][0]["path"] = ".claude/skills/../../CLAUDE.md"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            with patch.object(skill_registry, "ROOT", Path(directory)):
                with self.assertRaisesRegex(skill_registry.RegistryError, "escapes"):
                    skill_registry.load_registry(path)

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
