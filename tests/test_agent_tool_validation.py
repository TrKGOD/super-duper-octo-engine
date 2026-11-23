import unittest
from pathlib import Path

from scripts.validate_agent_tools import parse_frontmatter, validate_agents


class AgentToolValidationTests(unittest.TestCase):
    def test_repository_agent_tool_declarations_are_least_privilege(self):
        self.assertEqual(validate_agents(), [])

    def test_specialist_agent_frontmatter_is_parsed(self):
        path = Path(__file__).resolve().parents[1] / ".claude" / "agents" / "vulnerability-agent.md"
        name, tools = parse_frontmatter(path)
        self.assertEqual(name, "vulnerability-agent")
        self.assertEqual(tools, {"Read", "Grep", "Glob"})

    def test_orchestrator_is_the_only_agent_with_task_and_bash(self):
        root = Path(__file__).resolve().parents[1] / ".claude" / "agents"
        for path in root.rglob("*.md"):
            name, tools = parse_frontmatter(path)
            if name != "pentest-orchestrator":
                self.assertFalse({"Bash", "Task", "Write", "Edit", "WebFetch", "WebSearch"} & tools, path.name)


if __name__ == "__main__":
    unittest.main()
