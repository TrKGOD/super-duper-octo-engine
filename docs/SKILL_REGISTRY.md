# Skill Registry

The Skill Registry is a declarative catalogue for the repository's Claude Code Skills. It makes the existing methodology packages discoverable by stable ID, domain, tags, compatible specialist agents, prerequisites, risk class, and validation status.

## What it does

- Keeps the canonical Skill instructions in each `.claude/skills/**/SKILL.md` file.
- Stores discovery and compatibility metadata in `.claude/skills/registry.json`.
- Checks that every registry path exists, every Skill name matches its frontmatter, and every compatible agent exists in `.claude/agents/`.
- Supports deterministic local selection by domain, agent, and tags.

## Commands

Validate the catalogue and its references:

```bash
python scripts/skill_registry.py validate
```

List all registered Skills:

```bash
python scripts/skill_registry.py list
```

Select Skills compatible with a specialist and domain:

```bash
python scripts/skill_registry.py select --domain web --agent vulnerability-agent
```

Find Skills by one or more tags (OR semantics):

```bash
python scripts/skill_registry.py select --tag oauth2 --tag jwt
```

## Metadata contract

| Field | Meaning |
|---|---|
| `id` | Stable registry identifier |
| `name` | Must match the Skill's `SKILL.md` frontmatter name |
| `path` | Repository-relative path to `SKILL.md`; restricted to `.claude/skills/` |
| `domains` | One or more supported assessment domains |
| `tags` | Searchable capability labels |
| `compatible_agents` | Existing specialist agent filenames, without `.md` |
| `prerequisites` | Context required before using the methodology |
| `risk_class` | Catalogue classification, not a permission grant |
| `validation_status` | Whether runtime behavior has been verified |

## Safety and runtime boundaries

The status is `runtime_context_selection`. The bounded dispatcher reads this registry to select methodology files by task domain, compatible agent, and optional tags, then injects their text as untrusted context into the specialist prompt. This is context selection only: it does **not** grant tools, authorize targets, enable active testing, or override `CLAUDE.md`, engagement scope, hooks, or human approval. The dispatcher currently runs with tools disabled.

All current entries use `catalogued_unverified`: metadata and file references are checked locally, but the Skills have not yet been verified through a real Claude Code runtime integration test. Do not promote an entry to `runtime_verified` based only on this static validator.

The registry is not the source of truth for authorization or execution permissions. Risk classes describe the nature of the methodology content only.

## Maintenance

When adding or renaming a Skill:

1. Create or update its `SKILL.md` and frontmatter.
2. Add/update the corresponding registry entry.
3. Use only existing agent IDs from `.claude/agents/*.md`.
4. Run `python scripts/skill_registry.py validate` and `python -m unittest tests.test_skill_registry -v`.
5. Verify the Skill in a controlled Claude Code session before changing its status to `runtime_verified`.

Keep Skill instructions concise and reusable. Put long references or supporting scripts alongside the Skill only when they materially improve the methodology.
