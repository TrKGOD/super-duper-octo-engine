# Pentest Agent Framework

A Claude Code–first, evidence-driven multi-agent framework for **authorized** security assessments across Web, API, Mobile, Cloud, and Active Directory.

> Status: bootstrap / architecture baseline. This repository is a scaffold, not a production-ready autonomous scanner.

## Design principles

1. **Orchestrator, not super-pentester:** plan, delegate, track dependencies, and consolidate.
2. **Specialists on demand:** activate only the agents and skills relevant to the discovered attack surface.
3. **Evidence before claims:** observations, hypotheses, validated findings, and rejected findings are distinct states.
4. **Independent verification:** the agent proposing a finding must not be its sole validator.
5. **Scope-first execution:** explicit engagement scope and operator approval precede active testing.
6. **Persistent state:** engagement data is local and excluded from Git by default.
7. **Small, testable increments:** add specialists only when tests and benchmark cases justify them.

## Architecture

- `CLAUDE.md`: project-wide operating contract.
- `.claude/agents/`: Claude Code subagents (Model 1 baseline and hybrid roles).
- `.claude/skills/`: reusable methodologies loaded when relevant.
- `.claude/commands/`: operator-invoked workflows.
- `config/`: safe defaults, scope and model policy.
- `core/`: future orchestration, findings and persistence implementation.
- `hooks/`: defense-in-depth guardrails; not a substitute for OS/container/network isolation.
- `database/`: SQLite schema and migrations.
- `knowledge/`: curated, reviewed methodology references.
- `tests/`: configuration, scope and schema checks.
- `docs/`: technical specification, threat model and roadmap.

## Quick start

Requirements:
- Claude Code installed and authenticated.
- Python 3.11+ for local validation utilities.
- Git.

```bash
git clone <YOUR_PRIVATE_REPOSITORY_URL>
cd pentest-agent-framework
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python scripts/validate_config.py
python -m unittest discover -s tests -v
claude
```

The default configuration is deliberately **non-operational**:
- `config/engagement.example.json` contains no targets.
- `execution_enabled` is `false`.
- No autonomous network scanning is enabled.
- Agents are instructed to analyze supplied artifacts and request explicit authorization before active testing.

## First engagement setup

1. Copy `config/engagement.example.json` to a local engagement file (the local file is gitignored).
2. Add only explicitly authorized assets and testing windows.
3. Have the operator review scope, exclusions, rate limits, and allowed test classes.
4. Keep active execution disabled until guardrails and an isolated test environment are configured.
5. Record evidence and findings in the local engagement database; never commit client data.

## Important limitations

The initial hook is a **safety tripwire**, not a security boundary. Shell parsing is not a reliable sandbox. For active testing, enforce network egress restrictions and process isolation outside Claude Code (container/VM/firewall), use dedicated test credentials, and require human approval for intrusive or state-changing tests.

Do not store credentials, session cookies, client data, raw requests/responses, or production findings in this repository. Use an encrypted local evidence store with access controls and retention rules.

## Status

See `docs/TECHNICAL_SPEC.md` and `docs/ROADMAP.md`. The Model 1 baseline is preserved separately from the proposed hybrid architecture.
