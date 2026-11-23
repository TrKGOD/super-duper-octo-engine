# Pentest Agent Framework

A Claude Code–first, evidence-driven multi-agent framework for **authorized** security assessments across Web, API, Mobile, Cloud, and Active Directory.

> Status: early implementation. The repository includes deterministic finding checks, a SQLite state store, audit events, schema migrations, CI, and a secret-scanning hook configuration. It is not a production-ready autonomous scanner.

## Implemented components

- core/validation.py rejects validated/reported findings without evidence or an independent validator, and rejects self-validation.
- core/store.py persists engagements, tasks, agent runs, findings, and audit events in SQLite.
- scripts/migrate.py applies the baseline schema and ordered SQL migrations idempotently.
- scripts/validate_contracts.py validates JSON schemas and checked-in examples.
- .github/workflows/ci.yml runs configuration checks, migrations, tests, and contract validation.
- .pre-commit-config.yaml configures Gitleaks for local pre-commit scanning.

## Architecture

- CLAUDE.md: project-wide operating contract.
- .claude/agents/: Claude Code subagents, including the preserved Model 1 baseline.
- .claude/skills/: reusable methodologies loaded when relevant.
- .claude/commands/: operator-invoked workflows.
- config/: safe defaults, scope and model policy.
- core/: deterministic state and evidence controls.
- hooks/: defense-in-depth tripwires; not a substitute for OS/container/network isolation.
- database/: SQLite schema and versioned migrations.
- templates/: machine-readable contracts and examples.
- tests/: behavior and contract tests.

## Quick start

Requirements: Claude Code, Python 3.11+, and Git.

```bash
git clone https://github.com/TrKGOD/super-duper-octo-engine.git
cd super-duper-octo-engine
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python scripts/validate_config.py
python scripts/validate_contracts.py
python -m unittest discover -s tests -v
pre-commit install
python scripts/migrate.py --db .local/state.sqlite3
claude
```

The default configuration remains deliberately non-operational: no targets, execution_enabled=false, and no autonomous network scanning. StateStore is a local persistence layer; it does not execute agents or network tools.

## Safe operation

1. Use written authorization and an explicit engagement scope.
2. Keep client evidence, credentials, tokens, cookies, and personal data out of Git.
3. Use a local encrypted evidence store with access controls and retention rules.
4. Require operator approval for intrusive or state-changing activity.
5. Enforce process isolation and network egress controls outside Claude Code.

The command hook is a safety tripwire, not a sandbox. Gitleaks is a best-effort secret scanner, not a guarantee that sensitive data cannot be committed.

## Current limitations

The state engine is a small SQLite persistence layer, not a full orchestrator. It does not yet schedule subagents, enforce scope at the network layer, store evidence files, or provide concurrency controls. Agent contracts still need a least-privilege review and benchmark-driven consolidation. See docs/ROADMAP.md.
