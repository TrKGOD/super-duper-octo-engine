# Pentest Agent Framework

A Claude Code–first, evidence-driven multi-agent framework for authorized security assessments across Web, API, Mobile, Cloud and Active Directory.

> Status: early implementation. Includes deterministic finding validation, SQLite persistence, a workflow runner for plans/tasks/handoffs, evidence contracts, a local public-write-up knowledge base, audit events, migrations, CI and Gitleaks configuration. Claude Code still performs agent dispatch; this is not a production autonomous scanner.

## Implemented components
- `core/validation.py` enforces independent validation and evidence requirements.
- `core/store.py` persists engagements, tasks, linked agent runs, findings and audit events.
- `core/orchestration.py` validates task graphs, exact scope subsets, dependencies and handoffs.
- `scripts/workflow.py` is the CLI used by the orchestrator to persist lifecycle transitions and findings.
- `scripts/knowledge_base.py` ingests operator-curated public Markdown/text write-ups into a local SQLite FTS index and supports search/show.
- `scripts/migrate.py` applies ordered SQLite migrations.
- `scripts/validate_contracts.py` validates finding, handoff, plan, evidence and knowledge-document schemas/examples.
- `.github/workflows/ci.yml` runs config checks, migrations, unit tests and contract validation.
- `.pre-commit-config.yaml` configures Gitleaks.

## Quick start
Requirements: Claude Code, Python 3.11+, Git.

```bash
git clone https://github.com/TrKGOD/super-duper-octo-engine.git
cd super-duper-octo-engine
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/validate_config.py
python scripts/migrate.py --db .local/state.sqlite3
python -m unittest discover -s tests -v
python scripts/validate_contracts.py
pre-commit install
claude
```

Initialize the knowledge base and add a public report with a metadata sidecar:

```bash
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 init
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 ingest --file .local/knowledge-base-inbox/example.md --metadata .local/knowledge-base-inbox/example.meta.json
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 search --query "API IDOR authorization" --limit 5
```

Only ingest material explicitly disclosed for public use and with a documented rights basis. The importer does not scrape websites, bypass access controls, or access private platform APIs. See `docs/KNOWLEDGE_BASE.md` and `knowledge-base/README.md`.

Create config/engagement.local.json from config/engagement.example.json, keep execution_enabled=false, then ask the orchestrator to initialize the engagement and build a plan. See docs/ORCHESTRATOR_RUNTIME.md.

## Safety and limitations
The runner does not verify authorization documents, make network requests, execute tools or spawn agents. Claude Code dispatches subagents and submits their structured handoffs. The bootstrap rejects active-testing plans and requires execution_enabled=false. It enforces exact allowlisted scope subsets at task/handoff level, not at a network boundary.

The Bash hook allows narrowly enumerated local workflow commands and read-only knowledge-base searches while execution is disabled. Knowledge-base ingestion is operator-driven. The hook is defense-in-depth, not a sandbox. External process isolation and egress restrictions remain necessary. Keep .local/, local engagement configs, databases, evidence, credentials and handoffs out of Git.
