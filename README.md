# Pentest Agent Framework

A Claude Code–first scaffold for an evidence-driven assistant supporting authorized security assessments across Web, API, Mobile, Cloud and Active Directory.

> **Current status: early pre-alpha implementation.** The repository contains agent/skill prompt contracts, configuration validation, a deny-by-default Bash hook, a local public-research knowledge-base utility, a synthetic benchmark evaluator, SQLite persistence and migrations, deterministic task/finding lifecycle controls, an operator-driven local evidence vault with SHA-256 integrity verification, audit events, and a passive-only workflow coordinator. It is **not** a production autonomous pentest framework and does not autonomously dispatch Claude agents or execute active tests.

## What is implemented

- `scripts/validate_config.py`: validates a small set of safe bootstrap configuration invariants.
- `hooks/command_guard.py`: narrow local-command allowlist/tripwire. It is not a sandbox or an authorization verifier.
- `database/schema.sql` plus `database/migrations/`: SQLite baseline and ordered migrations consumed by `scripts/migrate.py`.
- `scripts/knowledge_base.py` and `scripts/kb_sources.py`: operator-run local research ingestion/search and public RSS/Atom metadata discovery. The KB workflow preserves source provenance and separates public research context from current-engagement evidence; it does not validate findings on a live target.
- `scripts/run_benchmark.py`: invokes the Claude Code CLI against synthetic fixtures, sends prompts through stdin to avoid variadic `--tools` argument parsing, and records per-case duration plus available CLI usage/cost metadata.
- `scripts/evaluate_benchmark.py`: computes metrics from supplied predictions against synthetic fixtures and rejects positive cases with incomplete fixture payloads; metrics are not a real-world pentest-effectiveness claim.
- `core/store.py`: SQLite persistence for engagements, tasks, agent runs, findings, evidence metadata, and audit events. Finding transitions are transactional and evidence references must resolve to records in the same engagement.
- `core/evidence.py`: stores operator-supplied evidence bytes under `.local/evidence/`, calculates SHA-256 from the stored payload, and verifies artifacts against the recorded digest.
- `core/orchestration.py`: deterministic passive workflow coordinator with plan, dependency, scope-subset, and handoff checks. Handoffs must reference persisted evidence records.
- `.claude/agents/`: differentiated specialist contracts for scope, recon, technology profiling, enumeration, vulnerability hypotheses, reproduction planning, independent validation, impact, deduplication, and reporting.
- `.claude/skills/`: reusable methodology packages; `.claude/skills/registry.json` catalogues domains, tags, compatible agents, prerequisites and metadata validation status. The registry is catalogue-only and does not grant permissions or dispatch agents.
- `scripts/skill_registry.py`: validates Skill paths/frontmatter/agent references and supports deterministic local selection.
- `docs/SKILL_REGISTRY.md`: Skill Registry contract, commands, safety boundaries and maintenance workflow.
- `docs/AGENT_SPECIALIZATION.md`: specialist boundaries, task contract, handoff expectations, and lifecycle separation.
- `templates/`: JSON data contracts; handoff and plan schemas are loaded by the workflow validator.
- `.pre-commit-config.yaml`: Gitleaks pre-commit hook configuration.

## Local checks

```bash
python -m pip install -r requirements-dev.txt
python scripts/validate_config.py
python scripts/skill_registry.py validate
python scripts/validate_agent_tools.py
python -m unittest discover -s tests -v
python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions benchmarks/predictions.example.json
pre-commit run --all-files
```

## Engagement configuration and sensitive data

Create a local copy of `config/engagement.example.json` as `config/engagement.local.json`. All `config/engagement.*.json` files are ignored by Git except the sanitized example. Verify with:

```bash
git check-ignore -v config/engagement.local.json
git check-ignore -v config/engagement.client-name.json
git check-ignore config/engagement.example.json
```

Never commit authorization references, client names, scope, contacts, credentials, screenshots, or engagement evidence. The ignore rule is defense-in-depth, not a substitute for reviewing `git status` and the staged diff before committing.

## Evidence handling

See [docs/EVIDENCE.md](docs/EVIDENCE.md) for the operator-driven artifact vault, hash verification, usage, and limitations. The `redacted` flag is an operator assertion; there is no automated redaction engine yet.

## Knowledge base

- `scripts/kb_sources.py` discovers candidate research URLs from configured public RSS/Atom feeds; metadata only, no article-body scraping.
- `scripts/knowledge_base.py` ingests operator-reviewed Markdown/text, imports the committed 21-pattern seed idempotently, and searches patterns by full-text terms, domain, and tag.
- `knowledge-base/seed/` contains original analyst-authored patterns for Web, API, Mobile, Cloud, and Active Directory.
- See `docs/KNOWLEDGE_BASE.md` for disclosure, licensing, ingestion, and retrieval rules.

Initialize/import the starter corpus with `python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 import-seed`, then query it with `python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 search-patterns --query "object authorization" --domain api`. Import is idempotent. The current runtime still requires an operator to select results and pass them into agent context; autonomous agent dispatch/retrieval is not implemented.

Only explicitly public material with a documented rights basis may be ingested. Platform-specific reports require confirmation of the exact report's disclosure status and permitted use. The adapters do not access private APIs or bypass disclosure controls.

## Synthetic benchmark and runtime smoke

- `benchmarks/cases/` contains synthetic positive and negative fixtures, including an adversarial untrusted-content case. Positive cases must include every required evidence field in their fixture payload.
- `scripts/run_benchmark.py` invokes the Claude Code CLI with the selected repository agent prompt, sends the prompt on stdin, and records per-case duration plus available usage/cost metadata.
- `scripts/evaluate_benchmark.py` reports precision, recall, F1, false-positive rate and evidence completeness from prediction JSON.
- `scripts/runtime_smoke.py` checks one named Claude Code custom agent in a bounded no-tool invocation. It does not prove orchestrator dispatch or dynamic Skill selection.
- `scripts/validate_agent_tools.py` statically checks least-privilege tool declarations in agent frontmatter; it is not a runtime permission boundary.
- See [docs/BENCHMARKING.md](docs/BENCHMARKING.md) for methodology and limitations.
- Synthetic metrics are not a real-world pentest-effectiveness claim.

## Planned / not yet implemented

- Automated redaction and sensitive-content detection.
- Encryption at rest, retention/deletion controls, and immutable evidence storage.
- Hardened multi-user filesystem isolation and crash/recovery reconciliation between filesystem and SQLite.
- Claude Code agent dispatch and least-privilege tool separation.
- Handoff generation by live agents (the current coordinator validates submitted handoffs but does not generate them).
- Evidence file ingestion, content hashing at capture time, redaction pipeline, and artifact retention controls.
- Crash recovery and robust concurrent multi-process orchestration.
- Automated Model 1 versus hybrid agent benchmark runs; the current runner evaluates a configured specialist prompt and does not prove end-to-end orchestration.

## Safety and limitations

The scaffold does not verify authorization documents, make network requests for pentest activity, execute scanners, or autonomously spawn agents. Active testing must remain disabled until authorization, scope enforcement, execution isolation, auditability and human approval controls are implemented and independently tested.
