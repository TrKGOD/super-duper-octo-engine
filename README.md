# Pentest Agent Framework

A Claude Code–first, evidence-driven multi-agent framework for authorized security assessments across Web, API, Mobile, Cloud and Active Directory.

> Status: early implementation. Includes deterministic finding validation, SQLite persistence, evidence contracts, a local public-write-up knowledge base, structured vulnerability patterns, audit events, CI and Gitleaks configuration. Claude Code still performs agent dispatch; this is not a production autonomous scanner.

## Knowledge base
- `scripts/kb_sources.py` discovers candidate research URLs from configured public RSS/Atom feeds; metadata only, no article-body scraping.
- `scripts/knowledge_base.py` ingests operator-reviewed Markdown/text and searches source documents plus normalized vulnerability patterns.
- `templates/knowledge-document.schema.json` and `templates/knowledge-pattern.schema.json` define provenance and structured extraction contracts.
- See `docs/KNOWLEDGE_BASE.md` for disclosure, licensing, ingestion, and agent retrieval rules.

```bash
python scripts/kb_sources.py --config config/knowledge-sources.example.json
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 init
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 search --query "API authorization IDOR"
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 search-patterns --query "BOLA object authorization"
```

Only explicitly public material with a documented rights basis may be ingested. Platform-specific reports require confirmation of the exact report's disclosure status and permitted use. The adapters do not access private APIs or bypass disclosure controls.

## Agent evaluation benchmark
- `benchmarks/cases/` contains synthetic positive and negative fixtures only.
- `scripts/evaluate_benchmark.py` reports precision, recall, F1, false-positive rate and evidence completeness from agent prediction JSON.
- See `benchmarks/README.md` for the prediction contract and limitations. These fixture metrics are not a real-world model-quality claim.

```bash
python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions benchmarks/predictions.example.json
```

## Core
- `core/validation.py` enforces independent finding validation.
- `core/store.py` persists engagements, tasks, runs, findings and audit events.
- `core/orchestration.py` validates plans, scope subsets, dependencies and handoffs.
- `scripts/workflow.py` persists lifecycle transitions.
- `scripts/validate_contracts.py` validates schemas and examples.
- `.github/workflows/ci.yml` runs unit tests and contract validation.

## Safety and limitations
The runner does not verify authorization documents, make network requests, execute scanners or spawn agents. The bootstrap rejects active-testing plans and requires `execution_enabled=false`. The RSS adapter is an operator-run research discovery utility, not a target scanner. Keep `.local/`, source documents, engagement evidence, credentials and client data out of Git.
