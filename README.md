# Pentest Agent Framework

A Claude Code–first scaffold for an evidence-driven assistant supporting authorized security assessments across Web, API, Mobile, Cloud and Active Directory.

> **Current status: early pre-alpha implementation.** The repository contains a bounded Claude Code specialist dispatcher for passive analysis of supplied artifacts, runtime Skill-context selection, SQLite task/run persistence, validated handoffs, a synthetic benchmark, and an operator-driven evidence vault with optional AES-256-GCM encryption. It is **not** a production autonomous pentest framework: tools are disabled in dispatched specialist runs, active tests are rejected, and no sandbox or live-target execution broker is implemented.

## What is implemented

- `scripts/validate_config.py`: validates a small set of safe bootstrap configuration invariants.
- `hooks/command_guard.py`: narrow local-command allowlist/tripwire. It is not a sandbox or an authorization verifier.
- `database/schema.sql` plus `database/migrations/`: SQLite baseline and ordered migrations consumed by `scripts/migrate.py`.
- `scripts/knowledge_base.py` and `scripts/kb_sources.py`: operator-run local research ingestion/search and public RSS/Atom metadata discovery. The KB workflow preserves source provenance and separates public research context from current-engagement evidence; it does not validate findings on a live target.
- `scripts/run_benchmark.py`: invokes the Claude Code CLI against synthetic fixtures, sends prompts through stdin to avoid variadic `--tools` argument parsing, and records per-case duration plus available CLI usage/cost metadata.
- `scripts/evaluate_benchmark.py`: computes metrics from supplied predictions against synthetic fixtures and rejects positive cases with incomplete fixture payloads; metrics are not a real-world pentest-effectiveness claim.
- `core/store.py`: SQLite persistence for engagements, tasks, agent runs, findings, evidence metadata, and audit events. Finding transitions are transactional and evidence references must resolve to records in the same engagement.
- `core/evidence.py`: stores operator-supplied evidence bytes under `.local/evidence/`, calculates SHA-256 from the stored payload, and verifies artifacts against the recorded digest.
- `scripts/redact_text_evidence.py`: creates a separate best-effort redacted copy of text evidence; manual review remains mandatory.
- `core/orchestration.py`: workflow coordinator with schema-validated plans, dependency gates, scope-subset enforcement and handoff persistence. Collected artifact claims must match registered evidence metadata.
- `core/dispatch.py`, `scripts/dispatch_task.py` and `scripts/run_plan.py`: invoke allowlisted Claude Code specialists sequentially with tools disabled, select methodology context from the Skill Registry, verify supplied evidence, validate structured handoffs, and persist run telemetry.
- `core/llm_orchestrator.py` and `scripts/run_orchestrator.py`: ask the orchestrator agent for a passive plan with tools disabled, validate exact scope and persist it, then optionally dispatch the dependency graph sequentially. Native Task-tool delegation is not enabled.
- `scripts/parse_program_policy.py`: extract a draft scope profile from operator-supplied bug bounty policy text, preserving source quotes and ambiguities. It does not browse program sites or approve authorization.
- `core/evidence_scoring.py`, `scripts/dedupe_findings.py` and `scripts/render_report.py`: score evidence readiness, identify possible duplicates without mutation, and render reports from independently validated findings with re-verified evidence.
- `scripts/run_architecture_benchmark.py` and `scripts/compare_architecture_results.py`: run fixed Model 1 and hybrid specialist sequences against the same synthetic corpus and compare metrics only when model and corpus hashes match.
- `.claude/agents/`: differentiated specialist contracts for scope, recon, technology profiling, enumeration, vulnerability hypotheses, reproduction planning, independent validation, impact, deduplication, and reporting.
- `.claude/skills/`: reusable methodology packages; `.claude/skills/registry.json` selects methodology context by domain, compatible agent and optional tags. Selected Skill text is injected into a specialist prompt as untrusted context; it does not grant permissions.
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
python -m compileall -q core scripts tests
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

See [docs/EVIDENCE.md](docs/EVIDENCE.md) for the operator-driven artifact vault, hash verification, usage, and limitations. See [docs/FINDING_LIFECYCLE.md](docs/FINDING_LIFECYCLE.md) for evidence scoring, duplicate triage and validated-only report generation. The `redacted` flag is an operator assertion; the text redaction helper is best-effort and cannot guarantee that an artifact contains no secrets or personal data.

## Knowledge base

- `scripts/kb_sources.py` discovers candidate research URLs from configured public RSS/Atom feeds; metadata only, no article-body scraping.
- `scripts/knowledge_base.py` ingests operator-reviewed Markdown/text, imports the committed 21-pattern seed idempotently, and searches patterns by full-text terms, domain, and tag.
- `knowledge-base/seed/` contains original analyst-authored patterns for Web, API, Mobile, Cloud, and Active Directory.
- See `docs/KNOWLEDGE_BASE.md` for disclosure, licensing, ingestion, and retrieval rules.

Initialize/import the starter corpus with `python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 import-seed`, then query it with `python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 search-patterns --query "object authorization" --domain api`. Import is idempotent. KB retrieval remains operator-driven; the dispatcher does not automatically ingest or retrieve KB reports.

Only explicitly public material with a documented rights basis may be ingested. Platform-specific reports require confirmation of the exact report's disclosure status and permitted use. The adapters do not access private APIs or bypass disclosure controls.

## Program policy reader

Supply a local Markdown/text copy of the program policy:

```bash
python scripts/parse_program_policy.py --input .local/program-policy.md --output .local/program-scope-draft.json
```

The output is always `draft_unverified`, includes source SHA-256, quoted line evidence, and ambiguities, and requires operator confirmation. Missing scope, exclusions, prohibited methods, or rate limits are treated conservatively. It is not proof of authorization and does not automatically configure an engagement.

## Specialist dispatch

Choose a passive plan template under `templates/examples/` (Model 1, hybrid Web, API, Mobile, Cloud, or Active Directory). Copy the chosen template to `.local/plan.json`, replace every `REPLACE-WITH-EXACT-IN-SCOPE-ASSET` placeholder with an exact asset from the engagement allowlist, then persist and run it:

```bash
python scripts/workflow.py --db .local/state.sqlite3 plan --engagement-id ENG-ID --file .local/plan.json
python scripts/run_plan.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
python scripts/workflow.py --db .local/state.sqlite3 status --engagement-id ENG-ID
```

The dispatcher invokes one allowlisted custom agent through the Claude Code CLI with tools disabled, injects Skills selected from task `domain`/`skill_tags`, verifies and inlines redacted evidence, and validates/persists the returned handoff. To ask the LLM orchestrator to generate a passive plan and run it, use `python scripts/run_orchestrator.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME`. For an existing operator-authored plan, use `python scripts/run_plan.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME`. It does not invoke pentest tools or access targets. See [docs/ORCHESTRATOR_RUNTIME.md](docs/ORCHESTRATOR_RUNTIME.md).

## Architecture comparison benchmark

Run both fixed specialist sequences against the exact same synthetic corpus and model identifier:

```bash
python scripts/run_architecture_benchmark.py --architecture model1 --plan templates/examples/plan.model1.passive.example.json --model MODEL_NAME --predictions-out .local/model1-predictions.json --manifest-out .local/model1-manifest.json
python scripts/run_architecture_benchmark.py --architecture hybrid --plan templates/examples/plan.hybrid.passive.example.json --model MODEL_NAME --predictions-out .local/hybrid-predictions.json --manifest-out .local/hybrid-manifest.json
python scripts/compare_architecture_results.py --model1-predictions .local/model1-predictions.json --model1-manifest .local/model1-manifest.json --hybrid-predictions .local/hybrid-predictions.json --hybrid-manifest .local/hybrid-manifest.json
```

This is a fixed sequential specialist-pipeline simulation, not autonomous Orchestrator/Task dispatch. Repeat runs to estimate variance before comparing results.

## Synthetic benchmark and runtime smoke

- `benchmarks/cases/` contains synthetic positive and negative fixtures, including an adversarial untrusted-content case. Positive cases must include every required evidence field in their fixture payload.
- `scripts/run_benchmark.py` invokes the Claude Code CLI with the selected repository agent prompt, sends the prompt on stdin, and records per-case duration plus available usage/cost metadata.
- `scripts/evaluate_benchmark.py` reports precision, recall, F1, false-positive rate and evidence completeness from prediction JSON.
- `scripts/runtime_smoke.py` checks one named Claude Code custom agent in a bounded no-tool invocation. It does not prove orchestrator dispatch or dynamic Skill selection.
- `scripts/validate_agent_tools.py` statically checks least-privilege tool declarations in agent frontmatter; it is not a runtime permission boundary.
- See [docs/BENCHMARKING.md](docs/BENCHMARKING.md) for methodology and limitations.
- Synthetic metrics are not a real-world pentest-effectiveness claim.

## Planned / not yet implemented

- Orchestrator-level autonomous planning and native Task-tool delegation; current multi-specialist plan execution is sequential and operator-authored.
- Isolated execution container, network egress allowlisting, and runtime per-tool approval broker.
- Managed KMS integration, key rotation/multi-key support, automated redaction review, retention/deletion and immutable evidence storage.
- Hardened multi-user filesystem isolation and crash/recovery reconciliation between filesystem and SQLite.
- Robust concurrent multi-process orchestration and resource budgets.
- Repeated authenticated Model 1/hybrid pipeline runs and a variance-aware benchmark report; the current comparison harness is implemented but has not been executed against a live Claude CLI in this session.

## Safety and limitations

The scaffold does not verify authorization documents, make network requests for pentest activity, execute scanners, or autonomously spawn agents. Active testing must remain disabled until authorization, scope enforcement, execution isolation, auditability and human approval controls are implemented and independently tested.
