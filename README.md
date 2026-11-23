# Pentest Agent Framework

**An execution-oriented, multi-agent framework for conducting authorized penetration tests.**

This project exists to plan, execute, validate, and report real security assessments across **Web applications, APIs, Mobile, Cloud, and Active Directory**. It is a pentesting framework—not a generic chatbot, documentation generator, or collection of agent prompts.

The intended operator workflow is straightforward: provide an engagement and its written rules, verify the exact scope, run reconnaissance and enumeration, investigate vulnerabilities, validate findings with reproducible evidence, and produce a professional report. The framework coordinates specialized agents and deterministic tooling to carry that workflow through.

> **Project maturity: early pre-alpha.** The repository already implements workflow persistence, specialist dispatch, Skill selection, validated handoffs, evidence integrity checks, a synthetic benchmark, and a scope-enforcing HTTP broker. Important execution capabilities are still limited: passive specialists currently run without tools, active HTTP is restricted to reviewed SHA-256-pinned manifests, and general scanner/browser/container integrations are not yet implemented. The project purpose is real authorized pentesting; this status statement describes what the current code can and cannot execute today.

## Product objective

The framework must turn an authorized engagement into an evidence-backed pentest workflow:

1. **Understand authorization:** ingest the program brief, identify explicit in-scope assets, exclusions, allowed test classes, limits, and test windows.
2. **Discover the attack surface:** perform scoped reconnaissance, service and technology identification, crawling, endpoint and parameter discovery, and API/mobile surface mapping.
3. **Find vulnerabilities:** use specialist methodology and appropriate testing tools to investigate concrete security hypotheses.
4. **Validate safely:** reproduce candidate issues with minimal proof, preserve authentic evidence, and require independent validation.
5. **Report professionally:** produce actionable findings with affected assets, prerequisites, reproduction steps, impact, severity, evidence, and remediation.

The orchestrator is responsible for coordinating actual assessment work—not merely generating a plan. A stage is complete only when its defined work has run and its output is validated. A proposed test, unexecuted request, or LLM hypothesis is not a finding.

## Current execution boundary

The framework is under active development toward that objective. Implemented workflow and safety infrastructure must not be mistaken for a complete autonomous scanner. In the current implementation, passive specialists are tool-disabled and the active-testing specialist can use only the bounded HTTP broker. The broker is not a crawler, scanner, browser, shell sandbox, or general exploitation engine. Missing capabilities should be implemented and tested against controlled local targets rather than claimed in documentation.

All live testing remains restricted to assets explicitly authorized by the relevant engagement. Safety gates are part of the pentesting engine: they must constrain execution without turning the product into a documentation-only workflow.

See [the project charter](docs/PROJECT_CHARTER.md) for the product definition, assessment lifecycle, and capability-status principles.

## Enumeration-First Multi-Agent Pipeline

The nine-stage scope → recon → enumeration → vulnerability → active testing → independent validation → impact → deduplication → reporting workflow is documented in [docs/ENUMERATION_FIRST_PIPELINE.md](docs/ENUMERATION_FIRST_PIPELINE.md). Every task must declare a domain and compatible Skill tags; the dispatcher fails closed if no methodology is selected. A synthetic end-to-end DAG test exercises handoffs and evidence without contacting external targets.

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
- `core/dispatch.py`, `scripts/dispatch_task.py` and `scripts/run_plan.py`: invoke passive specialists with tools disabled and the dedicated active-testing-agent with broker-only Bash access; select methodology context, verify evidence, validate handoffs, and persist run telemetry.
- `core/active_executor.py` and `scripts/active_http.py`: enforce exact engagement/task scope, DNS/IP checks, redirect validation, rate/response limits, request-manifest pinning, evidence capture, and audit logging for active HTTP requests.
- `core/llm_orchestrator.py` and `scripts/run_orchestrator.py`: ask the orchestrator agent for a plan with tools disabled, validate exact scope and persist it, then optionally dispatch the dependency graph sequentially. Native Task-tool delegation is not enabled.
- `scripts/parse_program_policy.py`: extract a draft scope profile from operator-supplied bug bounty policy text, preserving source quotes and ambiguities. It does not browse program sites or approve authorization.
- `core/evidence_scoring.py`, `scripts/dedupe_findings.py` and `scripts/render_report.py`: score evidence readiness, identify possible duplicates without mutation, and render reports from independently validated findings with re-verified evidence.
- `scripts/run_architecture_benchmark.py` and `scripts/compare_architecture_results.py`: run fixed Model 1 and hybrid specialist sequences against the same synthetic corpus and compare metrics only when model and corpus hashes match.
- `.claude/agents/`: differentiated specialist contracts for scope, recon, technology profiling, enumeration, vulnerability hypotheses, reproduction planning, independent validation, impact, deduplication, and reporting.
- `.claude/skills/`: reusable methodology packages; `.claude/skills/registry.json` selects methodology context by domain, compatible agent and required task tags. Selected Skill text is injected into a specialist prompt as untrusted context; it does not grant permissions.
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

Choose a plan template under `templates/examples/` (Model 1, hybrid Web, API, Mobile, Cloud, or Active Directory). Copy the chosen template to `.local/plan.json`, replace every `REPLACE-WITH-EXACT-IN-SCOPE-ASSET` placeholder with an exact asset from the engagement allowlist, then persist and run it:

```bash
python scripts/workflow.py --db .local/state.sqlite3 plan --engagement-id ENG-ID --file .local/plan.json
python scripts/run_plan.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
python scripts/workflow.py --db .local/state.sqlite3 status --engagement-id ENG-ID
```

Passive tasks remain tool-disabled. Active recon, enumeration and vulnerability specialists receive Bash only for the guarded `scripts/active_surface.py` runner, which performs same-origin GET/OPTIONS crawling, endpoint/form discovery, static JavaScript analysis and low-impact configuration checks through the evidence-capturing HTTP broker. Exploitation-agent and validation-agent receive only guarded broker access for separately SHA-256-pinned GET/HEAD/OPTIONS manifests. No agent receives general shell or unrestricted network access. Initialize with `execution_enabled=false`, then explicitly approve the engagement before creating active tasks:

```bash
python scripts/workflow.py --db .local/state.sqlite3 approve --engagement-id ENG-ID --operator "YOUR NAME" --authorization-reference "WRITTEN-AUTH-REF" --confirm-written-authorization --confirm-scope --confirm-rules
```

Use `python scripts/workflow.py --db .local/state.sqlite3 pause --engagement-id ENG-ID --operator "YOUR NAME" --reason "..."` as the kill switch. Operator-reviewed request manifests live under `.local/requests/` and are SHA-256 pinned. The bounded discovery runner generates its own pinned GET/OPTIONS manifests internally, while exploitation and active validation require separate operator-reviewed manifests. It does not run arbitrary shell, Nmap, Nuclei, SQLMap, browser automation, brute force or destructive tests. The initial Web/API checks are limited to observed surface mapping, static JS indicators, security headers, cookie attributes, CORS and OPTIONS behavior; candidates require independent validation. See [docs/ACTIVE_EXECUTION.md](docs/ACTIVE_EXECUTION.md) and [docs/ORCHESTRATOR_RUNTIME.md](docs/ORCHESTRATOR_RUNTIME.md).

After approval, the planner can run bounded discovery without pre-created manifests. Provide request manifests only when you want the exploitation-agent or validator to replay a specific reviewed request:

```bash
python scripts/run_orchestrator.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
```

In active mode, the planner receives only sanitized manifest metadata and their SHA-256 pins; it cannot read credentials or execute requests. Python validates each manifest against engagement and task scope before dispatch.

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

- Native Claude Task-tool delegation; the LLM planner creates validated plans and Python dispatches specialists sequentially.
- Isolated execution container and network egress allowlisting; broker integrations for scanners and non-HTTP tools.
- Managed KMS integration, key rotation/multi-key support, automated redaction review, retention/deletion and immutable evidence storage.
- Hardened multi-user filesystem isolation and crash/recovery reconciliation between filesystem and SQLite.
- Robust concurrent multi-process orchestration and resource budgets.
- Repeated authenticated Model 1/hybrid pipeline runs and a variance-aware benchmark report; the current comparison harness is implemented but has not been executed against a live Claude CLI in this session.

## Safety and limitations

The scaffold does not independently verify authorization documents, execute general-purpose scanners, or autonomously spawn agents. Active HTTP requests are supported only through the scope-enforcing broker after operator attestation, task-level scope checks, and request-manifest pinning. This pre-alpha broker is not a sandbox; use external process isolation and outbound network controls. Other active tool integrations remain disabled.
