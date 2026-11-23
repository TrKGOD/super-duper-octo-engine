# Orchestrator runtime integration

## Current implementation status

The Python workflow runner persists and validates plans and handoffs. The bounded dispatcher now invokes one explicitly queued Claude Code specialist at a time using the CLI, with tools disabled. This is a real model invocation and handoff persistence path for passive analysis of supplied artifacts, but it is not autonomous orchestrator planning or Task-tool delegation.

The following are separate capabilities and must not be conflated:

- **Workflow persistence:** implemented in Python/SQLite.
- **Agent definitions:** repository Markdown contracts loaded by Claude Code when selected.
- **Specialist dispatch:** `scripts/dispatch_task.py` invokes one allowlisted specialist, injects selected Skill text, validates the returned handoff and persists task/run state and telemetry.
- **Sequential multi-specialist plan execution:** implemented through `scripts/run_plan.py`; the operator authors the plan and starts the run.
- **LLM plan generation:** implemented through `scripts/run_orchestrator.py`; the orchestrator agent proposes a plan with tools disabled, then Python validates and persists it.
- **Native Task-tool delegation:** not implemented; Python dispatches specialists sequentially according to the validated plan.

## Bootstrap

```bash
python scripts/migrate.py --db .local/state.sqlite3
python scripts/workflow.py --db .local/state.sqlite3 init --engagement config/engagement.local.json
```

Initialization requires engagement_id, written-authorization reference, explicit scope, and rules_of_engagement.execution_enabled=false. It creates a draft engagement; it does not verify the underlying authorization document or approve active testing.

## Plan and persistence

Create a plan using `templates/plan.schema.json`, then:

```bash
python scripts/workflow.py --db .local/state.sqlite3 plan --engagement-id ENG-ID --file plan.json
python scripts/workflow.py --db .local/state.sqlite3 status --engagement-id ENG-ID
python scripts/workflow.py --db .local/state.sqlite3 start --task-id TASK-ID
```

Only allowlisted specialist names are accepted. Each task requires objective, completion criteria and a scope subset drawn from the engagement's explicit allowlist. Dependencies must exist and be acyclic. A task cannot start until its dependencies are completed.

The operator can invoke a single specialist manually and submit a JSON handoff:

```bash
python scripts/workflow.py --db .local/state.sqlite3 handoff --task-id TASK-ID --file handoff.json
```

The runner checks schema, task/engagement/agent identity, assigned scope, registered evidence IDs and SHA-256 integrity. Collected artifact claims must match the registered evidence metadata and actual stored bytes. It updates task and agent-run state and writes audit events. Partial handoffs are retained as blocked, not completed.

## LLM-assisted plan generation

The orchestrator can propose a passive plan from the persisted engagement scope:

```bash
python scripts/run_orchestrator.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME --plan-only --plan-out .local/generated-plan.json
```

To generate the plan and then run its dependency graph sequentially:

```bash
python scripts/run_orchestrator.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
```

The planner is invoked with tools disabled. Its JSON output is validated against the plan schema and then checked against the exact engagement allowlist and `execution_enabled=false` before persistence. It cannot run commands, use Task, or access targets. The Python dispatcher then runs the resulting tasks one by one. This is LLM-assisted planning plus deterministic dispatch, not native Claude Task delegation.

## Specialist dispatch

After creating a passive plan, dispatch a queued task:

```bash
python scripts/dispatch_task.py --db .local/state.sqlite3 --task-id TASK-ID --model MODEL_NAME
```

The dispatcher reads the persisted task and engagement, verifies `execution_enabled=false`, selects Skills using task `domain`, `skill_tags`, and agent compatibility, and injects the selected Skill files into the specialist context. It invokes `claude -p --agent <name>` with tools disabled and a bounded turn count. The specialist must return a JSON handoff matching `templates/handoff.schema.json`; task identity, engagement identity, agent identity, scope subset, and evidence references are checked before persistence.

The dispatcher rejects evidence IDs that were not supplied in the task. Handoff artifacts marked `collected` or `redacted_copy` must match a registered evidence record by engagement, path and SHA-256. Proposed or missing artifacts remain explicitly non-proof. Failed CLI calls or invalid handoffs fail the task and agent run closed.

This is operator-authored sequential dispatch, not an autonomous planning agent. To run the dependency graph in order:

```bash
python scripts/run_plan.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
```

The runner stops on the first task that does not complete and does not skip failed dependencies. No tools, shell, network, scanners, or target interaction are enabled. The operator still authors the plan, confirms authorization/scope, supplies artifacts and evidence, and triggers the run.

## Specialist runtime smoke

After installing and authenticating Claude Code, a bounded single-agent smoke test can be run:

```bash
python scripts/runtime_smoke.py --agent vulnerability-agent --model MODEL_NAME
```

The smoke test uses `claude -p --agent`, sends a synthetic prompt on stdin, disables tools, and records available CLI usage metadata. It proves only that the named custom agent can respond through the CLI. The dispatch command additionally tests Skill context selection and handoff persistence when run in an authenticated Claude Code environment.

## Benchmark runner

```bash
python scripts/run_benchmark.py --agent vulnerability-agent --model MODEL_NAME --timeout-seconds 120
python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions .local/predictions.json --json-out .local/benchmark-results.json
```

The benchmark runner passes prompts through stdin because the Claude CLI's `--tools` option is variadic. It records per-case elapsed time and usage/cost fields when the CLI returns them. Missing usage metadata is explicitly represented as unavailable, not zero. Positive fixtures must contain all required evidence fields before execution.

## Evidence package

Read `docs/EVIDENCE_PROTOCOL.md` and use `templates/evidence-manifest.schema.json`. Each finding should have a local evidence directory under `.local/evidence/<finding-id>/`, a manifest, sanitized request artifacts where applicable, authentic response evidence, and a screenshot capture plan.

In this bootstrap, the exploitation-agent drafts reproduction requests and screenshot requirements but does not execute network requests or capture screenshots. The validation-agent must not treat a proposed request as proof. Automated evidence capture is not implemented.

## Safety boundaries

- The runner requires `execution_enabled=false` and rejects active-testing plans.
- It does not issue network requests, execute pentest tools, spawn agents, or verify legal authorization.
- The specialist smoke and synthetic benchmark run without tools or network access.
- Bash in the orchestrator contract is intended only for workflow/migration scripts and local JSON file handling.
- Keep database, local engagement config and evidence out of Git.
- Runner and hooks are not a sandbox; external process isolation and egress restrictions remain necessary.
- No live-target test should run until authorization, explicit scope, exclusions, rate limits, test window, and permitted methods are confirmed by an operator.
