# Orchestrator runtime integration

## Current implementation status

The Python workflow runner persists and validates plans and handoffs. Passive specialists are invoked with tools disabled. The dedicated active-testing-agent receives only broker-scoped Bash access for operator-reviewed HTTP request manifests; it does not receive general shell or network tools. This is not autonomous scanner execution or native Task-tool delegation.

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

Initialization requires engagement_id, written-authorization reference, explicit scope, and rules_of_engagement.execution_enabled=false. The config's execution_mode defaults to active and is persisted with the engagement; this sets planning preference, not permission to execute. It creates a draft engagement. The operator must then run `workflow.py approve` with explicit attestations for written authorization, scope, and rules before active tasks can be planned.

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

The orchestrator can propose a plan from the persisted engagement scope:

```bash
python scripts/run_orchestrator.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME --plan-only --plan-out .local/generated-plan.json
```

To generate the plan and then run its dependency graph sequentially:

```bash
python scripts/run_orchestrator.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
```

The planner is invoked with tools disabled. Its JSON output is validated against the plan schema and the exact engagement allowlist. Active tasks are accepted only for an already approved active engagement and must reference operator-reviewed, SHA-256-pinned request manifests. The planner cannot access targets. The Python dispatcher then runs the resulting tasks one by one. This is LLM-assisted planning plus deterministic dispatch, not native Claude Task delegation.

## Specialist dispatch

After creating a plan, dispatch a queued task:

```bash
python scripts/dispatch_task.py --db .local/state.sqlite3 --task-id TASK-ID --model MODEL_NAME
```

The dispatcher reads the persisted task and engagement, selects Skills using task `domain`, `skill_tags`, and agent compatibility, and injects the selected Skill files. Passive specialists run with tools disabled. For an active task, only `active-testing-agent` is accepted; it receives Bash only with a bounded turn count, and the PreToolUse guard permits only `scripts/active_http.py` for a request file pinned in that task. The specialist must return a JSON handoff matching `templates/handoff.schema.json`; task identity, engagement identity, agent identity, scope subset, and evidence references are checked before persistence.

The dispatcher rejects evidence IDs that were not supplied in the task. Handoff artifacts marked `collected` or `redacted_copy` must match a registered evidence record by engagement, path and SHA-256. Proposed or missing artifacts remain explicitly non-proof. Failed CLI calls or invalid handoffs fail the task and agent run closed.

This is operator-authored sequential dispatch, not an autonomous planning agent. To run the dependency graph in order:

```bash
python scripts/run_plan.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
```

The runner stops on the first task that does not complete and does not skip failed dependencies. Passive tasks have no tools or target interaction. Active tasks can issue only bounded HTTP requests from pre-reviewed manifests through the broker; no general shell, scanner, or arbitrary network tool is exposed. The operator approves the engagement and request manifests before dispatch.

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

The active-testing-agent can collect bounded HTTP request/response artifacts through the broker. The exploitation-agent still drafts reproduction requests and screenshot requirements; browser screenshot capture is not implemented. The validation-agent must independently review authentic broker evidence and must not treat an unexecuted proposal as proof.

## Safety boundaries

- Active execution requires `status=active`, `execution_enabled=true`, `authorization_verified=true`, exact scope, and a pinned request manifest.
- The broker supports only bounded HTTP(S) requests; it does not execute Nmap/Nuclei or arbitrary pentest tools.
- The approval command records operator attestation; it does not independently verify the authorization document.
- The specialist smoke and synthetic benchmark run without tools or network access.
- The orchestrator's Bash is restricted to workflow lifecycle commands before activation and read-only status/KB queries while active; active-testing-agent's Bash is restricted to the scoped HTTP broker.
- Keep database, local engagement config and evidence out of Git.
- Runner and hooks are not a sandbox; external process isolation and egress restrictions remain necessary.
- No live-target test should run until authorization, explicit scope, exclusions, rate limits, test window, and permitted methods are confirmed by an operator.
