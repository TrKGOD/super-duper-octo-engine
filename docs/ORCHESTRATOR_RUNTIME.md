# Orchestrator runtime integration

## Current implementation status

The Python workflow runner is a deterministic persistence and validation layer. It does **not** call a model, spawn Claude Code subagents, or dispatch tasks. The orchestrator agent contract describes a human-operated sequence in which Claude Code is asked to invoke a specialist with the Task tool; this is not yet a proven end-to-end runtime integration.

The following are separate capabilities and must not be conflated:

- **Workflow persistence:** implemented in Python/SQLite.
- **Agent definitions:** repository Markdown contracts loaded by Claude Code when selected.
- **Specialist runtime smoke:** `scripts/runtime_smoke.py` checks that one named custom agent can be invoked through the Claude Code CLI with tools disabled.
- **Orchestrator-to-specialist dispatch and persisted handoff:** not yet implemented or proven by this repository.

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

The operator currently invokes Claude Code separately, obtains a JSON handoff, and submits it:

```bash
python scripts/workflow.py --db .local/state.sqlite3 handoff --task-id TASK-ID --file handoff.json
```

The runner checks schema, task/engagement/agent identity, and assigned scope. It updates task and agent-run state and writes audit events. Partial handoffs are retained as blocked, not completed. The runner does not generate the handoff.

## Specialist runtime smoke

After installing and authenticating Claude Code, a bounded single-agent smoke test can be run:

```bash
python scripts/runtime_smoke.py --agent vulnerability-agent --model MODEL_NAME
```

The smoke test uses `claude -p --agent`, sends a synthetic prompt on stdin, disables tools, and records available CLI usage metadata. It proves only that the named custom agent can respond through the CLI. It does not prove Task-based dispatch, dynamic Skill selection, handoff persistence, network testing, or target authorization.

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
