# Orchestrator runtime integration

This runtime is the execution and coordination layer of the Pentest Agent Framework. Its purpose is to move an authorized penetration test through specialist stages and preserve scope, evidence, and validation guarantees. It must not be treated as a standalone planning product.

## Current implementation status

The Python workflow runner persists and validates plans and handoffs. Passive tasks remain tool-disabled. The initial Web/API vertical gives recon, enumeration and vulnerability specialists Bash only for the guarded same-origin discovery runner; exploitation and validation specialists receive broker-only Bash for separately pinned read-only request manifests. No specialist receives general shell or unrestricted network tools. The runtime now performs bounded crawling, endpoint/form discovery, static JavaScript analysis, low-impact configuration checks and evidence-backed reproduction. It is not yet a full autonomous scanner, and native Task-tool delegation is not implemented.

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

The planner is invoked with tools disabled. Its JSON output is validated against the plan schema and the exact engagement allowlist. Active plans are accepted only for an already approved active engagement. Bounded discovery tasks may omit prebuilt manifests because the discovery runner generates and SHA-256-pins GET/OPTIONS manifests internally before broker execution. Exploitation and active validation tasks require operator-reviewed, separately pinned manifests. The planner cannot access targets. The Python dispatcher then runs the resulting tasks one by one. This is LLM-assisted planning plus deterministic dispatch, not native Claude Task delegation.

## Specialist dispatch

After creating a plan, dispatch a queued task:

```bash
python scripts/dispatch_task.py --db .local/state.sqlite3 --task-id TASK-ID --model MODEL_NAME
```

The dispatcher reads the persisted task and engagement, requires a non-empty `domain` and `skill_tags`, selects compatible Skills, and injects the selected Skill files. It fails closed when selection is empty. Direct dependency handoffs and deduplicated inherited evidence references are passed to the next specialist; evidence is re-verified from the engagement project root. Passive tasks run with tools disabled. Active tasks are accepted only for the allowlisted recon, enumeration, vulnerability, active-testing, exploitation and validation specialists. The PreToolUse guard permits only `scripts/active_surface.py` for bounded same-origin discovery or `scripts/active_http.py` for a request pinned to the running task. The discovery runner can create manifests only inside the task's isolated engagement context and pins their hashes before broker execution. The specialist must return a JSON handoff matching `templates/handoff.schema.json`; task identity, engagement identity, agent identity, scope subset, and evidence references are checked before persistence.

The dispatcher rejects evidence IDs that were not supplied in the task. Handoff artifacts marked `collected` or `redacted_copy` must match a registered evidence record by engagement, path and SHA-256. Proposed or missing artifacts remain explicitly non-proof. Failed CLI calls or invalid handoffs fail the task and agent run closed.

This is operator-authored sequential dispatch, not an autonomous planning agent. To run the dependency graph in order:

```bash
python scripts/run_plan.py --db .local/state.sqlite3 --engagement-id ENG-ID --model MODEL_NAME
```

The runner drains all currently runnable DAG branches. A blocked/partial/failed task blocks only its descendants; independent ready tasks continue. The final JSON reports all operator-gated tasks and dependency-blocked descendants together. Failed or active tasks are never automatically replayed. Passive tasks have no tools or target interaction. Active discovery tasks can issue only bounded same-origin GET/OPTIONS requests through the broker; active reproduction and validation tasks can issue only GET/HEAD/OPTIONS from separately reviewed manifests. No general shell, third-party scanner or arbitrary network tool is exposed. The operator approves the engagement before dispatch and reviews every reproduction/validation manifest.

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

The active discovery runner collects bounded HTTP request/response artifacts through the broker. The exploitation-agent can execute a minimal pinned read-only reproduction request. The validation-agent must be different from the proposer and can perform a fresh brokered reproduction only with its own separately pinned manifest; otherwise it reviews supplied evidence and must not claim fresh active reproduction. Browser screenshot capture is not implemented.

## Safety boundaries

- Active execution requires `status=active`, `execution_enabled=true`, `authorization_verified=true`, exact task/engagement scope, and either a bounded discovery task that generates pinned manifests internally or an operator-pinned reproduction/validation manifest.
- The broker supports only bounded HTTP(S) requests; it does not execute Nmap/Nuclei or arbitrary pentest tools.
- The approval command records operator attestation; it does not independently verify the authorization document.
- The specialist smoke and synthetic benchmark run without tools or network access.
- The orchestrator's Bash is restricted to the exact plan-and-dispatch entrypoint and allowlisted workflow commands. Specialist Bash is restricted to the guarded discovery runner or scoped HTTP broker.
- Keep database, local engagement config and evidence out of Git.
- Runner and hooks are not a sandbox; external process isolation and egress restrictions remain necessary.
- No live-target test should run until authorization, explicit scope, exclusions, rate limits, test window, and permitted methods are confirmed by an operator.

## Continuous dispatch and operator gates

`scripts/run_plan.py` drains every currently runnable task in dependency order. Completing a task immediately unlocks its dependent tasks. A non-completed handoff blocks only that task's descendants; unrelated branches continue and the runner returns a consolidated status (`completed`, `needs_operator`, `failed`, or `incomplete`) with blocker lists. These are expected workflow outcomes and are emitted as JSON; process exit code 2 is reserved for an execution/runtime error.

The dispatcher does not automatically retry failed or interrupted active tasks. Reconcile broker request logs, evidence and engagement budget before any manual retry to avoid duplicate traffic. Framework unit tests, synthetic benchmarks, secret scanning and CI are engineering checks, not pentest stages, and must never be inserted into an engagement DAG or run between target-assessment stages.


## Cumulative request quota removal

There is no `max_requests_per_engagement` quota and no plan-level reservation/count check. The broker remains rate-limited (maximum 5 requests/second), single-concurrency, scope-enforced, test-window-aware, method-restricted and evidence-logged. Per-run discovery page/depth and response-size bounds remain intentional controls.
