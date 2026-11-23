# Orchestrator runtime integration

The workflow runner is a deterministic persistence/control layer, not an agent executor. Claude Code selects and invokes subagents; the runner persists the plan, enforces task dependencies and scope subsets, validates handoffs, and records task/agent-run audit events.

## Bootstrap

```bash
python scripts/migrate.py --db .local/state.sqlite3
python scripts/workflow.py --db .local/state.sqlite3 init --engagement config/engagement.local.json
```

Initialization requires engagement_id, written-authorization reference, explicit scope, and rules_of_engagement.execution_enabled=false. It creates a draft engagement; it does not verify the underlying authorization document or approve active testing.

## Planning and dispatch

Create a plan using templates/plan.schema.json, then:

```bash
python scripts/workflow.py --db .local/state.sqlite3 plan --engagement-id ENG-ID --file plan.json
python scripts/workflow.py --db .local/state.sqlite3 status --engagement-id ENG-ID
python scripts/workflow.py --db .local/state.sqlite3 start --task-id TASK-ID
```

Only allowlisted specialist names are accepted. Each task requires objective, completion criteria and a scope subset drawn from the engagement's explicit allowlist. Dependencies must exist and be acyclic. A task cannot start until its dependencies are completed.

The orchestrator invokes the matching Claude Code subagent with persisted task context. Save the returned JSON handoff locally and submit:

```bash
python scripts/workflow.py --db .local/state.sqlite3 handoff --task-id TASK-ID --file handoff.json
```

The runner checks schema, task/engagement/agent identity, and assigned scope. It updates task and agent-run state and writes audit events. Partial handoffs are retained as blocked, not completed.

## Safety boundaries

- The runner requires execution_enabled=false and rejects active_testing plans.
- It does not issue network requests, execute tools, spawn agents, or verify legal authorization.
- Bash in the orchestrator is intended only for workflow/migration scripts and local JSON file handling.
- Keep database, local engagement config and evidence out of Git.
- Runner and hooks are not a sandbox; external process isolation and egress restrictions remain necessary.
