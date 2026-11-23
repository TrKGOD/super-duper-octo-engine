# Architecture Decision Records

## ADR-001 — Claude Code is the initial runtime
Status: Accepted

Claude Code is the initial agent runtime because the project is organized around subagents, skills, project instructions, and hooks. Keep domain logic and schemas runtime-neutral where practical.

## ADR-002 — Preserve Model 1
Status: Accepted

The original Recon → Enumeration → Vulnerability → Exploitation → Validation → Reporting model remains in `docs/model-1/` and `.claude/agents/model-1/`. It is a comparison baseline, not the target architecture.

## ADR-003 — Adopt hybrid orchestration
Status: Accepted

Use planning, selective execution, and independent verification. Specialist selection is dynamic and domain-specific.

## ADR-004 — Default-deny active execution
Status: Accepted

Bootstrap ships with execution disabled and no target allowlist. The local hook is only a tripwire; external isolation is required.

## ADR-005 — Local SQLite for engagement state
Status: Accepted

Use SQLite for initial single-operator persistence. Keep databases and evidence out of Git. Revisit only if concurrent multi-user operation becomes a real requirement.
