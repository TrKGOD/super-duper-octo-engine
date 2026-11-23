# Technical Specification

## 1. Product objective
A Claude Code–first multi-agent framework that assists authorized penetration tests by planning work, mapping attack surface, running specialist analyses, validating evidence independently, and producing auditable reports.

## 2. Scope
Initial domains:
- Web applications
- APIs
- Mobile (Android/iOS)
- Cloud (provider-specific modules added after threat-model review)
- Active Directory / Windows enterprise environments

Initial release does not provide unrestricted autonomous exploitation. Active testing remains disabled by default and requires explicit engagement authorization plus external isolation.

## 3. Architecture

### 3.1 Control plane
**Pentest Orchestrator** is the control plane. It:
- validates engagement metadata and scope;
- builds a task graph with dependencies;
- selects specialist agents and skills;
- chooses sequential or bounded-parallel execution;
- tracks task status, budgets, and handoffs;
- requests operator approval for risky actions;
- consolidates findings and produces a final report.

The orchestrator should not perform every specialist task itself.

### 3.2 Model 1 — preserved baseline
The original specialist model remains a documented baseline:
1. Recon Agent
2. Enumeration Agent
3. Vulnerability Agent
4. Exploitation Agent
5. Validation Agent
6. Reporting Agent

It is retained for comparison and regression testing. Do not silently replace or rename its roles.

### 3.3 Hybrid architecture — target design
The hybrid model combines:
- ProjectDiscovery-inspired planning / execution / verification;
- 0xSteph-inspired focused agents, tiers, and persistent findings;
- H-mmer-inspired vulnerability-specific specialists and evidence gates.

Phases:
1. **Planning & Intelligence:** scope analyst, recon, technology profiling, attack-surface mapping.
2. **Specialized Testing:** dynamically selected Web/API/Mobile/Cloud/AD specialists.
3. **Validation & Impact:** independent validator, PoC analyst, impact analyst, chain analyst.
4. **Knowledge & Reporting:** duplicate detection, risk scoring, reporting, retest tracking.

The phases are logical gates, not a rigid one-agent-per-phase sequence.

## 4. Agent contracts
Every agent must declare:
- name and concise description;
- allowed tools (least privilege);
- model policy (inherit by default until benchmark data exists);
- input schema and required context;
- allowed outputs;
- completion criteria;
- safety constraints;
- escalation conditions.

Agents return structured handoffs. They must distinguish facts from hypotheses and include evidence references.

## 5. Skill contracts
Skills contain reusable methodology, not orchestration policy. A skill should include:
- purpose and applicability;
- prerequisites and required authorization;
- test ideas and analysis workflow;
- safe/non-destructive constraints;
- evidence to collect;
- false-positive considerations;
- output schema;
- references and last-reviewed date.

Skills are loaded on demand. Do not put the entire methodology library in `CLAUDE.md`.

## 6. State and persistence
SQLite is the initial local persistence target. Core entities:
- engagements
- assets
- endpoints
- tasks
- findings
- evidence
- agent_runs
- audit_events

Engagement evidence is local, encrypted at rest where feasible, and excluded from Git. Database schema changes use migrations.

## 7. Finding lifecycle
`observation -> hypothesis -> validation_pending -> validated | rejected | needs_more_evidence -> reported -> retest_pending -> resolved`

A finding is not `validated` without independent reproduction or a documented reason why independent reproduction is not possible.

## 8. Security model
- Explicit scope allowlist and exclusions.
- Execution disabled by default.
- Least-privilege agent tools.
- Human approval for intrusive or state-changing tests.
- External container/VM and egress controls for active testing.
- Secret redaction and local evidence storage.
- Audit log for task, tool, and approval events.
- No stealth, persistence, destructive testing, or uncontrolled data access.

The Claude Code hook is defense-in-depth only. It is not a sandbox and cannot reliably secure arbitrary shell execution.

## 9. Model and cost policy
Start with `inherit` for agents. Introduce model routing only after measuring:
- task success;
- validated findings;
- false-positive rate;
- latency;
- token and monetary cost.

Optimize cost per validated finding, not raw token count.

## 10. Quality gates
- Static validation of agent frontmatter and configuration.
- Unit tests for scope parsing and finding lifecycle.
- Hook tests for default-deny behavior.
- Schema migration tests.
- Lab benchmark with known seeded vulnerabilities.
- Regression set for false positives and duplicate findings.

## 11. Non-goals for bootstrap
- Production-grade autonomous scanner.
- Automatic exploitation.
- Credential harvesting or persistence.
- Multi-tenant hosted service.
- Automatic upload of evidence to GitHub.
- Claims of effectiveness without controlled benchmark results.
