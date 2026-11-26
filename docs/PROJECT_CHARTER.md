# Witherhoard — Project Charter

## Product definition

The Witherhoard is an execution-oriented, multi-agent system for conducting **authorized penetration tests**. It is intended to accept an engagement's rules and verified scope, discover and assess the exposed attack surface, investigate vulnerabilities, validate findings, preserve evidence, and produce professional security reports.

It is not intended to be a generic conversational assistant, a documentation generator, or a set of agent prompts that only describe hypothetical testing.

## Primary outcome

Given a properly authorized engagement, the framework should carry out a repeatable assessment workflow:

1. **Engagement understanding:** parse the program brief and record exact targets, exclusions, permitted test classes, limits, test windows, and reporting rules.
2. **Scope-aware reconnaissance:** discover assets and services using permitted sources and methods; reject anything not explicitly authorized.
3. **Enumeration:** map reachable applications, routes, endpoints, parameters, technologies, authentication flows, and relevant API/mobile surfaces.
4. **Vulnerability discovery:** investigate concrete hypotheses using specialist methodology and appropriate tools.
5. **Controlled validation:** reproduce candidate issues with minimal, non-destructive proof and authentic evidence.
6. **Independent verification:** have a different specialist review the evidence and the claim.
7. **Impact and triage:** assess realistic impact, remove duplicates, and distinguish confirmed findings from hypotheses or rejected issues.
8. **Reporting:** generate actionable reports with affected asset, prerequisites, reproduction, impact, severity, evidence, and remediation.

A stage is complete only when its defined work actually ran and its output is recorded. A plan, prompt, unexecuted request, scanner suggestion, or LLM-generated hypothesis is not proof that a test occurred.

## Operating model

- A Pentest Orchestrator coordinates specialist agents and the assessment lifecycle.
- Specialist agents own distinct assessment responsibilities and use domain-appropriate Skills.
- Deterministic code enforces engagement scope, execution permissions, method limits, evidence integrity, task dependencies, and audit records.
- Findings move through explicit observation, hypothesis, validation, rejection, and reporting states.
- The proposing agent cannot be the sole validator.
- Engagement data, credentials, tokens, and evidence remain isolated from source control.

## Capability status must be explicit

The repository is early pre-alpha. Product purpose and current implementation maturity are separate facts.

| Capability | Current status |
|---|---|
| Multi-agent contracts and specialist roles | Implemented |
| Workflow persistence and dependency validation | Implemented |
| Skill registry and methodology injection | Implemented |
| Evidence registration and integrity verification | Implemented |
| Scope-enforcing bounded HTTP broker | Implemented with exact scope, DNS/IP pinning, rate limits, evidence capture and manifest pinning |
| LLM-assisted plan generation | Implemented; planner runs without tools |
| Sequential specialist dispatch | Implemented |
| Bounded same-origin Web/API reconnaissance | Initial implementation; GET/OPTIONS only, max 25 pages/depth 3 |
| HTML crawling and observed endpoint/form discovery | Initial implementation; same-origin only |
| Static JavaScript endpoint and sink analysis | Implemented; static parsing only, no JS execution |
| Automated low-impact vulnerability checks | Initial implementation; headers, cookie attributes, CORS and OPTIONS |
| Executable exploitation-agent | Implemented for separately pinned, non-destructive GET/HEAD/OPTIONS reproduction requests |
| Independent validation-agent | Implemented; distinct validator and optional fresh, separately pinned broker reproduction |
| General autonomous subdomain reconnaissance | Not implemented |
| Broad multi-host/API schema discovery | Not implemented |
| Deeper vulnerability workflows (SQLi, SSRF, authz/IDOR, OAuth/JWT) | Not implemented by the initial Web/API vertical |
| General scanner integration (for example Nuclei) | Not implemented |
| Browser-driven authenticated testing | Not implemented |
| Native Claude Task-tool delegation | Not implemented |
| Full autonomous end-to-end live pentest | Not yet implemented |

Never describe an unimplemented capability as available. Conversely, do not let the current pre-alpha limitations redefine the product as a planning assistant. They are gaps to close through code, tests, and controlled demonstrations.

## Engineering priorities

When improving the framework, prioritize functional pentesting capabilities over documentation-only changes:

1. Extend the initial same-origin discovery runner into broader authorized asset and API schema discovery.
2. Expand specialist least-privilege broker tools without granting unrestricted shell or network access.
3. Add deeper vulnerability-testing modules (SQLi, SSRF, authz/IDOR, OAuth/JWT) with explicit method and rate policies.
4. Preserve evidence automatically from actual tool executions.
5. Expand independent validation and reproducible reporting, including lab-based end-to-end seeded findings.
6. Demonstrate each capability against intentionally vulnerable local applications before claiming operational readiness.

## Authorization and safety

The framework performs security testing only when the operator has valid written authorization and the exact target is explicitly in scope. Scope ambiguity, exclusions, test windows, or prohibited methods must fail closed.

Do not perform destructive testing, denial of service, persistence, credential attacks, stealth/evasion, bulk extraction, or unauthorized access to real user data. Use minimal synthetic proof data. Require explicit operator approval for state-changing operations and engagement activation.

Safety controls are part of the execution engine. They must constrain real testing without reducing the framework to a documentation-only workflow.

## Definition of done

A meaningful end-to-end capability is demonstrated—not merely described—when the framework can:

- run it against a controlled local target or explicitly authorized engagement;
- capture the actual command/request and resulting output;
- preserve evidence with integrity metadata;
- produce a structured specialist handoff;
- enforce scope and execution policy;
- pass regression tests covering both successful and blocked paths.

For an end-to-end pentest demonstration, the framework must discover a seeded vulnerability in an intentionally vulnerable local application, validate it safely, independently review the evidence, and generate a complete report.
