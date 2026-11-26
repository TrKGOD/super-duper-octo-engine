# Agent-to-Tool Intelligence & Normalized Observations

**Component F.** Status: `lab_verified`. Connects agents to tools through a capability
interface with deterministic selection, and normalizes every tool result into one schema with
explicit dispositions, correlated into the engagement graph.

## Capability requests and selection (`core/tools/selection.py`)

An agent requests a **capability** (optionally a vulnerability class and a profile ceiling),
not a binary. `ToolSelector.select(CapabilityRequest)` resolves it deterministically:

- It calls the Component D registry's `select_tools` (available + profile-authorized tools;
  **RESTRICTED is never auto-selected**).
- It applies the agent's requested `max_profile` cap.
- **Redundancy control**: a tool whose capabilities are already covered by prior results is
  **deferred** (reason `capability_already_covered`), not run again without cause.

The result lists `selected`, `deferred` (with reasons) and `rejected` (with reasons) — full
observability of why each tool was or wasn't chosen. The selector is deterministic; an LLM may
propose, this layer decides.

## Normalized observation model (`core/tools/observations.py`, migration `013`)

Every adapter result is normalized into `tool_observations` rows (directive §7): one row per
observation, traceable to `tool_id` / `task_id` / `engagement_id` / `execution_id`, with
`observation_type`, `target`/`asset`/`endpoint` references, `vulnerability_class`,
`severity_candidate`, `confidence`, `execution_profile`, `raw_artifact_reference`, source
provenance, and a **disposition**:

| Disposition | Meaning |
|---|---|
| DETECTED | observed structure (a host, service, route) |
| CANDIDATE | a scanner lead (nuclei/dalfox result) — **not** a finding |
| SUPPORTED / REFUTED / INCONCLUSIVE | a validation-engine outcome |
| ERROR | a failed tool run |

`DETECTED` and `CANDIDATE` are never confirmed findings. Secrets are stripped from reference
URLs and redacted in the stored data; raw output stays an artifact reference, never copied
inline.

## Correlation (`correlate_to_graph`)

DETECTED structure is projected into the existing graph as **observed** nodes (subdomains →
`host`, services/routes → `route`) with provenance. CANDIDATE observations are **not** projected
as structure — they are counted and left as leads for the planner (hypotheses) and the
validation engine (confirmation). Tool output never creates an authorization edge or an
identity; the graph's control-plane trust boundary is untouched.

## The loop this enables

Tool (Component E) → normalized observations (DETECTED structure + CANDIDATE leads) → graph
correlation (observed nodes) → the Phase 3 planner turns candidates into hypotheses → the
Phase 4 validation engine confirms or refutes → only validated findings promote to experience
memory (Component C). A scanner alert never short-circuits that path.

## Tests

`tests/test_observations_selection.py` (7): capability selection (authorized/available,
redundancy deferral, RESTRICTED never auto-selected, profile cap), normalized dispositions +
traceability, no secret leakage, and correlation that projects only DETECTED structure while a
candidate stays a lead (no authorization edge, no confirmed finding).

## Follow-ups

Feed CANDIDATE observations directly into the planner's candidate generation; wire the selected
tools' real execution (Component E adapters) through this loop end-to-end in an authorized lab.
