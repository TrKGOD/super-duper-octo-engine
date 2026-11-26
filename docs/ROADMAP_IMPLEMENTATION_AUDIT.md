# Roadmap Implementation Audit

**Date:** 2026-11-25
**Audited revision:** `main` @ `e46f71e` (immediately after merging PR #25, "Complete scoped OIDC and Playwright authentication integration")
**Method:** Direct inspection of the repository tree, core modules, database schema/migrations, CI workflow, agent/skill definitions, tests, and PR #25's diff and CI history. No capability below is marked from documentation alone.

This document responds to the Master Engineering Roadmap directive. It verifies the *actual* implementation rather than trusting earlier architectural descriptions, classifies every roadmap capability, and proposes an implementation order. It is deliberately conservative: a prompt, Skill file, schema, or passing unit test does **not** by itself promote a capability.

---

## 1. Relationship to the existing roadmap

The repository already maintains [`docs/AUTONOMOUS_PLATFORM_ROADMAP.md`](AUTONOMOUS_PLATFORM_ROADMAP.md) with **Gates 0–6** and a four-level status vocabulary (`documented` → `implemented_unverified` → `lab_verified` → `production_ready`). The directive's **Phases 0–6** largely restate the same program under different names. This audit maps the directive's phases onto the existing gates to avoid creating a parallel, duplicate roadmap:

| Directive phase | Existing gate | Notes |
|---|---|---|
| Phase 0 — Authentication Manager | (new work; overlaps Gate 2 OAuth/OIDC/JWT) | Just advanced by PR #25 |
| Phase 1 — Browser Intelligence Engine | Gate 2 (browser automation) | Only auth-login browser exists today |
| Phase 2 — Attack Graph / Knowledge Graph | (new; overlaps Gate 4 memory) | No graph store today |
| Phase 3 — Adaptive Testing Planner | Gate 1 (adaptive orchestration) | Static DAG today, not adaptive |
| Phase 4 — Exploit Validation Engine | Gate 6 + existing validation | Adversarial review exists; deterministic oracles partial |
| Phase 5 — Isolated Execution Workers | Gate 3 (execution isolation) | Explicitly out of scope today |
| Phase 6 — Benchmark & Regression Lab | Gate 0 (measurement baseline) | Deterministic lab done; real-agent gated |

**Recommendation:** keep a single roadmap. Extend the existing gate vocabulary rather than introducing a second phase numbering in code or docs.

---

## 2. Existing architecture (verified)

A control/execution separation is already real, not aspirational:

- **Control plane:** `core/orchestration.py` (`Workflow`, deterministic plan validation, handoffs), `core/store.py` (`StateStore`, SQLite transactional lifecycle), `database/schema.sql` + migrations `002–008`.
- **Agent reasoning plane:** `.claude/agents/` (12 specialists + `orchestrator` + a preserved `model-1/orchestrator`), `core/llm_orchestrator.py` (tool-disabled plan generation), `core/dispatch.py` (specialist dispatch with injected Skill methodology), `core/model_router.py` (bounded escalation).
- **Execution plane:** `core/active_executor.py` (`ActiveHTTPExecutor`, scope-enforced HTTP broker with DNS-pinned connections, redirect blocking, response caps), `core/execution_policy.py` (RPS/concurrency leases), `hooks/command_guard.py` (PreToolUse allowlist).
- **Evidence & knowledge plane:** `core/evidence.py` (`EvidenceVault`, atomic writes + SHA-256), `core/evidence_contracts.py`, `core/evidence_scoring.py`, `core/evidence_adapters.py`, `knowledge-base/seed/` (public pattern seeds).
- **Evaluation plane:** `benchmarks/` (35 synthetic cases, positive/negative), `scripts/run_benchmark.py`, `scripts/evaluate_benchmark.py`, `scripts/compare_architecture_results.py`.

Key invariants are enforced deterministically and outside the LLM: scope/authorization checks live in `active_executor._resolve_and_authorize` and the new `core/auth/broker_transport.py`; the dispatcher fails closed when no Skill is selected; active tasks are never auto-replayed.

### Inventory snapshot
- **Core modules:** 33 under `core/` (incl. 10 under `core/auth/`).
- **Agents:** 13 definitions (12 specialists + orchestrator) plus the Model‑1 baseline.
- **Skills:** ~30 `SKILL.md` files under `.claude/skills/` (engagement-scope, recon, enumeration, validation, and a `web-testing/` family covering authn/authz/IDOR/SSRF/SQLi/XSS/OAuth‑JWT/etc.).
- **Scripts:** 32 under `scripts/` (dispatch, active_* executors, analyzers, benchmark, migrate, redaction).
- **Tests:** 35 files under `tests/`.
- **Migrations:** `schema.sql` + `002`–`008`.

---

## 3. Capability classification

Legend: **IMPLEMENTED** (code present, exercised by tests) · **PARTIAL** · **MISSING** · **BROKEN** · **NEEDS_SECURITY_REVIEW** · **NEEDS_INTEGRATION_TEST**. The repo's own maturity level (`implemented_unverified` / `lab_verified`) is given where it refines the picture.

### Phase 0 — Authentication Manager
| Capability | Status | Evidence |
|---|---|---|
| Manager lifecycle (register/auth/recover/revoke, challenge→pause) | IMPLEMENTED (`lab_verified`) | `core/auth/manager.py`; 403≠expiry, only 401 recovers; state-changing requests never auto-retried; `tests/test_authentication_manager.py`, `test_auth_plan_propagation.py` |
| Adapters: form, cookie, api_key, jwt, oauth2 | IMPLEMENTED (compact) | `core/auth/adapters/*` |
| OIDC strict ID‑token validation (RS256/ES256, iss/aud/azp/nonce/exp/iat/nbf, JWKS origin‑pinned, alg‑confusion & unsigned rejected) | IMPLEMENTED (`lab_verified`) | `core/auth/adapters/oidc.py` (post‑PR#25); real‑signature positive/negative tests in `tests/test_oidc_validation.py` |
| Browser (Playwright) form login — origin‑locked, headless, downloads/service‑workers blocked, challenge detection | IMPLEMENTED (`implemented_unverified` in CI) | `core/auth/playwright_runner.py`; `tests/test_playwright_auth_e2e.py` runs with an injected factory — real-browser E2E not exercised in CI |
| Engagement‑scoped broker transport for token/JWKS/discovery | IMPLEMENTED | `core/auth/broker_transport.py`; requires active engagement + `authentication-http` class + written auth ref; `tests/test_auth_broker_integration.py` |
| Encrypted session persistence / isolation / revocation | PARTIAL · NEEDS_SECURITY_REVIEW | `core/auth/session_store.py` (124 lines) + migration `006_evidence_encryption.sql`; confirm key provisioning is out‑of‑band and sessions are engagement+identity isolated under test |
| Secret handling (env‑reference only, never logged/persisted plaintext) | IMPLEMENTED | `AuthenticationManager._env_secret`; no‑secret‑leak assertions present — recommend an explicit redaction regression test across audit events |

**Phase 0 verdict:** substantially complete and the strongest-tested subsystem. Remaining: real-browser E2E (behind optional Playwright dep), an explicit session cross‑engagement‑isolation test, and a secret‑never‑persisted regression test. Document `AUTHENTICATION_MANAGER.md` exists but is thin (29 lines) and should be expanded to match the implementation.

### Phase 1 — Browser Intelligence Engine
| Capability | Status |
|---|---|
| Browser route/network/form discovery, normalization/dedup, coverage tracking, scope enforcement, identity comparison | IMPLEMENTED (`lab_verified`) — `core/browser/*`, `tests/test_browser_intelligence.py` (19 deterministic + 1 real-browser E2E). See `docs/BROWSER_INTELLIGENCE.md`. |
| Real Playwright driver (headless, origin-guarded) | IMPLEMENTED (`lab_verified` locally, skipped in CI without a browser binary) — `core/browser/playwright_driver.py`. |
| Workflow *execution* of safe flows; in-browser JS bundle route extraction; surface persistence to store/graph | MISSING — follow-up (PR C). |
| Static JS route/sink analysis (non-browser) | PARTIAL — `scripts/active_surface.py` (`_analyse_js`, regex route/sink indicators). |

### Phase 2 — Attack Graph / Knowledge Graph
| Capability | Status |
|---|---|
| Typed entity/edge graph over SQLite (migration `009`), trust-tiered provenance, deterministic dedup, cross-engagement isolation | IMPLEMENTED (`lab_verified`) — `core/graph/{schema,store,ingest,paths,query}.py`, `tests/test_attack_graph.py`. See `docs/ATTACK_GRAPH.md`. |
| Authorization trust boundary (untrusted data cannot assert authorization or invent identities) | IMPLEMENTED (`lab_verified`) — enforced at store + ingestion; tested. |
| Attack-path reasoning (BOLA/IDOR, BFLA) + planner query interface | IMPLEMENTED (`lab_verified`) — `propose_attack_paths`, `GraphQuery`. |
| Findings/evidence lifecycle edges from the validation engine; planner wiring | MISSING — follow-up (Phases 3–4). |

### Phase 3 — Adaptive Testing Planner
| Capability | Status |
|---|---|
| Static plan generation + DAG dispatch | IMPLEMENTED — `core/llm_orchestrator.generate_plan`, `core/dispatch.dispatch_plan`, `tests/test_enumeration_first_pipeline.py`. |
| Bounded adaptive loop (observe→hypothesize→select→execute→update), typed hypothesis objects, transparent prioritization scoring, redundancy control | IMPLEMENTED (`lab_verified`) — `core/planner/*` (migration `010`), `tests/test_adaptive_planner.py` proves results change next selection within budget and the policy layer blocks scope/identity/class violations (incl. LLM proposals). See `docs/ADAPTIVE_TESTING_PLANNER.md`. |
| Planner execution wired through the broker + independent validation | MISSING — executor is a seam today (follow-up, Phase 4). |

### Phase 4 — Exploit Validation Engine
| Capability | Status |
|---|---|
| Independent adversarial validation (proposer ≠ validator), bounded disproof | IMPLEMENTED — `core/adversarial_validation.py`, `core/finding_validation.py`, `validation-agent`; `tests/test_*` cover review. |
| Deterministic validators (authz differential, object ownership, reflected input, header/config) | IMPLEMENTED (`lab_verified`) — `core/validation_engine/` unifies the analyzers behind one SUPPORTED/REFUTED/INCONCLUSIVE contract with tamper-evident records. See `docs/EXPLOIT_VALIDATION.md`. |
| Finding lifecycle + retest | IMPLEMENTED (`lab_verified`) — `FindingValidator` drives the existing state machine; safe FIX_VERIFIED/STILL_PRESENT retest tested; confirmed-only reporting. |

### Phase 5 — Isolated Execution Workers
| Capability | Status |
|---|---|
| Worker manager, tool registry, resource/output/timeout bounds, per-engagement artifact isolation, observability, cleanup | IMPLEMENTED (`lab_verified`) — `core/workers/*` (migration `012`), `tests/test_isolated_workers.py`. See `docs/ISOLATED_EXECUTION.md`. |
| Hardened container backend (read-only, cap-drop, no-new-privileges, pids/memory/cpu, no privileged, no docker socket) | IMPLEMENTED, command-level tested; **runtime isolation NOT exercised in CI** (no Docker) — the container backend is the real isolation boundary. |
| Egress/DNS enforcement, concrete container runtime in CI, mid-run cancellation | MISSING — follow-up. The subprocess backend is explicitly **not** a sandbox; untrusted tools require the container backend + host controls. |

### Phase 6 — Benchmark & Regression Lab
| Capability | Status |
|---|---|
| Deterministic regression lab over the real graph→planner→validation pipeline; precision/recall/F1/coverage/cost; reproducibility; regression gate | IMPLEMENTED (`lab_verified`) — `core/benchmark/*`, `scripts/run_regression_benchmark.py`, `tests/test_benchmark_regression.py`. CI-safe (no live targets, no model). See `docs/BENCHMARK_LAB.md`. |
| Real-agent corpus + runner (gated) | IMPLEMENTED (`implemented_unverified`) — `benchmarks/cases/*` (35), `scripts/run_benchmark.py`, `scripts/evaluate_benchmark.py`; gated behind `vars.CLAUDE_BENCHMARK_MODEL` (correctly *skipped*, not failed). |
| External benchmark (XBEN etc.) integration | MISSING — not integrated; license/repro review required first. |

### Cross-cutting
| System | Status |
|---|---|
| Evidence store (IDs, type, SHA-256, redaction, retention) | IMPLEMENTED — `core/evidence.py`, migrations `005/006`, `scripts/redact_text_evidence.py`. |
| Coverage tracker | PARTIAL — `core/subsystem_coverage.py` tracks inventory progress; not yet route/endpoint/identity/workflow granular. |
| Audit/observability | IMPLEMENTED — `audit_events` table + audit callbacks throughout auth/broker. |
| Tool registry | PARTIAL — `config/tools.json`, `.claude/skills/registry.json`, `scripts/validate_agent_tools.py` enforce allowlists; no per-tool risk/timeout/output-limit schema object yet. |
| Migrations/rollback | IMPLEMENTED (forward) — `scripts/migrate.py` + numbered SQL; no explicit down-migrations. |

---

## 4. Security-sensitive code & invariants to preserve

- `core/active_executor.py` — scope resolution, DNS pinning, redirect/size caps. **Do not** route new network features around this.
- `core/auth/broker_transport.py` — the only sanctioned auth network path; preserve the active-engagement + written-authorization gate.
- `hooks/command_guard.py` — PreToolUse allowlist; specialists get no raw shell/network.
- `core/execution_policy.py` — RPS (hard max 5) + single concurrency + leases.
- Untrusted-data boundary: HAR/OpenAPI/HTML/JS/tool output must never mutate scope, policy, or authorization (CLAUDE.md rule; `scripts/ingest_har.py`, `tests/test_har_and_write_gates.py`).

**NEEDS_SECURITY_REVIEW:** session key provisioning/rotation (`session_store.py`); confirm no token/secret reaches `audit_events`, evidence, or task payloads (the auth modules are written to avoid this — add an explicit regression test).

---

## 5. Known limitations

- No execution sandbox/isolation (Gate 3 / Phase 5) — stated honestly in docs.
- No browser *intelligence* (only auth login) — Phase 1.
- No engagement attack graph — Phase 2.
- No adaptive planning loop — Phase 3 / Gate 1.
- Real-browser and real-agent paths are gated/optional and unproven in CI.
- `docs/AUTHENTICATION_MANAGER.md` under-describes the shipped implementation.

---

## 6. Dependencies between missing capabilities

```
Phase 1 (Browser Intelligence) ──┐
                                 ├─▶ Phase 2 (Attack Graph) ─▶ Phase 3 (Adaptive Planner) ─▶ Phase 4 (Validation Engine unification)
Enumeration output ──────────────┘                                   ▲
Phase 6 (Benchmark Lab, Gate 0) ──────────────────────────────────────┘ (measures all of the above)
Phase 5 (Isolated Workers) ── independent; required before expanding active tool surface
```

- The graph (Phase 2) needs real discovered surface (Phase 1 + existing enumeration) to be meaningful.
- The adaptive planner (Phase 3) needs the graph (Phase 2) to query "what's undertested / what differs between identities."
- The benchmark lab (Phase 6) should be strengthened early so later phases are measured, not asserted.
- Isolated workers (Phase 5) is independent and should land before any broader active-tool surface.

---

## 7. Recommended implementation order

1. **Phase 0 close-out (small):** expand `AUTHENTICATION_MANAGER.md`; add session cross-engagement isolation test + secret-non-persistence regression test; document real-browser E2E as optional/unverified. *(Low risk, high clarity.)*
2. **Phase 6 first slice (Gate 0):** lock a reproducible deterministic benchmark smoke that runs in CI without live targets, so subsequent phases are measurable.
3. **Phase 1 — Browser Intelligence Engine:** new `core/browser/` with route/network/form/workflow discovery + coverage, reusing the auth runner's origin-guard and the broker's scope model. Largest build; its own PR series.
4. **Phase 2 — Attack Graph:** typed entities/edges over the existing SQLite store (no graph DB) with provenance; query interface for the planner.
5. **Phase 3 — Adaptive Planner (Gate 1):** bounded typed-hypothesis loop layered over persisted DAG tasks; keep Model‑1 untouched.
6. **Phase 4 — Validation Engine:** unify existing analyzers behind one disposition contract (SUPPORTED/REFUTED/INCONCLUSIVE) + retest flow.
7. **Phase 5 — Isolated Execution Workers (Gate 3):** container/worker + egress/quotas, documented threat model and residual risk.

---

## 8. Files/modules expected to change per phase

- **P0 close-out:** `docs/AUTHENTICATION_MANAGER.md`, `tests/test_authentication_manager.py`, new `tests/test_auth_session_isolation.py`.
- **P6:** `scripts/evaluate_benchmark.py`, `tests/test_benchmark*.py`, `.github/workflows/ci.yml` (deterministic smoke only).
- **P1:** new `core/browser/*`, `tests/test_browser_*`, `docs/BROWSER_INTELLIGENCE.md`; synthetic local apps under a new fixtures dir.
- **P2:** new `core/graph/*` + migration `009_attack_graph.sql`, `tests/test_attack_graph.py`, `docs/ATTACK_GRAPH.md`.
- **P3:** new `core/planner/*`, `tests/test_adaptive_planner.py`, `docs/ADAPTIVE_TESTING_PLANNER.md`.
- **P4:** `core/validation.py`/`finding_validation.py` unification, `docs/EXPLOIT_VALIDATION.md`.
- **P5:** new `core/workers/*`, `docs/ISOLATED_EXECUTION.md`.

---

## 9. Phase 0 completion record

PR **#25** ("Complete scoped OIDC and Playwright authentication integration") was inspected diff‑by‑diff and merged to `main` (squash `e46f71e`) after independent verification:
- Required CI `test` job **passed** on the exact head commit `78169a78`; `agent-benchmark` correctly **skipped** (gated behind a repo variable, never run in ordinary CI).
- OIDC code performs real RS256/ES256 signature verification via `cryptography`, rejects `alg:none`/HS256 confusion, pins JWKS to the issuer origin, and validates iss/aud/azp/nonce/exp/iat/nbf.
- Tests use genuinely signed JWTs with negative cases (bad signature, wrong issuer/audience/nonce, expired, discovery mismatch) — not mocks.

This satisfies the directive's Phase 0 merge criterion. Remaining Phase 0 items are the close-out tasks in §7.1.
