# Intelligence Layer Audit

**Date:** 2026-11-26
**Audited revision:** `main` @ `6e9eae6` (after the previous roadmap's Phases 0–6 merged)
**Scope:** The Intelligence Layer program — Knowledge Base/RAG, write-up intelligence, Knowledge Graph integration, Validated Experience Memory, Tool Registry & Adapters, agent-to-tool integration, normalized observations, reporting engine, and intelligence-layer benchmarking.

This audit maps the program onto the **actual repository** so nothing already built is rebuilt. It was produced by inspecting the code, not the file names. Several components the directive asks for already exist in whole or part from the previous roadmap and the pre-existing codebase; those are called out as `NEEDS_INTEGRATION`/`PARTIALLY_IMPLEMENTED` with their exact integration points.

## 0. What already exists (do not rebuild)

| Area | Where | Reuse as |
|---|---|---|
| Knowledge Base + FTS | `scripts/knowledge_base.py` (336 lines): `kb_documents`/`kb_patterns` + FTS5 (`kb_search`, `kb_pattern_search_v2`), HTTPS-only public-source provenance, `content_sha256` dedup, JSON-schema metadata (`templates/knowledge-document.schema.json`), seed import | the KB substrate to extend (ingestion + retrieval) |
| Untrusted-content handling | `knowledge_base.sanitize_content` / `untrusted_block` — escapes prompt-injection directive text, wraps in `UNTRUSTED_KB_CONTENT` fence | the untrusted-data boundary for RAG |
| Seed patterns | `knowledge-base/seed/*.md` + `manifest.json` (web-api, mobile-cloud, active-directory) | initial corpus |
| Attack/Knowledge Graph | `core/graph/` (nodes/edges, trust tiers `control_plane`>`observed`>`inferred`, provenance, `GraphQuery`, `propose_attack_paths`) | the canonical engagement graph (§3) — **do not create a second graph** |
| Tool Registry (partial) | `core/workers/tools.py` (`ToolRegistry`, `ToolSpec`: params, permissions, network, risk, timeout, output limit; injection-safe argv) | extend, don't replace (§5) |
| Isolated execution / broker | `core/workers/manager.py` (`WorkerManager`), `core/workers/backends.py`, `core/active_executor.py` (scope-enforcing HTTP broker) | the only sanctioned execution path for tools (§5.2) |
| Validation engine + dispositions | `core/validation_engine/` (SUPPORTED/REFUTED/INCONCLUSIVE, tamper-evident records, finding lifecycle) | the disposition vocabulary (§7) and the promotion gate (§4) |
| Evidence vault + scanner adapters | `core/evidence.py`, `core/evidence_adapters.py` (`import_sarif`, `import_zap_json`, `import_burp_xml`), `scripts/import_scanner_evidence.py` | evidence persistence + importers (§7/§8) |
| Reporting | `scripts/render_report.py` (validated-findings report with integrity), `core/evidence_contracts.py` | extend into the reporting engine (§8) |
| Benchmark lab | `core/benchmark/` (deterministic pipeline benchmark), gated real-agent `scripts/run_benchmark.py` | extend with retrieval/tool-selection/report metrics (§9) |
| Browser Intelligence | `core/browser/` | **reuse**; do not create a second browser engine (§5C) |

**Important architectural fact:** the KB is a **separate SQLite database** (kept under `.local/`, per `CLAUDE.md`), distinct from the engagement state DB (`graph_nodes`, `evidence`, `findings`, …). This separation is deliberate (public research must never be confused with current-target evidence) and **must be preserved**: §3 bridges the two with provenance + trust level, it does not merge them.

## 1. Component classification

| # | Component (directive §) | Status | Integration point / gap |
|---|---|---|---|
| 1 | Security KB & RAG engine (§2) | PARTIALLY_IMPLEMENTED | FTS KB + provenance + dedup + untrusted handling exist. Missing: multi-format ingestion (PDF/HTML/JSON/JSONL/XML/SARIF — currently Markdown/text only), CWE/CVE/OWASP/CAPEC/ATT&CK reference fields, semantic/embedding retrieval, and a retrieval API object. |
| 2 | Bug-bounty / write-up intelligence (§2.2) | PARTIALLY_IMPLEMENTED · NEEDS_SECURITY_REVIEW | `kb_patterns` is the structured write-up representation; `import_pattern`/`import_seed` populate it manually. Missing: structured extraction from a document into a pattern. Must use official APIs/permitted sources only, never crawl or bypass paywalls/anti-bot (§2.2, §10). |
| 3 | Knowledge Graph integration (§3) | NEEDS_INTEGRATION | Graph exists; no KB↔graph bridge. Must add KB-pattern / CWE / technique / tool nodes with provenance and an **`inferred`/knowledge** trust level, and never let KB content create authorization edges or identities. |
| 4 | Validated Experience Memory (§4) | MISSING | No experience module/table. Must promote **only** independently validated findings (reuse `validation_engine`), store no secrets, and never turn past success into permission. |
| 5 | Tool Registry & Adapter Framework (§5) | PARTIALLY_IMPLEMENTED · NEEDS_INTEGRATION | `core/workers/tools.ToolSpec/ToolRegistry` exists but lacks category, capabilities, vulnerability classes, adapter, parser, evidence-extraction, and **execution profiles** (PASSIVE/SAFE/ACTIVE_CONTROLLED/RESTRICTED). Adapters must execute through `WorkerManager`/broker, never a raw shell. |
| 6 | Agent-to-tool intelligence (§6) | MISSING | No capability-request interface or deterministic tool-selection engine. Orchestrator/agents exist; wire a `capability → tool` selector that respects scope/approval/profile. |
| 7 | Normalized observation & evidence model (§7) | PARTIALLY_IMPLEMENTED | Evidence vault + adapters + validation dispositions exist. Missing: a unified **observation** record (table) with dispositions DETECTED/CANDIDATE/SUPPORTED/REFUTED/INCONCLUSIVE/ERROR and tool→graph correlation. |
| 8 | Reporting engine (§8) | PARTIALLY_IMPLEMENTED | `render_report.py` emits a validated-findings report; SARIF/ZAP/Burp **import** exist. Missing: multi-format output (HTML/PDF/SARIF-export/JSON), report templates (executive / technical / attack-surface / API / tool-execution), evidence package, and **Nessus** import. |
| 9 | Intelligence-layer benchmarking (§9) | PARTIALLY_IMPLEMENTED | `core/benchmark/` scores the detection pipeline. Missing: retrieval-quality, tool-selection, and reporting-quality metrics. |
| 10 | Security & reliability invariants (§10) | IMPLEMENTED (to preserve) | Scope/broker/untrusted-data/validation invariants are enforced today; every new component must preserve them and add none of its own authority. |

## 2. Non-negotiable integration constraints

- **Tool Registry is not an execution bypass.** Every adapter runs through `WorkerManager` (Phase 5) and, for HTTP, the `active_executor` broker. No adapter gets a raw shell; arguments use the injection-safe argv substitution already in `ToolSpec.build_argv`.
- **KB/RAG is not an authorization system.** Retrieved knowledge is untrusted context with provenance; it never grants scope, identity, or permission.
- **Experience Memory is not permission.** Only `validation_engine`-confirmed findings promote; a past success never authorizes a repeat on a new engagement.
- **Graph trust boundary preserved.** KB/write-up/tool-derived nodes are `observed`/`inferred` with provenance; they can never assert `control_plane` authorization edges (`core/graph/schema.ensure_authorization_trust` already enforces this).
- **Disposition honesty.** DETECTED/CANDIDATE are never confirmed findings; promotion to a finding goes through independent validation.

## 3. Recommended implementation order (Components A–H, each its own PR)

1. **A — Knowledge Intelligence (RAG):** extend `knowledge_base.py` ingestion (formats + CWE/CVE/OWASP refs); add a retrieval API (`core/knowledge/`) with FTS baseline + optional embedding backend + contextual, per-agent retrieval. *(Largest; keep the FTS baseline always functional.)*
2. **B — Knowledge Graph integration:** `core/knowledge/graph_bridge.py` — KB pattern/CWE/technique/tool nodes + provenance edges, preserving trust tiers; graph-assisted retrieval queries.
3. **C — Validated Experience Memory:** `core/experience/` + migration `013`; promotion from validated findings; similarity retrieval; lifecycle (promote/review/deprecate/version).
4. **D — Tool Registry extension:** extend `core/workers/tools.ToolSpec` (category, capabilities, vuln classes, execution profile, adapter, parser) + an adapter contract + profiles; registry APIs.
5. **E — Initial tool adapters:** a small, tested subset across recon/enumeration/web/API/validation — each with parser/schema/permission/scope/timeout/output tests and a synthetic integration test. Honest availability status; no fabricated integrations.
6. **F — Agent integration:** capability-request interface + deterministic tool-selection engine; normalized observations fed back to the graph.
7. **G — Reporting engine:** `core/reporting/` — normalized inputs, versioned templates, MD/HTML/PDF/SARIF/JSON outputs, evidence package; add Nessus import.
8. **H — Benchmarking:** extend `core/benchmark/` with retrieval, tool-selection, and reporting metrics + regression gates.

## 4. Expected files per component (new unless noted)

- **A:** `core/knowledge/{__init__,ingest,retrieval,taxonomy}.py` (+ extend `scripts/knowledge_base.py`), `docs/KNOWLEDGE_INGESTION.md`, `docs/RAG_ARCHITECTURE.md`.
- **B:** `core/knowledge/graph_bridge.py`, `docs/KNOWLEDGE_GRAPH_INTEGRATION.md`.
- **C:** `core/experience/*`, `database/migrations/013_experience_memory.sql`, `docs/VALIDATED_EXPERIENCE_MEMORY.md`.
- **D:** extend `core/workers/tools.py` + `core/tools/{registry,adapters,profiles}.py`, `docs/TOOL_REGISTRY.md`, `docs/TOOL_ADAPTER_DEVELOPMENT.md`, `docs/TOOL_EXECUTION_POLICIES.md`.
- **E:** `core/tools/adapters/*`, a tool-catalog doc with honest per-tool status.
- **F:** `core/tools/selection.py` + orchestration wiring; `database/migrations/014_tool_observations.sql`.
- **G:** `core/reporting/*` (+ extend `scripts/render_report.py`, `core/evidence_adapters.py`), `docs/REPORTING_ENGINE.md`, `docs/REPORT_TEMPLATES.md`.
- **H:** extend `core/benchmark/`, `docs/BENCHMARKING.md`.

## 5. Acceptance criteria mapping (§13)

The end-to-end flow the directive requires maps cleanly onto the plan: import knowledge (A) → ingest a write-up + extract patterns (A) → retrieve for a task (A) → connect to the graph (B) → retrieve a validated experience (C) → request a capability + select an authorized tool (D/F) → execute through the broker (D + Phase 5) → normalize output + correlate to graph (F/§7) → create a hypothesis (Phase 3 planner) → independently validate (Phase 4) → promote only validated results to experience (C) → generate technical + executive reports + SARIF/JSON + evidence package (G) → evaluate with the benchmark (H). Each step already has a home or a defined new module; none requires a second graph, a second browser, or an execution path around the broker.
