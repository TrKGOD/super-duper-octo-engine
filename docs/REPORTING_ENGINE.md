# Reporting Engine

**Component G.** Status: `lab_verified`. Turns persisted engagement state into technical,
executive, attack-surface, tool-execution and evidence-package reports in Markdown, HTML, JSON
and SARIF. It reuses the existing validated-findings gate and the evidence vault: **only
independently validated, integrity-verified findings appear in confirmed sections**; unvalidated
findings and scanner candidates are kept separate and never presented as confirmed.

## Pipeline

```
ReportContext (normalize state) -> template builder (structured dict) -> renderer (MD/HTML/JSON/SARIF)
```

`ReportingEngine(store, project_root)` is the entry point:

- `report_types()` → the five supported types.
- `build(report_type, engagement_id)` → the structured report dict (template applied).
- `render(structured, fmt)` → a string in the chosen format.
- `generate(report_type, engagement_id, fmt)` → build + render in one call.

Unknown report types and unknown formats raise `ReportingError`. `FORMATS` is
`("json", "markdown", "html", "sarif")`.

## Normalized inputs (`core/reporting/context.py`)

`ReportContext` gathers exactly what a report needs from SQLite — nothing is recomputed in a
template or a renderer:

- `engagement()` — id, status and scope. The **authorization reference is always `[REDACTED]`**;
  it is never emitted in any report or format.
- `confirmed_findings()` → `(included, excluded)`. Only findings in status
  `validated` / `reported` / `resolved` are considered, and each one's evidence integrity is
  **re-verified at report time** via `EvidenceVault.verify(...)["valid"]`. A finding with no
  evidence, or any evidence that fails the hash check, is moved to `excluded` (with a reason) and
  never appears in a confirmed section. The included shape carries the finding's
  independently-SUPPORTED vulnerability class, `validated_by`, validation record ids, and
  per-evidence `{evidence_id, type, sha256, redacted, integrity_verified}` — references and
  hashes only, never evidence bytes.
- `unvalidated()` — findings still in `observation` / `hypothesis` / `validation_pending` /
  `needs_more_evidence`, plus `CANDIDATE` scanner observations, under an explicit
  "NOT confirmed vulnerabilities" note.
- `attack_surface()` — `host` / `service` / `endpoint` / `route` / `parameter` / `technology`
  graph nodes (with their trust tier) and a count of `DETECTED` observations, under a
  coverage-is-not-complete note.
- `tool_execution()` — `worker_executions` broker records plus observation counts grouped by tool
  (`detected` / `candidates` / `errors`).

## Confirmed-only guarantee

The confirmed sections of every template are built **solely** from `confirmed_findings()[0]`.
Candidates and unvalidated findings are carried only in the separate `unvalidated` block or as
counts. Concretely, this preserves non-negotiable rules 7–9 and the Component C/Phase 4 chain:

- A scanner alert (nuclei/dalfox → `CANDIDATE`) can never reach a confirmed section — it is a
  lead, counted under `candidates_generated`, nothing more.
- A finding the proposer validated but whose evidence no longer verifies is **excluded**, not
  downgraded silently — report-time integrity is independent of the stored status.
- SARIF `results` are emitted only for confirmed findings, so machine consumers inherit the same
  gate as the human-readable report.

## Formats (`core/reporting/render.py`)

Rendering is pure (no I/O) and escapes untrusted text.

| Format | Purpose | Notes |
|---|---|---|
| `json` | full structured report | deterministic (`sort_keys`), machine-readable |
| `markdown` | human-readable report | confirmed findings, evidence hashes, limitations |
| `html` | printable report | escaped Markdown in `<pre>`; **PDF is produced by printing this** |
| `sarif` | CI / code-scanning ingest | SARIF 2.1.0, confirmed findings only |

**PDF is intentionally not a bundled format.** No headless renderer is vendored, so the engine
does not pretend to emit PDF; operators print the HTML to PDF. `render(..., "pdf")` raises
`ReportingError` and says so, rather than returning a broken or empty document.

## Vulnerability-scanner import (`core/evidence_adapters.py`)

`import_nessus(vault, engagement_id, xml_bytes, captured_by, redacted=True)` adds Nessus
(`.nessus`) to the existing SARIF / ZAP / Burp import adapters. Like the others it:

- **requires `redacted=True`** (raises `EvidenceAdapterError` otherwise) — scanner output is
  redacted before ingestion;
- captures each `ReportItem` as a `scanner_output` evidence artifact (raw output stays an
  artifact reference, never inlined into a finding);
- normalizes each item to `status="hypothesis"`, `proposed_by="vuln-scan-import-adapter"`, with
  the Nessus numeric severity mapped to `info/low/medium/high/critical`.

Imported scanner items are **hypotheses, never validated** — they still have to pass independent
validation before any reporting path will treat them as confirmed.

## Tests

`tests/test_reporting_engine.py` (9): technical report separates confirmed findings from scanner
candidates; executive summary and severity roll-up; attack-surface and tool-execution reports;
evidence package; all four renderers (Markdown contains the finding, HTML wraps it, JSON is valid
and keeps the confirmed count, SARIF is 2.1.0 with the confirmed finding's rule); **tampered
evidence is excluded from confirmed at report time**; unknown type/format raise; Nessus imports as
a hypothesis and requires redaction.

## Follow-ups

Wire `tool_execution` to richer broker telemetry once more real adapters run end-to-end; add a
diff/retest report over the finding lifecycle's `retest_pending` → `resolved` transition.
