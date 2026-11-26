# Report Templates

**Component G, template reference.** The templates (`core/reporting/templates.py`) turn a
`ReportContext` into a structured dict that renderers consume. They carry a `template_version`
(`TEMPLATE_VERSION`, currently `1.0`), so a stored report stays interpretable as the schema
evolves. Every template shares a base of `report_type`, `template_version` and `engagement`
(with the authorization reference redacted), and every confirmed section is built **only** from
validated, integrity-verified findings.

## Shared limitations block

Every human-facing template carries a `limitations` list stating, in the report itself, that
hypotheses/observations/rejected/pending findings are not confirmed, that scanner candidates are
leads, that evidence integrity is re-verified at report time (failures excluded), and that
authorization/scope/policy must be confirmed separately by the operator.

## Templates

### `technical`
The full engineering report.

| Key | Meaning |
|---|---|
| `confirmed_findings` | validated, integrity-verified findings (title, severity, vulnerability class, asset/method/parameter, description, impact, preconditions, `validated_by`, validation record ids, per-evidence hashes) |
| `excluded_findings` | findings dropped at report time, each with a reason (e.g. failed evidence integrity) |
| `unvalidated` | `unvalidated_findings` + `candidate_observations` + a NOT-confirmed note |
| `confirmed_count` | `len(confirmed_findings)` |

### `executive`
The leadership summary — counts and headline risks, no raw evidence.

| Key | Meaning |
|---|---|
| `executive_summary` | one line: N independently validated findings in scope |
| `overall_posture` | `needs_attention` or `no_confirmed_findings` |
| `confirmed_by_severity` | severity → count, confirmed findings only |
| `key_risks` | top 5 confirmed findings (title, severity, asset) |
| `remediation_priorities` | finding ids of confirmed critical/high findings |

### `attack_surface`
What discovery mapped — `surface` holds `hosts` / `services` / `endpoints` / `routes` /
`parameters` / `technologies` (each item carries its graph **trust** tier), a `detected_observations`
count, and a `coverage_note` that discovery is not asserted complete.

### `tool_execution`
Tool activity and its honest yield.

| Key | Meaning |
|---|---|
| `tool_execution.workers` | `worker_executions` broker records (backend, status, cleanup, per-tool executions) |
| `tool_execution.by_tool` | per tool: `detected` / `candidates` / `errors` observation counts |
| `candidates_generated` | number of scanner candidates (leads, **not** findings) |
| `findings_confirmed` | number of independently validated findings |

The `candidates_generated` vs `findings_confirmed` split is deliberate: it shows how many leads a
tool produced against how many survived independent validation, without ever presenting the former
as the latter.

### `evidence_package`
A per-finding bundle for review/hand-off: for each confirmed finding, its `evidence` (ids, types,
SHA-256 hashes, redaction flag — references only, no bytes) and its `validation_records`. Integrity
is re-verified when the package is built.

## Formats per template

All templates render through every format in `FORMATS` (`json`, `markdown`, `html`, `sarif`).
`json` serializes the whole structured dict; `markdown`/`html` are human-readable; `sarif` emits
SARIF 2.1.0 `results` for confirmed findings only (so `attack_surface`/`tool_execution`, which have
no confirmed findings of their own, render an empty SARIF run rather than fabricating results). PDF
is produced by printing the HTML — it is not a bundled format (see
[REPORTING_ENGINE.md](REPORTING_ENGINE.md)).

## Adding a template

1. Add a `build_<name>(ctx) -> dict` that starts from `_base(ctx, "<name>")` and draws confirmed
   data **only** from `ctx.confirmed_findings()[0]`.
2. Register it in `BUILDERS`.
3. Extend each renderer's per-type branch in `core/reporting/render.py` if it needs bespoke
   human-readable output (JSON/SARIF need no change).
4. Add a case to `tests/test_reporting_engine.py`.

Bump `TEMPLATE_VERSION` on any change to an existing template's shape.
