# Finding lifecycle, duplicate triage and reporting

## Lifecycle

The persisted finding state machine separates observations, hypotheses, validation-pending candidates, independently validated findings, rejected candidates, and reported/resolved states. A proposing agent cannot validate its own finding. A validated/reported finding requires at least one evidence reference.

Specialist handoffs remain task outputs. They do not automatically promote hypotheses to validated findings. An operator or an explicit workflow step must persist a finding and route it to a distinct validation identity.

## Evidence readiness

`core/evidence_scoring.py` calculates a transparent 0–100 evidence-readiness score from integrity, request/response pairing, independent validation metadata, reproduction notes, screenshot presence, and finding metadata.

The score is **not** a vulnerability confidence score and does not change finding state. It does not prove exploitability, impact, authorization, or completeness.

## Duplicate triage

```bash
python scripts/dedupe_findings.py --db .local/state.sqlite3 --engagement-id ENG-ID --threshold 0.72
```

The script compares normalized asset, method and parameter values plus title/description similarity. It returns possible duplicate pairs for operator review. It never merges, deletes, rejects, or changes finding state.

## Report rendering

```bash
python scripts/render_report.py \
  --db .local/state.sqlite3 \
  --engagement-id ENG-ID \
  --project-root . \
  --output .local/reports/ENG-ID.md
```

Only persisted `validated` or `reported` findings are eligible. Every evidence reference is rechecked against its stored SHA-256 at render time. Findings with missing, unregistered, or tampered evidence are excluded and listed separately. Authorization references are not printed.

The report renderer is deterministic. It does not create findings, change statuses, or substitute for a human review before delivery.
