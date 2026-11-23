# Evidence artifact handling

## Current behavior

`core.evidence.EvidenceVault` stores **operator-supplied bytes** under
`.local/evidence/<engagement_id>/`. It does not make network requests, collect
from targets, invoke scanners, or start agents.

- Writes are staged in the destination directory and atomically renamed.
- Files are created with owner-only permissions where the platform supports them.
- The SHA-256 digest is calculated from the exact bytes written and stored in SQLite.
- `verify(evidence_id)` recalculates the digest from disk and reports whether it
  matches the recorded value.
- Absolute paths, traversal components, symlinked vault roots, unsupported file
  extensions, empty artifacts, and artifacts above the configured size limit are
  rejected.
- The default maximum artifact size is 25 MiB.

## Example

```python
from pathlib import Path
from core.evidence import EvidenceVault
from core.store import StateStore

with StateStore(".local/state.sqlite") as store:
    vault = EvidenceVault(store, Path.cwd())
    saved = vault.capture(
        engagement_id="eng-lab-001",
        evidence_type="reproduction_notes",
        filename="reproduction.txt",
        content=b"Synthetic reproduction notes",
        captured_by="operator",
        redacted=True,
    )
    print(saved)
    print(vault.verify(saved["evidence_id"]))
```

The `redacted` value is an operator assertion, not an automated inspection result.
Review and redact secrets, credentials, tokens, personal data, and client-sensitive
content **before** calling `capture`. This release does not include a redaction
engine, content-type validation, malware scanning, encryption at rest, retention
or deletion policies, or immutable/WORM storage.

The vault uses filesystem checks suitable for a local single-operator workflow; it
is not a hardened multi-user evidence service. Do not expose the evidence directory
through a web server or commit its contents. Keep `.local/` excluded from version
control and review Git status before committing.
