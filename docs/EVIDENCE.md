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

The `redacted` value is an operator assertion, not an automated inspection result. The specialist dispatcher accepts only evidence IDs already registered in the same engagement; it rejects invented IDs. A handoff artifact labelled `collected` or `redacted_copy` must match a registered evidence record by engagement, path and SHA-256. Proposed artifacts are never treated as collected proof.
Review and redact secrets, credentials, tokens, personal data, and client-sensitive
content **before** calling `capture`. A best-effort helper is available:

```bash
python scripts/redact_text_evidence.py --input .local/raw-capture.txt --output .local/redacted-capture.txt
```

The helper masks common token/header/credential patterns and email addresses, never
overwrites the source, and reports counts. It is not a complete secret/PII detector;
manual review is mandatory before marking the resulting artifact as redacted. This
release does not include content-type validation, malware scanning, encryption at
rest, retention or deletion policies, or immutable/WORM storage.

The vault uses filesystem checks suitable for a local single-operator workflow; it
is not a hardened multi-user evidence service. Do not expose the evidence directory
through a web server or commit its contents. Keep `.local/` excluded from version
control and review Git status before committing.


## Optional AES-256-GCM encryption at rest

The vault supports opt-in authenticated encryption. Generate a 32-byte key outside the repository:

\`\`\`bash
python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
\`\`\`

Set the resulting base64 value in the process environment as PENTEST_EVIDENCE_KEY before capturing or reading encrypted artifacts. The key is never stored in SQLite or beside the evidence. When configured, new captures are encrypted with AES-256-GCM using a fresh 96-bit nonce and engagement ID as associated data. The database records the algorithm and SHA-256 covers the stored ciphertext.

Without the key, ciphertext integrity can still be checked, but plaintext cannot be read or injected into specialist context. Losing the key makes encrypted evidence unrecoverable. Store it in an external secrets manager and back it up according to the engagement's key-management policy. This implementation does not provide KMS integration, key rotation, multi-key decryption, or automatic migration of existing plaintext artifacts. Encryption is opt-in; existing records remain marked as unencrypted.
