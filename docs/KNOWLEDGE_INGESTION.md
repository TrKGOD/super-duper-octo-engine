# Knowledge Ingestion

**Component A (part 1).** Status: `lab_verified`. Extends the existing Markdown/text
Knowledge Base (`scripts/knowledge_base.py`) to more formats and adds taxonomy references,
without replacing the KB, its schema, its provenance rules, or its untrusted-content
handling.

## What it adds

- **Multi-format extraction** (`core/knowledge/ingest.extract_text`): `text/plain`,
  `text/markdown`, `text/html`, `application/xhtml+xml`, `application/xml`/`text/xml`,
  `image/svg+xml`, `application/json`, and `application/jsonl`/`x-ndjson`. `application/pdf`
  is an explicitly optional extractor (not bundled, not used in CI) — it raises with
  guidance rather than pretending to support it. Unknown types are rejected.
- **Safe markup parsing**: HTML and XML are reduced to text by **tag-stripping only**
  (`html.parser`), with `<script>`, `<style>`, `<template>` and `<noscript>` contents dropped,
  comments never extracted, and **no DTD/entity resolution**, so untrusted markup cannot trigger
  entity expansion or XXE (`test_xml_entities_are_not_expanded`). A parser fault **fails closed**
  with `IngestError`; it never falls back to storing the raw markup.
- **Taxonomy references** (`core/knowledge/taxonomy`): CWE, CVE, OWASP (Top 10 + API Top 10),
  CAPEC and MITRE ATT&CK identifiers are extracted from the content by pattern, normalized to
  canonical forms, and persisted to a new `kb_references` table. Metadata cannot declare
  references: the document metadata schema rejects unknown keys, so only well-formed ids that
  appear in the text are recorded (and later projected into the graph).
- **Semantic index seam**: when an embedding backend (a callable `text -> vector`) is
  supplied, ingestion also stores a vector in `kb_embeddings`. Without one, nothing changes
  and the FTS baseline is used. The vector is validated before anything is written: 1–4096
  finite numbers, otherwise `IngestError`.

## Bounds and atomicity

Imported documents are untrusted input, so extraction is bounded **before** parsing:

| Bound | Value | Failure |
|---|---|---|
| document size | 2,000,000 bytes (the same ceiling as the Markdown/text path) | `IngestError` |
| metadata size | 64,000 bytes | `IngestError` |
| JSON nesting | 100 levels (a deeper document, including a recursion bomb, is rejected) | `IngestError` |
| JSON values | 200,000 per document (shared across all lines of a JSONL file) | `IngestError` |
| embedding | 1–4,096 finite dimensions | `IngestError` |

Ingestion is **all-or-nothing**: everything that can fail on external input (extraction, metadata
validation, the embedder) runs before the first write, and a failure while writing rolls the
whole document back, so a document is never left without its index, references or embedding.
The embedder is not called for a duplicate.

Only explicitly public material with a documented rights basis is accepted
(`disclosure_status=public`, HTTPS source, rights basis of at least eight characters). The
rights basis is the operator's attestation; nothing here can verify it.

## Retrieval of imported text

Both retrieval paths hand imported text to an agent only inside an `UNTRUSTED_KB_CONTENT`
block with directive-like lines escaped: the full-text path (`scripts/knowledge_base.search`) and the
embedding path (`KnowledgeRetriever.semantic_documents`, which previously returned titles and
source URLs raw). A corrupt stored vector is skipped instead of disabling semantic retrieval.
Retrieval results carry `trust="untrusted_knowledge"` and grant no authorization.

## What it reuses (not rebuilt)

- `knowledge_base.validate_meta` (JSON-schema metadata, HTTPS-only public source, documented
  rights basis), `sanitize_content`/`untrusted_block` (prompt-injection-escaping untrusted
  handling), `_index_document` (FTS indexing), and the `content_sha256` dedup — every
  ingested document still passes through all of them.
- The `kb_documents`/`kb_patterns` schema and the separate KB database (kept under `.local/`,
  distinct from engagement evidence).

## Provenance retained per document

Original source + URL, author/publication date when present, import timestamp, content hash,
document type, vulnerability/technology/asset tags, and the extracted CWE/CVE/OWASP/CAPEC/
ATT&CK references. Only explicitly public material with a documented rights basis is accepted.

## Security

Imported documents are **untrusted knowledge**, never instructions: content is sanitized and
fenced as `UNTRUSTED_KB_CONTENT`, directive-like lines are escaped, markup cannot resolve
entities, and ingestion confers no scope, identity, or authorization. The pipeline uses only
operator-provided content; it does not crawl platforms or bypass authentication/paywalls.

## Tests

`tests/test_knowledge_intelligence.py` covers HTML tag-stripping + script dropping, JSON/
JSONL/XML extraction, XXE-safety, taxonomy extraction + normalization, dedup, reference
lookup, and rejection of unsupported/PDF formats. `tests/test_kb_ingestion_safety.py` covers the
size, depth and value bounds, fail-closed markup handling, the public-only / rights gate (nothing is
stored on rejection), embedding validation and atomic rollback, and the untrusted wrapping of
semantic results. `tests/test_kb_sources.py` covers the research-feed discovery adapter.

## Research-feed discovery (`scripts/kb_sources.py`)

Metadata only, never article bodies. Feeds are fetched over HTTPS from a fixed host allow-list; a
redirect off the list is refused; the response is capped at 1 MB with a 10-second timeout; and a feed
containing a DTD or entity declaration is refused before parsing (it never needs one). Items are
written as `disclosure_status: review_required`, `content_downloaded: false`. The script's JSON
error path previously crashed with a `TypeError`; it now reports `{"error": ...}` and exits 2.
Not verified: behaviour against a real feed (no network was used) and DNS-level protections — the
allow-listed hosts are trusted to resolve to public addresses.
