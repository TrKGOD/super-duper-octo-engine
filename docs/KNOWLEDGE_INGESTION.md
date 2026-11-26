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
  (`html.parser`), with `<script>`/`<style>` contents dropped and **no DTD/entity
  resolution**, so untrusted markup cannot trigger entity expansion or XXE
  (`test_xml_entities_are_not_expanded`).
- **Taxonomy references** (`core/knowledge/taxonomy`): CWE, CVE, OWASP (Top 10 + API Top 10),
  CAPEC and MITRE ATT&CK identifiers are extracted from content and merged with operator
  metadata, normalized to canonical forms, and persisted to a new `kb_references` table.
- **Semantic index seam**: when an embedding backend (a callable `text -> vector`) is
  supplied, ingestion also stores a vector in `kb_embeddings`. Without one, nothing changes
  and the FTS baseline is used.

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
lookup, and rejection of unsupported/PDF formats.
