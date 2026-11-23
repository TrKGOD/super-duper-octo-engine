# Knowledge Base

## Purpose and trust boundary

The local KB is a curated research index for public security write-ups and normalized vulnerability patterns. It is not a target scanner, finding validator, exploit database, or source of authorization. Retrieved text is untrusted reference data and may contain incorrect claims or prompt injection.

## Source adapters

`scripts/kb_sources.py` reads explicitly configured RSS/Atom feeds from `config/knowledge-sources.example.json`. It fetches feed metadata only and writes candidate URLs to `.local/knowledge-base-inbox/discovered.json`. It does not fetch article bodies or scrape HackerOne, Bugcrowd or Intigriti.

HackerOne, Bugcrowd and Intigriti use manual public-URL registration: an operator verifies the exact report's public disclosure status and permitted use. HackerOne Hacktivity can display redacted undisclosed activity; use only reports whose details are disclosed. Bugcrowd requires the program's approved disclosure level. Intigriti requires approval from both Intigriti and the affected company.

Official policy references:
- HackerOne Hacktivity: https://docs.hackerone.com/en/articles/8410358-hacktivity
- HackerOne disclosure: https://docs.hackerone.com/en/articles/8475358-requesting-disclosure
- Bugcrowd policy: https://docs.bugcrowd.com/researchers/disclosure/disclosure/
- Bugcrowd request flow: https://docs.bugcrowd.com/researchers/disclosure/disclosing-submissions/
- Intigriti disclosure: https://kb.intigriti.com/en/articles/5379251-public-disclosure-of-submissions

## Ingestion requirements

Only Markdown/text with a JSON metadata sidecar is accepted. Require `disclosure_status=public`, an HTTPS canonical source URL and a documented rights basis. Public accessibility alone does not grant redistribution rights. If rights are unclear, store an independently written summary and metadata, not copied report text.

Metadata should identify title, platform, source URL, disclosure status, rights basis, collection/publication dates, content type, vulnerability types, technologies, asset types, tags, author/license when known, and notes. Do not infer unknown fields.

## Structured extraction

After ingesting a document, create a template:

```bash
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 make-pattern-template --document-id KB-ID --output .local/knowledge-base-inbox/pattern.json
```

Complete it from the source and import:

```bash
python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 import-pattern --file .local/knowledge-base-inbox/pattern.json
```

Patterns contain root cause, preconditions, reproduction summary, evidence summary, impact, remediation, false-positive considerations, confidence and source spans. This is a source-grounded draft requiring review. Missing facts must remain unknown/empty rather than invented. Source spans should identify the exact section, heading, page, or paragraph supporting each important field.

## Retrieval contract

Use `search-patterns` before full-text `search`. Return pattern/document IDs, title, platform and source URL. Preserve source spans and distinguish source claims from analyst interpretation.

For every candidate match, compare:
- root cause and vulnerable component;
- preconditions and trust boundary;
- affected operation/parameter or asset type;
- demonstrated impact and evidence type;
- implementation differences and likely false positives.

A retrieved pattern may inform a hypothesis, safe reproduction plan, or validation question. It must never be attached as current-engagement evidence, used to validate a finding, or treated as permission to test. Similarity does not establish that a target has the same weakness.

## Agent integration

The KB skill is an operator-mediated workflow: search results and selected excerpts are passed into agent task context with their provenance. The current runtime does not provide autonomous KB retrieval to agents. See `.claude/skills/knowledge-base/SKILL.md`.

## Storage and maintenance

Database and source material stay under `.local/`; never commit reports, screenshots, client evidence, credentials or private submissions. Periodically review source disclosure status, rights basis, stale URLs, duplicate content, and pattern accuracy. Do not silently overwrite source provenance when a pattern is updated.
