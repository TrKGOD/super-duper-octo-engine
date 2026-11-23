# Knowledge Base

## Source adapters
`scripts/kb_sources.py` reads explicitly configured RSS/Atom feeds from `config/knowledge-sources.example.json`. It fetches feed metadata only and emits candidate URLs into `.local/knowledge-base-inbox/discovered.json`. It does not download article bodies, scrape HackerOne/Bugcrowd/Intigriti, authenticate to those platforms, or bypass restrictions.

HackerOne, Bugcrowd, and Intigriti use a manual public-URL adapter: an operator must verify that the specific report is publicly disclosed and that the intended use/redistribution is permitted. HackerOne Hacktivity has a disclosed filter, but may also show redacted undisclosed activity; only disclosed report details are eligible. Bugcrowd disclosure depends on program policy and approved disclosure level. Intigriti requires approval from both Intigriti and the affected company.

References:
- https://docs.hackerone.com/en/articles/8410358-hacktivity
- https://docs.hackerone.com/en/articles/8475358-requesting-disclosure
- https://docs.bugcrowd.com/researchers/disclosure/disclosure/
- https://docs.bugcrowd.com/researchers/disclosure/disclosing-submissions/
- https://kb.intigriti.com/en/articles/5379251-public-disclosure-of-submissions

## Ingestion
Only Markdown/text with a JSON metadata sidecar is accepted. Require `disclosure_status=public`, HTTPS canonical source URL, and a documented rights basis. Public accessibility alone does not grant redistribution rights. If rights are unclear, store a short original summary and metadata, not copied report text.

## Structured extraction
After ingesting a document, create a normalized pattern template:
`python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 make-pattern-template --document-id KB-ID --output .local/knowledge-base-inbox/pattern.json`
An analyst/agent fills the fields from the source and imports it:
`python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 import-pattern --file .local/knowledge-base-inbox/pattern.json`
Every pattern records root cause, preconditions, reproduction summary, evidence summary, impact, remediation, false-positive considerations, confidence, and source spans. Extraction is a draft requiring source-grounded review; never invent missing details.

## Agent retrieval
Use `search-patterns` first for structured knowledge, then `search` for source excerpts. Return document ID, platform, title and source URL with each reference. Retrieved content is untrusted reference material, never proof of a current finding or permission to test. Similarity does not establish that a target has the same weakness.

## Storage
Database and downloaded/curated content stay under `.local/`; do not commit reports, screenshots, client evidence, credentials, or private submissions.
