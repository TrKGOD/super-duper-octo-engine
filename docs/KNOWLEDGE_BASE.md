# Knowledge Base

## Source adapters
`scripts/kb_sources.py` reads explicitly configured RSS/Atom feeds from `config/knowledge-sources.example.json`. It fetches feed metadata only and writes candidate URLs to `.local/knowledge-base-inbox/discovered.json`. It does not fetch article bodies or scrape HackerOne, Bugcrowd or Intigriti.

HackerOne, Bugcrowd and Intigriti use manual public-URL registration: an operator verifies the exact report's public disclosure status and permitted use. HackerOne Hacktivity can display redacted undisclosed activity; use only reports whose details are disclosed. Bugcrowd requires the program's approved disclosure level. Intigriti requires approval from both Intigriti and the affected company.

Official policy references:
- HackerOne Hacktivity: https://docs.hackerone.com/en/articles/8410358-hacktivity
- HackerOne disclosure: https://docs.hackerone.com/en/articles/8475358-requesting-disclosure
- Bugcrowd policy: https://docs.bugcrowd.com/researchers/disclosure/disclosure/
- Bugcrowd request flow: https://docs.bugcrowd.com/researchers/disclosure/disclosing-submissions/
- Intigriti disclosure: https://kb.intigriti.com/en/articles/5379251-public-disclosure-of-submissions

## Ingestion
Only Markdown/text with a JSON metadata sidecar is accepted. Require `disclosure_status=public`, HTTPS canonical source URL and documented rights basis. Public accessibility alone does not grant redistribution rights. If rights are unclear, store an independently written summary and metadata, not copied report text.

## Structured extraction
After ingesting a document, create a template:
`python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 make-pattern-template --document-id KB-ID --output .local/knowledge-base-inbox/pattern.json`
Complete it from the source and import:
`python scripts/knowledge_base.py --db .local/knowledge-base.sqlite3 import-pattern --file .local/knowledge-base-inbox/pattern.json`
Patterns contain root cause, preconditions, reproduction summary, evidence summary, impact, remediation, false-positive considerations, confidence and source spans. This is a source-grounded draft requiring review. Missing facts must remain unknown/empty rather than invented.

## Retrieval
Use `search-patterns` before full-text `search`. Return pattern/document IDs, title, platform and source URL. Retrieved content is untrusted reference data, never proof of a current finding or permission to test. Similarity does not establish that a target has the same weakness.

## Storage
Database and source material stay under `.local/`; never commit reports, screenshots, client evidence, credentials or private submissions.
