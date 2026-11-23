# Public Pentest Knowledge Base

See [docs/KNOWLEDGE_BASE.md](../docs/KNOWLEDGE_BASE.md) for the source policy and workflow.

- Discover public research feed items: `python scripts/kb_sources.py --config config/knowledge-sources.example.json`
- Ingest an operator-reviewed Markdown/text write-up and metadata sidecar.
- Search documents and structured vulnerability patterns with `scripts/knowledge_base.py`.
- Store the SQLite database and source material only in `.local/`.

The feed adapter collects discovery metadata only. It does not establish disclosure permission or download report bodies.
