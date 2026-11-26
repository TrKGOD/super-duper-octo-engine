# RAG Architecture

**Component A (part 2).** Status: `lab_verified`. Hybrid retrieval over the Knowledge Base
that gives agents relevant, provenance-carrying context — and nothing more. **RAG provides
knowledge, not authorization.**

## Retrieval (`core/knowledge/retrieval.py`)

- **FTS baseline (always functional):** `KnowledgeRetriever.retrieve_documents` and
  `retrieve_patterns` wrap the KB's existing FTS5 search (with its LIKE fallback), add
  technology / vulnerability-class query augmentation and metadata filters (`domain`, `tag`),
  and re-rank patterns by source confidence. The system is **never** dependent on an external
  embedding provider.
- **Optional semantic layer:** when an embedding backend is injected, `semantic_documents`
  ranks by cosine similarity over `kb_embeddings`, and `hybrid_documents` merges FTS +
  semantic results (deduplicated). Without a backend, these degrade gracefully to empty /
  FTS-only.
- **Provenance + trust on every result:** each result carries `trust: "untrusted_knowledge"`,
  a `provenance` block (document id, source URL, platform), the extracted references, and a
  note stating the content confers no authorization and that similarity is not evidence.

## Contextual retrieval (`ContextualRetriever`)

Agents receive only the knowledge relevant to their task, under a hard item budget
(`MAX_CONTEXT_ITEMS = 8`), never the whole KB. Per-agent profiles decide what to return:

| Agent | Returns |
|---|---|
| recon-agent | documents |
| enumeration-agent | patterns + documents |
| vulnerability-agent | patterns |
| exploitation-agent | patterns |
| validation-agent | patterns |
| reporting-agent | documents |

`for_task(agent=…, query=…, technologies=…, vulnerability_classes=…, domain=…, limit=…)`
classifies the request, applies the profile and budget, and returns results with provenance,
a completeness flag, and the untrusted-knowledge note.

## Security boundary

- Retrieval is read-only and grants nothing: no scope, identity, permission or approval.
- Results are untrusted context; they never become instructions and never enter the control
  plane. (The graph's authorization trust boundary — Roadmap 1 Phase 2 — is untouched; KB
  content will connect to the graph only as `inferred`/knowledge provenance in Component B.)
- Similarity to a public report is explicitly **not** evidence that the current target is
  vulnerable; that requires the engagement's own evidence and independent validation.

## Follow-ups

Wire real embedding backends (optional, configured) behind the same seam; connect retrieved
patterns to the engagement graph (Component B); fold retrieval-quality metrics into the
benchmark (Component H).
