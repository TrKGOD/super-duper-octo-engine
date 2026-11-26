# Knowledge Graph Integration

**Component B.** Status: `lab_verified`. Connects the Knowledge Base into the **existing**
engagement attack graph (`core/graph/`) so retrieved knowledge becomes queryable alongside
the application's own entities — without a second graph and without weakening the graph's
authorization trust boundary.

## What it adds

New knowledge node types (`core/graph/schema.py`): `knowledge_pattern`, `vulnerability_class`,
`cwe`, `cve`, `capec`, `owasp`, `attack_technique`, `tool`. New knowledge edge types:

| Edge | Meaning |
|---|---|
| `knowledge_pattern` **DESCRIBES** `vulnerability_class` | the class a pattern is about |
| `knowledge_pattern` **REFERENCES_WEAKNESS** `cwe`/`cve`/`capec`/`owasp`/`attack_technique` | taxonomy links |
| `knowledge_pattern` **RELEVANT_TO** `endpoint`/`route`/`technology`/`vulnerability_class` | where a pattern applies |
| `cwe`/`capec`/`attack_technique`/`vulnerability_class` **APPLIES_TO** `technology` | weakness ↔ tech |
| `tool` **TESTS_FOR** `vulnerability_class` | which tool tests a class |
| `finding`/`hypothesis` **SIMILAR_TO** `knowledge_pattern` | validated work ↔ known patterns |

None of these are authorization edges.

## The bridge (`core/knowledge/graph_bridge.py`)

`KnowledgeGraphBridge(graph, kb_db)` reads KB patterns and their taxonomy references from the
KB database (the clean, unwrapped values) and projects them into the engagement graph. It
links a pattern to an endpoint and/or a technology when given, and `register_tool` records an
operator-declared tool capability. Graph-assisted queries answer the directive's questions:

- `patterns_for_endpoint(graph, endpoint)` — which known patterns apply here?
- `patterns_for_technology(graph, tech)` / `patterns_for_vulnerability_class(graph, vclass)`
- `tools_for_vulnerability_class(graph, vclass)` — which tools test this class?
- `weaknesses_of_pattern(graph, pattern_id)` — its CWE/CVE/… references.

## Trust boundary preserved (tested)

Every knowledge node/edge is written with **`inferred`** trust (operator-declared tool
capabilities are `observed`) and carries provenance (`source`, `document_id`, `pattern_id`).
The bridge creates **only** knowledge node/edge types — never an `identity`, `role`,
`permission`, or any authorization edge. Two independent guarantees hold:

1. **By construction:** the bridge API has no way to create principals or authorization edges;
   `test_knowledge_creates_no_authorization_or_principals` confirms no `CAN_ACCESS`/`HAS_ROLE`
   edges and no identity/role/permission nodes appear after ingesting KB content.
2. **By the store:** a knowledge node can never be the source of an authorization grant —
   `upsert_edge(knowledge_pattern, "CAN_ACCESS", …)` is rejected, and `ensure_authorization_trust`
   still refuses any authorization edge below control-plane trust.

So untrusted KB content enriches reasoning (what to look at, which tool, which CWE) but can
never grant scope, identity or permission. Model 1's baseline and the Phase 2 graph
authorization tests are untouched.

## Tests

`tests/test_knowledge_graph_integration.py` (6): pattern projection as inferred knowledge with
provenance, the graph-assisted queries, tool-capability registration, and the two
authorization-boundary guarantees.

## Follow-ups

Link validated findings to the patterns that motivated them (`SIMILAR_TO`) as the planner/
validation loop runs; feed `tools_for_vulnerability_class` into Component F's tool selection.
