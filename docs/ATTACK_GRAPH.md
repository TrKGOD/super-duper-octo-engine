# Attack / Knowledge Graph

**Phase 2 — foundation.** Status: `lab_verified`. A structured, engagement-scoped
representation of an application's security-relevant entities and relationships that
improves test selection, coverage and validation. It is **not** a visualization layer.

## Why relational, not a graph database

Per the roadmap's engineering rules, a new dependency must earn its place. The graph is
persisted as two typed tables over the **existing SQLite store** (`graph_nodes`,
`graph_edges`, migration `009_attack_graph.sql`). The access patterns we need —
neighbors of a node, edges of a type, path enumeration over a small per-engagement graph —
are served well by indexed edge rows. No graph database is introduced.

## Data model

- **Nodes** (`graph_nodes`): `node_type`, natural `node_key`, `label`, `attributes_json`,
  `trust`, `provenance_json`, `confidence`. Deterministic `node_id = sha256(engagement ∥
  type ∥ key)`, unique per `(engagement, type, key)`.
- **Edges** (`graph_edges`): typed `src → dst` with `trust`, `provenance_json`,
  `evidence_refs_json`, `confidence`; unique per `(engagement, src, type, dst)`.
- **Node types**: engagement, application, host, service, endpoint, route, parameter,
  input, object, object_identifier, identity, user, role, permission, session,
  auth_mechanism, workflow, technology, hypothesis, finding, evidence, trust_boundary.
- **Edge types** (with source/destination constraints in `core/graph/schema.py`): HAS_ROLE,
  HAS_PERMISSION, CAN_ACCESS, OBSERVED_ACCESS, ACCEPTS, RETURNS, REFERENCES, INVOKES,
  DEPENDS_ON, USES, BELONGS_TO, CROSSES, HOSTS, AUTHENTICATES_WITH, TARGETS, SUPPORTS,
  VALIDATED_BY.

## Trust boundary (the security-critical rule)

Every node and edge carries a trust level — `control_plane` > `observed` > `inferred` —
and the strongest assertion wins on upsert. The **authorization/policy edges**
(`HAS_ROLE`, `HAS_PERMISSION`, `CAN_ACCESS`, `BELONGS_TO`) may be asserted **only** from the
control plane. This is enforced in two independent places:

1. **Store** (`store.upsert_edge` → `schema.ensure_authorization_trust`): refuses an
   authorization edge below control-plane trust, regardless of caller.
2. **Ingestion** (`ingest.GraphIngestor.propose`): untrusted agent/target-derived proposals
   cannot assert authorization/observation edges and cannot create principal nodes
   (identity/user/role/permission/trust_boundary).

So an *observation* that identity A reached endpoint E is recorded as `OBSERVED_ACCESS`
(evidence), never as `CAN_ACCESS` (an authorization grant). Untrusted content can never
mutate authorization relationships or invent identities — directly satisfying the roadmap
invariant.

## Ingestion (`core/graph/ingest.py`)

- **Control plane** (operator facts): `register_identity`, `register_role`,
  `grant_role`, `grant_permission`, `authorize_access`, `authorize_role_access`,
  `declare_object_owner`, `register_endpoint`.
- **Observations** (trusted pipeline): `observe_access` (requires a registered identity),
  and `ingest_browser_report`, which folds a Phase 1 Browser Intelligence report into
  observed endpoint/parameter/route/workflow nodes plus `OBSERVED_ACCESS` for the
  operator-supplied identity. This is the Phase 1 → Phase 2 bridge.
- **Proposals** (untrusted): `propose` persists agent hypotheses as `inferred`, refusing
  authorization edges and principal nodes.

## Attack-path reasoning (`core/graph/paths.py`)

Detectors emit **hypotheses for the planner**, never confirmed findings, and only over
entities already in the graph (no scope/identity broadening):

- `detect_cross_identity_object_access` (BOLA/IDOR): identity A reaches an endpoint that
  `REFERENCES`/`RETURNS` an object that `BELONGS_TO` identity B ≠ A.
- `detect_function_level_escalation` (BFLA): an identity was `OBSERVED_ACCESS` on an
  endpoint whose `CAN_ACCESS` is restricted to a role the identity does not hold.

Each proposed path carries start, target, intermediate nodes, relationship explanations,
supporting evidence, **missing evidence**, required authorization (the authorized
identities involved), a concrete proposed test, the expected observation, and a risk
classification. `find_paths` provides generic acyclic traversal.

## Query interface (`core/graph/query.py`)

`GraphQuery` exposes the planner-facing reads: `endpoints_for_object`,
`endpoints_for_identity`, `objects_referenced_by_multiple_endpoints`,
`workflows_using_endpoint`, `hypotheses_without_validation`, `low_coverage_endpoints`,
and `identity_access_differences`.

## Tests

`tests/test_attack_graph.py` (20 tests): migration/table creation, node/edge persistence
and dedup, provenance merge, trust upgrade, cross-engagement isolation, invalid-type and
invalid-endpoint rejection, the authorization trust boundary (store-level refusal +
untrusted-proposal refusal + identity-invention refusal), traversal, BOLA and BFLA path
generation (and a true-negative when the actor owns the object), evidence association, the
query methods, identity comparison, and Browser-report ingestion.

## Maturity and follow-ups

`lab_verified` against synthetic in-memory engagements. Follow-ups: persist findings/
evidence lifecycle edges from the validation engine (Phase 4); wire the planner (Phase 3)
to consume `GraphQuery` + `propose_attack_paths`; add more path detectors (SSRF reachability,
trust-boundary crossing) as those test families mature.
