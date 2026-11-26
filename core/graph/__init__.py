"""Attack / knowledge graph.

A structured, engagement-scoped representation of an application's security-relevant
entities and relationships, persisted as typed nodes and edges over the existing SQLite
store (no graph database). The graph improves test selection, coverage and validation; it
is not a visualization.

Invariants:

- **Engagement isolation**: every node/edge is scoped to one engagement by foreign key and
  unique constraint; a graph handle for one engagement cannot read or mutate another's.
- **Trust-tiered provenance**: `control_plane` > `observed` > `inferred`. Authorization and
  policy edges (`HAS_ROLE`, `HAS_PERMISSION`, `CAN_ACCESS`, `BELONGS_TO`) may be asserted
  only from the control plane; untrusted/observed data can never grant authorization.
- **Deterministic, traceable updates**: deduplicated by natural key, with merged provenance
  and highest-seen confidence.
- **Reasoning proposes, never broadens**: attack-path detectors emit hypotheses over
  existing entities only; they never invent identities or expand scope.
"""
from core.graph.ingest import GraphIngestor, IngestError
from core.graph.paths import (AttackPath, detect_cross_identity_object_access,
                              detect_function_level_escalation, find_paths, propose_attack_paths)
from core.graph.query import GraphQuery
from core.graph.schema import (AUTHORIZATION_EDGE_TYPES, EDGE_SPECS, EDGE_TYPES, GraphError,
                               NODE_TYPES, TRUST_LEVELS)
from core.graph.store import AttackGraph

__all__ = [
    "AttackGraph", "AttackPath", "AUTHORIZATION_EDGE_TYPES", "EDGE_SPECS", "EDGE_TYPES",
    "GraphError", "GraphIngestor", "GraphQuery", "IngestError", "NODE_TYPES", "TRUST_LEVELS",
    "detect_cross_identity_object_access", "detect_function_level_escalation", "find_paths",
    "propose_attack_paths",
]
