"""Attack-graph type system and validation rules.

Defines the allowed node and edge types, the source/destination constraints for each
edge, the trust levels, and — critically — which edge types express **authorization or
policy** and may therefore only be asserted from the trusted control plane. Untrusted,
target- or agent-derived data can never assert those relationships as fact.
"""
from __future__ import annotations


class GraphError(ValueError):
    pass


# Trust levels, strongest first. A stronger assertion upgrades a weaker one on upsert.
TRUST_LEVELS = ("control_plane", "observed", "inferred")
_TRUST_RANK = {name: index for index, name in enumerate(TRUST_LEVELS)}


def trust_rank(trust: str) -> int:
    if trust not in _TRUST_RANK:
        raise GraphError("Unknown trust level: " + str(trust))
    return _TRUST_RANK[trust]


def stronger_trust(a: str, b: str) -> str:
    return a if trust_rank(a) <= trust_rank(b) else b


NODE_TYPES = frozenset({
    "engagement", "application", "host", "service", "endpoint", "route", "parameter",
    "input", "object", "object_identifier", "identity", "user", "role", "permission",
    "session", "auth_mechanism", "workflow", "technology", "hypothesis", "finding",
    "evidence", "trust_boundary",
    # Knowledge-layer entities (Intelligence Layer Component B). These carry inferred/
    # observed knowledge provenance only; they never participate in authorization edges.
    "knowledge_pattern", "vulnerability_class", "cwe", "cve", "capec", "owasp",
    "attack_technique", "tool",
})

_IDENTITY_LIKE = frozenset({"identity", "user"})

# edge_type -> (allowed source node types, allowed destination node types)
EDGE_SPECS: dict[str, tuple[frozenset, frozenset]] = {
    "HAS_ROLE": (_IDENTITY_LIKE, frozenset({"role"})),
    "HAS_PERMISSION": (frozenset({"role"}), frozenset({"permission"})),
    "CAN_ACCESS": (_IDENTITY_LIKE | frozenset({"role"}), frozenset({"endpoint", "route", "object"})),
    "OBSERVED_ACCESS": (_IDENTITY_LIKE, frozenset({"endpoint", "route"})),
    "ACCEPTS": (frozenset({"endpoint", "route"}), frozenset({"parameter", "input"})),
    "RETURNS": (frozenset({"endpoint", "route"}), frozenset({"object"})),
    "REFERENCES": (frozenset({"endpoint", "route"}), frozenset({"object", "object_identifier"})),
    "INVOKES": (frozenset({"workflow"}), frozenset({"endpoint", "route"})),
    "DEPENDS_ON": (frozenset({"endpoint", "route"}), frozenset({"endpoint", "route"})),
    "USES": (frozenset({"application", "host", "service"}), frozenset({"technology"})),
    "BELONGS_TO": (frozenset({"object", "object_identifier", "session"}), _IDENTITY_LIKE),
    "CROSSES": (frozenset({"endpoint", "route"}), frozenset({"trust_boundary"})),
    "HOSTS": (frozenset({"host", "application"}), frozenset({"service", "endpoint", "application"})),
    "AUTHENTICATES_WITH": (_IDENTITY_LIKE, frozenset({"auth_mechanism", "session"})),
    "TARGETS": (frozenset({"hypothesis", "finding"}), frozenset({"endpoint", "route", "object", "parameter"})),
    "SUPPORTS": (frozenset({"evidence"}), frozenset({"hypothesis", "finding"})),
    "VALIDATED_BY": (frozenset({"finding", "hypothesis"}), frozenset({"evidence"})),
    # Knowledge-layer edges (Component B) — never authorization (not in AUTHORIZATION_EDGE_TYPES).
    "DESCRIBES": (frozenset({"knowledge_pattern"}), frozenset({"vulnerability_class"})),
    "REFERENCES_WEAKNESS": (frozenset({"knowledge_pattern", "finding", "hypothesis"}),
                            frozenset({"cwe", "cve", "capec", "owasp", "attack_technique"})),
    "RELEVANT_TO": (frozenset({"knowledge_pattern"}),
                    frozenset({"endpoint", "route", "technology", "vulnerability_class"})),
    "APPLIES_TO": (frozenset({"cwe", "capec", "attack_technique", "vulnerability_class"}),
                   frozenset({"technology"})),
    "TESTS_FOR": (frozenset({"tool"}), frozenset({"vulnerability_class"})),
    "SIMILAR_TO": (frozenset({"finding", "hypothesis"}), frozenset({"knowledge_pattern"})),
}

EDGE_TYPES = frozenset(EDGE_SPECS)

# Edges that express authorization / policy. Only control-plane trust may assert these;
# an observation that an identity *reached* an endpoint is OBSERVED_ACCESS (evidence),
# never CAN_ACCESS (an authorization grant).
AUTHORIZATION_EDGE_TYPES = frozenset({
    "HAS_ROLE", "HAS_PERMISSION", "CAN_ACCESS", "BELONGS_TO",
})


def validate_node_type(node_type: str) -> None:
    if node_type not in NODE_TYPES:
        raise GraphError("Unknown node type: " + str(node_type))


def validate_edge(edge_type: str, src_type: str, dst_type: str) -> None:
    if edge_type not in EDGE_SPECS:
        raise GraphError("Unknown edge type: " + str(edge_type))
    allowed_src, allowed_dst = EDGE_SPECS[edge_type]
    if src_type not in allowed_src:
        raise GraphError(f"Edge {edge_type} cannot start at node type {src_type}")
    if dst_type not in allowed_dst:
        raise GraphError(f"Edge {edge_type} cannot end at node type {dst_type}")


def ensure_authorization_trust(edge_type: str, trust: str) -> None:
    """Fail closed if an authorization/policy edge is asserted below control-plane trust."""
    if edge_type in AUTHORIZATION_EDGE_TYPES and trust != "control_plane":
        raise GraphError(
            f"Authorization edge {edge_type} requires control_plane trust; "
            f"untrusted/observed data cannot assert authorization relationships"
        )
