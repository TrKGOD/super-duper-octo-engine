-- Attack / knowledge graph: typed entities and relationships over the existing SQLite
-- store (no graph database). Nodes and edges are engagement-scoped (FK + UNIQUE), carry
-- provenance, trust and confidence, and deduplicate on their natural key.

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    node_type TEXT NOT NULL,
    node_key TEXT NOT NULL,
    label TEXT,
    attributes_json TEXT NOT NULL DEFAULT '{}',
    trust TEXT NOT NULL CHECK(trust IN ('control_plane','observed','inferred')),
    provenance_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(engagement_id, node_type, node_key)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    src_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
    dst_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
    edge_type TEXT NOT NULL,
    trust TEXT NOT NULL CHECK(trust IN ('control_plane','observed','inferred')),
    attributes_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '[]',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(engagement_id, src_node_id, edge_type, dst_node_id)
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_engagement_type ON graph_nodes(engagement_id, node_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(engagement_id, src_node_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(engagement_id, dst_node_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges(engagement_id, edge_type);
