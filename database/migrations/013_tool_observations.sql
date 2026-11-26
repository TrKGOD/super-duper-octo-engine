-- Normalized tool observations (directive §7). One row per normalized observation from a
-- tool execution, engagement-scoped and traceable to its tool/task/engagement/execution.
-- Dispositions distinguish structure (DETECTED), scanner leads (CANDIDATE) and validation
-- outcomes (SUPPORTED/REFUTED/INCONCLUSIVE) plus ERROR. DETECTED/CANDIDATE are never
-- confirmed findings.

CREATE TABLE IF NOT EXISTS tool_observations (
    observation_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    task_id TEXT,
    execution_id TEXT,
    tool_id TEXT NOT NULL,
    tool_version TEXT,
    observation_type TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN (
        'DETECTED','CANDIDATE','SUPPORTED','REFUTED','INCONCLUSIVE','ERROR')),
    target_reference TEXT,
    asset_reference TEXT,
    endpoint_reference TEXT,
    vulnerability_class TEXT,
    severity_candidate TEXT,
    confidence REAL NOT NULL DEFAULT 0.0,
    execution_profile TEXT,
    raw_artifact_reference TEXT,
    evidence_references_json TEXT NOT NULL DEFAULT '[]',
    source_provenance_json TEXT NOT NULL DEFAULT '{}',
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_observations_engagement
ON tool_observations(engagement_id, disposition);
CREATE INDEX IF NOT EXISTS idx_tool_observations_tool
ON tool_observations(engagement_id, tool_id);
