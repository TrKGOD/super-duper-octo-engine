-- Isolated worker observability (directive §10.5). One row per provisioned worker,
-- engagement-scoped, recording lifecycle, resource usage, tool executions and cleanup.

CREATE TABLE IF NOT EXISTS worker_executions (
    worker_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    task_id TEXT NOT NULL,
    backend TEXT NOT NULL,
    image TEXT,
    status TEXT NOT NULL CHECK(status IN ('provisioned','running','completed','failed','cancelled','torn_down')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    tool_executions_json TEXT NOT NULL DEFAULT '[]',
    resource_usage_json TEXT NOT NULL DEFAULT '{}',
    artifacts_json TEXT NOT NULL DEFAULT '[]',
    cleanup_status TEXT NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_worker_executions_engagement
ON worker_executions(engagement_id, started_at);
