CREATE TABLE IF NOT EXISTS active_execution_state (
    engagement_id TEXT PRIMARY KEY REFERENCES engagements(engagement_id),
    last_started_epoch REAL NOT NULL DEFAULT 0,
    lock_token TEXT,
    lock_expires_epoch REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS active_request_log (
    execution_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    request_id TEXT NOT NULL,
    target_host TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('running','completed','failed')),
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(engagement_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_active_request_task
ON active_request_log(engagement_id, task_id);
