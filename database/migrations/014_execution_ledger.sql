-- Execution ledger, evidence->execution association and the validation evidence chain.
--
-- Strictly additive: no existing table is rebuilt and no existing row is rewritten, so
-- historical engagements (findings, evidence, active_request_log, worker_executions, ...)
-- upgrade in place. New columns are nullable / defaulted so legacy rows stay valid; legacy
-- validation records are honestly marked evidence_verified=0.

-- 1. One row per execution of a tool, HTTP request or browser action. The state machine is
--    enforced in core/execution_ledger.py (compare-and-swap transitions); the CHECKs below are
--    the last line of defence against an out-of-band writer.
CREATE TABLE IF NOT EXISTS executions (
    execution_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    task_id TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('tool','http','browser','validation')),
    tool_id TEXT NOT NULL,
    execution_profile TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'CREATED','QUEUED','AUTHORIZED','RUNNING','COMPLETED','FAILED','PARTIAL',
        'CANCELLED','INTERRUPTED','RECONCILIATION_REQUIRED')),
    side_effect_risk TEXT NOT NULL DEFAULT 'read_only'
        CHECK(side_effect_risk IN ('read_only','state_changing')),
    authorization_json TEXT NOT NULL DEFAULT '{}',
    request_json TEXT NOT NULL DEFAULT '{}',
    external_ref TEXT,
    owner TEXT,
    lease_expires_at REAL,
    request_dispatched INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    exit_status INTEGER,
    resource_usage_json TEXT NOT NULL DEFAULT '{}',
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    failure_json TEXT,
    reconciliation_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_executions_engagement_status ON executions(engagement_id, status);
CREATE INDEX IF NOT EXISTS idx_executions_task ON executions(engagement_id, task_id);
CREATE INDEX IF NOT EXISTS idx_executions_external ON executions(engagement_id, external_ref);

-- 2. Append-only audit trail of every transition.
CREATE TABLE IF NOT EXISTS execution_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT NOT NULL REFERENCES executions(execution_id),
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    from_status TEXT,
    to_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_execution_events_execution ON execution_events(execution_id, event_id);

CREATE TRIGGER IF NOT EXISTS execution_events_no_update
BEFORE UPDATE ON execution_events
BEGIN SELECT RAISE(ABORT, 'execution_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS execution_events_no_delete
BEFORE DELETE ON execution_events
BEGIN SELECT RAISE(ABORT, 'execution_events is append-only'); END;

-- 3. Evidence knows which execution (and task) produced it. Nullable: operator-supplied and
--    pre-014 evidence has no execution.
ALTER TABLE evidence ADD COLUMN execution_id TEXT;
ALTER TABLE evidence ADD COLUMN task_id TEXT;
CREATE INDEX IF NOT EXISTS idx_evidence_execution ON evidence(execution_id);

CREATE TRIGGER IF NOT EXISTS evidence_execution_engagement_insert
BEFORE INSERT ON evidence
WHEN NEW.execution_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM executions
    WHERE execution_id=NEW.execution_id AND engagement_id=NEW.engagement_id
 )
BEGIN
    SELECT RAISE(ABORT, 'evidence execution must belong to the same engagement');
END;

-- 4. A validation record states whether the oracle ran on vault-verified evidence, the hashes
--    of that evidence, and what further evidence it needs when inconclusive.
ALTER TABLE validation_records ADD COLUMN evidence_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE validation_records ADD COLUMN evidence_hashes_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE validation_records ADD COLUMN evidence_requests_json TEXT NOT NULL DEFAULT '[]';

-- 5. A hypothesis remembers what it was last tried against, so it is only retried when the
--    surrounding facts actually changed ("no repeat without new justification").
ALTER TABLE planner_hypotheses ADD COLUMN attempt_fingerprint TEXT;
ALTER TABLE planner_hypotheses ADD COLUMN evidence_requests_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE planner_hypotheses ADD COLUMN last_execution_id TEXT;
-- 1 once a test was really executed against the target (an attempt that was refused, or that has no
-- automated executor, is not coverage).
ALTER TABLE planner_hypotheses ADD COLUMN executed INTEGER NOT NULL DEFAULT 0;
