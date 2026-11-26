-- Exploit validation records: an independent, integrity-hashed disposition per validation
-- run, separate from the finding it concerns. Engagement-scoped; references are stored,
-- not raw bodies or secrets.

CREATE TABLE IF NOT EXISTS validation_records (
    record_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    finding_id TEXT REFERENCES findings(finding_id),
    hypothesis_id TEXT,
    vulnerability_class TEXT NOT NULL,
    oracle TEXT NOT NULL,
    validator_id TEXT NOT NULL,
    validator_version TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('SUPPORTED','REFUTED','INCONCLUSIVE')),
    explanation TEXT NOT NULL,
    comparison_json TEXT NOT NULL DEFAULT '{}',
    request_refs_json TEXT NOT NULL DEFAULT '[]',
    response_refs_json TEXT NOT NULL DEFAULT '[]',
    baseline_refs_json TEXT NOT NULL DEFAULT '[]',
    sanitized INTEGER NOT NULL DEFAULT 1,
    integrity_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_validation_records_finding ON validation_records(finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_validation_records_engagement ON validation_records(engagement_id, created_at);
