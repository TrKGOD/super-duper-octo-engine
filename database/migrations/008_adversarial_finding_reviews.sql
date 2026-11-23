CREATE TABLE IF NOT EXISTS finding_reviews (
 review_id TEXT PRIMARY KEY,
 finding_id TEXT NOT NULL REFERENCES findings(finding_id),
 engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
 reviewer TEXT NOT NULL,
 decision TEXT NOT NULL CHECK(decision IN ('rejected','needs_more_evidence','eligible_for_independent_validation')),
 review_json TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_reviews_finding ON finding_reviews(finding_id,created_at);
