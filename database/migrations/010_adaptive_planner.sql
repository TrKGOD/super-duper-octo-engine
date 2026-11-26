-- Adaptive testing planner: evidence-driven hypotheses and per-decision observability.
-- Hypotheses are engagement-scoped and deduplicated by a deterministic signature so the
-- same (category, target, identity) is never tracked twice. Decisions record why each
-- test was selected or deferred, for full planner observability.

CREATE TABLE IF NOT EXISTS planner_hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    category TEXT NOT NULL,
    test_class TEXT NOT NULL,
    skill TEXT,
    target_node_id TEXT,
    target_label TEXT,
    required_identity TEXT,
    required_state TEXT,
    preconditions_json TEXT NOT NULL DEFAULT '[]',
    supporting_evidence_json TEXT NOT NULL DEFAULT '[]',
    contradictory_evidence_json TEXT NOT NULL DEFAULT '[]',
    proposed_test TEXT NOT NULL,
    expected_outcomes TEXT,
    risk TEXT NOT NULL DEFAULT 'medium',
    state_changing INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.0,
    score REAL NOT NULL DEFAULT 0.0,
    score_breakdown_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK(status IN (
        'PROPOSED','READY','RUNNING','SUPPORTED','REFUTED','INCONCLUSIVE','BLOCKED','DEFERRED')),
    status_reason TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS planner_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(engagement_id),
    cycle INTEGER NOT NULL,
    hypothesis_id TEXT NOT NULL REFERENCES planner_hypotheses(hypothesis_id),
    selected INTEGER NOT NULL,
    score REAL NOT NULL DEFAULT 0.0,
    rationale_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_planner_hypotheses_engagement_status
ON planner_hypotheses(engagement_id, status);
CREATE INDEX IF NOT EXISTS idx_planner_decisions_engagement_cycle
ON planner_decisions(engagement_id, cycle);
