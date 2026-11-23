-- Keep evidence linked only to findings in the same engagement.
CREATE INDEX IF NOT EXISTS idx_evidence_engagement ON evidence(engagement_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_running_run_per_task
    ON agent_runs(task_id)
    WHERE task_id IS NOT NULL AND status='running';

CREATE TRIGGER IF NOT EXISTS evidence_finding_engagement_insert
BEFORE INSERT ON evidence
WHEN NEW.finding_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM findings
    WHERE finding_id=NEW.finding_id AND engagement_id=NEW.engagement_id
 )
BEGIN
    SELECT RAISE(ABORT, 'evidence and finding must belong to the same engagement');
END;

CREATE TRIGGER IF NOT EXISTS evidence_finding_engagement_update
BEFORE UPDATE OF finding_id, engagement_id ON evidence
WHEN NEW.finding_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM findings
    WHERE finding_id=NEW.finding_id AND engagement_id=NEW.engagement_id
 )
BEGIN
    SELECT RAISE(ABORT, 'evidence and finding must belong to the same engagement');
END;
