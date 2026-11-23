ALTER TABLE agent_runs ADD COLUMN task_id TEXT REFERENCES tasks(task_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_task ON agent_runs(task_id);
