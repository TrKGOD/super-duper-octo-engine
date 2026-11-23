-- Add explicit domain and tags to normalized KB patterns.
ALTER TABLE kb_patterns ADD COLUMN domain TEXT NOT NULL DEFAULT 'other';
ALTER TABLE kb_patterns ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
CREATE INDEX IF NOT EXISTS idx_kb_patterns_domain ON kb_patterns(domain);
