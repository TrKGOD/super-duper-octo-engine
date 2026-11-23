ALTER TABLE evidence
ADD COLUMN encryption_algorithm TEXT NOT NULL DEFAULT 'none';
