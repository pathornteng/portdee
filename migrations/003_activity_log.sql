-- 003_activity_log: who did what, from which device/IP (v1.2.0).
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS ip TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS device TEXT;
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at);
CREATE INDEX IF NOT EXISTS audit_log_user_at ON audit_log (user_id, at);
