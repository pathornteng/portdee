-- 006_log_protection: tamper-evident activity log (v1.3.0).
-- Every row written by the app carries an HMAC chained to the previous row, and the table only
-- accepts INSERT: UPDATE/DELETE are refused unless they come from the app itself (retention cleanup).
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hash TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_id BIGINT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT;
CREATE OR REPLACE FUNCTION portdee_audit_guard() RETURNS trigger AS $fn$
BEGIN
  IF coalesce(current_setting('portdee.via_app', true), '') = '1' THEN RETURN COALESCE(NEW, OLD); END IF;
  RAISE EXCEPTION 'audit_log is append-only (PortDee)';
END $fn$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS portdee_audit_guard ON audit_log;
CREATE TRIGGER portdee_audit_guard BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION portdee_audit_guard();
