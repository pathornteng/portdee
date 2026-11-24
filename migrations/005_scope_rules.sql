-- 005_scope_rules: several access rules per user (v1.3.0).
-- Each rule: {"b": "*" or [brokers], "t": "*" or [asset types], "l": "view" or "edit"}.
-- Existing scopes are converted once by the server at start-up (only for accounts whose seal is intact).
-- The old scope_* columns are kept but no longer used.
ALTER TABLE users ADD COLUMN IF NOT EXISTS scope_rules JSONB NOT NULL DEFAULT '[]'::jsonb;
