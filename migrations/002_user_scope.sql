-- 002_user_scope: per-user access to brokers and asset types (v1.2.0).
-- New and existing users (except the owner) start with NO access until an admin sets it.
ALTER TABLE users ADD COLUMN IF NOT EXISTS scope_all_brokers BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS scope_brokers TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS scope_all_types BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS scope_types TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
