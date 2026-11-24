-- 001_init: schema as of PortDee v1.1.0.
-- Written with IF NOT EXISTS so it is safe on databases created by v1.0.x / v1.1.0.
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','creator','viewer')),
  disabled BOOLEAN NOT NULL DEFAULT false,
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS alerts_seen_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS seal TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_one_owner ON users ((true)) WHERE is_owner;

CREATE TABLE IF NOT EXISTS portfolio (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  data JSONB NOT NULL,
  rev INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO portfolio (id, data, rev) VALUES (1, '{"items":[],"fx":{"THB":1,"USD":33.5},"cash":[]}', 0) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  username TEXT,
  action TEXT NOT NULL,
  detail TEXT,
  rev INTEGER
);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS security BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS portfolio_history (
  rev INTEGER PRIMARY KEY,
  data JSONB NOT NULL,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id INTEGER
);
