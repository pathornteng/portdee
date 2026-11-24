-- 004_price_feed: automatic prices (v1.2.0).
CREATE TABLE IF NOT EXISTS app_state (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS price_quotes (
  id BIGSERIAL PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  symbol TEXT NOT NULL,
  source TEXT NOT NULL,
  price NUMERIC NOT NULL,
  currency TEXT,
  quote_time TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS price_quotes_symbol_at ON price_quotes (symbol, at DESC);
