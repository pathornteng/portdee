// Migration runner. Applies migrations/NNN_name.sql in order, once each, inside a transaction.
// Used automatically on server start, or by hand:
//   npm run migrate          apply pending migrations
//   npm run migrate:status   list applied / pending
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DIR = path.join(__dirname, '..', 'migrations');

function listFiles() {
  return fs.readdirSync(DIR).filter(f => /^\d{3}_[\w-]+\.sql$/.test(f)).sort()
    .map(f => ({ name: f, sql: fs.readFileSync(path.join(DIR, f), 'utf8') }))
    .map(m => ({ ...m, checksum: crypto.createHash('sha256').update(m.sql).digest('hex').slice(0, 16) }));
}

async function ensureTable(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
}

async function status(pool) {
  await ensureTable(pool);
  const done = new Map((await pool.query('SELECT name, checksum, applied_at FROM schema_migrations')).rows.map(r => [r.name, r]));
  return listFiles().map(m => ({ name: m.name, applied: done.has(m.name), applied_at: done.get(m.name)?.applied_at || null,
    changed: done.has(m.name) && done.get(m.name).checksum !== m.checksum }));
}

async function migrate(pool, log = console.log) {
  await ensureTable(pool);
  // one runner at a time (e.g. two instances starting together)
  const lock = await pool.connect();
  try {
    await lock.query('SELECT pg_advisory_lock(424242)');
    const done = new Set((await lock.query('SELECT name FROM schema_migrations')).rows.map(r => r.name));
    const applied = [];
    for (const m of listFiles()) {
      if (done.has(m.name)) continue;
      try {
        await lock.query('BEGIN');
        await lock.query(m.sql);
        await lock.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [m.name, m.checksum]);
        await lock.query('COMMIT');
        applied.push(m.name);
        log(`migration applied: ${m.name}`);
      } catch (e) {
        await lock.query('ROLLBACK').catch(() => {});
        throw new Error(`migration ${m.name} failed (nothing from it was applied): ${e.message}`);
      }
    }
    return applied;
  } finally {
    await lock.query('SELECT pg_advisory_unlock(424242)').catch(() => {});
    lock.release();
  }
}

module.exports = { migrate, status, listFiles };

if (require.main === module) {
  const { Pool } = require('pg');
  if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set'); process.exit(1); }
  const url = process.env.DATABASE_URL;
  const ssl = process.env.DATABASE_SSL === 'true' || (process.env.DATABASE_SSL !== 'false' && !/railway\.internal|localhost|127\.0\.0\.1/.test(url));
  const pool = new Pool({ connectionString: url, ssl: ssl ? { rejectUnauthorized: false } : false });
  (async () => {
    if (process.argv.includes('--status')) {
      for (const s of await status(pool)) console.log(`${s.applied ? '✔ applied ' : '… pending '} ${s.name}${s.applied_at ? '  ' + new Date(s.applied_at).toISOString() : ''}${s.changed ? '  (file changed after it was applied!)' : ''}`);
    } else {
      const a = await migrate(pool);
      console.log(a.length ? `done: ${a.length} migration(s) applied` : 'database is up to date');
    }
    await pool.end();
  })().catch(e => { console.error(e.message); process.exit(1); });
}
