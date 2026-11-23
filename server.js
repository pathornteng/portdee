// PortDee – server
// Express + PostgreSQL. Users have one of three roles:
//   admin   – everything, plus managing creator/viewer users and viewing the change log
//   creator – view and edit the portfolio
//   viewer  – view only
// One admin is the OWNER: only the owner can create, promote, demote, disable, delete or
// reset the password of an admin, and only the owner can hand ownership to another admin.
// Any change to the users table made outside the app (directly in the database) is logged
// by a database trigger and shown to the owner as a security alert.
'use strict';

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const VERSION = require('./package.json').version;
const PORT = Number(process.env.PORT) || 3000;
const APP_NAME = process.env.APP_NAME || 'PortDee';
const PROD = process.env.NODE_ENV === 'production';
const ROLES = ['admin', 'creator', 'viewer'];
const COOKIE = 'pd_session';
const SESSION_DAYS = Number(process.env.SESSION_DAYS) || 14;

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. On Railway, add a variable DATABASE_URL = ${{Postgres.DATABASE_URL}}');
  process.exit(1);
}
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (PROD) {
    console.error('JWT_SECRET must be set to a random string of at least 32 characters.');
    process.exit(1);
  }
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('JWT_SECRET not set – using a temporary one (everyone is logged out on restart).');
}

// USER SEAL: every user row carries an HMAC over (id, username, role, owner flag, disabled, password hash).
// A change made directly in the database (e.g. viewer → admin, or a swapped password hash) breaks the
// seal: that account is locked, its role is not honoured, and the owner sees a security alert.
// SEAL_SECRET must stay the same; if it is ever changed, set RESEAL_USERS=true for one deploy.
const SEAL_SECRET = process.env.SEAL_SECRET || crypto.createHmac('sha256', JWT_SECRET).update('portdee-user-seal').digest('hex');
if (!process.env.SEAL_SECRET) console.warn('SEAL_SECRET not set – deriving it from JWT_SECRET (changing JWT_SECRET will then lock every account; set SEAL_SECRET).');
const sealOf = u => crypto.createHmac('sha256', SEAL_SECRET)
  .update([u.id, u.username, u.role, !!u.is_owner, !!u.disabled, u.password_hash].join('|')).digest('hex');
const sealOk = u => !!u.seal && u.seal.length === 64 && crypto.timingSafeEqual(Buffer.from(u.seal), Buffer.from(sealOf(u)));
async function reseal(c, id) {
  const u = (await c.query('SELECT * FROM users WHERE id=$1', [id])).rows[0];
  if (u) await c.query('UPDATE users SET seal=$1 WHERE id=$2', [sealOf(u), id]);
}
const flagged = new Set(); // avoid repeating the same alert
async function flagTamper(u) {
  const key = u.id + ':' + (u.seal || '') + ':' + sealOf(u);
  if (flagged.has(key)) return;
  flagged.add(key);
  console.warn(`SECURITY: user "${u.username}" was changed outside the app – account locked.`);
  const detail = `บัญชี ${u.username} (สิทธิ์ในฐานข้อมูล: ${u.role}${u.is_owner ? ', เจ้าของ' : ''}) ถูกแก้นอกโปรแกรม ระบบล็อกบัญชีนี้ไว้ เจ้าของต้องตรวจและกดยืนยัน`;
  const seen = await pool.query(`SELECT 1 FROM audit_log WHERE action='tamper_detected' AND detail=$1 AND at > now() - interval '7 days' LIMIT 1`, [detail]);
  if (!seen.rows.length) await audit(null, 'tamper_detected', detail, null, true);
}

// Railway's internal network does not use SSL; public/external URLs usually do.
const dbUrl = process.env.DATABASE_URL;
const useSsl = process.env.DATABASE_SSL === 'true' ||
  (process.env.DATABASE_SSL !== 'false' && !/railway\.internal|localhost|127\.0\.0\.1/.test(dbUrl));
const pool = new Pool({ connectionString: dbUrl, ssl: useSsl ? { rejectUnauthorized: false } : false, max: 5 });

async function migrate() {
  await pool.query(`
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
    CREATE TABLE IF NOT EXISTS portfolio (
      id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      data JSONB NOT NULL,
      rev INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id BIGSERIAL PRIMARY KEY,
      at TIMESTAMPTZ NOT NULL DEFAULT now(),
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      username TEXT,
      action TEXT NOT NULL,
      detail TEXT,
      rev INTEGER
    );
    CREATE TABLE IF NOT EXISTS portfolio_history (
      rev INTEGER PRIMARY KEY,
      data JSONB NOT NULL,
      at TIMESTAMPTZ NOT NULL DEFAULT now(),
      user_id INTEGER
    );
  `);
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS alerts_seen_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS seal TEXT;
    ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS security BOOLEAN NOT NULL DEFAULT false;
    CREATE UNIQUE INDEX IF NOT EXISTS users_one_owner ON users ((true)) WHERE is_owner;
    CREATE OR REPLACE FUNCTION portdee_users_guard() RETURNS trigger AS $fn$
    DECLARE ch TEXT;
    BEGIN
      IF coalesce(current_setting('portdee.via_app', true), '') = '1' THEN RETURN COALESCE(NEW, OLD); END IF;
      IF TG_OP = 'DELETE' THEN
        INSERT INTO audit_log (action, detail, security) VALUES ('db_direct_change', 'ลบผู้ใช้ ' || OLD.username || ' โดยตรงในฐานข้อมูล', true);
        RETURN OLD;
      ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (action, detail, security) VALUES ('db_direct_change', 'เพิ่มผู้ใช้ ' || NEW.username || ' (' || NEW.role || ') โดยตรงในฐานข้อมูล', true);
        RETURN NEW;
      END IF;
      ch := concat_ws(', ',
        CASE WHEN NEW.username IS DISTINCT FROM OLD.username THEN 'ชื่อผู้ใช้ ' || OLD.username || '→' || NEW.username END,
        CASE WHEN NEW.role IS DISTINCT FROM OLD.role THEN 'สิทธิ์ ' || OLD.role || '→' || NEW.role END,
        CASE WHEN NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN 'เปลี่ยนรหัสผ่าน' END,
        CASE WHEN NEW.disabled IS DISTINCT FROM OLD.disabled THEN CASE WHEN NEW.disabled THEN 'ปิดใช้งาน' ELSE 'เปิดใช้งาน' END END,
        CASE WHEN NEW.is_owner IS DISTINCT FROM OLD.is_owner THEN CASE WHEN NEW.is_owner THEN 'ตั้งเป็นเจ้าของ' ELSE 'ถอดจากเจ้าของ' END END);
      IF ch <> '' THEN
        INSERT INTO audit_log (action, detail, security) VALUES ('db_direct_change', 'แก้ผู้ใช้ ' || NEW.username || ' โดยตรงในฐานข้อมูล: ' || ch, true);
      END IF;
      RETURN NEW;
    END $fn$ LANGUAGE plpgsql;
    DROP TRIGGER IF EXISTS portdee_users_guard ON users;
    CREATE TRIGGER portdee_users_guard AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION portdee_users_guard();
  `);
  await pool.query(`INSERT INTO portfolio (id, data, rev) VALUES (1, $1, 0) ON CONFLICT (id) DO NOTHING`,
    [{ items: [], fx: { THB: 1, USD: 33.5 }, cash: [] }]);

  // Emergency reset: set ADMIN_RESET=true together with ADMIN_USERNAME / ADMIN_PASSWORD, deploy once, then remove ADMIN_RESET.
  if (process.env.ADMIN_RESET === 'true' && process.env.ADMIN_PASSWORD) {
    const username = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await tx(async c => { const r = await c.query(`INSERT INTO users (username, display_name, password_hash, role) VALUES ($1,'Admin',$2,'admin')
      ON CONFLICT (username) DO UPDATE SET role='admin', disabled=false, password_hash=EXCLUDED.password_hash, token_version=users.token_version+1 RETURNING id`,
      [username, hash]); await reseal(c, r.rows[0].id); });
    await audit(null, 'admin_reset', `รีเซ็ตรหัสผ่าน/สิทธิ์ของ ${username} ผ่านตัวแปร ADMIN_RESET บน Railway`, null, true);
    console.warn(`ADMIN_RESET: password for "${username}" was reset. Remove the ADMIN_RESET variable now.`);
  }
  const { rows } = await pool.query(`SELECT count(*)::int AS n FROM users WHERE role='admin' AND NOT disabled`);
  if (rows[0].n === 0) {
    const username = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
    let password = process.env.ADMIN_PASSWORD;
    if (!password) {
      password = crypto.randomBytes(9).toString('base64url');
      console.warn('==========================================================');
      console.warn(` First admin created: username "${username}"  password "${password}"`);
      console.warn(' Log in and change this password straight away.');
      console.warn('==========================================================');
    }
    const hash = await bcrypt.hash(password, 12);
    await tx(async c => { const r = await c.query(
      `INSERT INTO users (username, display_name, password_hash, role) VALUES ($1,$2,$3,'admin')
       ON CONFLICT (username) DO UPDATE SET role='admin', disabled=false, password_hash=EXCLUDED.password_hash RETURNING id`,
      [username, 'Admin', hash]); await reseal(c, r.rows[0].id); });
    console.log(`Admin user "${username}" is ready.`);
  }
  // exactly one owner: if none, the earliest active admin becomes owner
  const own = await pool.query('SELECT id FROM users WHERE is_owner');
  if (!own.rows.length) {
    await tx(async c => { const r = await c.query(`UPDATE users SET is_owner=true WHERE id=(SELECT id FROM users WHERE role='admin' AND NOT disabled ORDER BY id LIMIT 1) RETURNING id, seal`);
      // only re-seal if the row was already sealed and valid before (first run seals below)
      if (r.rows[0] && r.rows[0].seal) await reseal(c, r.rows[0].id); });
    const o = (await pool.query('SELECT username FROM users WHERE is_owner')).rows[0];
    if (o) { console.log(`Owner is "${o.username}".`); await audit(null, 'owner_set', `ตั้ง ${o.username} เป็นเจ้าของระบบ (อัตโนมัติ)`, null, true); }
  }
  const all = (await pool.query('SELECT * FROM users ORDER BY id')).rows;
  const fresh = all.filter(u => !u.seal);
  if (process.env.RESEAL_USERS === 'true') {
    await tx(async c => { for (const u of all) await reseal(c, u.id); });
    await audit(null, 'reseal_all', 'ประทับตราบัญชีผู้ใช้ทั้งหมดใหม่ผ่านตัวแปร RESEAL_USERS (' + all.map(u => u.username + ':' + u.role).join(', ') + ')', null, true);
    console.warn('RESEAL_USERS: all users re-sealed. Remove the RESEAL_USERS variable now.');
  } else if (fresh.length) {
    await tx(async c => { for (const u of fresh) await reseal(c, u.id); });
    if (fresh.length !== all.length || all.length > 1)
      await audit(null, 'seal_init', 'ประทับตราบัญชีครั้งแรก: ' + fresh.map(u => u.username + ' (' + u.role + (u.is_owner ? ', เจ้าของ' : '') + ')').join(', ') + ' — กรุณาตรวจว่าสิทธิ์ถูกต้อง', null, true);
  }
  for (const u of (await pool.query('SELECT * FROM users')).rows) if (!sealOk(u)) await flagTamper(u);
}

// Run user-table writes inside a transaction marked as coming from the app, so the
// database trigger does not flag them as direct database edits.
async function tx(fn) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query("SELECT set_config('portdee.via_app', '1', true)");
    const r = await fn(c);
    await c.query('COMMIT');
    return r;
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}
async function audit(user, action, detail, rev, security = false) {
  try {
    await pool.query('INSERT INTO audit_log (user_id, username, action, detail, rev, security) VALUES ($1,$2,$3,$4,$5,$6)',
      [user ? user.id : null, user ? user.username : null, action, detail ? String(detail).slice(0, 2000) : null, rev ?? null, !!security]);
  } catch (e) { console.error('audit failed', e.message); }
}

const app = express();
app.set('trust proxy', 1); // Railway sits behind a proxy
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'", "'unsafe-inline'"],
      'script-src-attr': ["'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      'font-src': ["'self'", 'https://fonts.gstatic.com', 'data:'],
      'img-src': ["'self'", 'data:', 'blob:'],
      'connect-src': ["'self'"],
      'upgrade-insecure-requests': PROD ? [] : null,
    },
  },
}));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ---- sessions ----
function setSession(res, user) {
  const token = jwt.sign({ uid: user.id, tv: user.token_version }, JWT_SECRET, { expiresIn: SESSION_DAYS + 'd' });
  res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: SESSION_DAYS * 864e5, path: '/' });
}
async function currentUser(req) {
  const token = req.cookies[COOKIE];
  if (!token) return null;
  try {
    const p = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [p.uid]);
    const u = rows[0];
    if (!u || u.disabled || u.token_version !== p.tv) return null;
    if (!sealOk(u)) { await flagTamper(u); return null; }
    return u;
  } catch { return null; }
}
const pub = u => ({ id: u.id, username: u.username, displayName: u.display_name || u.username, role: u.role, isOwner: !!u.is_owner });
function need(...roles) {
  return async (req, res, next) => {
    const u = await currentUser(req);
    if (!u) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' });
    if (roles.length && !roles.includes(u.role)) return res.status(403).json({ error: 'ไม่มีสิทธิ์ทำรายการนี้' });
    req.user = u;
    next();
  };
}
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---- auth ----
const loginLimiter = rateLimit({ windowMs: 15 * 60e3, limit: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'ลองเข้าสู่ระบบบ่อยเกินไป กรุณารอ 15 นาที' } });

app.post('/api/login', loginLimiter, wrap(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  const u = rows[0];
  if (u && !sealOk(u)) { await flagTamper(u); return res.status(403).json({ error: 'บัญชีนี้ถูกแก้ไขนอกโปรแกรม ระบบล็อกไว้ กรุณาติดต่อเจ้าของระบบ' }); }
  const ok = u && !u.disabled && await bcrypt.compare(password, u.password_hash);
  if (!ok) { await audit(null, 'login_failed', username); return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' }); }
  await pool.query('UPDATE users SET last_login_at=now() WHERE id=$1', [u.id]);
  setSession(res, u);
  await audit(u, 'login');
  res.json({ user: pub(u) });
}));
app.get('/api/app', (req, res) => res.json({ app: APP_NAME, version: VERSION }));
app.post('/api/logout', (req, res) => { res.clearCookie(COOKIE, { path: '/' }); res.json({ ok: true }); });
app.get('/api/me', need(), wrap(async (req, res) => {
  let alerts = 0;
  if (req.user.is_owner) {
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM audit_log WHERE security AND at > COALESCE($1, \'-infinity\'::timestamptz) AND (user_id IS DISTINCT FROM $2)',
      [req.user.alerts_seen_at, req.user.id]);
    alerts = rows[0].n;
  }
  res.json({ user: pub(req.user), app: APP_NAME, version: VERSION, alerts });
}));
app.get('/api/alerts', need('admin'), wrap(async (req, res) => {
  if (!req.user.is_owner) return res.status(403).json({ error: 'เฉพาะเจ้าของระบบ' });
  const { rows } = await pool.query(`SELECT id, at, username, action, detail, (at > COALESCE($1, '-infinity'::timestamptz) AND user_id IS DISTINCT FROM $2) AS unseen
    FROM audit_log WHERE security ORDER BY id DESC LIMIT 200`, [req.user.alerts_seen_at, req.user.id]);
  res.json({ alerts: rows });
}));
app.post('/api/alerts/seen', need('admin'), wrap(async (req, res) => {
  if (!req.user.is_owner) return res.status(403).json({ error: 'เฉพาะเจ้าของระบบ' });
  await pool.query('UPDATE users SET alerts_seen_at=now() WHERE id=$1', [req.user.id]);
  res.json({ ok: true });
}));
app.post('/api/me/password', need(), wrap(async (req, res) => {
  const { current, next: nw } = req.body || {};
  if (!nw || String(nw).length < 8) return res.status(400).json({ error: 'รหัสผ่านใหม่ต้องยาวอย่างน้อย 8 ตัวอักษร' });
  if (!await bcrypt.compare(String(current || ''), req.user.password_hash)) return res.status(400).json({ error: 'รหัสผ่านเดิมไม่ถูกต้อง' });
  const hash = await bcrypt.hash(String(nw), 12);
  const { rows } = await tx(async c => { await c.query('UPDATE users SET password_hash=$1, token_version=token_version+1 WHERE id=$2', [hash, req.user.id]); await reseal(c, req.user.id); return c.query('SELECT * FROM users WHERE id=$1', [req.user.id]); });
  setSession(res, rows[0]);
  await audit(req.user, 'password_changed', null, null, req.user.role === 'admin');
  res.json({ ok: true });
}));

// ---- portfolio ----
app.get('/api/portfolio', need(), wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT p.data, p.rev, p.updated_at, u.display_name, u.username
    FROM portfolio p LEFT JOIN users u ON u.id=p.updated_by WHERE p.id=1`);
  const r = rows[0];
  if (req.query.since !== undefined && Number(req.query.since) === r.rev) return res.json({ rev: r.rev, unchanged: true });
  res.json({ data: r.data, rev: r.rev, updatedAt: r.updated_at, updatedBy: r.display_name || r.username || null });
}));

app.put('/api/portfolio', need('admin', 'creator'), wrap(async (req, res) => {
  const { data, rev, desc } = req.body || {};
  if (!data || !Array.isArray(data.items) || typeof data.fx !== 'object' || (data.cash !== undefined && !Array.isArray(data.cash)))
    return res.status(400).json({ error: 'รูปแบบข้อมูลไม่ถูกต้อง' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = (await client.query('SELECT data, rev FROM portfolio WHERE id=1 FOR UPDATE')).rows[0];
    if (Number(rev) !== cur.rev) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'มีคนอื่นแก้ข้อมูลไปก่อน', data: cur.data, rev: cur.rev });
    }
    // keep the previous version so an admin can roll back
    await client.query('INSERT INTO portfolio_history (rev, data, user_id) VALUES ($1,$2,$3) ON CONFLICT (rev) DO NOTHING',
      [cur.rev, cur.data, req.user.id]);
    await client.query(`DELETE FROM portfolio_history WHERE rev < $1`, [cur.rev - 200]);
    const next = cur.rev + 1;
    await client.query('UPDATE portfolio SET data=$1, rev=$2, updated_at=now(), updated_by=$3 WHERE id=1',
      [{ items: data.items, fx: data.fx, cash: data.cash || [] }, next, req.user.id]);
    await client.query('COMMIT');
    await audit(req.user, 'save', Array.isArray(desc) ? desc.join(' · ') : desc, next);
    res.json({ rev: next });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}));

// ---- admin: users ----
// Rules: the owner may manage everyone. Other admins may only manage creator/viewer accounts
// and may not grant the admin role. Nobody can demote, disable or delete the owner; the owner
// hands over ownership first.
const isOwner = u => !!u.is_owner;
function canManage(actor, target) {
  if (target.is_owner) return actor.id === target.id ? 'self-owner' : false;
  if (isOwner(actor)) return true;
  return target.role !== 'admin';
}
app.get('/api/users', need('admin'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users ORDER BY is_owner DESC, id');
  res.json({ users: rows.map(u => ({ id: u.id, username: u.username, display_name: u.display_name, role: u.role, is_owner: u.is_owner, disabled: u.disabled,
    created_at: u.created_at, last_login_at: u.last_login_at, tampered: !sealOk(u) })) });
}));
app.post('/api/users', need('admin'), wrap(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const display = String(req.body.displayName || '').trim();
  const role = String(req.body.role || 'viewer');
  const password = String(req.body.password || '');
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) return res.status(400).json({ error: 'ชื่อผู้ใช้ใช้ a-z 0-9 . _ - ยาว 3–32 ตัว' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'สิทธิ์ไม่ถูกต้อง' });
  if (role === 'admin' && !isOwner(req.user)) return res.status(403).json({ error: 'เฉพาะเจ้าของระบบเท่านั้นที่เพิ่ม admin ได้' });
  if (password.length < 8) return res.status(400).json({ error: 'รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร' });
  const hash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await tx(async c => { const r = await c.query('INSERT INTO users (username, display_name, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING id',
      [username, display || username, hash, role]); await reseal(c, r.rows[0].id); return r; });
    await audit(req.user, 'user_created', `${username} (${role})`, null, true);
    res.json({ id: rows[0].id });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'มีชื่อผู้ใช้นี้แล้ว' });
    throw e;
  }
}));
app.patch('/api/users/:id', need('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
  const u = rows[0];
  if (!u) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  const b = req.body || {};
  const perm = canManage(req.user, u);
  if (!perm) return res.status(403).json({ error: u.is_owner ? 'แก้บัญชีเจ้าของระบบไม่ได้' : 'เฉพาะเจ้าของระบบเท่านั้นที่แก้บัญชี admin ได้' });
  if (!sealOk(u)) return res.status(400).json({ error: 'บัญชีนี้ถูกแก้นอกโปรแกรม เจ้าของต้องกด "ยืนยันบัญชี" หรือลบบัญชีก่อน' });
  if (perm === 'self-owner' && ((b.role !== undefined && b.role !== 'admin') || b.disabled === true))
    return res.status(400).json({ error: 'เจ้าของระบบลดสิทธิ์หรือปิดใช้ตัวเองไม่ได้ ให้โอนความเป็นเจ้าของก่อน' });
  if (b.role === 'admin' && u.role !== 'admin' && !isOwner(req.user)) return res.status(403).json({ error: 'เฉพาะเจ้าของระบบเท่านั้นที่ตั้ง admin ได้' });
  const sets = [], vals = [], notes = [];
  const add = (sql, v) => { vals.push(v); sets.push(sql.replace('?', '$' + vals.length)); };
  if (b.role !== undefined && b.role !== u.role) { if (!ROLES.includes(b.role)) return res.status(400).json({ error: 'สิทธิ์ไม่ถูกต้อง' }); add('role=?', b.role); notes.push('สิทธิ์ ' + u.role + '→' + b.role); }
  if (b.displayName !== undefined) { add('display_name=?', String(b.displayName).trim() || u.username); notes.push('ชื่อ'); }
  if (b.disabled !== undefined && !!b.disabled !== u.disabled) { add('disabled=?', !!b.disabled); notes.push(b.disabled ? 'ปิดใช้งาน' : 'เปิดใช้งาน'); }
  if (b.password !== undefined) {
    if (String(b.password).length < 8) return res.status(400).json({ error: 'รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร' });
    add('password_hash=?', await bcrypt.hash(String(b.password), 12)); notes.push('ตั้งรหัสผ่านใหม่');
  }
  if (!sets.length) return res.json({ ok: true });
  if (b.role !== undefined || b.disabled || b.password !== undefined) sets.push('token_version=token_version+1'); // log them out
  vals.push(id);
  await tx(async c => { await c.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${vals.length}`, vals); await reseal(c, id); });
  await audit(req.user, 'user_updated', `${u.username}: ${notes.join(', ')}`, null, true);
  res.json({ ok: true });
}));
app.delete('/api/users/:id', need('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'ลบบัญชีตัวเองไม่ได้' });
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
  const u = rows[0];
  if (!u) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  if (!canManage(req.user, u)) return res.status(403).json({ error: u.is_owner ? 'ลบบัญชีเจ้าของระบบไม่ได้' : 'เฉพาะเจ้าของระบบเท่านั้นที่ลบ admin ได้' });
  await tx(c => c.query('DELETE FROM users WHERE id=$1', [id]));
  await audit(req.user, 'user_deleted', `${u.username} (${u.role})`, null, true);
  res.json({ ok: true });
}));
app.post('/api/users/:id/approve', need('admin'), wrap(async (req, res) => {
  if (!isOwner(req.user)) return res.status(403).json({ error: 'เฉพาะเจ้าของระบบเท่านั้น' });
  if (!await bcrypt.compare(String((req.body || {}).password || ''), req.user.password_hash)) return res.status(400).json({ error: 'รหัสผ่านไม่ถูกต้อง' });
  const id = Number(req.params.id);
  const u = (await pool.query('SELECT * FROM users WHERE id=$1', [id])).rows[0];
  if (!u) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  await tx(async c => { await c.query('UPDATE users SET token_version=token_version+1 WHERE id=$1', [id]); await reseal(c, id); });
  await audit(req.user, 'tamper_approved', `เจ้าของยืนยันบัญชี ${u.username} ตามสภาพปัจจุบัน (สิทธิ์ ${u.role}${u.disabled ? ', ปิดใช้' : ''})`, null, true);
  res.json({ ok: true });
}));
app.post('/api/users/:id/make-owner', need('admin'), wrap(async (req, res) => {
  if (!isOwner(req.user)) return res.status(403).json({ error: 'เฉพาะเจ้าของระบบเท่านั้น' });
  if (!await bcrypt.compare(String((req.body || {}).password || ''), req.user.password_hash)) return res.status(400).json({ error: 'รหัสผ่านไม่ถูกต้อง' });
  const id = Number(req.params.id);
  const t = (await pool.query('SELECT * FROM users WHERE id=$1', [id])).rows[0];
  if (!t || t.role !== 'admin' || t.disabled) return res.status(400).json({ error: 'โอนได้เฉพาะให้ admin ที่ใช้งานอยู่' });
  await tx(async c => {
    await c.query('UPDATE users SET is_owner=false WHERE id=$1', [req.user.id]);
    await c.query('UPDATE users SET is_owner=true WHERE id=$1', [id]);
    await reseal(c, req.user.id); await reseal(c, id);
  });
  await audit(req.user, 'owner_transfer', `โอนความเป็นเจ้าของจาก ${req.user.username} ให้ ${t.username}`, null, true);
  res.json({ ok: true });
}));

// ---- admin: change log and roll back ----
app.get('/api/audit', need('admin'), wrap(async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const { rows } = await pool.query('SELECT id, at, username, action, detail, rev, security FROM audit_log ORDER BY id DESC LIMIT $1', [limit]);
  res.json({ log: rows });
}));
app.get('/api/history', need('admin'), wrap(async (req, res) => {
  const { rows } = await pool.query(`SELECT h.rev, h.at, u.username, jsonb_array_length(h.data->'items') AS items
    FROM portfolio_history h LEFT JOIN users u ON u.id=h.user_id ORDER BY h.rev DESC LIMIT 100`);
  res.json({ history: rows });
}));
app.post('/api/history/:rev/restore', need('admin'), wrap(async (req, res) => {
  const rev = Number(req.params.rev);
  const h = (await pool.query('SELECT data FROM portfolio_history WHERE rev=$1', [rev])).rows[0];
  if (!h) return res.status(404).json({ error: 'ไม่พบเวอร์ชันนี้' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = (await client.query('SELECT data, rev FROM portfolio WHERE id=1 FOR UPDATE')).rows[0];
    await client.query('INSERT INTO portfolio_history (rev, data, user_id) VALUES ($1,$2,$3) ON CONFLICT (rev) DO NOTHING', [cur.rev, cur.data, req.user.id]);
    await client.query('UPDATE portfolio SET data=$1, rev=$2, updated_at=now(), updated_by=$3 WHERE id=1', [h.data, cur.rev + 1, req.user.id]);
    await client.query('COMMIT');
    await audit(req.user, 'restore', 'กู้คืนข้อมูล ณ เวอร์ชัน ' + rev, cur.rev + 1);
    res.json({ rev: cur.rev + 1 });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}));

// ---- pages and static files ----
app.get('/healthz', wrap(async (req, res) => { await pool.query('SELECT 1'); res.json({ ok: true, version: VERSION }); }));
const vendor = (pkg, file) => path.join(path.dirname(require.resolve(pkg + '/package.json')), file);
app.get('/vendor/xlsx.full.min.js', (req, res) => res.sendFile(vendor('xlsx', 'dist/xlsx.full.min.js'), { maxAge: '30d' }));
app.get('/vendor/exceljs.min.js', (req, res) => res.sendFile(vendor('exceljs', 'dist/exceljs.min.js'), { maxAge: '30d' }));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/', wrap(async (req, res) => {
  if (!await currentUser(req)) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
}));
app.use(express.static(path.join(__dirname, 'public'), { index: false, maxAge: '1h' }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'เกิดข้อผิดพลาดที่เซิร์ฟเวอร์' });
});

async function integrityCheck() {
  try {
    const t = await pool.query(`SELECT tgenabled FROM pg_trigger WHERE tgname='portdee_users_guard' AND NOT tgisinternal`);
    if (!t.rows.length || t.rows[0].tgenabled === 'D') {
      await audit(null, 'guard_missing', 'ตัวตรวจจับการแก้ฐานข้อมูลถูกลบหรือปิดไว้ ระบบติดตั้งคืนให้แล้ว (มีคนแก้โครงสร้างฐานข้อมูลโดยตรง)', null, true);
      await migrate();
    }
    for (const u of (await pool.query('SELECT * FROM users')).rows) if (!sealOk(u)) await flagTamper(u);
  } catch (e) { console.error('integrity check failed', e.message); }
}

migrate()
  .then(() => { setInterval(integrityCheck, 5 * 60e3); app.listen(PORT, () => console.log(`${APP_NAME} v${VERSION} listening on port ${PORT}`)); })
  .catch(e => { console.error('Database setup failed:', e); process.exit(1); });
