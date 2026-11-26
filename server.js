// PortDee – server
// Express + PostgreSQL. Users have one of three roles:
//   admin   – everything, plus managing creator/viewer users and viewing the change log
//   creator – view and edit the portfolio
//   viewer  – view only
// One admin is the OWNER: only the owner can create, promote, demote, disable, delete or
// reset the password of an admin, and only the owner can hand ownership to another admin.
// Any change to the users table made outside the app (directly in the database) is logged
// by a database trigger and shown to the owner as a security alert.
// v1.2.0: per-user access scope (brokers × asset types), activity log with IP/device,
// numbered database migrations (migrations/*.sql) and automatic prices (lib/prices.js).
// v1.3.0: several view/edit rules per user, per-account login protection, Telegram alerts,
// tamper-evident activity log (hash chain + append-only table).
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
const { AsyncLocalStorage } = require('async_hooks');
const { migrate: runMigrations } = require('./db/migrate');
const SC = require('./lib/scope');
const PX = require('./lib/prices');
const NOTIFY = require('./lib/notify');

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
// v2 (PortDee 1.2.0+) also covers the access scope, so widening someone's scope in the database is caught too.
const hmac = s => crypto.createHmac('sha256', SEAL_SECRET).update(s).digest('hex');
const sealBase = u => [u.id, u.username, u.role, !!u.is_owner, !!u.disabled, u.password_hash].join('|');
const scopeKey = u => JSON.stringify([!!u.scope_all_brokers, [...(u.scope_brokers || [])].sort(), !!u.scope_all_types, [...(u.scope_types || [])].sort()]);
const sealV1 = u => hmac(sealBase(u));
const sealV2 = u => hmac('v2|' + sealBase(u) + '|' + scopeKey(u));
// v3 (1.3.0+): covers the access rules
const sealOf = u => hmac('v3|' + sealBase(u) + '|' + SC.rulesKey(u.scope_rules));
const eq = (a, b) => !!a && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const sealOk = u => eq(u.seal, sealOf(u));
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

// Database setup on every start:
//  1. numbered migrations in migrations/*.sql (tables and columns; each runs once)
//  2. the users-table guard trigger (re-installed every start and by the integrity check)
//  3. first admin / owner bootstrap and user seals
async function installGuard() {
  await pool.query(`
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
        CASE WHEN NEW.is_owner IS DISTINCT FROM OLD.is_owner THEN CASE WHEN NEW.is_owner THEN 'ตั้งเป็นเจ้าของ' ELSE 'ถอดจากเจ้าของ' END END,
        CASE WHEN NEW.scope_all_brokers IS DISTINCT FROM OLD.scope_all_brokers OR NEW.scope_brokers IS DISTINCT FROM OLD.scope_brokers
          OR NEW.scope_all_types IS DISTINCT FROM OLD.scope_all_types OR NEW.scope_types IS DISTINCT FROM OLD.scope_types
          OR NEW.scope_rules IS DISTINCT FROM OLD.scope_rules THEN 'สิทธิ์การเข้าถึง' END,
        CASE WHEN NEW.seal IS DISTINCT FROM OLD.seal AND NEW.password_hash IS NOT DISTINCT FROM OLD.password_hash AND NEW.role IS NOT DISTINCT FROM OLD.role THEN 'ตราประทับ' END);
      IF ch <> '' THEN
        INSERT INTO audit_log (action, detail, security) VALUES ('db_direct_change', 'แก้ผู้ใช้ ' || NEW.username || ' โดยตรงในฐานข้อมูล: ' || ch, true);
      END IF;
      RETURN NEW;
    END $fn$ LANGUAGE plpgsql;
    DROP TRIGGER IF EXISTS portdee_users_guard ON users;
    CREATE TRIGGER portdee_users_guard AFTER INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION portdee_users_guard();
  `);
  await pool.query(`
    CREATE OR REPLACE FUNCTION portdee_audit_guard() RETURNS trigger AS $fn$
    BEGIN
      IF coalesce(current_setting('portdee.via_app', true), '') = '1' THEN RETURN COALESCE(NEW, OLD); END IF;
      RAISE EXCEPTION 'audit_log is append-only (PortDee)';
    END $fn$ LANGUAGE plpgsql;
    DROP TRIGGER IF EXISTS portdee_audit_guard ON audit_log;
    CREATE TRIGGER portdee_audit_guard BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION portdee_audit_guard();
  `);
}

const auditLater = [];
async function setup() {
  const applied = await runMigrations(pool, m => console.log(m));
  // a guard that was installed before but is now missing or switched off means someone changed the database
  const tg = (await pool.query(`SELECT tgname, tgenabled FROM pg_trigger WHERE tgname IN ('portdee_users_guard','portdee_audit_guard') AND NOT tgisinternal`)).rows;
  const off = ['portdee_users_guard', 'portdee_audit_guard'].filter(n => !(n === 'portdee_audit_guard' && applied.includes('006_log_protection.sql')) && !(n === 'portdee_users_guard' && applied.includes('001_init.sql')))
    .filter(n => !tg.some(r => r.tgname === n && r.tgenabled !== 'D'));
  await installGuard();
  if (off.length) await auditLater.push(['guard_missing', 'ตัวป้องกันในฐานข้อมูลถูกลบหรือปิดไว้ระหว่างที่ระบบหยุด (' + off.join(', ') + ') ระบบติดตั้งคืนให้แล้ว']);
  await upgradeSealsToV2(applied);
  await upgradeSealsToV3();
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
  for (const [act, det] of auditLater.splice(0)) await audit(null, act, det, null, true);
}

// One-time step when upgrading to 1.2.0: switch untouched v1 seals to v2 and give every
// existing user except the owner NO access until an admin sets their scope.
async function upgradeSealsToV2() {
  if (await state.get('seal_v2')) return;
  const all = (await pool.query('SELECT * FROM users ORDER BY id')).rows;
  const reset = [];
  await tx(async c => {
    for (const u of all) {
      if (!u.seal || !eq(u.seal, sealV1(u))) continue; // unsealed or already tampered: handled by the normal checks
      if (!u.is_owner) {
        await c.query(`UPDATE users SET scope_all_brokers=false, scope_brokers='{}', scope_all_types=false, scope_types='{}' WHERE id=$1`, [u.id]);
        reset.push(u.username);
      }
      await reseal(c, u.id);
    }
  });
  await state.set('seal_v2', { at: new Date().toISOString() });
  if (reset.length) {
    await audit(null, 'scope_reset', 'อัปเกรดเป็น v1.2.0: ผู้ใช้ ' + reset.join(', ') + ' ยังไม่เห็นข้อมูลพอร์ต จนกว่า admin จะตั้งขอบเขต (โบรก/ประเภท) ให้', null, true);
    console.log('Upgrade 1.2.0: scope reset for ' + reset.join(', '));
  }
}

// One-time step when upgrading to 1.3.0: turn each intact v1.2.0 scope into one rule
// (creators/admins get "view and edit", viewers "view") and switch the seal to v3.
async function upgradeSealsToV3() {
  if (await state.get('seal_v3')) return;
  const all = (await pool.query('SELECT * FROM users ORDER BY id')).rows;
  const done = [];
  await tx(async c => {
    for (const u of all) {
      if (!u.seal || !eq(u.seal, sealV2(u))) continue;
      const rules = u.is_owner ? [] : SC.legacyRule(u);
      await c.query('UPDATE users SET scope_rules=$1 WHERE id=$2', [JSON.stringify(rules), u.id]);
      await reseal(c, u.id);
      if (!u.is_owner) done.push(u.username + ': ' + scopeTxt(rules));
    }
  });
  await state.set('seal_v3', { at: new Date().toISOString() });
  if (done.length) await audit(null, 'scope_reset', 'อัปเกรดเป็น v1.3.0: แปลงขอบเขตเดิมเป็นกฎสิทธิ์ — ' + done.join(' · '), null, true);
}

// small key/value store (app_state table)
const state = {
  async get(k) { const r = await pool.query('SELECT value FROM app_state WHERE key=$1', [k]); return r.rows[0] ? r.rows[0].value : null; },
  async set(k, v) { await pool.query('INSERT INTO app_state (key, value, updated_at) VALUES ($1,$2,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()', [k, JSON.stringify(v)]); },
};

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
// Every request runs with its IP and device in context, so audit() can record them.
const reqCtx = new AsyncLocalStorage();
function deviceOf(ua) {
  ua = String(ua || '');
  if (!ua) return '';
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Windows/.test(ua) ? 'Windows'
    : /Mac OS X|Macintosh/.test(ua) ? 'Mac' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : '';
  const br = /Line\//.test(ua) ? 'LINE' : /Edg\//.test(ua) ? 'Edge' : /SamsungBrowser/.test(ua) ? 'Samsung' : /OPR\//.test(ua) ? 'Opera'
    : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|python|node|axios|Go-http/i.test(ua) ? 'สคริปต์' : 'อื่นๆ';
  return [br, os].filter(Boolean).join(' · ');
}
const ipOf = req => String(req.ip || req.socket.remoteAddress || '').replace(/^::ffff:/, '');
// Activity log rows are chained: hash = HMAC(prev_hash | row). Rows are inserted one at a time
// (advisory lock), and the table refuses UPDATE/DELETE except from the app (see migration 006).
const logHash = (prevHash, r) => hmac('log|' + [prevHash || '', r.id, r.at, r.user_id ?? '', r.username ?? '', r.action, r.detail ?? '', r.rev ?? '', r.security ? 1 : 0, r.ip ?? '', r.device ?? ''].join('|'));
const ACTION_SHORT = { tamper_detected: 'บัญชีถูกแก้นอกโปรแกรม', db_direct_change: 'แก้ฐานข้อมูลโดยตรง', admin_reset: 'รีเซ็ต admin', reseal_all: 'ประทับตราใหม่ทั้งหมด',
  guard_missing: 'ตัวตรวจจับถูกปิด', login_attack: 'มีคนพยายามเดารหัสผ่าน', log_tamper: 'ประวัติการใช้งานถูกแก้/ลบ', owner_transfer: 'โอนความเป็นเจ้าของ',
  user_created: 'เพิ่มผู้ใช้', user_updated: 'แก้ผู้ใช้', user_deleted: 'ลบผู้ใช้', password_changed: 'เปลี่ยนรหัสผ่าน', tamper_approved: 'ยืนยันบัญชี', scope_reset: 'แปลงสิทธิ์ตอนอัปเกรด', seal_init: 'ประทับตราบัญชีครั้งแรก', owner_set: 'ตั้งเจ้าของระบบ' };
async function audit(user, action, detail, rev, security = false) {
  const ctx = reqCtx.getStore() || {};
  const r = { user_id: user ? user.id : null, username: user ? user.username : null, action, detail: detail ? String(detail).slice(0, 2000) : null,
    rev: rev ?? null, security: !!security, ip: ctx.ip || null, device: ctx.device || null };
  try {
    await tx(async c => {
      await c.query('SELECT pg_advisory_xact_lock(4243)');
      const last = (await c.query('SELECT id, hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1')).rows[0];
      r.id = String((await c.query("SELECT nextval(pg_get_serial_sequence('audit_log','id')) AS id")).rows[0].id);
      r.at = new Date().toISOString();
      const prevHash = last ? last.hash : null;
      await c.query(`INSERT INTO audit_log (id, at, user_id, username, action, detail, rev, security, ip, device, prev_id, prev_hash, hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [r.id, r.at, r.user_id, r.username, r.action, r.detail, r.rev, r.security, r.ip, r.device, last ? last.id : null, prevHash, logHash(prevHash, r)]);
    });
  } catch (e) { console.error('audit failed', e.message); }
  if (security) NOTIFY.send(`⚠️ ${APP_NAME}: ${ACTION_SHORT[action] || action}${r.username ? ' · ' + r.username : ''}${r.detail ? '\n' + r.detail : ''}${r.ip ? '\nIP ' + r.ip + (r.device ? ' · ' + r.device : '') : ''}`);
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
app.use((req, res, next) => reqCtx.run({ ip: ipOf(req), device: deviceOf(req.get('user-agent')) }, next));

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
const scopePub = u => { const s = SC.scopeOf(u); return { full: s.full, fullEdit: s.fullEdit, rules: s.owner ? [] : s.rules, owner: s.owner }; };
const pub = u => ({ id: u.id, username: u.username, displayName: u.display_name || u.username, role: u.role, isOwner: !!u.is_owner, scope: scopePub(u) });
// "last active" – written at most once a minute per user
const seenAt = new Map();
function touch(u) {
  const now = Date.now();
  if (now - (seenAt.get(u.id) || 0) < 60e3) return;
  seenAt.set(u.id, now);
  pool.query('UPDATE users SET last_seen_at=now() WHERE id=$1', [u.id]).catch(() => {});
}
function need(...roles) {
  return async (req, res, next) => {
    const u = await currentUser(req);
    if (!u) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' });
    if (roles.length && !roles.includes(u.role)) return res.status(403).json({ error: 'ไม่มีสิทธิ์ทำรายการนี้' });
    req.user = u;
    touch(u);
    next();
  };
}
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---- auth ----
// Login protection, counted per account rather than per network: someone guessing a password on the
// office network does not lock out the real owner. A browser that has logged in to an account before
// carries a signed "known device" cookie and gets its own allowance for that account.
const DEV_COOKIE = 'pd_dev';
const tries = new Map(); // key -> timestamps of failures
const WINDOW = 15 * 60e3;
function recent(key) { const now = Date.now(), a = (tries.get(key) || []).filter(t => now - t < WINDOW); if (a.length) tries.set(key, a); else tries.delete(key); return a; }
function fail(...keys) { const now = Date.now(); for (const k of keys) tries.set(k, [...recent(k), now]); }
setInterval(() => { for (const k of [...tries.keys()]) recent(k); }, 10 * 60e3).unref();
const attackAlerted = new Map();
function knownDevice(req, u) {
  try { const p = jwt.verify(req.cookies[DEV_COOKIE] || '', JWT_SECRET); return u && p.uids && p.uids.includes(u.id) ? p : null; } catch { return null; }
}
function rememberDevice(req, res, u) {
  let p = null; try { p = jwt.verify(req.cookies[DEV_COOKIE] || '', JWT_SECRET); } catch {}
  const uids = [...new Set([...(p && p.uids) || [], u.id])].slice(-10);
  res.cookie(DEV_COOKIE, jwt.sign({ d: (p && p.d) || crypto.randomBytes(9).toString('base64url'), uids }, JWT_SECRET, { expiresIn: '400d' }),
    { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 400 * 864e5, path: '/api/login' });
}
app.post('/api/login', wrap(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase().slice(0, 64);
  const password = String(req.body.password || '');
  const ip = ipOf(req);
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  const u = rows[0];
  const dev = knownDevice(req, u);
  const key = dev ? 'dev:' + dev.d + ':' + u.id : 'acct:' + username + '|' + ip;
  if (recent(key).length >= (dev ? 20 : 8) || (!dev && recent('ip:' + ip).length >= 40))
    return res.status(429).json({ error: 'ลองเข้าสู่ระบบผิดหลายครั้ง กรุณารอ 15 นาที' });
  if (u && !sealOk(u)) { await flagTamper(u); return res.status(403).json({ error: 'บัญชีนี้ถูกแก้ไขนอกโปรแกรม ระบบล็อกไว้ กรุณาติดต่อเจ้าของระบบ' }); }
  const ok = u && !u.disabled && await bcrypt.compare(password, u.password_hash);
  if (!ok) {
    fail(key, 'ip:' + ip, 'name:' + username);
    await audit(u && !u.disabled ? u : null, 'login_failed', u && u.disabled ? username + ' (บัญชีถูกปิดใช้)' : username);
    // several wrong passwords for one account → security alert (at most once an hour per account)
    const n = recent('name:' + username).length;
    if (u && n >= 5 && Date.now() - (attackAlerted.get(username) || 0) > 3600e3) {
      attackAlerted.set(username, Date.now());
      await audit(null, 'login_attack', `มีการใส่รหัสผ่านผิด ${n} ครั้งใน 15 นาที สำหรับบัญชี ${username} (ล่าสุดจาก IP ${ip}) · ถ้าไม่ใช่คุณ ให้ตรวจว่าใครเข้าได้`, null, true);
    }
    return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
  }
  tries.delete(key);
  await pool.query('UPDATE users SET last_login_at=now(), last_seen_at=now() WHERE id=$1', [u.id]);
  setSession(res, u);
  rememberDevice(req, res, u);
  await audit(u, 'login');
  res.json({ user: pub(u) });
}));
app.get('/api/app', (req, res) => res.json({ app: APP_NAME, version: VERSION }));
app.post('/api/logout', wrap(async (req, res) => {
  const u = await currentUser(req);
  if (u) await audit(u, 'logout');
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
}));
app.get('/api/me', need(), wrap(async (req, res) => {
  let alerts = 0;
  if (req.user.is_owner) {
    const { rows } = await pool.query('SELECT count(*)::int AS n FROM audit_log WHERE security AND at > COALESCE($1, \'-infinity\'::timestamptz) AND (user_id IS DISTINCT FROM $2)',
      [req.user.alerts_seen_at, req.user.id]);
    alerts = rows[0].n;
  }
  res.json({ user: pub(req.user), app: APP_NAME, version: VERSION, alerts, telegram: req.user.is_owner ? NOTIFY.enabled() : undefined });
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
app.post('/api/notify/test', need('admin'), wrap(async (req, res) => {
  if (!req.user.is_owner) return res.status(403).json({ error: 'เฉพาะเจ้าของระบบ' });
  if (!NOTIFY.enabled()) return res.status(400).json({ error: 'ยังไม่ได้ตั้ง TELEGRAM_BOT_TOKEN และ TELEGRAM_CHAT_ID' });
  const ok = await NOTIFY.send(`✅ ${APP_NAME}: ทดสอบการแจ้งเตือนจาก ${req.user.username} สำเร็จ`);
  ok ? res.json({ ok: true }) : res.status(502).json({ error: 'ส่งไม่สำเร็จ ตรวจ token และ chat id' });
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
  const sc = SC.scopeOf(req.user);
  if (req.query.since === undefined) logView(req.user);
  res.json({ data: SC.filterData(sc, r.data), rev: r.rev, updatedAt: r.updated_at,
    updatedBy: r.display_name || r.username || (r.rev > 0 ? 'ระบบ (ดึงราคาอัตโนมัติ)' : null),
    scoped: !sc.full, noAccess: !sc.rules.length });
}));
// "opened the portfolio" – logged at most once every 30 minutes per user
const viewAt = new Map();
function logView(u) {
  const now = Date.now();
  if (now - (viewAt.get(u.id) || 0) < 30 * 60e3) return;
  viewAt.set(u.id, now);
  audit(u, 'view');
}

app.put('/api/portfolio', need('admin', 'creator'), wrap(async (req, res) => {
  const { data, rev, desc } = req.body || {};
  if (!data || !Array.isArray(data.items) || typeof data.fx !== 'object' || (data.cash !== undefined && !Array.isArray(data.cash)) || (data.cfg !== undefined && (typeof data.cfg !== 'object' || Array.isArray(data.cfg))))
    return res.status(400).json({ error: 'รูปแบบข้อมูลไม่ถูกต้อง' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const cur = (await client.query('SELECT data, rev FROM portfolio WHERE id=1 FOR UPDATE')).rows[0];
    const sc = SC.scopeOf(req.user);
    if (Number(rev) !== cur.rev) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'มีคนอื่นแก้ข้อมูลไปก่อน', data: SC.filterData(sc, cur.data), rev: cur.rev });
    }
    // a user with a limited scope only replaces the part they can see
    const merged = SC.mergeData(sc, cur.data, { items: data.items, fx: data.fx, cash: data.cash || [], cfg: data.cfg });
    if (merged.error) { await client.query('ROLLBACK'); return res.status(403).json({ error: merged.error }); }
    // keep the previous version so an admin can roll back
    await client.query('INSERT INTO portfolio_history (rev, data, user_id) VALUES ($1,$2,$3) ON CONFLICT (rev) DO NOTHING',
      [cur.rev, cur.data, req.user.id]);
    await client.query(`DELETE FROM portfolio_history WHERE rev < $1`, [cur.rev - 200]);
    const next = cur.rev + 1;
    await client.query('UPDATE portfolio SET data=$1, rev=$2, updated_at=now(), updated_by=$3 WHERE id=1',
      [merged.data, next, req.user.id]);
    await client.query('COMMIT');
    await audit(req.user, 'save', (Array.isArray(desc) ? desc.join(' · ') : desc || '') + (merged.ignored.length ? ' · ไม่ได้แก้ (ดูอย่างเดียว): ' + merged.ignored.join(', ') : ''), next);
    // when something the user may only view was left as it was, send back what was really saved
    if (merged.ignored.length) return res.json({ rev: next, data: SC.filterData(sc, merged.data), ignored: merged.ignored });
    res.json({ rev: next });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}));

// ---- admin: users ----
// Rules: the owner may manage everyone. Other admins may only manage creator/viewer accounts
// and may not grant the admin role. Nobody can demote, disable or delete the owner; the owner
// hands over ownership first.
const isOwner = u => !!u.is_owner;
const fullScope = u => SC.scopeOf(u).fullEdit;
const TYPE_TH = { th: 'หุ้นไทย', fd: 'กองทุนรวม', fx: 'หุ้นต่างประเทศ', etf: 'ETF', au: 'ทองคำ', bd: 'พันธบัตร/หุ้นกู้', gsb: 'ฉลากออมสิน', cs: 'เงินฝาก/เงินสด' };
const scopeTxt = rules => (rules || []).length ? rules.map(r => (r.l === 'edit' ? 'แก้' : 'ดู') + ' ' + (r.b === '*' ? 'ทุกโบรก' : r.b.join(', ')) + ' × ' +
  (r.t === '*' ? 'ทุกประเภท' : r.t.map(t => TYPE_TH[t] || t).join(', '))).join(' · ') : 'ยังไม่มีสิทธิ์';
function canManage(actor, target) {
  if (target.is_owner) return actor.id === target.id ? 'self-owner' : false;
  if (isOwner(actor)) return true;
  return target.role !== 'admin';
}
app.get('/api/users', need('admin'), wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users ORDER BY is_owner DESC, id');
  const st = new Map((await pool.query(`SELECT user_id, count(*) FILTER (WHERE action='login')::int AS logins,
      count(*) FILTER (WHERE action IN ('save','restore'))::int AS edits
    FROM audit_log WHERE at > now() - interval '30 days' AND user_id IS NOT NULL GROUP BY user_id`)).rows.map(r => [r.user_id, r]));
  res.json({ users: rows.map(u => ({ id: u.id, username: u.username, display_name: u.display_name, role: u.role, is_owner: u.is_owner, disabled: u.disabled,
    created_at: u.created_at, last_login_at: u.last_login_at, last_seen_at: u.last_seen_at, tampered: !sealOk(u), scope: scopePub(u),
    logins30: (st.get(u.id) || {}).logins || 0, edits30: (st.get(u.id) || {}).edits || 0 })) });
}));
// brokers that exist in the portfolio (limited to what the asking admin can see), for the scope editor
app.get('/api/scope-options', need('admin'), wrap(async (req, res) => {
  const d = (await pool.query('SELECT data FROM portfolio WHERE id=1')).rows[0].data;
  const sc = SC.scopeOf(req.user);
  const o = SC.scopeOptions(SC.filterData(sc, d));
  const ruleBrokers = sc.rules.flatMap(r => r.b === '*' ? [] : r.b);
  const types = sc.rules.some(r => r.t === '*') ? SC.TYPES : [...new Set(sc.rules.flatMap(r => r.t))];
  res.json({ brokers: [...new Set([...o.brokers, ...ruleBrokers])].sort((a, b) => a.localeCompare(b, 'th')), types, mine: scopePub(req.user), anyBroker: sc.rules.some(r => r.b === '*') });
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
  // new users see nothing until rules are given
  const rules = req.body.rules !== undefined ? SC.parseRules(req.body.rules) : [];
  if (!rules) return res.status(400).json({ error: 'สิทธิ์ไม่ถูกต้อง' });
  if (!SC.withinScope(req.user, rules)) return res.status(403).json({ error: 'ให้สิทธิ์เกินกว่าที่คุณมีไม่ได้' });
  const hash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await tx(async c => { const r = await c.query(`INSERT INTO users (username, display_name, password_hash, role, scope_rules)
      VALUES ($1,$2,$3,$4,$5) RETURNING id`, [username, display || username, hash, role, JSON.stringify(rules)]); await reseal(c, r.rows[0].id); return r; });
    await audit(req.user, 'user_created', `${username} (${role}) · สิทธิ์: ${scopeTxt(rules)}`, null, true);
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
  if (b.rules !== undefined) {
    if (u.is_owner) return res.status(400).json({ error: 'เจ้าของระบบเห็นและแก้ได้ทั้งหมดเสมอ' });
    const rules = SC.parseRules(b.rules);
    if (!rules) return res.status(400).json({ error: 'สิทธิ์ไม่ถูกต้อง' });
    if (!SC.withinScope(req.user, rules)) return res.status(403).json({ error: 'ให้สิทธิ์เกินกว่าที่คุณมีไม่ได้' });
    add('scope_rules=?', JSON.stringify(rules));
    notes.push('สิทธิ์: ' + scopeTxt(rules));
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
  if (!fullScope(req.user)) return res.status(403).json({ error: 'เฉพาะผู้ที่เห็นข้อมูลทั้งหมด' });
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const { rows } = await pool.query(`SELECT id, at, username, action, detail, rev, security FROM audit_log
    WHERE action IN ('save','restore','import','price_auto','price_manual') ORDER BY id DESC LIMIT $1`, [limit]);
  res.json({ log: rows });
}));
app.get('/api/history', need('admin'), wrap(async (req, res) => {
  if (!fullScope(req.user)) return res.status(403).json({ error: 'เฉพาะผู้ที่เห็นข้อมูลทั้งหมด' });
  const { rows } = await pool.query(`SELECT h.rev, h.at, u.username, jsonb_array_length(h.data->'items') AS items
    FROM portfolio_history h LEFT JOIN users u ON u.id=h.user_id ORDER BY h.rev DESC LIMIT 100`);
  res.json({ history: rows });
}));
app.post('/api/history/:rev/restore', need('admin'), wrap(async (req, res) => {
  if (!fullScope(req.user)) return res.status(403).json({ error: 'เฉพาะผู้ที่เห็นข้อมูลทั้งหมด' });
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

// ---- activity log ----
// Events the browser reports (Excel files, reports). Everything else is logged by the server itself.
const CLIENT_EVENTS = ['export_backup', 'export_template', 'import', 'report_fee', 'report_income', 'report_realized', 'export_activity'];
const activityLimiter = rateLimit({ windowMs: 60e3, limit: 60, standardHeaders: true, legacyHeaders: false });
app.post('/api/activity', activityLimiter, need(), wrap(async (req, res) => {
  const { action, detail } = req.body || {};
  if (!CLIENT_EVENTS.includes(action)) return res.status(400).json({ error: 'ไม่รู้จักเหตุการณ์นี้' });
  if (action === 'import' && req.user.role === 'viewer') return res.status(403).json({ error: 'ไม่มีสิทธิ์' });
  await audit(req.user, action, detail ? String(detail).slice(0, 500) : null);
  res.json({ ok: true });
}));
const GROUPS = {
  login: ['login', 'logout', 'login_failed'],
  view: ['view'],
  edit: ['save', 'restore', 'import'],
  excel: ['export_backup', 'export_template', 'import', 'export_activity'],
  report: ['report_fee', 'report_income', 'report_realized'],
  users: ['user_created', 'user_updated', 'user_deleted', 'owner_transfer', 'tamper_approved', 'password_changed', 'scope_reset', 'owner_set'],
  price: ['price_auto', 'price_manual'],
};
// Who sees what: the owner sees everything; other admins see their own events and those of
// creator/viewer users (no security alerts); creators and viewers see only their own.
app.get('/api/activity', need(), wrap(async (req, res) => {
  const q = req.query, me = req.user, where = [], vals = [];
  const add = (sql, v) => { vals.push(v); where.push(sql.replace(/\?/g, '$' + vals.length)); };
  if (me.is_owner) { /* everything */ }
  else if (me.role === 'admin') {
    add(`(a.user_id = ? OR a.user_id IN (SELECT id FROM users WHERE role IN ('creator','viewer')))`, me.id);
    where.push('NOT a.security');
  } else add('a.user_id = ?', me.id);
  if (q.user) add('a.user_id = ?', Number(q.user));
  if (q.from && /^\d{4}-\d{2}-\d{2}$/.test(q.from)) add(`a.at >= (?::date)::timestamp AT TIME ZONE 'Asia/Bangkok'`, q.from);
  if (q.to && /^\d{4}-\d{2}-\d{2}$/.test(q.to)) add(`a.at < ((?::date + 1)::timestamp AT TIME ZONE 'Asia/Bangkok')`, q.to);
  if (q.group === 'security') where.push('a.security');
  else if (GROUPS[q.group]) add('a.action = ANY(?)', GROUPS[q.group]);
  if (q.before) add('a.id < ?', Number(q.before));
  const limit = Math.min(Number(q.limit) || 300, 5000);
  vals.push(limit);
  const { rows } = await pool.query(`SELECT a.id, a.at, a.user_id, a.username, u.display_name, u.role, a.action, a.detail, a.ip, a.device, a.security, a.rev
    FROM audit_log a LEFT JOIN users u ON u.id = a.user_id ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY a.id DESC LIMIT $${vals.length}`, vals);
  res.json({ log: rows, more: rows.length === limit });
}));

// ---- automatic prices ----
const PRICE_ON = process.env.PRICE_FEED !== 'off';
const DAILY_HOUR = Number(process.env.PRICE_DAILY_HOUR ?? 18); // Bangkok time, after the Thai market closes
const bkkDate = (d = new Date()) => new Date(d.getTime() + 7 * 3600e3).toISOString().slice(0, 10);
const bkkHour = (d = new Date()) => new Date(d.getTime() + 7 * 3600e3).getUTCHours();
const heldQty = it => (it.txns || []).reduce((q, t) => q + (t.side === 'buy' ? +t.qty || 0 : t.side === 'sell' ? -(+t.qty || 0) : 0), 0);
let priceRun = null;
// trigger: 'start' | 'daily' | 'login' | 'manual'
async function runPriceFeed(trigger, user) {
  if (!PRICE_ON) return { skipped: 'ปิดการดึงราคาอัตโนมัติไว้ (PRICE_FEED=off)' };
  if (priceRun) return priceRun; // one run at a time; others wait for it
  const last = await state.get('price_last');
  const age = last ? Date.now() - Date.parse(last.at) : Infinity;
  const minAge = { login: 15 * 60e3, manual: 60e3, daily: 0, start: 0 }[trigger] ?? 0;
  if (age < minAge) return { skipped: 'เพิ่งดึงราคาไปเมื่อ ' + Math.round(age / 60e3) + ' นาทีก่อน', last };
  priceRun = (async () => {
    const started = Date.now();
    const d0 = (await pool.query('SELECT data FROM portfolio WHERE id=1')).rows[0].data;
    const live = (d0.items || []).filter(i => heldQty(i) > 1e-9);
    const fetched = await PX.fetchAll(live, state);
    const client = await pool.connect();
    let result, rev = null;
    try {
      await client.query('BEGIN');
      const cur = (await client.query('SELECT data, rev FROM portfolio WHERE id=1 FOR UPDATE')).rows[0];
      const liveIds = new Set(live.map(i => i.id));
      // only items that are still held get new prices; the rest of the data is untouched
      const part = { items: cur.data.items.filter(i => liveIds.has(i.id)), fx: cur.data.fx, cash: [] };
      const { data: upd, res } = PX.applyQuotes(part, fetched);
      result = res;
      const byId = new Map(upd.items.map(i => [i.id, i]));
      const next = { ...cur.data, items: cur.data.items.map(i => byId.get(i.id) || i), fx: upd.fx };
      const changed = res.updated.length || (res.fx && res.fx.from !== res.fx.rate);
      if (changed) {
        rev = cur.rev + 1;
        await client.query('UPDATE portfolio SET data=$1, rev=$2, updated_at=now(), updated_by=NULL WHERE id=1', [next, rev]);
      }
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
    finally { client.release(); }
    for (const [key, q] of Object.entries(fetched.quotes)) if (q && !q.error)
      pool.query('INSERT INTO price_quotes (symbol, source, price, currency, quote_time) VALUES ($1,$2,$3,$4,$5)',
        [key, q.source, q.price, q.currency, /^\d{4}-\d{2}-\d{2}/.test(String(q.at || '')) ? q.at : null]).catch(() => {});
    if (fetched.fx && fetched.fx.rate) pool.query('INSERT INTO price_quotes (symbol, source, price, currency) VALUES ($1,$2,$3,$4)', ['fx:USDTHB', fetched.fx.source, fetched.fx.rate, 'THB']).catch(() => {});
    const summary = { at: new Date().toISOString(), trigger, by: user ? user.username : null, ms: Date.now() - started, rev, ...result };
    await state.set('price_last', summary);
    const TRIG = { start: 'เริ่มระบบ', daily: 'รอบประจำวัน', login: 'เข้าสู่ระบบ', manual: 'กดดึงราคา' };
    await audit(user || null, trigger === 'manual' ? 'price_manual' : 'price_auto',
      `ดึงราคา (${TRIG[trigger] || trigger}): อัปเดต ${result.updated.length} รายการ` +
      (result.fx ? ` · USD/THB ${result.fx.rate}` : '') +
      (result.failed.length ? ` · ไม่สำเร็จ ${result.failed.length}: ` + result.failed.map(f => f.name).join(', ') : ''), rev);
    if (result.failed.length) console.warn('price feed failures:', result.failed.map(f => `${f.name} (${f.symbol || ''}): ${f.error}`).join(' | '));
    return summary;
  })();
  try { return await priceRun; } finally { priceRun = null; }
}
// what a user may see of the last run (only their own items)
async function priceStatusFor(u, last) {
  if (!last) return null;
  const sc = SC.scopeOf(u);
  if (sc.full) return last;
  const d = (await pool.query('SELECT data FROM portfolio WHERE id=1')).rows[0].data;
  const names = new Set(SC.filterData(sc, d).items.map(i => i.name));
  return { ...last, updated: (last.updated || []).filter(x => names.has(x.name)), failed: (last.failed || []).filter(x => names.has(x.name) || x.name === 'USD/THB') };
}
app.post('/api/prices/refresh', need(), wrap(async (req, res) => {
  const reason = (req.body || {}).reason === 'manual' ? 'manual' : 'login';
  if (reason === 'manual' && req.user.role === 'viewer') return res.status(403).json({ error: 'ไม่มีสิทธิ์' });
  try {
    const r = await runPriceFeed(reason, req.user);
    if (r.skipped) return res.json({ skipped: r.skipped, last: await priceStatusFor(req.user, r.last || await state.get('price_last')) });
    res.json({ ran: true, rev: r.rev, last: await priceStatusFor(req.user, r) });
  } catch (e) {
    console.error('price feed failed', e);
    res.status(502).json({ error: 'ดึงราคาไม่สำเร็จ: ' + e.message });
  }
}));
app.get('/api/prices/status', need(), wrap(async (req, res) => {
  res.json({ enabled: PRICE_ON, dailyHour: DAILY_HOUR, fundKey: !!(process.env.SEC_API_KEY || '').trim(),
    last: await priceStatusFor(req.user, await state.get('price_last')) });
}));

// daily jobs: prices once a day after DAILY_HOUR (Bangkok), activity log retention
const HEARTBEAT_HOUR = Number(process.env.TELEGRAM_DAILY_HOUR ?? 8);
const RETENTION_DAYS = Math.max(30, Number(process.env.ACTIVITY_RETENTION_DAYS) || 365);
async function housekeeping() {
  try {
    if (PRICE_ON) {
      const last = await state.get('price_last');
      if (bkkHour() >= DAILY_HOUR && (await state.get('price_daily_day')) !== bkkDate()) {
        await runPriceFeed('daily', null);
        await state.set('price_daily_day', bkkDate());
      } else if (!last || Date.now() - Date.parse(last.at) > 26 * 3600e3) {
        await runPriceFeed('start', null); // never fetched, or the server was off for a while
      }
    }
    const day = bkkDate();
    if ((await state.get('retention_day')) !== day) {
      const r = await tx(async c => {
        const w = (await c.query(`SELECT max(id) AS w FROM audit_log WHERE NOT security AND at < now() - make_interval(days => $1)`, [RETENTION_DAYS])).rows[0].w;
        const del = await c.query(`DELETE FROM audit_log WHERE NOT security AND at < now() - make_interval(days => $1)`, [RETENTION_DAYS]);
        if (w) await c.query(`INSERT INTO app_state (key, value) VALUES ('log_retention', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`,
          [JSON.stringify({ w: String(w), sig: hmac('ret|' + w) })]);
        return del;
      });
      await pool.query(`DELETE FROM price_quotes WHERE at < now() - interval '400 days'`);
      await state.set('retention_day', day);
      if (r.rowCount) console.log(`activity log: removed ${r.rowCount} entries older than ${RETENTION_DAYS} days`);
    }
    // daily "all is well" message: if it stops arriving, something is wrong with the server or the settings
    if (NOTIFY.enabled() && bkkHour() >= HEARTBEAT_HOUR && (await state.get('heartbeat_day')) !== day) {
      await state.set('heartbeat_day', day);
      const st = (await pool.query(`SELECT count(*) FILTER (WHERE action='login')::int AS logins, count(*) FILTER (WHERE action IN ('save','restore'))::int AS edits,
        count(*) FILTER (WHERE security)::int AS sec, count(*) FILTER (WHERE action='login_failed')::int AS fails FROM audit_log WHERE at > now() - interval '24 hours'`)).rows[0];
      NOTIFY.send(`✅ ${APP_NAME} v${VERSION} ทำงานปกติ\n24 ชม.ที่ผ่านมา: เข้าระบบ ${st.logins} ครั้ง · บันทึกข้อมูล ${st.edits} ครั้ง · ใส่รหัสผิด ${st.fails} ครั้ง · แจ้งเตือนความปลอดภัย ${st.sec} รายการ${logState.broken ? '\n⚠️ ประวัติการใช้งานเคยถูกแก้/ลบ ดูแถบแดงในโปรแกรม' : ''}`);
    }
  } catch (e) { console.error('housekeeping failed', e.message); }
}

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

// Check the activity log chain. Full check at start-up, then only new rows.
const logState = { last: null, maxSeen: 0, broken: false, reported: new Set() };
async function logAlert(key, detail) {
  if (logState.reported.has(key)) return;
  logState.reported.add(key); logState.broken = true;
  const seen = await pool.query(`SELECT 1 FROM audit_log WHERE action='log_tamper' AND detail=$1 LIMIT 1`, [detail]);
  if (!seen.rows.length) await audit(null, 'log_tamper', detail, null, true);
}
async function verifyLog() {
  const ret = await state.get('log_retention');
  if (ret && !eq(ret.sig, hmac('ret|' + ret.w))) await logAlert('ret', 'ค่าการลบประวัติเก่าถูกแก้ในฐานข้อมูลโดยตรง');
  const W = ret && eq(ret.sig, hmac('ret|' + ret.w)) ? Number(ret.w) : 0;
  let after = logState.last ? Number(logState.last.id) : 0, prev = logState.last;
  for (;;) {
    const { rows } = await pool.query(`SELECT id, at, user_id, username, action, detail, rev, security, ip, device, prev_id, prev_hash, hash
      FROM audit_log WHERE id > $1 ORDER BY id LIMIT 5000`, [after]);
    if (!rows.length) break;
    for (const r of rows) {
      after = Number(r.id);
      if (!r.hash) {
        // rows without a hash: older than v1.3.0, or written by the database trigger itself
        if (prev && r.action !== 'db_direct_change') await logAlert('fake:' + r.id, `มีรายการในประวัติที่ไม่ได้มาจากโปรแกรม (รายการที่ ${r.id}: ${r.action})`);
        continue;
      }
      const row = { ...r, id: String(r.id), at: new Date(r.at).toISOString() };
      if (logHash(r.prev_hash, row) !== r.hash) await logAlert('mod:' + r.id, `ประวัติรายการที่ ${r.id} (${r.action}) ถูกแก้ในฐานข้อมูลโดยตรง`);
      const expectId = prev ? String(prev.id) : null;
      if (String(r.prev_id ?? '') !== String(expectId ?? '') || (prev && r.prev_hash !== prev.hash)) {
        const gone = r.prev_id ? Number(r.prev_id) : 0;
        if (!(gone && gone <= W) && !(!prev && !r.prev_id))
          await logAlert('gap:' + r.id, `ประวัติก่อนรายการที่ ${r.id} ถูกลบในฐานข้อมูลโดยตรง (หายไปตั้งแต่รายการที่ ${r.prev_id ?? '?'})`);
      }
      prev = { id: String(r.id), hash: r.hash };
    }
  }
  logState.last = prev;
  // rows removed from the end since the last check
  const mx = Number((await pool.query('SELECT max(id) AS m FROM audit_log WHERE hash IS NOT NULL')).rows[0].m || 0);
  if (mx < logState.maxSeen) await logAlert('tail:' + logState.maxSeen, `ประวัติการใช้งานล่าสุดถูกลบในฐานข้อมูลโดยตรง (เคยมีถึงรายการที่ ${logState.maxSeen} ตอนนี้เหลือถึง ${mx})`);
  logState.maxSeen = Math.max(logState.maxSeen, mx);
  if (logState.last && mx < Number(logState.last.id)) logState.last = null; // re-check from the start next time
}

async function integrityCheck() {
  try {
    const t = await pool.query(`SELECT tgname, tgenabled FROM pg_trigger WHERE tgname IN ('portdee_users_guard','portdee_audit_guard') AND NOT tgisinternal`);
    const ok = n => t.rows.some(r => r.tgname === n && r.tgenabled !== 'D');
    if (!ok('portdee_users_guard') || !ok('portdee_audit_guard')) {
      await installGuard();
      await audit(null, 'guard_missing', 'ตัวป้องกันในฐานข้อมูลถูกลบหรือปิดไว้ ระบบติดตั้งคืนให้แล้ว (มีคนแก้โครงสร้างฐานข้อมูลโดยตรง)', null, true);
    }
    for (const u of (await pool.query('SELECT * FROM users')).rows) if (!sealOk(u)) await flagTamper(u);
    await verifyLog();
  } catch (e) { console.error('integrity check failed', e.message); }
}

setup()
  .then(() => {
    setInterval(integrityCheck, 5 * 60e3); integrityCheck();
    NOTIFY.send(`▶️ ${APP_NAME} v${VERSION} เริ่มทำงาน (deploy หรือรีสตาร์ต) · ถ้าคุณไม่ได้สั่ง ให้ตรวจว่าใครแก้ระบบ`);
    setInterval(housekeeping, 30 * 60e3); housekeeping();
    app.listen(PORT, () => console.log(`${APP_NAME} v${VERSION} listening on port ${PORT}`));
  })
  .catch(e => { console.error('Database setup failed:', e); process.exit(1); });
