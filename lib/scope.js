// Access rules: what each user may see and edit.
// A user has a list of rules; each rule covers some brokers × some asset types at a level:
//   { b: '*' | ['KTX', ...], t: '*' | ['th', 'au', ...], l: 'view' | 'edit' }
// e.g. view Dime (all types) · view KTX gold · edit KTX Thai stocks.
// The owner always has everything. Viewers are limited to 'view' whatever their rules say.
// Filtering happens on the server, so data outside the rules never reaches the browser.
'use strict';

const NOBRK = 'ไม่ระบุโบรกเกอร์';
const TYPES = ['th', 'fd', 'fx', 'etf', 'au', 'bd', 'gsb', 'cs'];
const brokerOf = item => (item && item.acc) || NOBRK;
const cashBroker = c => (c && c.acc) || NOBRK;
const ALL = { b: '*', t: '*', l: 'edit' };

function cleanRule(r) {
  if (!r || typeof r !== 'object') return null;
  const b = r.b === '*' ? '*' : Array.isArray(r.b) ? [...new Set(r.b.map(x => String(x).trim()).filter(Boolean))].slice(0, 200) : null;
  const t = r.t === '*' ? '*' : Array.isArray(r.t) ? [...new Set(r.t.map(String))].filter(x => TYPES.includes(x)) : null;
  if (!b || !t || (b !== '*' && (!b.length || b.some(x => x.length > 100))) || (t !== '*' && !t.length)) return null;
  return { b: b === '*' ? '*' : b.sort(), t: t === '*' ? '*' : t.sort(), l: r.l === 'edit' ? 'edit' : 'view' };
}
// validate rules sent by the browser; returns null if anything is malformed
function parseRules(list) {
  if (!Array.isArray(list) || list.length > 50) return null;
  const out = [];
  for (const r of list) { const c = cleanRule(r); if (!c) return null; out.push(c); }
  return out;
}
const rulesKey = rules => JSON.stringify((rules || []).map(r => [r.b, r.t, r.l]).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))));

function scopeOf(u) {
  if (u.is_owner) return { owner: true, full: true, fullEdit: true, rules: [ALL] };
  let rules = (Array.isArray(u.scope_rules) ? u.scope_rules : []).map(cleanRule).filter(Boolean);
  if (u.role === 'viewer') rules = rules.map(r => ({ ...r, l: 'view' }));
  const all = r => r.b === '*' && r.t === '*';
  return { owner: false, full: rules.some(all), fullEdit: rules.some(r => all(r) && r.l === 'edit'), rules };
}
const covers = (r, b, t) => (r.b === '*' || r.b.includes(b)) && (t === null || r.t === '*' || r.t.includes(t));
const canSeeItem = (sc, i) => sc.rules.some(r => covers(r, brokerOf(i), i.type));
const canEditItem = (sc, i) => sc.rules.some(r => r.l === 'edit' && covers(r, brokerOf(i), i.type));
const canSeeCash = (sc, c) => sc.rules.some(r => covers(r, cashBroker(c), null));
const canEditCash = (sc, c) => sc.rules.some(r => r.l === 'edit' && covers(r, cashBroker(c), null));

function filterCfg(cfg, keep) {
  const bc = (cfg && cfg.bcost) || {};
  return { ...(cfg || {}), bcost: Object.fromEntries(Object.entries(bc).filter(([b]) => keep(b))) };
}
function filterData(sc, data) {
  if (sc.full) return data;
  const items = (data.items || []).filter(i => canSeeItem(sc, i));
  const cash = (data.cash || []).filter(c => canSeeCash(sc, c));
  const seen = new Set([...items.map(brokerOf), ...cash.map(cashBroker)]);
  return { items, fx: data.fx, cash, cfg: filterCfg(data.cfg, b => seen.has(b)) };
}

const strip = i => JSON.stringify({ ...i, price: undefined, pxAt: undefined, pxSrc: undefined });
// Combine what a user saved with everything they may not change.
// Items they can only view are kept as stored (a changed shared price, for example, is ignored).
// Returns { data, ignored: [names] } or { error }.
function mergeData(sc, stored, submitted) {
  const sub = { items: submitted.items || [], fx: submitted.fx, cash: submitted.cash || [], cfg: submitted.cfg };
  if (sc.fullEdit) return { data: { items: sub.items, fx: sub.fx, cash: sub.cash, cfg: sub.cfg || stored.cfg || {} }, ignored: [] };
  const ignored = [];
  const hiddenItems = (stored.items || []).filter(i => !canSeeItem(sc, i));
  const visible = new Map((stored.items || []).filter(i => canSeeItem(sc, i)).map(i => [i.id, i]));
  const hiddenCash = (stored.cash || []).filter(c => !canSeeCash(sc, c));
  const visCash = new Map((stored.cash || []).filter(c => canSeeCash(sc, c)).map(c => [c.id, c]));
  const hiddenIds = new Set([...hiddenItems.map(i => i.id), ...hiddenCash.map(c => c.id)]);
  const items = [], cash = [], seenIds = new Set();
  for (const i of sub.items) {
    if (hiddenIds.has(i.id) || seenIds.has(i.id)) return { error: 'ข้อมูลไม่ถูกต้อง (รหัสรายการซ้ำ)' };
    seenIds.add(i.id);
    const old = visible.get(i.id);
    if (old && !canEditItem(sc, old)) { items.push(old); if (strip(old) !== strip(i)) ignored.push(old.name); continue; }
    if (!canEditItem(sc, i)) return { error: `"${i.name}" (${brokerOf(i)}) อยู่นอกขอบเขตที่คุณแก้ไขได้` };
    items.push(i);
  }
  for (const [id, old] of visible) if (!seenIds.has(id)) {
    if (canEditItem(sc, old)) continue; // deleted
    items.push(old); ignored.push(old.name);
  }
  for (const c of sub.cash) {
    if (hiddenIds.has(c.id) || seenIds.has(c.id)) return { error: 'ข้อมูลไม่ถูกต้อง (รหัสรายการซ้ำ)' };
    seenIds.add(c.id);
    const old = visCash.get(c.id);
    if (old && !canEditCash(sc, old)) { cash.push(old); if (JSON.stringify(old) !== JSON.stringify(c)) ignored.push('เงินสด ' + cashBroker(old)); continue; }
    if (!canEditCash(sc, c)) return { error: `เงินสดของโบรก "${cashBroker(c)}" อยู่นอกขอบเขตที่คุณแก้ไขได้` };
    cash.push(c);
  }
  for (const [id, old] of visCash) if (!seenIds.has(id) && !canEditCash(sc, old)) { cash.push(old); ignored.push('เงินสด ' + cashBroker(old)); }
  return {
    // exchange rates and broker settings affect everyone: only users who can edit everything change them
    data: { items: [...hiddenItems, ...items], fx: stored.fx, cash: [...hiddenCash, ...cash], cfg: stored.cfg || {} },
    ignored: [...new Set(ignored)],
  };
}

function scopeOptions(data) {
  const brokers = new Set();
  for (const i of data.items || []) brokers.add(brokerOf(i));
  for (const c of data.cash || []) brokers.add(cashBroker(c));
  return { brokers: [...brokers].sort((a, b) => a.localeCompare(b, 'th')), types: TYPES };
}

// Can `actor` hand out these rules? Every broker × type × level in them must be covered by the actor's own rules.
function withinScope(actor, rules) {
  const a = scopeOf(actor);
  if (a.fullEdit) return true;
  const ok = (b, t, l) => a.rules.some(r => (l === 'view' || r.l === 'edit') &&
    (r.b === '*' || (b !== '*' && r.b.includes(b))) && (r.t === '*' || (t !== '*' && r.t.includes(t))));
  for (const r of rules) {
    for (const b of r.b === '*' ? ['*'] : r.b) for (const t of r.t === '*' ? ['*'] : r.t) if (!ok(b, t, r.l)) return false;
  }
  return true;
}
// legacy single scope (v1.2.0 columns) → one rule
function legacyRule(u) {
  const b = u.scope_all_brokers ? '*' : (u.scope_brokers || []);
  const t = u.scope_all_types ? '*' : (u.scope_types || []);
  if ((b !== '*' && !b.length) || (t !== '*' && !t.length)) return [];
  return [cleanRule({ b, t, l: u.role === 'viewer' ? 'view' : 'edit' })].filter(Boolean);
}

module.exports = { NOBRK, TYPES, scopeOf, parseRules, rulesKey, canSeeItem, canEditItem, canSeeCash, canEditCash, filterData, mergeData, scopeOptions, withinScope, legacyRule };
