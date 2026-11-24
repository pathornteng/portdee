// Per-user access scope: which brokers and which asset types a user may see and edit.
// The owner always sees everything. Everyone else sees an item only if BOTH its broker
// and its asset type are inside their scope. Filtering happens on the server, so data
// outside the scope never reaches the browser.
'use strict';

const NOBRK = 'ไม่ระบุโบรกเกอร์';
const TYPES = ['th', 'fd', 'fx', 'etf', 'au', 'bd', 'gsb', 'cs'];
const brokerOf = item => (item && item.acc) || NOBRK;
const cashBroker = c => (c && c.acc) || NOBRK;

function scopeOf(u) {
  if (u.is_owner) return { full: true, allBrokers: true, allTypes: true, brokers: [], types: [] };
  const allBrokers = !!u.scope_all_brokers, allTypes = !!u.scope_all_types;
  return { full: allBrokers && allTypes, allBrokers, allTypes, brokers: u.scope_brokers || [], types: u.scope_types || [] };
}
const brokerOk = (sc, b) => sc.allBrokers || sc.brokers.includes(b);
const typeOk = (sc, t) => sc.allTypes || sc.types.includes(t);
const canSeeItem = (sc, item) => brokerOk(sc, brokerOf(item)) && typeOk(sc, item.type);
const canSeeCash = (sc, c) => brokerOk(sc, cashBroker(c));

function filterData(sc, data) {
  if (sc.full) return data;
  return {
    items: (data.items || []).filter(i => canSeeItem(sc, i)),
    fx: data.fx,
    cash: (data.cash || []).filter(c => canSeeCash(sc, c)),
  };
}

// Combine what a scoped user saved with everything they cannot see.
// Returns { data } or { error }.
function mergeData(sc, stored, submitted) {
  if (sc.full) return { data: { items: submitted.items, fx: submitted.fx, cash: submitted.cash || [] } };
  const hiddenItems = (stored.items || []).filter(i => !canSeeItem(sc, i));
  const hiddenCash = (stored.cash || []).filter(c => !canSeeCash(sc, c));
  const hiddenIds = new Set([...hiddenItems.map(i => i.id), ...hiddenCash.map(c => c.id)]);
  for (const i of submitted.items || []) {
    if (!canSeeItem(sc, i)) return { error: `"${i.name}" (${brokerOf(i)}) อยู่นอกขอบเขตที่คุณมีสิทธิ์` };
    if (hiddenIds.has(i.id)) return { error: 'ข้อมูลไม่ถูกต้อง (รหัสซ้ำกับรายการที่คุณไม่มีสิทธิ์)' };
  }
  for (const c of submitted.cash || []) {
    if (!canSeeCash(sc, c)) return { error: `เงินสดของโบรก "${cashBroker(c)}" อยู่นอกขอบเขตที่คุณมีสิทธิ์` };
    if (hiddenIds.has(c.id)) return { error: 'ข้อมูลไม่ถูกต้อง (รหัสซ้ำกับรายการที่คุณไม่มีสิทธิ์)' };
  }
  return {
    data: {
      items: [...hiddenItems, ...(submitted.items || [])],
      fx: stored.fx, // only users with full scope may change exchange rates
      cash: [...hiddenCash, ...(submitted.cash || [])],
    },
  };
}

// Brokers / types that exist in the data (for the scope editor).
function scopeOptions(data) {
  const brokers = new Set();
  for (const i of data.items || []) brokers.add(brokerOf(i));
  for (const c of data.cash || []) brokers.add(cashBroker(c));
  return { brokers: [...brokers].sort((a, b) => a.localeCompare(b, 'th')), types: TYPES };
}

// Can `actor` grant scope `sc`? A limited admin can only hand out what they have.
function withinScope(actor, sc) {
  const a = scopeOf(actor);
  if (a.full) return true;
  if (sc.allBrokers && !a.allBrokers) return false;
  if (sc.allTypes && !a.allTypes) return false;
  if (!a.allBrokers && sc.brokers.some(b => !a.brokers.includes(b))) return false;
  if (!a.allTypes && sc.types.some(t => !a.types.includes(t))) return false;
  return true;
}

module.exports = { NOBRK, TYPES, scopeOf, canSeeItem, canSeeCash, filterData, mergeData, scopeOptions, withinScope };
