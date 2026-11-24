'use strict';
const assert = require('assert');
const SC = require('../lib/scope');
const d = { items: [
  { id: '1', acc: 'KTX', type: 'th', name: 'PTT', price: 30 }, { id: '2', acc: 'KTX', type: 'au', name: 'GOLD', price: 2600 },
  { id: '3', acc: 'Dime', type: 'fx', name: 'AMD', price: 450 }, { id: '4', acc: 'KS', type: 'th', name: 'SCB', price: 110 },
  { id: '5', acc: 'Dime', type: 'th', name: 'PTT', price: 30 }],
  fx: { USD: 33 }, cash: [{ id: 'c1', acc: 'KTX' }, { id: 'c2', acc: 'Dime' }, { id: 'c3', acc: 'KS' }],
  cfg: { bcost: { Dime: 'fifo', KTX: 'fifo', KS: 'fifo' } } };
// the user's example: view Dime (all) · view KTX gold · edit KTX Thai stocks
const u = { role: 'creator', scope_rules: [{ b: ['Dime'], t: '*', l: 'view' }, { b: ['KTX'], t: ['au'], l: 'view' }, { b: ['KTX'], t: ['th'], l: 'edit' }] };
const sc = SC.scopeOf(u);
const f = SC.filterData(sc, d);
assert.deepStrictEqual(f.items.map(i => i.id), ['1', '2', '3', '5']);
assert.deepStrictEqual(f.cash.map(c => c.id), ['c1', 'c2']);
assert.deepStrictEqual(Object.keys(f.cfg.bcost).sort(), ['Dime', 'KTX'], 'broker settings only for visible brokers');
assert.ok(SC.canEditItem(sc, d.items[0]) && !SC.canEditItem(sc, d.items[1]) && !SC.canEditItem(sc, d.items[2]));
// edit PTT@KTX, try to change AMD (view-only) and price of PTT@Dime (shared price) → kept as stored
const sub = JSON.parse(JSON.stringify(f));
sub.items[0].note = 'mine'; sub.items[2].name = 'HACK'; sub.items[3].price = 31; sub.fx = { USD: 99 };
sub.items.push({ id: '9', acc: 'KTX', type: 'th', name: 'KBANK', txns: [] });
let m = SC.mergeData(sc, d, sub);
assert.ok(!m.error, m.error);
const byId = Object.fromEntries(m.data.items.map(i => [i.id, i]));
assert.strictEqual(byId['1'].note, 'mine'); assert.strictEqual(byId['3'].name, 'AMD'); assert.strictEqual(byId['5'].price, 30);
assert.ok(byId['9'] && byId['4'], 'new editable item added, hidden item kept');
assert.deepStrictEqual(m.ignored, ['AMD'], 'price-only change on a view-only sibling is not reported');
assert.strictEqual(m.data.fx.USD, 33);
// deleting a view-only item is ignored; deleting an editable one works
const sub2 = JSON.parse(JSON.stringify(f)); sub2.items = sub2.items.filter(i => i.id !== '2' && i.id !== '1');
m = SC.mergeData(sc, d, sub2);
assert.ok(m.data.items.some(i => i.id === '2') && !m.data.items.some(i => i.id === '1'));
// adding outside edit rules is refused; moving an editable item to a view-only broker is refused
assert.ok(SC.mergeData(sc, d, { items: [...f.items, { id: '8', acc: 'Dime', type: 'th', name: 'X' }], cash: f.cash }).error);
const sub3 = JSON.parse(JSON.stringify(f)); sub3.items[0].acc = 'Dime';
assert.ok(SC.mergeData(sc, d, sub3).error);
// cash: KTX editable (edit rule on KTX), Dime view-only
const sub4 = JSON.parse(JSON.stringify(f)); sub4.cash.push({ id: 'c9', acc: 'KTX', amt: 5 });
assert.ok(!SC.mergeData(sc, d, sub4).error);
const sub5 = JSON.parse(JSON.stringify(f)); sub5.cash.push({ id: 'c8', acc: 'Dime', amt: 5 });
assert.ok(SC.mergeData(sc, d, sub5).error);
// viewers never edit
const v = SC.scopeOf({ role: 'viewer', scope_rules: [{ b: '*', t: '*', l: 'edit' }] });
assert.ok(v.full && !v.fullEdit && !SC.canEditItem(v, d.items[0]));
// owner
assert.ok(SC.scopeOf({ is_owner: true }).fullEdit);
// handing out rules
assert.ok(SC.withinScope(u, [{ b: ['KTX'], t: ['th'], l: 'edit' }, { b: ['Dime'], t: ['fx'], l: 'view' }]));
assert.ok(!SC.withinScope(u, [{ b: ['Dime'], t: ['fx'], l: 'edit' }]));
assert.ok(!SC.withinScope(u, [{ b: '*', t: ['th'], l: 'view' }]));
// validation and legacy conversion
assert.strictEqual(SC.parseRules([{ b: [], t: '*', l: 'view' }]), null);
assert.deepStrictEqual(SC.parseRules([{ b: ['B', 'A'], t: ['au', 'th', 'zz'], l: 'x' }]), [{ b: ['A', 'B'], t: ['au', 'th'], l: 'view' }]);
assert.deepStrictEqual(SC.legacyRule({ role: 'creator', scope_all_brokers: false, scope_brokers: ['KS'], scope_all_types: true }), [{ b: ['KS'], t: '*', l: 'edit' }]);
assert.deepStrictEqual(SC.legacyRule({ role: 'viewer', scope_brokers: [], scope_types: ['th'] }), []);
console.log('scope: all ok');
