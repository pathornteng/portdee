'use strict';
const assert = require('assert');
process.env.SEC_API_KEY = 'testkey';
const mock = require('./mock-fetch');
const PX = require('../lib/prices');
PX.setFetch(mock.fetch);
const mem = {}; const state = { get: async k => mem[k], set: async (k, v) => { mem[k] = v; } };
const it = (id, type, name, cur, extra = {}) => ({ id, type, name, cur, price: 1, txns: [{ side: 'buy', qty: 1, price: 1 }], ...extra });
(async () => {
  const items = [
    it('a', 'th', 'PTT', 'THB'), it('b', 'fx', 'AAPL', 'USD'), it('c', 'etf', 'VOO', 'USD'),
    it('d', 'au', 'GOLD', 'USD'), it('e', 'au', 'ทองไทย', 'THB'),
    it('f', 'fd', 'K-USA-A(A)', 'THB'), it('g', 'fd', 'SCBSET', 'THB'), it('h', 'fd', 'K-USA', 'THB'),
    it('i', 'th', 'NOPE', 'THB'), it('j', 'bd', 'LB30DA', 'THB'), it('k', 'th', 'PTT', 'THB', { acc: 'B2' }),
    it('l', 'fx', 'BABA', 'USD', { sym: '-' }), it('m', 'fx', 'SCB', 'USD', { sym: 'SCB.BK' }),
  ];
  const f = await PX.fetchAll(items, state);
  const { data, res } = PX.applyQuotes({ items, fx: { THB: 1, USD: 33.5 }, cash: [] }, f, '2026-11-24T11:00:00Z');
  const P = id => data.items.find(x => x.id === id).price;
  assert.strictEqual(data.fx.USD, 33.87);
  assert.strictEqual(P('a'), 34.25); assert.strictEqual(P('k'), 34.25);        // same stock, two brokers, one price
  assert.strictEqual(P('b'), 231.5); assert.strictEqual(P('c'), 540.1);
  assert.strictEqual(P('d'), 2660.55);                                          // gold USD/oz from xaus
  assert.strictEqual(P('e'), +(2660.55 * 33.87).toFixed(2));                    // gold in THB per oz
  assert.strictEqual(P('f'), 15.1234);                                          // fund class picked by name
  assert.strictEqual(P('g'), 9.8765);
  assert.strictEqual(P('h'), 1, 'K-USA has several classes → not guessed');
  assert.ok(res.failed.find(x => x.name === 'K-USA' && /หลายชนิดหน่วย/.test(x.error)));
  assert.ok(res.failed.find(x => x.name === 'NOPE'));
  assert.strictEqual(P('j'), 1); assert.strictEqual(P('l'), 1);                  // bonds and "-" skipped
  assert.strictEqual(P('m'), +(118 / 33.87).toFixed(4));                        // THB quote → USD item
  assert.ok(data.items.find(x => x.id === 'a').pxSrc.startsWith('Yahoo PTT.BK'));
  assert.strictEqual(items[0].price, 1, 'input not mutated');
  assert.strictEqual(mock.calls.filter(u => u.includes('PTT.BK')).length, 1, 'each symbol fetched once');
  // index cached: a second run does not reload the fund list
  const before = mock.calls.filter(u => u.includes('profiles')).length;
  await PX.fetchAll([it('f', 'fd', 'K-USA-A(A)', 'THB')], state);
  assert.strictEqual(mock.calls.filter(u => u.includes('profiles')).length, before);
  // fallbacks
  PX._reset();
  PX.setFetch(async (url, o) => /xaus|frankfurter/.test(url) ? { ok: false, status: 503, json: async () => ({}) } : mock.fetch(url, o));
  const g = await PX.goldUsdOz(); assert.strictEqual(g.price, 2650); assert.match(g.source, /GC=F/);
  const x = await PX.usdThb(); assert.strictEqual(x.rate, 34.1);
  // no key
  delete process.env.SEC_API_KEY;
  await assert.rejects(PX.fundNav('SCBSET', null), /SEC_API_KEY/);
  assert.strictEqual(PX.sourceFor({ type: 'fx', name: 'BRK.B', cur: 'USD' }).symbol, 'BRK-B');
  assert.strictEqual(PX.sourceFor({ type: 'th', name: 'BBL.R', cur: 'THB' }).symbol, 'BBL.R.BK');
  assert.strictEqual(PX.sourceFor({ type: 'fx', name: 'BRK.B', cur: 'USD', sym: 'BRK.B' }).symbol, 'BRK.B', 'own symbol wins');
  console.log('prices: all ok');
})().catch(e => { console.error(e); process.exit(1); });
