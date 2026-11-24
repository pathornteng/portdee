// Fake price sources for tests (PRICE_FEED_MOCK=test/mock-fetch.js). No network needed.
'use strict';
const json = (o, status = 200) => ({ ok: status < 400, status, json: async () => o });
const STOCK = { 'PTT.BK': [34.25, 'THB'], 'AAPL': [231.5, 'USD'], 'VOO': [540.1, 'USD'], 'SCB.BK': [118, 'THB'], 'GC=F': [2650, 'USD'], 'THB=X': [34.1, 'THB'] };
exports.calls = [];
exports.fetch = async (url, opt) => {
  exports.calls.push(url);
  const u = new URL(url);
  if (u.host === 'query1.finance.yahoo.com') {
    const sym = decodeURIComponent(u.pathname.split('/').pop());
    const s = STOCK[sym];
    if (!s) return json({ chart: { result: null, error: { code: 'Not Found', description: 'No data found, symbol may be delisted' } } }, 404);
    return json({ chart: { result: [{ meta: { regularMarketPrice: s[0], currency: s[1], regularMarketTime: 1764000000 } }], error: null } });
  }
  if (u.host === 'xaus.com') return json({ spot_usd_oz: 2660.55, timestamp: '2026-11-24T10:00:00Z' });
  if (u.host === 'api.frankfurter.dev') return json({ amount: 1, base: 'USD', date: '2026-11-24', rates: { THB: 33.87 } });
  if (u.host === 'api.sec.or.th') {
    if (opt.headers['Ocp-Apim-Subscription-Key'] !== 'testkey') return json({ message: 'denied' }, 401);
    if (u.pathname.endsWith('/general-info/profiles')) {
      if (u.searchParams.get('fund_status') === 'IPO') return json({ items: [] });
      if (!u.searchParams.get('next_cursor')) return json({ items: [{ proj_id: 'M0001_2550', proj_abbr_name: 'K-USA' }, { proj_id: 'M0002_2560', proj_abbr_name: 'SCBSET' }], next_cursor: 'p2' });
      return json({ items: [{ proj_id: 'M0003_2563', proj_abbr_name: 'KKP GB THAI ESG' }] });
    }
    if (u.pathname.endsWith('/daily-info/nav')) {
      const p = u.searchParams.get('proj_id');
      if (p === 'M0001_2550') return json({ items: [
        { proj_id: p, fund_class_name: 'K-USA-A(A)', nav_date: '2026-11-21', last_val: 15.1234 },
        { proj_id: p, fund_class_name: 'K-USA-A(A)', nav_date: '2026-11-20', last_val: 15.0 },
        { proj_id: p, fund_class_name: 'K-USA-SSF', nav_date: '2026-11-21', last_val: 12.5 }] });
      if (p === 'M0002_2560') return json({ items: [{ proj_id: p, fund_class_name: null, nav_date: '2026-11-21', last_val: 9.8765 }] });
      return json({ items: [] });
    }
  }
  throw new Error('mock: unexpected URL ' + url);
};
