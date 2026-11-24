// Automatic prices from free sources.
//   Thai stocks / Thai ETFs (THB)   Yahoo Finance chart API, symbol NAME.BK
//   Foreign stocks / ETFs (USD)     Yahoo Finance chart API, symbol NAME
//   Gold (99.99%, USD per ounce)    xaus.com spot (no key); Yahoo GC=F as backup
//   USD/THB                         Frankfurter (ECB); Yahoo THB=X as backup
//   Thai mutual funds (NAV)         SEC Open Data API v2 – needs a free key in SEC_API_KEY
// Bonds, GSB lottery bonds and cash have no market price and are skipped.
// Every source is unofficial or best-effort: a failure never stops the others, and each
// result says where the price came from so it can be checked.
'use strict';

const UA = 'Mozilla/5.0 (PortDee price feed)';
let fetchImpl = globalThis.fetch;
if (process.env.PRICE_FEED_MOCK) fetchImpl = require(require('path').resolve(process.env.PRICE_FEED_MOCK)).fetch;
const setFetch = f => { fetchImpl = f; };

async function getJson(url, headers = {}, timeoutMs = 12000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetchImpl(url, { headers: { 'User-Agent': UA, Accept: 'application/json', ...headers }, signal: ctl.signal });
    if (!r.ok) { const e = new Error(`HTTP ${r.status}`); e.status = r.status; throw e; }
    return await r.json();
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('หมดเวลารอ (timeout)');
    throw e;
  } finally { clearTimeout(t); }
}
const num = v => (v === null || v === undefined || v === '' || !isFinite(+v)) ? null : +v;

// ---------- sources ----------
async function yahoo(symbol) {
  const d = await getJson(`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(symbol)}?interval=1d&range=5d`);
  const m = d && d.chart && d.chart.result && d.chart.result[0] && d.chart.result[0].meta;
  if (!m || num(m.regularMarketPrice) === null) throw new Error(`Yahoo ไม่มีราคา ${symbol}` + (d && d.chart && d.chart.error ? ' (' + (d.chart.error.description || d.chart.error.code) + ')' : ''));
  return { price: +m.regularMarketPrice, currency: m.currency || null, at: m.regularMarketTime ? new Date(m.regularMarketTime * 1000).toISOString() : null, source: 'Yahoo ' + symbol };
}

async function goldUsdOz() {
  try {
    const d = await getJson('https://xaus.com/api/v1/spot');
    const p = num(d.spot_usd_oz ?? (d.data && d.data.spot_usd_oz));
    if (p === null) throw new Error('xaus ไม่มีราคา');
    return { price: p, currency: 'USD', at: d.timestamp || d.updated_at || null, source: 'xaus.com spot' };
  } catch (e) {
    const y = await yahoo('GC=F').catch(e2 => { throw new Error(`xaus: ${e.message}; Yahoo GC=F: ${e2.message}`); });
    return { ...y, source: 'Yahoo GC=F (สำรอง)' };
  }
}

async function usdThb() {
  try {
    const d = await getJson('https://api.frankfurter.dev/v1/latest?base=USD&symbols=THB');
    const p = num(d.rates && d.rates.THB);
    if (p === null) throw new Error('Frankfurter ไม่มีค่า THB');
    return { rate: p, at: d.date || null, source: 'Frankfurter (ECB)' };
  } catch (e) {
    const y = await yahoo('THB=X').catch(e2 => { throw new Error(`Frankfurter: ${e.message}; Yahoo THB=X: ${e2.message}`); });
    return { rate: y.price, at: y.at, source: 'Yahoo THB=X (สำรอง)' };
  }
}

// --- Thai funds (SEC Open Data API v2) ---
const SEC = 'https://api.sec.or.th/v2/fund';
const secKey = () => (process.env.SEC_API_KEY || '').trim();
async function secAll(path, params, maxPages = 400) {
  const out = [];
  let cursor = null;
  for (let i = 0; i < maxPages; i++) {
    const q = new URLSearchParams({ ...params, page_size: '100' });
    if (cursor) q.set('next_cursor', cursor);
    let d;
    try { d = await getJson(`${SEC}${path}?${q}`, { 'Ocp-Apim-Subscription-Key': secKey() }, 20000); }
    catch (e) {
      if (e.status === 401) throw new Error('SEC_API_KEY ไม่ถูกต้องหรือหมดอายุ');
      if (e.status === 204 || e.status === 404) break;
      throw e;
    }
    out.push(...((d && d.items) || []));
    cursor = d && d.next_cursor;
    if (!cursor) break;
  }
  return out;
}
const norm = s => String(s || '').trim().toUpperCase();
// abbreviation → proj_id, cached for a week
let fundIndex = null;
async function loadFundIndex(state) {
  if (fundIndex && Date.now() - fundIndex.at < 7 * 864e5) return fundIndex;
  const cached = state && await state.get('sec_fund_index');
  if (cached && Date.now() - cached.at < 7 * 864e5) return (fundIndex = cached);
  const map = {};
  for (const status of ['Registered', 'IPO']) {
    for (const r of await secAll('/general-info/profiles', { fund_status: status })) {
      if (r.proj_id && r.proj_abbr_name) map[norm(r.proj_abbr_name)] = r.proj_id;
    }
  }
  if (!Object.keys(map).length) throw new Error('ดึงรายชื่อกองทุนจาก ก.ล.ต. ไม่ได้');
  fundIndex = { at: Date.now(), map };
  if (state) await state.set('sec_fund_index', fundIndex);
  return fundIndex;
}
// Fund names often carry a class, e.g. "K-USA-A(A)" or "SCBS&P500-SSF". Accept "PROJ|CLASS" too.
async function fundNav(name, state) {
  if (!secKey()) throw new Error('ยังไม่ได้ตั้ง SEC_API_KEY (ขอคีย์ฟรีที่ secopendata.sec.or.th)');
  const raw = norm(name);
  const [projPart, classPart] = raw.includes('|') ? raw.split('|') : [raw, raw];
  const idx = await loadFundIndex(state);
  let abbr = idx.map[projPart] ? projPart : null;
  if (!abbr) { // longest project abbreviation that the name starts with
    for (const k of Object.keys(idx.map)) if (projPart.startsWith(k) && (!abbr || k.length > abbr.length)) abbr = k;
  }
  if (!abbr) throw new Error(`ไม่พบกองทุน "${name}" ใน ก.ล.ต. (ใส่ชื่อย่อให้ตรง หรือรหัสแบบ PROJ|CLASS)`);
  const end = new Date(), start = new Date(Date.now() - 14 * 864e5);
  const d = x => x.toISOString().slice(0, 10);
  const rows = (await secAll('/daily-info/nav', { proj_id: idx.map[abbr], start_nav_date: d(start), end_nav_date: d(end) }, 5))
    .filter(r => num(r.last_val) !== null && r.last_val > 0 && (!r.proj_id || r.proj_id === idx.map[abbr]));
  if (!rows.length) throw new Error(`ไม่มี NAV ของ ${abbr} ใน 14 วันล่าสุด`);
  const classes = [...new Set(rows.map(r => norm(r.fund_class_name || r.class_abbr_name || '')))];
  let pick = rows;
  if (classes.length > 1) {
    pick = rows.filter(r => [norm(r.fund_class_name), norm(r.class_abbr_name)].includes(classPart));
    if (!pick.length) throw new Error(`${abbr} มีหลายชนิดหน่วย (${classes.join(', ')}) ใส่รหัสดึงราคาเป็น ${abbr}|ชื่อชนิดหน่วย`);
  }
  pick.sort((a, b) => String(b.nav_date).localeCompare(String(a.nav_date)));
  return { price: +pick[0].last_val, currency: 'THB', at: String(pick[0].nav_date).slice(0, 10), source: 'ก.ล.ต. NAV ' + abbr + (classes.length > 1 ? '|' + classPart : '') };
}

// ---------- which source for which item ----------
// Returns { kind, symbol } or null when the item has no market price.
// item.sym (set by the user) overrides the default symbol.
function sourceFor(item) {
  const sym = String(item.sym || '').trim();
  if (sym === '-') return null; // user turned the feed off for this item
  const name = String(item.name || '').trim().toUpperCase();
  switch (item.type) {
    case 'th': return { kind: 'yahoo', symbol: sym || (name.endsWith('.BK') ? name : name + '.BK') };
    case 'etf': return { kind: 'yahoo', symbol: sym || (item.cur === 'THB' && !name.includes('.') ? name + '.BK' : name) };
    case 'fx': return { kind: 'yahoo', symbol: sym || name };
    case 'au': return sym ? { kind: 'yahoo', symbol: sym } : { kind: 'gold', symbol: 'XAU' };
    case 'fd': return { kind: 'fund', symbol: sym || name };
    default: return sym ? { kind: 'yahoo', symbol: sym } : null; // bonds, GSB, cash: only if a symbol was set
  }
}

// Fetch every distinct symbol once. Returns { fx, quotes: {key: quote|{error}} } where key = kind:symbol.
async function fetchAll(items, state) {
  const want = new Map();
  for (const it of items) { const s = sourceFor(it); if (s) want.set(s.kind + ':' + s.symbol, s); }
  const quotes = {};
  let fx = null;
  try { fx = await usdThb(); } catch (e) { fx = { error: e.message }; }
  const jobs = [...want.entries()];
  // a few at a time, to be polite to free services
  for (let i = 0; i < jobs.length; i += 4) {
    await Promise.all(jobs.slice(i, i + 4).map(async ([key, s]) => {
      try {
        quotes[key] = s.kind === 'gold' ? await goldUsdOz() : s.kind === 'fund' ? await fundNav(s.symbol, state) : await yahoo(s.symbol);
      } catch (e) { quotes[key] = { error: e.message }; }
    }));
  }
  return { fx, quotes };
}

// Put fetched prices into the portfolio data. Converts between THB and USD when the
// quote's currency differs from the item's currency. Returns a summary for the log.
function applyQuotes(data, fetched, now = new Date().toISOString()) {
  const out = { items: data.items.map(i => ({ ...i })), fx: { ...data.fx }, cash: data.cash || [] };
  const res = { updated: [], failed: [], skipped: 0, fx: null };
  if (fetched.fx && fetched.fx.rate) {
    out.fx.USD = +fetched.fx.rate.toFixed(4);
    res.fx = { from: data.fx.USD ?? null, rate: out.fx.USD, source: fetched.fx.source, at: fetched.fx.at };
  } else if (fetched.fx) res.failed.push({ name: 'USD/THB', error: fetched.fx.error });
  const usd = out.fx.USD || 0;
  const seen = new Set();
  for (const it of out.items) {
    const s = sourceFor(it);
    if (!s) { res.skipped++; continue; }
    const q = fetched.quotes[s.kind + ':' + s.symbol];
    const label = `${it.name}`;
    if (!q || q.error) { if (!seen.has(label + 'x')) { res.failed.push({ name: label, symbol: s.symbol, error: q ? q.error : 'ไม่ได้ดึง' }); seen.add(label + 'x'); } continue; }
    let p = q.price;
    const qc = (q.currency || it.cur || '').toUpperCase();
    if (qc === 'GBP' || qc === 'GBX' || qc === 'EUR' || qc === 'JPY' || qc === 'HKD') {
      if (!seen.has(label + 'c')) { res.failed.push({ name: label, symbol: s.symbol, error: `ราคาเป็นสกุล ${qc} (โปรแกรมรองรับ THB/USD)` }); seen.add(label + 'c'); }
      continue;
    }
    if (qc === 'USD' && it.cur === 'THB') { if (!usd) continue; p = p * usd; }
    if (qc === 'THB' && it.cur === 'USD') { if (!usd) continue; p = p / usd; }
    p = +p.toFixed(p >= 100 ? 2 : 4);
    if (it.price !== p) {
      if (!seen.has(label)) res.updated.push({ name: label, from: it.price ?? null, to: p, cur: it.cur, source: q.source });
      seen.add(label);
    }
    it.price = p; it.pxAt = Date.parse(now); it.pxSrc = q.source + (q.at ? ' · ' + String(q.at).slice(0, 16).replace('T', ' ') : '');
  }
  return { data: out, res };
}

module.exports = { fetchAll, applyQuotes, sourceFor, setFetch, yahoo, goldUsdOz, usdThb, fundNav, _reset: () => { fundIndex = null; } };
