// Telegram alerts (optional). Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to turn them on.
// Messages leave the server at once, so someone who later edits the database cannot take them back.
'use strict';
let fetchImpl = globalThis.fetch;
if (process.env.NOTIFY_MOCK) fetchImpl = require(require('path').resolve(process.env.NOTIFY_MOCK)).fetch;
const token = () => (process.env.TELEGRAM_BOT_TOKEN || '').trim();
const chat = () => (process.env.TELEGRAM_CHAT_ID || '').trim();
const enabled = () => !!(token() && chat());
async function send(text) {
  if (!enabled()) return false;
  try {
    const r = await fetchImpl(`https://api.telegram.org/bot${token()}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chat(), text: String(text).slice(0, 4000), disable_web_page_preview: true }),
    });
    if (!r.ok) console.error('telegram: HTTP ' + r.status);
    return r.ok;
  } catch (e) { console.error('telegram failed:', e.message); return false; }
}
module.exports = { send, enabled };
