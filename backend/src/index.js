// Tish's Kitchen API, on api.tishxkitchen.com
//
//   GET  /api/health                      are we alive
//   GET  /api/menu                        public menu and delivery fee for tishxkitchen.com
//   POST /api/orders                      the customer site sends orders here
//
//   Everything under /api/admin needs   Authorization: Bearer <ADMIN_KEY>
//   GET  /api/admin/check                 is this key right
//   GET  /api/admin/orders?after=<id>     new online orders for Tish's app
//   POST /api/admin/orders/received       { ids } her app has them
//   PUT  /api/admin/menu                  { items, fee } her app's menu becomes the public one
//   GET  /api/admin/push/key              VAPID public key for notifications
//   POST /api/admin/push/subscribe        { sub, label }
//   POST /api/admin/push/unsubscribe      { endpoint }
//   POST /api/admin/push/test             send a test notification

import { ensureSchema, getSetting, setSetting } from './schema.js';
import { notifyAll, vapidKeys } from './push.js';

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
const bad = (msg, status = 400) => json({ error: msg }, status);

function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
}
function cors(request, env) {
  const origin = request.headers.get('Origin') || '';
  const list = allowedOrigins(env);
  if (!list.includes(origin)) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
    'Access-Control-Allow-Headers': 'content-type,authorization',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

// Constant time compare, so the key cannot be guessed one character at a time.
async function sameSecret(a, b) {
  const e = new TextEncoder();
  const [x, y] = await Promise.all([
    crypto.subtle.digest('SHA-256', e.encode(String(a))),
    crypto.subtle.digest('SHA-256', e.encode(String(b))),
  ]);
  const p = new Uint8Array(x), q = new Uint8Array(y);
  let d = 0;
  for (let i = 0; i < p.length; i++) d |= p[i] ^ q[i];
  return d === 0;
}
async function isAdmin(request, env) {
  const key = env.ADMIN_KEY;
  // No key configured means nobody gets in, not everybody.
  if (!key || String(key).length < 24) return false;
  const h = request.headers.get('Authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return false;
  return sameSecret(m[1].trim(), key);
}

async function ipHash(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  const day = new Date().toISOString().slice(0, 10);
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`tk|${day}|${ip}`));
  return [...new Uint8Array(d)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Curaçao is UTC-4 all year, no daylight saving.
const curacaoToday = () => new Date(Date.now() - 4 * 3600 * 1000).toISOString().slice(0, 10);
const cents = (x) => Math.round(Number(x) * 100);
const xcg = (c) => Math.round(c) / 100;
const clip = (s, n) => String(s == null ? '' : s).trim().slice(0, n);

function makeRef() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const r = crypto.getRandomValues(new Uint8Array(4));
  let s = '';
  for (const b of r) s += c[b % c.length];
  return `TK-${s}`;
}

async function readMenu(env) {
  const rows = (await env.DB.prepare('SELECT * FROM menu ORDER BY position, rowid').all()).results || [];
  const fee = Number(await getSetting(env, 'fee_cents')) || 0;
  const day = (await getSetting(env, 'day')) || '';
  return {
    currency: env.CURRENCY || 'XCG',
    fee: xcg(fee),
    day,                       // cooking day "YYYY-MM-DD"; every order is for this day. '' = any day
    today: curacaoToday(),
    items: rows.map((r) => ({
      id: r.id, name: r.name, price: xcg(r.price_cents), cat: r.cat,
      emoji: r.emoji || '', img: r.img || '', off: !!r.off,
    })),
  };
}

function orderOut(r) {
  return {
    id: r.id, ref: r.ref, ts: r.created_at,
    items: JSON.parse(r.items),
    subtotal: xcg(r.subtotal_cents), fee: xcg(r.fee_cents), total: xcg(r.total_cents),
    cust: { name: r.cust_name, phone: r.cust_phone, addr: r.cust_addr || '' },
    type: r.type, when: r.want_at, pay: r.pay, note: r.note || '',
    status: r.status, receivedAt: r.received_at,
  };
}

// ------------------------------------------------------------- public

async function placeOrder(request, env, ctx) {
  let b;
  try { b = await request.json(); } catch { return bad('That order could not be read.'); }
  if (!b || typeof b !== 'object') return bad('That order could not be read.');

  // Spam trap: a field real people never see. Bots get a polite yes.
  if (b.website) return json({ ok: true, ref: 'TK-0000', total: 0 });

  const name = clip(b.cust && b.cust.name, 80);
  const phone = clip(b.cust && b.cust.phone, 30);
  const type = b.type === 'delivery' ? 'delivery' : 'pickup';
  const addr = type === 'delivery' ? clip(b.cust && b.cust.addr, 300) : '';
  const pay = b.pay === 'online' ? 'online' : 'cash';
  const note = clip(b.note, 500);
  let when = b.when == null || b.when === '' ? null : String(b.when);

  if (!name) return bad('Please add your name.');
  if (phone.replace(/\D/g, '').length < 7) return bad('Please add your WhatsApp number.');
  if (type === 'delivery' && !addr) return bad('Please add your delivery address.');
  if (when !== null && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(when)) return bad('Please pick a day and time.');

  const wanted = Array.isArray(b.items) ? b.items : [];
  if (!wanted.length) return bad('Your order is empty.');
  if (wanted.length > 30) return bad('That is a very big order. Please message Tish on WhatsApp.');

  // Prices come from the menu here, never from the browser.
  const menu = await readMenu(env);
  if (menu.day) {
    if (menu.day < menu.today) return bad('Ordering for this menu is closed. The next menu is coming soon.', 409);
    if (!when || when.slice(0, 10) !== menu.day) return bad('Please pick a time on the cooking day.', 409);
  }
  const byId = Object.fromEntries(menu.items.map((m) => [m.id, m]));
  const lines = [];
  let sub = 0;
  for (const w of wanted) {
    const m = byId[w && w.id];
    const qty = Number(w && w.qty);
    if (!m) return bad('Something in your order is no longer on the menu. Please refresh the page.', 409);
    if (m.off) return bad(`${m.name} is sold out today. Please remove it.`, 409);
    if (!Number.isInteger(qty) || qty < 1 || qty > 50) return bad('Please check the amounts in your order.');
    const existing = lines.find((l) => l.id === m.id);
    if (existing) existing.qty += qty;
    else lines.push({ id: m.id, name: m.name, price: m.price, qty });
    sub += cents(m.price) * qty;
  }
  const fee = type === 'delivery' ? cents(menu.fee) : 0;
  const total = sub + fee;

  const ip = await ipHash(request);
  const recent = await env.DB.prepare('SELECT COUNT(*) AS n FROM orders WHERE ip_hash = ? AND created_at > ?')
    .bind(ip, Date.now() - 10 * 60 * 1000).first();
  if (recent && recent.n >= Number(env.MAX_ORDERS_PER_10MIN || 8)) {
    return bad('Too many orders from this phone in a short time. Please message Tish on WhatsApp.', 429);
  }

  let row = null;
  for (let tries = 0; tries < 6 && !row; tries++) {
    try {
      row = await env.DB.prepare(
        `INSERT INTO orders (ref, created_at, items, subtotal_cents, fee_cents, total_cents,
           cust_name, cust_phone, cust_addr, type, want_at, pay, note, ip_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`,
      ).bind(makeRef(), Date.now(), JSON.stringify(lines), sub, fee, total,
        name, phone, addr || null, type, when, pay, note || null, ip).first();
    } catch (e) {
      if (!/UNIQUE/i.test(String(e && e.message))) throw e;
    }
  }
  if (!row) return bad('Could not save the order. Please try again.', 500);

  const what = lines.map((l) => `${l.qty}× ${l.name}`).join(', ');
  const whenTxt = when ? when.replace('T', ' ') : 'ASAP';
  ctx.waitUntil(notifyAll(env, {
    title: `New order ${row.ref} · XCG ${xcg(total)}`,
    body: `${name}: ${what}\n${type === 'delivery' ? 'Delivery' : 'Pickup'} · ${whenTxt} · ${pay === 'online' ? 'Pays online' : 'Cash'}`,
    tag: row.ref,
    url: `/?order=${row.ref}`,
  }));

  return json({ ok: true, ref: row.ref, total: xcg(total), subtotal: xcg(sub), fee: xcg(fee), items: lines }, 201);
}

// -------------------------------------------------------------- admin

async function listOrders(url, env) {
  const after = Math.max(0, parseInt(url.searchParams.get('after') || '0', 10) || 0);
  const limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get('limit') || '100', 10) || 100));
  const rows = (await env.DB.prepare('SELECT * FROM orders WHERE id > ? ORDER BY id LIMIT ?').bind(after, limit).all()).results || [];
  return json({ orders: rows.map(orderOut), last: rows.length ? rows[rows.length - 1].id : after });
}

async function markReceived(request, env) {
  const b = await request.json().catch(() => ({}));
  const ids = (Array.isArray(b.ids) ? b.ids : []).map(Number).filter(Number.isInteger).slice(0, 200);
  if (!ids.length) return json({ ok: true, updated: 0 });
  const now = Date.now();
  await env.DB.batch(ids.map((id) =>
    env.DB.prepare("UPDATE orders SET status = 'received', received_at = COALESCE(received_at, ?) WHERE id = ?").bind(now, id)));
  return json({ ok: true, updated: ids.length });
}

async function putMenu(request, env) {
  const b = await request.json().catch(() => null);
  const items = b && Array.isArray(b.items) ? b.items : null;
  if (!items || !items.length || items.length > 100) return bad('Send the whole menu as items.');
  const clean = [];
  const seen = new Set();
  for (const m of items) {
    const id = clip(m && m.id, 60);
    const price = Number(m && m.price);
    if (!id || seen.has(id) || !clip(m.name, 80) || !(price >= 0) || price > 100000) return bad(`Menu item ${id || '?'} is not valid.`);
    seen.add(id);
    clean.push({ id, name: clip(m.name, 80), price_cents: cents(price), cat: clip(m.cat, 40) || 'Other',
      emoji: clip(m.emoji, 8), img: clip(m.img, 200), off: m.off ? 1 : 0 });
  }
  const stmts = [env.DB.prepare('DELETE FROM menu')];
  clean.forEach((m, i) => stmts.push(env.DB.prepare(
    'INSERT INTO menu (id, name, price_cents, cat, emoji, img, off, position) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  ).bind(m.id, m.name, m.price_cents, m.cat, m.emoji, m.img, m.off, i)));
  if (b.day !== undefined) {
    const day = String(b.day || '');
    if (day && !/^\d{4}-\d{2}-\d{2}$/.test(day)) return bad('Cooking day is not a date.');
    stmts.push(env.DB.prepare("INSERT INTO settings (key, value) VALUES ('day', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(day));
  }
  if (b.fee != null && Number(b.fee) >= 0) {
    stmts.push(env.DB.prepare("INSERT INTO settings (key, value) VALUES ('fee_cents', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .bind(String(cents(b.fee))));
  }
  await env.DB.batch(stmts); // all or nothing, never half a menu
  return json({ ok: true, ...(await readMenu(env)) });
}

async function subscribe(request, env) {
  const b = await request.json().catch(() => ({}));
  const sub = b && b.sub;
  if (!sub || typeof sub.endpoint !== 'string' || !/^https:\/\//.test(sub.endpoint) || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
    return bad('That is not a push subscription.');
  }
  await env.DB.prepare(
    'INSERT INTO push_subs (endpoint, sub, label, created_at) VALUES (?, ?, ?, ?) ' +
    'ON CONFLICT(endpoint) DO UPDATE SET sub = excluded.sub, label = excluded.label',
  ).bind(sub.endpoint, JSON.stringify({ endpoint: sub.endpoint, keys: sub.keys }), clip(b.label, 60) || null, Date.now()).run();
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs').first();
  return json({ ok: true, devices: n.n });
}

// ------------------------------------------------------------- router

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname.replace(/\/+$/, '') || '/';
  const m = request.method;

  if (p === '/api/health') return json({ ok: true, at: new Date().toISOString() });

  await ensureSchema(env);

  if (p === '/api/menu' && m === 'GET') {
    return json(await readMenu(env), 200, { 'cache-control': 'public, max-age=30' });
  }
  if (p === '/api/orders' && m === 'POST') return placeOrder(request, env, ctx);

  if (p.startsWith('/api/admin/')) {
    if (!(await isAdmin(request, env))) return bad('Not allowed.', 401);
    if (p === '/api/admin/check' && m === 'GET') {
      const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs').first();
      return json({ ok: true, devices: n.n });
    }
    if (p === '/api/admin/orders' && m === 'GET') return listOrders(url, env);
    if (p === '/api/admin/orders/received' && m === 'POST') return markReceived(request, env);
    if (p === '/api/admin/menu' && m === 'PUT') return putMenu(request, env);
    if (p === '/api/admin/push/key' && m === 'GET') return json({ publicKey: (await vapidKeys(env)).publicKey });
    if (p === '/api/admin/push/subscribe' && m === 'POST') return subscribe(request, env);
    if (p === '/api/admin/push/unsubscribe' && m === 'POST') {
      const b = await request.json().catch(() => ({}));
      await env.DB.prepare('DELETE FROM push_subs WHERE endpoint = ?').bind(String(b.endpoint || '')).run();
      return json({ ok: true });
    }
    if (p === '/api/admin/push/test' && m === 'POST') {
      return json(await notifyAll(env, { title: "TutiKuti", body: 'Notifications are working ✓', tag: 'test', url: '/' }));
    }
  }
  return bad('Not found.', 404);
}

export default {
  async fetch(request, env, ctx) {
    const c = cors(request, env);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: c });
    let res;
    try {
      res = await route(request, env, ctx);
    } catch (e) {
      console.error('error', e && e.stack || e);
      res = bad('Something went wrong on our side. Please try again.', 500);
    }
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(c)) out.headers.set(k, v);
    return out;
  },
};

export { setSetting };
