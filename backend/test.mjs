// Runs the Worker in Miniflare (Cloudflare's own runtime) with a throwaway
// D1 database. Touches nothing real. `node test.mjs`
import { Miniflare } from 'miniflare';
import assert from 'node:assert/strict';
import { webcrypto as wc } from 'node:crypto';

const KEY = 'test-admin-key-0123456789abcdef';
const pushed = [];
let pushStatus = 201;

const mf = new Miniflare({
  modules: true,
  scriptPath: 'src/index.js',
  modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }],
  compatibilityDate: '2026-08-01',
  d1Databases: { DB: 'test-' + Date.now() },
  bindings: {
    ADMIN_KEY: KEY,
    ALLOWED_ORIGINS: 'https://tishxkitchen.com,https://admin.tishxkitchen.com',
    MAX_ORDERS_PER_10MIN: '5',
  },
  outboundService: async (req) => {
    pushed.push({ url: req.url, headers: Object.fromEntries(req.headers), body: new Uint8Array(await req.arrayBuffer()) });
    return new Response('', { status: pushStatus });
  },
});

const base = 'https://api.tishxkitchen.com';
const call = (path, opt = {}) => mf.dispatchFetch(base + path, opt);
const admin = (path, opt = {}) => call(path, { ...opt, headers: { authorization: 'Bearer ' + KEY, 'content-type': 'application/json', ...(opt.headers || {}) } });
const post = (path, body, headers = {}) => call(path, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json', ...headers } });

const order = (over = {}) => ({
  items: [{ id: 'pasta-chicken', qty: 2, price: 1 }, { id: 'peachy', qty: 1 }],
  cust: { name: 'Maria', phone: '5612345', addr: 'Kaya Flamboyan 12' },
  type: 'delivery', when: null, pay: 'cash', note: 'extra sauce', ...over,
});

let passed = 0;
async function t(name, fn) {
  try { await fn(); passed++; console.log('  ok  ', name); }
  catch (e) { console.log('  FAIL', name); console.error(e); process.exitCode = 1; }
}

// ---- RFC 8291 decrypt, the receiver side, to prove the Worker's encryption
const b64u = (b) => Buffer.from(b).toString('base64url');
async function hkdf(salt, ikm, info, len) {
  const k = await wc.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await wc.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function decrypt(body, receiver, auth) {
  const salt = body.slice(0, 16);
  const idlen = body[20];
  const asPub = body.slice(21, 21 + idlen);
  const cipher = body.slice(21 + idlen);
  const uaPub = new Uint8Array(await wc.subtle.exportKey('raw', receiver.publicKey));
  const asKey = await wc.subtle.importKey('raw', asPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await wc.subtle.deriveBits({ name: 'ECDH', public: asKey }, receiver.privateKey, 256));
  const e = new TextEncoder();
  const info = new Uint8Array([...e.encode('WebPush: info\0'), ...uaPub, ...asPub]);
  const ikm = await hkdf(auth, shared, info, 32);
  const cek = await hkdf(salt, ikm, e.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, e.encode('Content-Encoding: nonce\0'), 12);
  const k = await wc.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
  const plain = new Uint8Array(await wc.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, k, cipher));
  assert.equal(plain[plain.length - 1], 2, 'last record delimiter');
  return new TextDecoder().decode(plain.slice(0, -1));
}

console.log('Tish\'s Kitchen API');

await t('health', async () => {
  const r = await call('/api/health');
  assert.equal(r.status, 200);
});

await t('public menu is seeded with the 7 items and fee 10', async () => {
  const r = await call('/api/menu');
  const j = await r.json();
  assert.equal(j.items.length, 7);
  assert.equal(j.fee, 10);
  assert.equal(j.items.find((i) => i.id === 'pasta-chicken').price, 35);
});

let receiver, authSecret;
await t('admin can register a phone for notifications', async () => {
  receiver = await wc.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  authSecret = wc.getRandomValues(new Uint8Array(16));
  const p256dh = b64u(new Uint8Array(await wc.subtle.exportKey('raw', receiver.publicKey)));
  const key = await (await admin('/api/admin/push/key')).json();
  assert.ok(key.publicKey.length > 80);
  const r = await admin('/api/admin/push/subscribe', { method: 'POST', body: JSON.stringify({
    sub: { endpoint: 'https://fcm.googleapis.com/fcm/send/abc123', keys: { p256dh, auth: b64u(authSecret) } }, label: 'Tish phone' }) });
  assert.equal((await r.json()).devices, 1);
});

let first;
await t('order is saved with server prices, browser price ignored', async () => {
  const r = await post('/api/orders', order(), { origin: 'https://tishxkitchen.com' });
  assert.equal(r.status, 201);
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://tishxkitchen.com');
  first = await r.json();
  assert.match(first.ref, /^TK-[A-Z2-9]{4}$/);
  assert.equal(first.subtotal, 75); // 2x35 + 5, not 2x1
  assert.equal(first.fee, 10);
  assert.equal(first.total, 85);
});

await t('Tish gets an encrypted notification that decrypts to the order', async () => {
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(pushed.length, 1);
  const p = pushed[0];
  assert.equal(p.url, 'https://fcm.googleapis.com/fcm/send/abc123');
  assert.equal(p.headers['content-encoding'], 'aes128gcm');
  assert.match(p.headers.authorization, /^vapid t=[\w-]+\.[\w-]+\.[\w-]+, k=[\w-]+$/);
  const msg = JSON.parse(await decrypt(p.body, receiver, authSecret));
  assert.equal(msg.tag, first.ref);
  assert.match(msg.title, /XCG 85/);
  assert.match(msg.body, /Maria: 2× Pasta Chicken \+ Drink, 1× Peachy/);
});

await t('VAPID token is a valid ES256 signature with our public key', async () => {
  const auth = pushed[0].headers.authorization;
  const [, jwt, k] = /t=([^,]+), k=(.+)$/.exec(auth);
  const [h, c, s] = jwt.split('.');
  const pub = await wc.subtle.importKey('raw', Buffer.from(k, 'base64url'), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const ok = await wc.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, Buffer.from(s, 'base64url'), new TextEncoder().encode(h + '.' + c));
  assert.ok(ok);
  const claims = JSON.parse(Buffer.from(c, 'base64url'));
  assert.equal(claims.aud, 'https://fcm.googleapis.com');
});

await t('pickup has no delivery fee and drops the address', async () => {
  const j = await (await post('/api/orders', order({ type: 'pickup', items: [{ id: 'biscoff-cup', qty: 1 }] }))).json();
  assert.equal(j.total, 15);
  assert.equal(j.fee, 0);
});

await t('bad orders are refused with a message', async () => {
  let r = await post('/api/orders', order({ cust: { name: '', phone: '5612345' } }));
  assert.equal(r.status, 400);
  r = await post('/api/orders', order({ cust: { name: 'A', phone: '12' } }));
  assert.equal(r.status, 400);
  r = await post('/api/orders', order({ cust: { name: 'A', phone: '5612345', addr: '' } }));
  assert.equal(r.status, 400);
  r = await post('/api/orders', order({ items: [{ id: 'lobster', qty: 1 }] }));
  assert.equal(r.status, 409);
  r = await post('/api/orders', order({ items: [{ id: 'peachy', qty: 0 }] }));
  assert.equal(r.status, 400);
  r = await post('/api/orders', order({ when: 'tomorrow' }));
  assert.equal(r.status, 400);
});

await t('spam trap answers yes and saves nothing', async () => {
  const r = await post('/api/orders', order({ website: 'http://spam' }));
  assert.equal((await r.json()).ref, 'TK-0000');
});

await t('admin routes refuse without the key, or with a wrong one', async () => {
  assert.equal((await call('/api/admin/orders')).status, 401);
  assert.equal((await call('/api/admin/orders', { headers: { authorization: 'Bearer nope' } })).status, 401);
});

let list;
await t('Tish\'s app lists new orders and can page with after=', async () => {
  list = await (await admin('/api/admin/orders')).json();
  assert.equal(list.orders.length, 2);
  assert.equal(list.orders[0].ref, first.ref);
  assert.equal(list.orders[0].cust.addr, 'Kaya Flamboyan 12');
  assert.equal(list.orders[1].cust.addr, '');
  const none = await (await admin('/api/admin/orders?after=' + list.last)).json();
  assert.equal(none.orders.length, 0);
});

await t('marking received', async () => {
  await admin('/api/admin/orders/received', { method: 'POST', body: JSON.stringify({ ids: [list.orders[0].id] }) });
  const again = await (await admin('/api/admin/orders')).json();
  assert.equal(again.orders[0].status, 'received');
  assert.equal(again.orders[1].status, 'new');
});

await t('menu from Tish\'s app becomes the public menu, sold out is refused', async () => {
  const items = [
    { id: 'pasta-chicken', name: 'Pasta Chicken + Drink', price: 40, cat: 'Meals', emoji: '🍝', img: 'images/pasta-chicken.webp', off: false },
    { id: 'peachy', name: 'Peachy', price: 5, cat: 'Drinks', emoji: '🍑', off: true },
  ];
  const r = await admin('/api/admin/menu', { method: 'PUT', body: JSON.stringify({ items, fee: 12 }) });
  assert.equal(r.status, 200);
  const pub = await (await call('/api/menu')).json();
  assert.equal(pub.items.length, 2);
  assert.equal(pub.fee, 12);
  const ok = await (await post('/api/orders', order({ items: [{ id: 'pasta-chicken', qty: 1 }] }))).json();
  assert.equal(ok.total, 52);
  const no = await post('/api/orders', order({ items: [{ id: 'peachy', qty: 1 }] }));
  assert.equal(no.status, 409);
});

await t('weekly menu: orders only for the cooking day, closed after it', async () => {
  const items = [{ id: 'pasta-porkchop', name: 'Pasta Porkchop + Drink', price: 35, cat: 'Meals' }];
  await admin('/api/admin/menu', { method: 'PUT', body: JSON.stringify({ items, fee: 10, day: '2099-01-03' }) });
  const pub = await (await call('/api/menu')).json();
  assert.equal(pub.day, '2099-01-03');
  let r = await post('/api/orders', order({ items: [{ id: 'pasta-porkchop', qty: 1 }], when: null }), { 'cf-connecting-ip': '9.9.9.1' });
  assert.equal(r.status, 409);
  r = await post('/api/orders', order({ items: [{ id: 'pasta-porkchop', qty: 1 }], when: '2099-01-04T12:00' }), { 'cf-connecting-ip': '9.9.9.1' });
  assert.equal(r.status, 409);
  r = await post('/api/orders', order({ items: [{ id: 'pasta-porkchop', qty: 1 }], when: '2099-01-03T12:30' }), { 'cf-connecting-ip': '9.9.9.1' });
  assert.equal(r.status, 201);
  await admin('/api/admin/menu', { method: 'PUT', body: JSON.stringify({ items, day: '2000-01-01' }) });
  r = await post('/api/orders', order({ items: [{ id: 'pasta-porkchop', qty: 1 }], when: '2000-01-01T12:30' }), { 'cf-connecting-ip': '9.9.9.1' });
  assert.equal(r.status, 409);
  assert.match((await r.json()).error, /closed/);
  await admin('/api/admin/menu', { method: 'PUT', body: JSON.stringify({ items, day: '' }) });
});

await t('a dead phone subscription is removed', async () => {
  pushStatus = 410;
  const r = await (await admin('/api/admin/push/test', { method: 'POST' })).json();
  assert.equal(r.failed, 1);
  const c = await (await admin('/api/admin/check')).json();
  assert.equal(c.devices, 0);
  pushStatus = 201;
});

await t('too many orders from one phone in 10 minutes is slowed down', async () => {
  let last;
  for (let i = 0; i < 4; i++) last = await post('/api/orders', order({ items: [{ id: 'pasta-porkchop', qty: 1 }] }));
  assert.equal(last.status, 429);
});

await t('CORS preflight only for our own sites', async () => {
  const ok = await call('/api/orders', { method: 'OPTIONS', headers: { origin: 'https://tishxkitchen.com' } });
  assert.equal(ok.headers.get('access-control-allow-origin'), 'https://tishxkitchen.com');
  const no = await call('/api/orders', { method: 'OPTIONS', headers: { origin: 'https://evil.example' } });
  assert.equal(no.headers.get('access-control-allow-origin'), null);
});

await mf.dispose();
console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}`);
