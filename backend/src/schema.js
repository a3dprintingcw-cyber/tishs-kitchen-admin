// The schema is created by the Worker itself the first time it is needed.
// Deploys run from GitHub Actions and nobody has to remember a migration
// step: CREATE ... IF NOT EXISTS is safe to run on every cold start.
//
// Money is stored in cents (XCG) so nothing depends on float maths.

const STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS orders (
     id           INTEGER PRIMARY KEY AUTOINCREMENT,
     ref          TEXT NOT NULL UNIQUE,          -- TK-7GG5, what the customer sees
     created_at   INTEGER NOT NULL,              -- epoch ms
     items        TEXT NOT NULL,                 -- JSON [{id,name,price,qty}] price in XCG
     subtotal_cents INTEGER NOT NULL,
     fee_cents    INTEGER NOT NULL DEFAULT 0,
     total_cents  INTEGER NOT NULL,
     cust_name    TEXT NOT NULL,
     cust_phone   TEXT NOT NULL,
     cust_addr    TEXT,
     type         TEXT NOT NULL,                 -- pickup | delivery
     want_at      TEXT,                          -- null = as soon as possible, else local "YYYY-MM-DDTHH:MM"
     pay          TEXT NOT NULL,                 -- cash | online
     note         TEXT,
     status       TEXT NOT NULL DEFAULT 'new',   -- new | received (Tish's app has it)
     received_at  INTEGER,
     ip_hash      TEXT
   )`,
  `CREATE INDEX IF NOT EXISTS orders_created ON orders (created_at)`,
  `CREATE INDEX IF NOT EXISTS orders_ip ON orders (ip_hash, created_at)`,
  `CREATE TABLE IF NOT EXISTS menu (
     id          TEXT PRIMARY KEY,
     name        TEXT NOT NULL,
     price_cents INTEGER NOT NULL,
     cat         TEXT NOT NULL DEFAULT 'Other',
     emoji       TEXT,
     img         TEXT,
     off         INTEGER NOT NULL DEFAULT 0,
     position    INTEGER NOT NULL DEFAULT 0
   )`,
  `CREATE TABLE IF NOT EXISTS settings (
     key   TEXT PRIMARY KEY,
     value TEXT
   )`,
  `CREATE TABLE IF NOT EXISTS push_subs (
     endpoint   TEXT PRIMARY KEY,
     sub        TEXT NOT NULL,                   -- the whole PushSubscription JSON
     label      TEXT,
     created_at INTEGER NOT NULL
   )`,
];

// Same menu as both sites shipped with. Only used to fill an empty table;
// after that the admin app is the source of truth and pushes its menu here.
export const DEFAULT_MENU = [
  { id: 'pasta-porkchop',      name: 'Pasta Porkchop + Drink',         price: 35, cat: 'Meals',     emoji: '🍝', img: 'images/pasta-porkchop.webp' },
  { id: 'pasta-chicken',       name: 'Pasta Chicken + Drink',          price: 35, cat: 'Meals',     emoji: '🍝', img: 'images/pasta-chicken.webp' },
  { id: 'burrito-chicken',     name: 'Burrito Chicken, Takis + Drink', price: 35, cat: 'Meals',     emoji: '🌯', img: 'images/burrito-chicken.webp' },
  { id: 'biscoff-cup',         name: 'Biscoff Cookie Cake Cup',        price: 15, cat: 'Cake cups', emoji: '🍪', img: 'images/biscoff-cup.webp' },
  { id: 'tresleches-cup',      name: 'Strawberry Tres Leches Cup',     price: 15, cat: 'Cake cups', emoji: '🍓', img: 'images/tresleches-cup.webp' },
  { id: 'strawberry-lemonade', name: 'Strawberry Lemonade',            price: 5,  cat: 'Drinks',    emoji: '🍹', img: 'images/strawberry-lemonade.webp' },
  { id: 'peachy',              name: 'Peachy',                         price: 5,  cat: 'Drinks',    emoji: '🍑', img: 'images/peachy.webp' },
];
export const DEFAULT_FEE = 10;

let ready = false;
export async function ensureSchema(env) {
  if (ready) return;
  await env.DB.batch(STATEMENTS.map((s) => env.DB.prepare(s)));
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM menu').first();
  if (!n || !n.n) {
    await env.DB.batch(DEFAULT_MENU.map((m, i) =>
      env.DB.prepare('INSERT OR IGNORE INTO menu (id, name, price_cents, cat, emoji, img, off, position) VALUES (?, ?, ?, ?, ?, ?, 0, ?)')
        .bind(m.id, m.name, Math.round(m.price * 100), m.cat, m.emoji, m.img, i)));
  }
  await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('fee_cents', ?)")
    .bind(String(DEFAULT_FEE * 100)).run();
  ready = true;
}

export async function getSetting(env, key) {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return row ? row.value : null;
}
export async function setSetting(env, key, value) {
  await env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .bind(key, value).run();
}
