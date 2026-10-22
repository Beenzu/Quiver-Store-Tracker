'use strict';

const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SECRET =
  process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('stock-tracker|' + ADMIN_PASSWORD).digest('hex');
const DB_SSL = process.env.DB_SSL !== 'false';
const TIMEZONE = process.env.TIMEZONE || 'Africa/Lusaka';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: DB_SSL ? { rejectUnauthorized: false } : false,
});

const app = express();
app.use(express.urlencoded({ extended: false }));

// ---------- helpers ----------

class UserError extends Error {}

const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = (n) =>
  'K ' + (Number(n) || 0).toLocaleString('en-US', { maximumFractionDigits: 2 });
const num = (n) => (Number(n) || 0).toLocaleString('en-US');
const clean = (v, max = 100) => String(v ?? '').trim().slice(0, max);
const toInt = (v) => Math.max(0, parseInt(v, 10) || 0);
const toPrice = (v) => Math.max(0, Number(v) || 0);
const when = (d) =>
  new Date(d).toLocaleString('en-GB', { timeZone: TIMEZONE, dateStyle: 'medium', timeStyle: 'short' });

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const flash = (ok, msg, hash = '') =>
  `/admin?ok=${ok ? 1 : 0}&msg=${encodeURIComponent(msg)}${hash}`;

// Admin access: a signed cookie derived from the admin password.
const TOKEN = crypto.createHmac('sha256', SECRET).update('admin').digest('hex');

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return '';
}

function isAdmin(req) {
  if (!ADMIN_PASSWORD) return false;
  const c = readCookie(req, 'admin');
  return c.length === TOKEN.length && crypto.timingSafeEqual(Buffer.from(c), Buffer.from(TOKEN));
}

function passwordOk(input) {
  const a = Buffer.from(String(input || ''));
  const b = Buffer.from(ADMIN_PASSWORD);
  return ADMIN_PASSWORD !== '' && a.length === b.length && crypto.timingSafeEqual(a, b);
}

const adminPost = (fn) =>
  wrap(async (req, res) => {
    if (!isAdmin(req)) return res.redirect('/admin/login');
    try {
      res.redirect(await fn(req));
    } catch (e) {
      if (e instanceof UserError) return res.redirect(flash(false, e.message));
      throw e;
    }
  });

// ---------- database ----------

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS stalls (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    position INT NOT NULL DEFAULT 0
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    stall_id INT NOT NULL REFERENCES stalls(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    sku TEXT NOT NULL DEFAULT '',
    stock INT NOT NULL DEFAULT 0,
    reorder_at INT NOT NULL DEFAULT 0,
    price NUMERIC(12,2) NOT NULL DEFAULT 0,
    sold INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sales (
    id SERIAL PRIMARY KEY,
    stall_id INT NOT NULL REFERENCES stalls(id) ON DELETE CASCADE,
    product_id INT REFERENCES products(id) ON DELETE SET NULL,
    product_name TEXT NOT NULL,
    qty INT NOT NULL,
    amount NUMERIC(12,2) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('business_name', 'My Business') ON CONFLICT (key) DO NOTHING`
  );
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM stalls');
  if (rows[0].n === 0) {
    await pool.query(`INSERT INTO stalls (name, position) VALUES ('Stall 1', 1), ('Stall 2', 2), ('Stall 3', 3)`);
  }
}

async function businessName() {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'business_name'`);
  return rows[0] ? rows[0].value : 'My Business';
}

async function stalls() {
  return (await pool.query('SELECT * FROM stalls ORDER BY position, id')).rows;
}

async function stallStats() {
  const { rows } = await pool.query(`
    SELECT s.id, s.name,
      (SELECT COUNT(*)::int FROM products p WHERE p.stall_id = s.id) AS items,
      (SELECT COALESCE(SUM(p.stock), 0)::int FROM products p WHERE p.stall_id = s.id) AS stock,
      (SELECT COUNT(*)::int FROM products p WHERE p.stall_id = s.id AND p.stock <= p.reorder_at) AS low,
      (SELECT COALESCE(SUM(x.qty), 0)::int FROM sales x WHERE x.stall_id = s.id) AS units,
      (SELECT COALESCE(SUM(x.amount), 0)::float8 FROM sales x WHERE x.stall_id = s.id) AS revenue
    FROM stalls s
    ORDER BY s.position, s.id`);
  return rows;
}

async function lowItems() {
  const { rows } = await pool.query(`
    SELECT p.name, p.stock, p.reorder_at, s.name AS stall_name
    FROM products p JOIN stalls s ON s.id = p.stall_id
    WHERE p.stock <= p.reorder_at
    ORDER BY s.position, s.id, p.name`);
  return rows;
}

// ---------- shared rendering ----------

const CSS = `
*{box-sizing:border-box}
body{margin:0;background:#F6F4EF;color:#1E1E1C;font:15px/1.45 Inter,system-ui,sans-serif}
a{color:#2F6B4F}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;padding:16px 24px;background:#fff;border-bottom:1px solid #E4E0D6}
.brand{font-weight:700;font-size:18px;color:#1E1E1C;text-decoration:none}
nav{display:flex;gap:16px;flex-wrap:wrap}
nav a{text-decoration:none;font-weight:500}
main{max-width:1200px;margin:0 auto;padding:28px 24px;display:flex;flex-direction:column;gap:24px}
h1{margin:0;font-size:30px}
h2{margin:0 0 12px;font-size:20px}
h3{margin:20px 0 8px;font-size:13px;color:#6B6A64;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.muted{color:#6B6A64}
.warn{color:#B5582B}
.card{background:#fff;border:1px solid #E4E0D6;border-radius:12px;padding:20px}
.tiles{display:flex;gap:16px;flex-wrap:wrap}
.tile{flex:1 1 200px;background:#fff;border:1px solid #E4E0D6;border-radius:12px;padding:18px}
.tile .label{font-size:13px;color:#6B6A64}
.tile .value{font-size:26px;font-weight:700;margin-top:4px}
.cols{display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start}
.cols > *{flex:1 1 360px;min-width:0}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 8px;border-bottom:1px solid #EEEBE3;text-align:left;vertical-align:middle}
th{color:#6B6A64;font-weight:500}
ul.list{list-style:none;margin:0;padding:0;font-size:14px}
ul.list li{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid #EEEBE3}
input,select{padding:9px 10px;border:1px solid #D6D2C8;border-radius:8px;font:inherit;background:#fff;color:#1E1E1C;min-width:0}
button{padding:9px 14px;border:0;border-radius:8px;background:#2F6B4F;color:#fff;font:inherit;font-weight:600;cursor:pointer}
button.link{background:none;color:#6B6A64;text-decoration:underline;padding:0;font-weight:400}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;align-items:end}
label{display:flex;flex-direction:column;gap:4px;font-size:13px;color:#6B6A64}
.notice{padding:12px 14px;border-radius:10px;border:1px solid;font-size:14px}
.notice.ok{background:#EAF3EE;border-color:#B9D6C5;color:#1F4A35}
.notice.bad{background:#FBEFE8;border-color:#E9C6B0;color:#8A2E12}
.login{max-width:360px;margin:60px auto}
`;

async function layout(title, content) {
  const [biz, list] = await Promise.all([businessName(), stalls()]);
  const nav = list.map((s) => `<a href="/stalls/${s.id}">${esc(s.name)}</a>`).join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · ${esc(biz)}</title><style>${CSS}</style></head>
<body>
<header><a class="brand" href="/">${esc(biz)}</a><nav><a href="/">Home</a>${nav}<a href="/admin">Admin</a></nav></header>
<main>${content}</main>
</body></html>`;
}

function statusOf(p) {
  const stock = Number(p.stock) || 0;
  if (stock === 0) return { text: 'Out', color: '#8A2E12' };
  if (stock <= (Number(p.reorder_at) || 0)) return { text: 'Low', color: '#B5582B' };
  return { text: 'In stock', color: '#2F6B4F' };
}

function productTable(prods, admin) {
  if (!prods.length) return '<p class="muted">No products yet.</p>';
  const rows = prods
    .map((p) => {
      const st = statusOf(p);
      const remove = admin
        ? `<td><form method="post" action="/admin/products/${p.id}/delete" style="display:inline"><button class="link">Remove</button></form></td>`
        : '';
      return `<tr>
<td>${esc(p.name)}</td><td>${esc(p.sku)}</td><td>${num(p.stock)}</td><td>${num(p.reorder_at)}</td>
<td>${money(p.price)}</td><td>${num(p.sold)}</td>
<td><span style="color:${st.color};font-weight:600">${st.text}</span></td>${remove}
</tr>`;
    })
    .join('');
  const removeHead = admin ? '<th></th>' : '';
  return `<div class="scroll"><table>
<thead><tr><th>Item</th><th>SKU</th><th>In stock</th><th>Reorder at</th><th>Price</th><th>Sold</th><th>Status</th>${removeHead}</tr></thead>
<tbody>${rows}</tbody></table></div>`;
}

// ---------- public pages ----------

app.get('/', wrap(async (req, res) => {
  const [stats, low] = await Promise.all([stallStats(), lowItems()]);
  const t = stats.reduce(
    (a, s) => ({
      items: a.items + s.items,
      units: a.units + s.units,
      revenue: a.revenue + s.revenue,
      stock: a.stock + s.stock,
      low: a.low + s.low,
    }),
    { items: 0, units: 0, revenue: 0, stock: 0, low: 0 }
  );
  const rows = stats
    .map((s) => {
      const share = t.revenue > 0 ? Math.round((s.revenue / t.revenue) * 100) : 0;
      return `<tr>
<td><a href="/stalls/${s.id}"><strong>${esc(s.name)}</strong></a></td>
<td>${num(s.items)}</td><td>${num(s.units)}</td><td>${money(s.revenue)} <span class="muted">(${share}%)</span></td>
<td class="warn">${num(s.low)}</td></tr>`;
    })
    .join('');
  const alerts = low
    .map((p) => `<li><span>${esc(p.stall_name)} · ${esc(p.name)}</span><span class="warn">${num(p.stock)} left, reorder at ${num(p.reorder_at)}</span></li>`)
    .join('');

  res.send(
    await layout(
      'Home',
      `<div><h1>Business overview</h1><div class="muted">Totals across every stall, to date</div></div>
<div class="tiles">
<div class="tile"><div class="label">Total revenue</div><div class="value">${money(t.revenue)}</div></div>
<div class="tile"><div class="label">Units sold</div><div class="value">${num(t.units)}</div></div>
<div class="tile"><div class="label">Stock on hand</div><div class="value">${num(t.stock)} units</div><div class="muted">${num(t.items)} items tracked</div></div>
<div class="tile"><div class="label">Low-stock items</div><div class="value warn">${num(t.low)}</div></div>
</div>
<section class="card"><h2>Stalls compared</h2><div class="scroll"><table>
<thead><tr><th>Stall</th><th>Items</th><th>Units sold</th><th>Revenue</th><th>Low stock</th></tr></thead>
<tbody>${rows}</tbody></table></div></section>
<section class="card"><h2>Reorder alerts</h2>
${alerts ? `<ul class="list">${alerts}</ul>` : '<p class="muted">Nothing is low on stock.</p>'}
</section>`
    )
  );
}));

app.get('/stalls/:id', wrap(async (req, res) => {
  const id = toInt(req.params.id);
  const st = (await stalls()).find((s) => s.id === id);
  if (!st) {
    return res.status(404).send(await layout('Not found', '<section class="card">Stall not found.</section>'));
  }
  const [stats, prods, sales] = await Promise.all([
    stallStats(),
    pool.query('SELECT * FROM products WHERE stall_id = $1 ORDER BY name', [id]),
    pool.query('SELECT * FROM sales WHERE stall_id = $1 ORDER BY created_at DESC LIMIT 10', [id]),
  ]);
  const s = stats.find((x) => x.id === id);
  const recent = sales.rows.length
    ? `<ul class="list">${sales.rows
        .map((x) => `<li><span>${esc(x.product_name)} × ${num(x.qty)}</span><span>${money(x.amount)} <span class="muted">${when(x.created_at)}</span></span></li>`)
        .join('')}</ul>`
    : '<p class="muted">No sales recorded yet.</p>';

  res.send(
    await layout(
      st.name,
      `<div><div class="muted"><a href="/">All stalls</a> / ${esc(st.name)}</div><h1>${esc(st.name)}</h1></div>
<div class="tiles">
<div class="tile"><div class="label">Items</div><div class="value">${num(s.items)}</div></div>
<div class="tile"><div class="label">Units sold</div><div class="value">${num(s.units)}</div></div>
<div class="tile"><div class="label">Revenue</div><div class="value">${money(s.revenue)}</div></div>
<div class="tile"><div class="label">Low stock</div><div class="value warn">${num(s.low)}</div></div>
</div>
<div class="cols">
<section class="card"><h2>Inventory</h2>${productTable(prods.rows, false)}</section>
<section class="card"><h2>Recent sales</h2>${recent}</section>
</div>`
    )
  );
}));

// ---------- admin: login ----------

app.get('/admin/login', wrap(async (req, res) => {
  const err = req.query.bad ? '<div class="notice bad">Wrong password.</div>' : '';
  const body = ADMIN_PASSWORD
    ? `<section class="card login"><h2>Admin login</h2>${err}
<form method="post" action="/admin/login" class="row" style="flex-direction:column;align-items:stretch">
<label>Password <input type="password" name="password" required autofocus></label>
<button>Log in</button></form></section>`
    : '<section class="card login"><div class="notice bad">ADMIN_PASSWORD is not set on the server.</div></section>';
  res.send(await layout('Admin login', body));
}));

app.post('/admin/login', (req, res) => {
  if (!passwordOk(req.body.password)) return res.redirect('/admin/login?bad=1');
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `admin=${TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${secure}`);
  res.redirect('/admin');
});

app.post('/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.redirect('/admin/login');
});

// ---------- admin: page ----------

function stallAdminSection(st, prods, recent) {
  const opts = prods.length
    ? prods.map((p) => `<option value="${p.id}">${esc(p.name)} (${num(p.stock)} left)</option>`).join('')
    : '';
  const saleForm = prods.length
    ? `<form method="post" action="/admin/sales" class="grid">
<input type="hidden" name="stall_id" value="${st.id}">
<label>Item <select name="product_id" required>${opts}</select></label>
<label>Quantity <input name="qty" type="number" min="1" value="1" required></label>
<button>Process sale</button></form>`
    : '<p class="muted">Add a product first, then you can process sales for it.</p>';
  const recentList = recent.length
    ? `<ul class="list">${recent
        .map((x) => `<li><span>${esc(x.product_name)} × ${num(x.qty)}</span><span>${money(x.amount)} <span class="muted">${when(x.created_at)}</span></span></li>`)
        .join('')}</ul>`
    : '<p class="muted">No sales yet.</p>';

  return `<section class="card" id="stall-${st.id}">
<h2>${esc(st.name)}</h2>
<form method="post" action="/admin/stalls/${st.id}/rename" class="row">
<label>Stall name <input name="name" value="${esc(st.name)}" maxlength="100" required></label>
<button>Rename stall</button></form>

<h3>Add a product</h3>
<form method="post" action="/admin/stalls/${st.id}/products" class="grid">
<label>Name <input name="name" maxlength="100" required></label>
<label>SKU <input name="sku" maxlength="40" placeholder="optional"></label>
<label>Opening stock <input name="stock" type="number" min="0" value="0"></label>
<label>Reorder at <input name="reorder_at" type="number" min="0" value="0"></label>
<label>Price (K) <input name="price" type="number" min="0" step="0.01" value="0"></label>
<button>Add product</button></form>

<h3>Products</h3>
${productTable(prods, true)}

<h3>Process a sale</h3>
${saleForm}

<h3>Recent sales</h3>
${recentList}
</section>`;
}

app.get('/admin', wrap(async (req, res) => {
  if (!isAdmin(req)) return res.redirect('/admin/login');
  const [biz, list, prods, sales] = await Promise.all([
    businessName(),
    stalls(),
    pool.query('SELECT * FROM products ORDER BY name'),
    pool.query('SELECT * FROM sales ORDER BY created_at DESC LIMIT 300'),
  ]);
  const msg = req.query.msg
    ? `<div class="notice ${req.query.ok === '1' ? 'ok' : 'bad'}">${esc(req.query.msg)}</div>`
    : '';
  const sections = list
    .map((st) =>
      stallAdminSection(
        st,
        prods.rows.filter((p) => p.stall_id === st.id),
        sales.rows.filter((x) => x.stall_id === st.id).slice(0, 10)
      )
    )
    .join('');

  res.send(
    await layout(
      'Admin',
      `<div class="row" style="justify-content:space-between"><h1>Admin</h1>
<form method="post" action="/admin/logout"><button class="link">Log out</button></form></div>
${msg}
<section class="card"><h2>Business</h2>
<form method="post" action="/admin/business" class="row">
<label>Business name <input name="name" value="${esc(biz)}" maxlength="80" required></label>
<button>Save name</button></form></section>
${sections}`
    )
  );
}));

// ---------- admin: actions ----------

app.post('/admin/business', adminPost(async (req) => {
  const name = clean(req.body.name, 80);
  if (!name) throw new UserError('Enter a business name.');
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('business_name', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [name]
  );
  return flash(true, 'Business name saved.');
}));

app.post('/admin/stalls/:id/rename', adminPost(async (req) => {
  const id = toInt(req.params.id);
  const name = clean(req.body.name);
  if (!name) throw new UserError('Enter a stall name.');
  const { rowCount } = await pool.query('UPDATE stalls SET name = $1 WHERE id = $2', [name, id]);
  if (!rowCount) throw new UserError('Stall not found.');
  return flash(true, 'Stall renamed.', `#stall-${id}`);
}));

app.post('/admin/stalls/:id/products', adminPost(async (req) => {
  const sid = toInt(req.params.id);
  const name = clean(req.body.name);
  if (!name) throw new UserError('Enter a product name.');
  const check = await pool.query('SELECT 1 FROM stalls WHERE id = $1', [sid]);
  if (!check.rowCount) throw new UserError('Stall not found.');
  await pool.query(
    `INSERT INTO products (stall_id, name, sku, stock, reorder_at, price)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [sid, name, clean(req.body.sku, 40), toInt(req.body.stock), toInt(req.body.reorder_at), toPrice(req.body.price)]
  );
  return flash(true, `Added ${name}.`, `#stall-${sid}`);
}));

app.post('/admin/products/:id/delete', adminPost(async (req) => {
  const { rows } = await pool.query(
    'DELETE FROM products WHERE id = $1 RETURNING stall_id, name',
    [toInt(req.params.id)]
  );
  if (!rows[0]) throw new UserError('Product not found.');
  return flash(true, `Removed ${rows[0].name}. Past sales are kept.`, `#stall-${rows[0].stall_id}`);
}));

app.post('/admin/sales', adminPost(async (req) => {
  const sid = toInt(req.body.stall_id);
  const pid = toInt(req.body.product_id);
  const qty = toInt(req.body.qty);
  if (qty < 1) throw new UserError('Quantity must be at least 1.');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'SELECT * FROM products WHERE id = $1 AND stall_id = $2 FOR UPDATE',
      [pid, sid]
    );
    const p = rows[0];
    if (!p) throw new UserError('Item not found for this stall.');
    if (qty > p.stock) throw new UserError(`Only ${p.stock} in stock for ${p.name}.`);
    await client.query('UPDATE products SET stock = stock - $1, sold = sold + $1 WHERE id = $2', [qty, p.id]);
    await client.query(
      `INSERT INTO sales (stall_id, product_id, product_name, qty, amount)
       VALUES ($1, $2, $3, $4, $5)`,
      [sid, p.id, p.name, qty, qty * Number(p.price)]
    );
    await client.query('COMMIT');
    return flash(true, `Sale recorded: ${qty} × ${p.name}.`, `#stall-${sid}`);
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

// ---------- errors and startup ----------

app.use((req, res) => {
  res.status(404).send('Not found');
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something went wrong.');
});

init()
  .then(() => {
    app.listen(PORT, () => console.log(`Stock tracker running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('Could not start:', err);
    process.exit(1);
  });
