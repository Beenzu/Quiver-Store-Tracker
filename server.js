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
app.use(express.urlencoded({ extended: false, limit: '25mb' }));

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

// ---------- time periods for the home overview ----------
// Dates are calendar days in TIMEZONE, as YYYY-MM-DD strings.
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const ALL_TIME = { period: 'all', from: '1970-01-01', to: '9999-12-31', label: 'All time' };
const PERIODS = [
  ['today', 'Today'],
  ['week', 'Last 7 days'],
  ['month', 'This month'],
  ['year', 'This year'],
  ['all', 'All time'],
  ['custom', 'Custom dates'],
];
const todayStr = () => new Intl.DateTimeFormat('en-CA', { timeZone: TIMEZONE }).format(new Date());
function shiftDays(ymd, n) {
  const d = new Date(ymd + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}
function parseRange(q) {
  const today = todayStr();
  const period = PERIODS.some(([v]) => v === q.period) ? q.period : 'all';
  const presets = {
    today: [today, today, 'Today'],
    week: [shiftDays(today, -6), today, 'Last 7 days'],
    month: [today.slice(0, 8) + '01', today, 'This month'],
    year: [today.slice(0, 4) + '-01-01', today, 'This year'],
  };
  if (period === 'custom') {
    let from = DAY.test(q.from || '') ? q.from : today;
    let to = DAY.test(q.to || '') ? q.to : today;
    if (from > to) [from, to] = [to, from];
    return { period, from, to, label: `${from} to ${to}` };
  }
  if (period === 'all') return ALL_TIME;
  const [from, to, label] = presets[period];
  return { period, from, to, label };
}
const periodOptions = (selected) =>
  PERIODS.map(([v, l]) => `<option value="${v}"${v === selected ? ' selected' : ''}>${l}</option>`).join('');

const flash = (ok, msg, hash = '') =>
  `/admin?ok=${ok ? 1 : 0}&msg=${encodeURIComponent(msg)}${hash}`;

// ---------- auth ----------
// Two kinds of login share one form:
//   - the business owner (ADMIN_PASSWORD, no email) sees and manages everything
//   - a vendor (email + password) sees and manages only the stalls assigned to them

const ADMIN_TOKEN = crypto.createHmac('sha256', SECRET).update('admin').digest('hex');
// Including the password hash means a vendor's session dies when their password changes.
const vendorSig = (id, hash) =>
  crypto.createHmac('sha256', SECRET).update(`vendor|${id}|${hash}`).digest('hex');

function safeEq(a, b) {
  const x = Buffer.from(String(a ?? ''));
  const y = Buffer.from(String(b ?? ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) {
      try {
        return decodeURIComponent(v.join('='));
      } catch {
        return '';
      }
    }
  }
  return '';
}

function setCookie(res, name, value, maxAge = 2592000) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.append('Set-Cookie', `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`);
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `scrypt$${salt}$${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
}

function checkPassword(pw, stored) {
  const [alg, salt, hash] = String(stored || '').split('$');
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const calc = crypto.scryptSync(String(pw), salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return expected.length === calc.length && crypto.timingSafeEqual(calc, expected);
}

const ownerPasswordOk = (input) => ADMIN_PASSWORD !== '' && safeEq(input, ADMIN_PASSWORD);

// Returns { role: 'admin' } | { role: 'vendor', id, name } | null. Cached per request.
async function actorOf(req) {
  if (req.actor !== undefined) return req.actor;
  let actor = null;
  if (ADMIN_PASSWORD && safeEq(readCookie(req, 'admin'), ADMIN_TOKEN)) {
    actor = { role: 'admin' };
  } else {
    const c = readCookie(req, 'vendor');
    const dot = c.indexOf('.');
    const id = dot > 0 ? toInt(c.slice(0, dot)) : 0;
    if (id) {
      const { rows } = await pool.query(
        'SELECT id, name, business_name, password_hash, suspended FROM vendors WHERE id = $1',
        [id]
      );
      if (rows[0] && !rows[0].suspended && safeEq(c.slice(dot + 1), vendorSig(rows[0].id, rows[0].password_hash))) {
        actor = {
          role: 'vendor',
          id: rows[0].id,
          name: rows[0].name,
          business: rows[0].business_name || rows[0].name,
        };
      }
    }
  }
  req.actor = actor;
  return actor;
}

// Every management POST goes through this: must be logged in, and optionally the owner.
// ownerOnly: onboarding, suspending, reinstating and password resets (business owner only).
// vendorOnly: stalls, products, sales and the vendor's own business name (vendors only).
const manage = (fn, { ownerOnly = false, vendorOnly = false } = {}) =>
  wrap(async (req, res) => {
    const actor = await actorOf(req);
    if (!actor) return res.redirect('/admin/login');
    if (ownerOnly && actor.role !== 'admin') {
      return res.redirect(flash(false, 'Only the business owner can do that.'));
    }
    if (vendorOnly && actor.role !== 'vendor') {
      return res.redirect(flash(false, 'Only vendors manage stalls, products and sales.'));
    }
    try {
      res.redirect(await fn(req, actor));
    } catch (e) {
      if (e instanceof UserError) return res.redirect(flash(false, e.message));
      throw e;
    }
  });

// Throws unless the actor may manage this stall. Vendors get the same "not found" as a missing stall.
async function assertStall(actor, id) {
  const { rows } = await pool.query('SELECT id, vendor_id FROM stalls WHERE id = $1', [id]);
  if (!rows[0] || actor.role !== 'vendor' || rows[0].vendor_id !== actor.id) {
    throw new UserError('Stall not found.');
  }
  return rows[0];
}

async function vendorExists(id) {
  const { rowCount } = await pool.query('SELECT 1 FROM vendors WHERE id = $1', [id]);
  return rowCount > 0;
}

// ---------- database ----------

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS vendors (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  // Each vendor's business name is shown in the top bar when they are signed in.
  await pool.query(`ALTER TABLE vendors ADD COLUMN IF NOT EXISTS business_name TEXT NOT NULL DEFAULT ''`);
  // A suspended vendor cannot log in, and any session they already have stops working.
  await pool.query(`ALTER TABLE vendors ADD COLUMN IF NOT EXISTS suspended BOOLEAN NOT NULL DEFAULT false`);
  await pool.query(`CREATE TABLE IF NOT EXISTS stalls (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    position INT NOT NULL DEFAULT 0
  )`);
  // Existing stalls get no vendor, so they stay under the owner until assigned.
  await pool.query(`ALTER TABLE stalls ADD COLUMN IF NOT EXISTS vendor_id INT REFERENCES vendors(id) ON DELETE SET NULL`);
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
    // Old installs seeded 'Stall 1'-'Stall 3'. Remove those once; only stalls created later show up.
  }
  const cleaned = await pool.query(`SELECT 1 FROM settings WHERE key = 'premade_stalls_removed'`);
  if (!cleaned.rowCount) {
    await pool.query(`DELETE FROM stalls WHERE vendor_id IS NULL AND name IN ('Stall 1', 'Stall 2', 'Stall 3')`);
    await pool.query(`INSERT INTO settings (key, value) VALUES ('premade_stalls_removed', '1')`);
  }
}

async function businessName() {
  const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'business_name'`);
  return rows[0] ? rows[0].value : 'My Business';
}

async function stalls() {
  return (await pool.query('SELECT * FROM stalls ORDER BY position, id')).rows;
}

// Sales counts only those whose calendar day (in TIMEZONE) falls in the range. Stock is current.
async function stallStats(range, vendorId = null) {
  const params = [range.from, range.to, TIMEZONE];
  let where = '';
  if (vendorId) {
    params.push(vendorId);
    where = 'WHERE s.vendor_id = $4';
  }
  const { rows } = await pool.query(`
    SELECT s.id, s.name,
      (SELECT COUNT(*)::int FROM products p WHERE p.stall_id = s.id) AS items,
      (SELECT COALESCE(SUM(p.stock), 0)::int FROM products p WHERE p.stall_id = s.id) AS stock,
      (SELECT COUNT(*)::int FROM products p WHERE p.stall_id = s.id AND p.stock <= p.reorder_at) AS low,
      (SELECT COALESCE(SUM(x.qty), 0)::int FROM sales x WHERE x.stall_id = s.id
        AND (x.created_at AT TIME ZONE $3)::date BETWEEN $1::date AND $2::date) AS units,
      (SELECT COALESCE(SUM(x.amount), 0)::float8 FROM sales x WHERE x.stall_id = s.id
        AND (x.created_at AT TIME ZONE $3)::date BETWEEN $1::date AND $2::date) AS revenue
    FROM stalls s ${where}
    ORDER BY s.position, s.id`, params);
  return rows;
}

async function lowItems(vendorId = null) {
  const { rows } = await pool.query(`
    SELECT p.name, p.stock, p.reorder_at, s.name AS stall_name
    FROM products p JOIN stalls s ON s.id = p.stall_id
    WHERE p.stock <= p.reorder_at ${vendorId ? 'AND s.vendor_id = $1' : ''}
    ORDER BY s.position, s.id, p.name`, vendorId ? [vendorId] : []);
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

// brandName replaces the top-bar name (a vendor's business, or a stall's owner business).
// viewer is the signed-in actor. Without one (the login page) no stall names or links are shown.
async function layout(title, content, brandName = '', viewer = null) {
  const [defaultBiz, list] = await Promise.all([businessName(), viewer ? stalls() : []]);
  const biz = brandName || defaultBiz;
  const visible = !viewer ? [] : viewer.role === 'admin' ? list : list.filter((s) => s.vendor_id === viewer.id);
  const nav = visible.map((s) => `<a href="/stalls/${s.id}">${esc(s.name)}</a>`).join('');
  const links = viewer ? `<a href="/">Home</a>${nav}<a href="/admin">Admin</a>` : '';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · ${esc(biz)}</title><style>${CSS}</style></head>
<body>
<header><a class="brand" href="/">${esc(biz)}</a><nav>${links}</nav></header>
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
        ? `<td><details><summary>Edit</summary>
<form method="post" action="/admin/products/${p.id}/edit" class="grid" style="margin-top:10px;min-width:460px">
<label>Name <input name="name" value="${esc(p.name)}" maxlength="100" required></label>
<label>SKU <input name="sku" value="${esc(p.sku)}" maxlength="40"></label>
<label>Stock <input name="stock" type="number" min="0" value="${Number(p.stock) || 0}"></label>
<label>Reorder at <input name="reorder_at" type="number" min="0" value="${Number(p.reorder_at) || 0}"></label>
<label>Price (K) <input name="price" type="number" min="0" step="0.01" value="${Number(p.price) || 0}"></label>
<button>Save product</button></form></details>
<form method="post" action="/admin/products/${p.id}/delete" style="display:inline" onsubmit="return confirm(${esc(JSON.stringify(`Delete ${p.name}? Its stock is removed. Past sales are kept.`))})"><button class="link">Remove</button></form></td>`
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

// ---------- access gate ----------
// Nothing is public. Every page and every request needs a signed-in owner or vendor,
// except the login page itself. Anyone else is sent to the login form.
app.use(
  wrap(async (req, res, next) => {
    if (req.path === '/admin/login') return next();
    if (await actorOf(req)) return next();
    res.redirect('/admin/login');
  })
);

// ---------- pages (signed-in owner or vendor only) ----------

app.get('/', wrap(async (req, res) => {
  const actor = await actorOf(req);
  const vendorId = actor && actor.role === 'vendor' ? actor.id : null;
  const range = parseRange(req.query);
  const [stats, low] = await Promise.all([stallStats(range, vendorId), lowItems(vendorId)]);
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
      `<div><h1>${vendorId ? esc(actor.business) : 'Business overview'}</h1><div class="muted">${vendorId ? 'Your stalls only' : 'Totals across every stall'} · ${esc(range.label)}</div></div>
<form method="get" action="/" class="card row" style="align-items:flex-end">
<label>Period <select name="period">${periodOptions(range.period)}</select></label>
<label>From <input type="date" name="from" value="${range.period === 'all' ? '' : range.from}"></label>
<label>To <input type="date" name="to" value="${range.period === 'all' ? '' : range.to}"></label>
<button>Show</button></form>
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
</section>`,
      vendorId ? actor.business : '',
      actor
    )
  );
}));

app.get('/stalls/:id', wrap(async (req, res) => {
  const actor = await actorOf(req);
  const id = toInt(req.params.id);
  const st = (await stalls()).find((s) => s.id === id);
  // A vendor gets the same "not found" for another vendor's stall as for a missing one.
  if (!st || (actor.role !== 'admin' && st.vendor_id !== actor.id)) {
    return res.status(404).send(await layout('Not found', '<section class="card">Stall not found.</section>', '', actor));
  }
  const [stats, prods, sales] = await Promise.all([
    stallStats(ALL_TIME),
    pool.query('SELECT * FROM products WHERE stall_id = $1 ORDER BY name', [id]),
    pool.query('SELECT * FROM sales WHERE stall_id = $1 ORDER BY created_at DESC LIMIT 10', [id]),
  ]);
  const owner = st.vendor_id
    ? (await pool.query('SELECT name, business_name FROM vendors WHERE id = $1', [st.vendor_id])).rows[0]
    : null;
  const brand = owner ? owner.business_name || owner.name : '';
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
</div>`,
      brand,
      actor
    )
  );
}));

// ---------- admin: login ----------

app.get('/admin/login', wrap(async (req, res) => {
  const err = req.query.bad ? '<div class="notice bad">Login failed. Check the email and password.</div>' : '';
  const note = ADMIN_PASSWORD
    ? ''
    : '<div class="notice bad">Owner login is off: ADMIN_PASSWORD is not set on the server. Vendors can still log in with their email.</div>';
  res.send(
    await layout(
      'Admin login',
      `<section class="card login"><h2>Admin login</h2>${err}${note}
<form method="post" action="/admin/login" class="row" style="flex-direction:column;align-items:stretch">
<label>Vendor email <span class="muted">(leave blank if you are the business owner)</span>
<input type="email" name="email" autocomplete="username"></label>
<label>Password <input type="password" name="password" required autocomplete="current-password"></label>
<button>Log in</button></form></section>`
    )
  );
}));

app.post('/admin/login', wrap(async (req, res) => {
  const email = clean(req.body.email, 200).toLowerCase();
  const password = String(req.body.password || '');

  if (!email) {
    if (!ownerPasswordOk(password)) return res.redirect('/admin/login?bad=1');
    setCookie(res, 'admin', ADMIN_TOKEN);
    return res.redirect('/admin');
  }

  const { rows } = await pool.query('SELECT id, password_hash, suspended FROM vendors WHERE email = $1', [email]);
  if (!rows[0] || rows[0].suspended || !checkPassword(password, rows[0].password_hash)) {
    return res.redirect('/admin/login?bad=1');
  }
  setCookie(res, 'vendor', `${rows[0].id}.${vendorSig(rows[0].id, rows[0].password_hash)}`);
  res.redirect('/admin');
}));

app.post('/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', [
    'admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
    'vendor=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0',
  ]);
  res.redirect('/admin/login');
});

// ---------- admin: page ----------
// The business owner sees only the vendor list: onboard, suspend/reinstate, set passwords.
// A vendor sees and manages only their own business name, stalls, products and sales.

function vendorsSection(vendors, allStalls) {
  const rows = vendors
    .map((v) => {
      const n = allStalls.filter((s) => s.vendor_id === v.id).length;
      const status = v.suspended
        ? '<span style="color:#8A2E12;font-weight:600">Suspended</span>'
        : '<span style="color:#2F6B4F;font-weight:600">Active</span>';
      const toggle = v.suspended
        ? `<form method="post" action="/admin/vendors/${v.id}/unsuspend"><button>Reinstate</button></form>`
        : `<form method="post" action="/admin/vendors/${v.id}/suspend" onsubmit="return confirm('Suspend this vendor? They will be signed out and cannot log in until reinstated.')"><button class="link">Suspend</button></form>`;
      return `<tr>
<td>${esc(v.name)}</td><td>${esc(v.email)}</td><td>${num(n)}</td><td>${status}</td>
<td><form method="post" action="/admin/vendors/${v.id}/password" class="row" style="flex-wrap:nowrap">
<input type="password" name="password" minlength="8" placeholder="New password" required style="width:160px"><button>Set password</button></form></td>
<td>${toggle}</td></tr>`;
    })
    .join('');
  return `<section class="card"><h2>Vendors</h2>
<p class="muted" style="margin:0 0 12px">Vendors manage their own business name, stalls, products and sales. Here you onboard them, suspend or reinstate them, and set their passwords.</p>
${
  vendors.length
    ? `<div class="scroll"><table><thead><tr><th>Vendor</th><th>Login email</th><th>Stalls</th><th>Status</th><th>Password</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p class="muted">No vendors yet.</p>'
}
<h3>Onboard a vendor</h3>
<form method="post" action="/admin/vendors" class="grid">
<label>Vendor name <input name="name" maxlength="100" required></label>
<label>Login email <input name="email" type="email" maxlength="200" required></label>
<label>Password (min 8) <input name="password" type="password" minlength="8" required></label>
<button>Onboard vendor</button></form></section>`;
}

function vendorAccountCard(actor) {
  return `<section class="card"><h2>Your business name</h2>
<p class="muted" style="margin:0 0 12px">Shown in the top bar when you are signed in.</p>
<form method="post" action="/admin/account/business-name" class="row">
<label>Business name <input name="business_name" value="${esc(actor.business)}" maxlength="100" required></label>
<button>Save name</button></form></section>`;
}

function addStallForm() {
  return `<section class="card"><h2>Add a stall</h2>
<form method="post" action="/admin/stalls" class="row">
<label>Stall name <input name="name" maxlength="100" required></label>
<button>Add stall</button></form></section>`;
}

function stallAdminSection(st, prods, recent) {
  const opts = prods.length
    ? prods.map((p) => `<option value="${p.id}">${esc(p.name)} (${num(p.stock)} left)</option>`).join('')
    : '';
  const saleForm = prods.length
    ? `<form method="post" action="/admin/sales" class="grid" onsubmit="return confirm('Record this sale now? The stock will be reduced. You can undo it from Recent sales.')">
<input type="hidden" name="stall_id" value="${st.id}">
<label>Item <select name="product_id" required>${opts}</select></label>
<label>Quantity <input name="qty" type="number" min="1" value="1" required></label>
<button>Process sale</button></form>`
    : '<p class="muted">Add a product first, then you can process sales for it.</p>';
  const recentList = recent.length
    ? `<ul class="list">${recent
        .map((x) => `<li><span>${esc(x.product_name)} × ${num(x.qty)}</span><span>${money(x.amount)} <span class="muted">${when(x.created_at)}</span></span>
<form method="post" action="/admin/sales/${x.id}/undo" onsubmit="return confirm('Undo this sale? The items go back into stock.')"><button class="link">Undo</button></form></li>`)
        .join('')}</ul>`
    : '<p class="muted">No sales yet.</p>';

  return `<section class="card" id="stall-${st.id}">
<div class="row" style="justify-content:space-between;align-items:center"><h2 style="margin:0">${esc(st.name)}</h2>
<form method="post" action="/admin/stalls/${st.id}/delete" onsubmit="return confirm('Delete this stall, its products and its sales records? This cannot be undone.')"><button class="link">Delete stall</button></form></div>
<form method="post" action="/admin/stalls/${st.id}/rename" class="row" style="margin-top:12px">
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
  const actor = await actorOf(req);
  if (!actor) return res.redirect('/admin/login');
  const msg = req.query.msg
    ? `<div class="notice ${req.query.ok === '1' ? 'ok' : 'bad'}">${esc(req.query.msg)}</div>`
    : '';
  const header = (who) =>
    `<div class="row" style="justify-content:space-between"><div><h1>Admin</h1><div class="muted">${who}</div></div>
<form method="post" action="/admin/logout"><button class="link">Log out</button></form></div>`;

  if (actor.role === 'admin') {
    const [allStalls, vendorRows] = await Promise.all([
      stalls(),
      pool.query('SELECT id, name, email, suspended FROM vendors ORDER BY name, id'),
    ]);
    return res.send(
      await layout(
        'Admin',
        `${header('Business owner')}
${msg}
${vendorsSection(vendorRows.rows, allStalls)}`
      )
    );
  }

  const [allStalls, prods, sales] = await Promise.all([
    stalls(),
    pool.query('SELECT * FROM products ORDER BY name'),
    pool.query('SELECT * FROM sales ORDER BY created_at DESC LIMIT 300'),
  ]);
  const list = allStalls.filter((s) => s.vendor_id === actor.id);
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
      `${header(`Signed in as ${esc(actor.name)}`)}
${msg}
${vendorAccountCard(actor)}
${addStallForm()}
${list.length ? sections : '<section class="card"><p class="muted">No stalls yet.</p></section>'}`,
      actor.business,
      actor
    )
  );
}));

// ---------- owner: vendor onboarding, suspension and passwords ----------

app.post('/admin/vendors', manage(async (req) => {
  const name = clean(req.body.name);
  const email = clean(req.body.email, 200).toLowerCase();
  const pw = String(req.body.password || '');
  if (!name) throw new UserError('Enter a vendor name.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new UserError('Enter a valid vendor email.');
  if (pw.length < 8) throw new UserError('Password must be at least 8 characters.');
  try {
    // The vendor sets their business name later, from their own admin page.
    await pool.query(
      'INSERT INTO vendors (name, email, password_hash, business_name) VALUES ($1, $2, $3, $4)',
      [name, email, hashPassword(pw), name]
    );
  } catch (e) {
    if (e.code === '23505') throw new UserError('A vendor with that email already exists.');
    throw e;
  }
  return flash(true, `Onboarded vendor ${name}.`);
}, { ownerOnly: true }));

app.post('/admin/vendors/:id/password', manage(async (req) => {
  const pw = String(req.body.password || '');
  if (pw.length < 8) throw new UserError('Password must be at least 8 characters.');
  // Changing the hash also signs the vendor out everywhere.
  const { rows } = await pool.query(
    'UPDATE vendors SET password_hash = $1 WHERE id = $2 RETURNING name',
    [hashPassword(pw), toInt(req.params.id)]
  );
  if (!rows[0]) throw new UserError('Vendor not found.');
  return flash(true, `Password updated for ${rows[0].name}. They will need to log in again.`);
}, { ownerOnly: true }));

// Suspending signs the vendor out at once (the session check reads this flag) and blocks login.
const setSuspended = (suspended) =>
  manage(async (req) => {
    const { rows } = await pool.query(
      'UPDATE vendors SET suspended = $1 WHERE id = $2 RETURNING name',
      [suspended, toInt(req.params.id)]
    );
    if (!rows[0]) throw new UserError('Vendor not found.');
    return flash(
      true,
      suspended
        ? `Suspended ${rows[0].name}. They are signed out and cannot log in until reinstated.`
        : `Reinstated ${rows[0].name}.`
    );
  }, { ownerOnly: true });

app.post('/admin/vendors/:id/suspend', setSuspended(true));
app.post('/admin/vendors/:id/unsuspend', setSuspended(false));

// ---------- vendor: own business name, stalls, products, sales ----------

app.post('/admin/account/business-name', manage(async (req, actor) => {
  const name = clean(req.body.business_name, 100);
  if (!name) throw new UserError('Enter a business name.');
  await pool.query('UPDATE vendors SET business_name = $1 WHERE id = $2', [name, actor.id]);
  return flash(true, 'Business name saved.');
}, { vendorOnly: true }));

app.post('/admin/stalls', manage(async (req, actor) => {
  const name = clean(req.body.name);
  if (!name) throw new UserError('Enter a stall name.');
  // A vendor always owns the stalls they create.
  const { rows } = await pool.query(
    `INSERT INTO stalls (name, position, vendor_id)
     VALUES ($1, (SELECT COALESCE(MAX(position), 0) + 1 FROM stalls), $2)
     RETURNING id`,
    [name, actor.id]
  );
  return flash(true, `Added ${name}.`, `#stall-${rows[0].id}`);
}, { vendorOnly: true }));

// Stalls with sales are kept so the sales history is not lost.
app.post('/admin/stalls/:id/delete', manage(async (req, actor) => {
  const id = toInt(req.params.id);
  await assertStall(actor, id);
  const { rows: sold } = await pool.query('SELECT COUNT(*)::int AS n FROM sales WHERE stall_id = $1', [id]);
  if (sold[0].n > 0) {
    throw new UserError('This stall has recorded sales, so it cannot be deleted.');
  }
  const { rows } = await pool.query('DELETE FROM stalls WHERE id = $1 RETURNING name', [id]);
  return flash(true, `Deleted ${rows[0].name}.`);
}, { vendorOnly: true }));

app.post('/admin/stalls/:id/rename', manage(async (req, actor) => {
  const id = toInt(req.params.id);
  await assertStall(actor, id);
  const name = clean(req.body.name);
  if (!name) throw new UserError('Enter a stall name.');
  await pool.query('UPDATE stalls SET name = $1 WHERE id = $2', [name, id]);
  return flash(true, 'Stall renamed.', `#stall-${id}`);
}, { vendorOnly: true }));

app.post('/admin/stalls/:id/products', manage(async (req, actor) => {
  const sid = toInt(req.params.id);
  await assertStall(actor, sid);
  const name = clean(req.body.name);
  if (!name) throw new UserError('Enter a product name.');
  await pool.query(
    `INSERT INTO products (stall_id, name, sku, stock, reorder_at, price)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [sid, name, clean(req.body.sku, 40), toInt(req.body.stock), toInt(req.body.reorder_at), toPrice(req.body.price)]
  );
  return flash(true, `Added ${name}.`, `#stall-${sid}`);
}, { vendorOnly: true }));

app.post('/admin/products/:id/edit', manage(async (req, actor) => {
  const pid = toInt(req.params.id);
  const { rows: found } = await pool.query('SELECT stall_id FROM products WHERE id = $1', [pid]);
  if (!found[0]) throw new UserError('Product not found.');
  await assertStall(actor, found[0].stall_id);
  const name = clean(req.body.name);
  if (!name) throw new UserError('Enter a product name.');
  await pool.query(
    'UPDATE products SET name = $1, sku = $2, stock = $3, reorder_at = $4, price = $5 WHERE id = $6',
    [name, clean(req.body.sku, 40), toInt(req.body.stock), toInt(req.body.reorder_at), toPrice(req.body.price), pid]
  );
  return flash(true, `Saved ${name}.`, `#stall-${found[0].stall_id}`);
}, { vendorOnly: true }));

app.post('/admin/products/:id/delete', manage(async (req, actor) => {
  const pid = toInt(req.params.id);
  const { rows: found } = await pool.query('SELECT stall_id FROM products WHERE id = $1', [pid]);
  if (!found[0]) throw new UserError('Product not found.');
  await assertStall(actor, found[0].stall_id);
  const { rows } = await pool.query('DELETE FROM products WHERE id = $1 RETURNING stall_id, name', [pid]);
  return flash(true, `Removed ${rows[0].name}. Past sales are kept.`, `#stall-${rows[0].stall_id}`);
}, { vendorOnly: true }));

app.post('/admin/sales', manage(async (req, actor) => {
  const sid = toInt(req.body.stall_id);
  const pid = toInt(req.body.product_id);
  const qty = toInt(req.body.qty);
  if (qty < 1) throw new UserError('Quantity must be at least 1.');
  await assertStall(actor, sid);

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
}, { vendorOnly: true }));

// Puts the sold items back into stock and removes the sale.
app.post('/admin/sales/:id/undo', manage(async (req, actor) => {
  const id = toInt(req.params.id);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query('SELECT * FROM sales WHERE id = $1 FOR UPDATE', [id]);
    const sale = rows[0];
    if (!sale) throw new UserError('Sale not found.');
    await assertStall(actor, sale.stall_id);
    if (sale.product_id) {
      await client.query(
        'UPDATE products SET stock = stock + $1, sold = GREATEST(sold - $1, 0) WHERE id = $2',
        [sale.qty, sale.product_id]
      );
    }
    await client.query('DELETE FROM sales WHERE id = $1', [id]);
    await client.query('COMMIT');
    return flash(true, `Undid sale of ${sale.qty} × ${sale.product_name}. Stock restored.`, `#stall-${sale.stall_id}`);
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}, { vendorOnly: true }));

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
