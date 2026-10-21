'use strict';
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error('SECURITY: Set ADMIN_PASSWORD to a strong password of at least 12 characters before starting.');
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('SECURITY: Set SESSION_SECRET to a random secret of at least 32 characters before starting.');
  process.exit(1);
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  identity_number TEXT NOT NULL,
  fuel TEXT NOT NULL CHECK (fuel IN ('بنزين','ديزل')),
  phone TEXT NOT NULL,
  vehicle_number TEXT NOT NULL,
  vehicle_type TEXT NOT NULL,
  vehicle_color TEXT NOT NULL,
  vin TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_requests_identity_created ON requests(identity_number, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at DESC);
CREATE TABLE IF NOT EXISTS admin_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
`);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"] } }}));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  name: 'vehicle_admin_session',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 2 * 60 * 60 * 1000 }
}));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

const clean = (v, max=200) => typeof v === 'string' ? v.trim().replace(/[\u0000-\u001F\u007F]/g, '').slice(0, max) : '';
const normalizeIdentity = (v) => clean(v, 40).replace(/\s+/g, '').toUpperCase();
const validPhone = (v) => /^\+?[0-9]{8,15}$/.test(v);
const validVin = (v) => /^[A-HJ-NPR-Z0-9]{5,30}$/i.test(v);
const adminOnly = (req, res, next) => req.session && req.session.isAdmin ? next() : res.status(401).json({ error: 'يلزم تسجيل دخول الإدارة أولاً.' });

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Public request endpoint. Server-side DB check is authoritative; client-side checks are not trusted.
app.post('/api/requests', (req, res) => {
  const fullName = clean(req.body.fullName, 160);
  const identityNumber = normalizeIdentity(req.body.nationalId);
  const fuel = clean(req.body.fuel, 20);
  const phone = clean(req.body.phone, 20).replace(/[\s()-]/g, '');
  const vehicleNumber = clean(req.body.vehicleNumber, 40);
  const vehicleType = clean(req.body.vehicleType, 100);
  const vehicleColor = clean(req.body.vehicleColor, 50);
  const vin = clean(req.body.vin, 30).toUpperCase();

  if (!fullName || fullName.split(/\s+/).length < 2) return res.status(400).json({ error: 'يرجى إدخال الاسم الكامل.' });
  if (!identityNumber || !/^[A-Z0-9-]{5,40}$/.test(identityNumber)) return res.status(400).json({ error: 'الرقم الوطني أو الإداري غير صحيح.' });
  if (!['بنزين', 'ديزل'].includes(fuel)) return res.status(400).json({ error: 'يرجى اختيار نوع الوقود.' });
  if (!validPhone(phone)) return res.status(400).json({ error: 'رقم الهاتف غير صحيح؛ أدخل من 8 إلى 15 رقماً.' });
  if (!vehicleNumber || !vehicleType || !vehicleColor) return res.status(400).json({ error: 'يرجى استكمال رقم المركبة ونوعها ولونها.' });
  if (!validVin(vin)) return res.status(400).json({ error: 'رقم الهيكل غير صحيح. أدخل من 5 إلى 30 حرفاً أو رقماً، دون I أو O أو Q.' });

  const insert = db.transaction(() => {
    const prior = db.prepare(`SELECT created_at FROM requests WHERE identity_number = ? ORDER BY created_at DESC LIMIT 1`).get(identityNumber);
    if (prior) {
      const priorTime = new Date(prior.created_at).getTime();
      const expiry = priorTime + WINDOW_MS;
      if (Number.isFinite(priorTime) && Date.now() < expiry) {
        return { duplicate: true, remainingMs: expiry - Date.now(), nextAllowedAt: new Date(expiry).toISOString() };
      }
    }
    const result = db.prepare(`INSERT INTO requests (full_name, identity_number, fuel, phone, vehicle_number, vehicle_type, vehicle_color, vin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(fullName, identityNumber, fuel, phone, vehicleNumber, vehicleType, vehicleColor, vin);
    return { duplicate: false, id: Number(result.lastInsertRowid) };
  });

  try {
    const result = insert();
    if (result.duplicate) {
      const days = Math.ceil(result.remainingMs / (24 * 60 * 60 * 1000));
      return res.status(409).json({ error: `سبق تسجيل طلب بهذا الرقم. يمكن تقديم طلب جديد بعد ${days} يومًا تقريبًا.`, nextAllowedAt: result.nextAllowedAt });
    }
    return res.status(201).json({ ok: true, message: 'تم إرسال الطلب بنجاح.', requestId: result.id });
  } catch (err) {
    console.error('Request submission failed:', err.message);
    return res.status(500).json({ error: 'تعذر حفظ الطلب حالياً. يرجى المحاولة لاحقاً.' });
  }
});

app.post('/api/admin/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false }), (req, res) => {
  const username = clean(req.body.username, 80);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const a = Buffer.from(username);
  const b = Buffer.from(ADMIN_USER);
  const c = Buffer.from(password);
  const d = Buffer.from(ADMIN_PASSWORD);
  const userOk = a.length === b.length && crypto.timingSafeEqual(a, b);
  const passOk = c.length === d.length && crypto.timingSafeEqual(c, d);
  if (!userOk || !passOk) {
    db.prepare('INSERT INTO admin_audit(event) VALUES (?)').run('failed_login');
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
  }
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'تعذر بدء جلسة الإدارة.' });
    req.session.isAdmin = true;
    req.session.username = ADMIN_USER;
    db.prepare('INSERT INTO admin_audit(event) VALUES (?)').run('admin_login');
    res.json({ ok: true, message: 'تم تسجيل الدخول.' });
  });
});
app.post('/api/admin/logout', adminOnly, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/admin/me', adminOnly, (req, res) => res.json({ ok: true, username: req.session.username }));

app.get('/api/admin/summary', adminOnly, (_req, res) => {
  const total = db.prepare('SELECT COUNT(*) AS n FROM requests').get().n;
  const today = db.prepare("SELECT COUNT(*) AS n FROM requests WHERE date(created_at) = date('now')").get().n;
  const month = db.prepare("SELECT COUNT(*) AS n FROM requests WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')").get().n;
  const fuel = db.prepare('SELECT fuel, COUNT(*) AS count FROM requests GROUP BY fuel').all();
  const monthly = db.prepare("SELECT strftime('%Y-%m', created_at) AS month, COUNT(*) AS count FROM requests GROUP BY month ORDER BY month DESC LIMIT 12").all();
  res.json({ total, today, month, fuel, monthly });
});
app.get('/api/admin/requests', adminOnly, (req, res) => {
  const q = clean(req.query.q, 100);
  const from = clean(req.query.from, 10);
  const to = clean(req.query.to, 10);
  const page = Math.max(1, Math.min(100000, Number.parseInt(req.query.page || '1', 10) || 1));
  const limit = Math.max(1, Math.min(100, Number.parseInt(req.query.limit || '25', 10) || 25));
  const where = [];
  const args = [];
  if (q) { where.push('(full_name LIKE ? OR identity_number LIKE ? OR phone LIKE ? OR vehicle_number LIKE ? OR vin LIKE ?)'); const like = `%${q}%`; args.push(like, like, like, like, like); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(from)) { where.push('date(created_at) >= date(?)'); args.push(from); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(to)) { where.push('date(created_at) <= date(?)'); args.push(to); }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = db.prepare(`SELECT COUNT(*) AS n FROM requests ${clause}`).get(...args).n;
  const rows = db.prepare(`SELECT id, full_name AS fullName, identity_number AS nationalId, fuel, phone, vehicle_number AS vehicleNumber, vehicle_type AS vehicleType, vehicle_color AS vehicleColor, vin, created_at AS createdAt FROM requests ${clause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...args, limit, (page - 1) * limit);
  res.json({ rows, total, page, pages: Math.ceil(total / limit) });
});
app.get('/api/admin/export.csv', adminOnly, (_req, res) => {
  const rows = db.prepare('SELECT id, full_name, identity_number, fuel, phone, vehicle_number, vehicle_type, vehicle_color, vin, created_at FROM requests ORDER BY created_at DESC').all();
  const cols = ['id','full_name','identity_number','fuel','phone','vehicle_number','vehicle_type','vehicle_color','vin','created_at'];
  const cell = (v) => { let s = String(v ?? ''); if (/^[=+@\-]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const csv = '\uFEFF' + [cols, ...rows.map(r => cols.map(c => r[c]))].map(row => row.map(cell).join(',')).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="vehicle-requests.csv"');
  res.send(csv);
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Vehicle request app running on port ${PORT}`));
