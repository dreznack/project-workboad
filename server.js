require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const pool = require('./db');

const PgSession = require('connect-pg-simple')(session);

const app = express();
const PORT = process.env.PORT || 4100;
const isProd = process.env.NODE_ENV === 'production';

const DEFAULT_STATE = {
  company: { name: 'Your Company' },
  projects: [],
};

app.use(cors({ origin: process.env.CORS_ORIGIN || true, credentials: true }));
app.use(express.json({ limit: '20mb' }));

// Railway (and most hosting platforms) terminate HTTPS at their edge and forward
// plain HTTP internally. Without this, Express thinks every request is insecure,
// and silently refuses to set the login cookie (since it's marked "secure").
app.set('trust proxy', 1);

app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'insecure-dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
  },
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

/* ---------------- Startup migrations ---------------- */

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_auth (
      id INTEGER PRIMARY KEY,
      password_hash TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid VARCHAR NOT NULL COLLATE "default",
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL,
      CONSTRAINT session_pkey PRIMARY KEY (sid)
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS IDX_session_expire ON session (expire);`);
}

/* ---------------- Auth routes ---------------- */

app.get('/api/auth/status', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT 1 FROM app_auth WHERE id = 1');
    res.json({
      authenticated: !!(req.session && req.session.authed),
      needsSetup: rows.length === 0,
      environment: process.env.APP_ENV || 'production',
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error checking auth status.' });
  }
});

app.post('/api/auth/setup', async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    const existing = await pool.query('SELECT 1 FROM app_auth WHERE id = 1');
    if (existing.rows.length) {
      return res.status(400).json({ error: 'Already set up — use the login screen instead.' });
    }
    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO app_auth (id, password_hash) VALUES (1, $1)', [hash]);
    await pool.query(
      'INSERT INTO app_state (id, data, version) VALUES (1, $1, 1) ON CONFLICT (id) DO NOTHING',
      [DEFAULT_STATE]
    );
    req.session.authed = true;
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error during setup.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { password } = req.body || {};
    const { rows } = await pool.query('SELECT password_hash FROM app_auth WHERE id = 1');
    if (!rows.length) return res.status(400).json({ error: 'App not set up yet.' });
    const ok = await bcrypt.compare(password || '', rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect password.' });
    req.session.authed = true;
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    const { rows } = await pool.query('SELECT password_hash FROM app_auth WHERE id = 1');
    const ok = await bcrypt.compare(currentPassword || '', rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Current password is incorrect.' });
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE app_auth SET password_hash = $1 WHERE id = 1', [hash]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error changing password.' });
  }
});

/* ---------------- State routes (optimistic concurrency, same pattern as subcontract-control) ---------------- */

app.get('/api/state', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT data, version FROM app_state WHERE id = 1');
    if (!rows.length) return res.json({ data: DEFAULT_STATE, version: 1 });
    res.json({ data: rows[0].data, version: rows[0].version });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error loading state.' });
  }
});

app.post('/api/state', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { data, expectedVersion } = req.body || {};
    if (!data) return res.status(400).json({ error: 'Missing data.' });

    await client.query('BEGIN');
    const { rows } = await client.query('SELECT version FROM app_state WHERE id = 1 FOR UPDATE');
    const currentVersion = rows.length ? rows[0].version : 0;

    if (typeof expectedVersion === 'number' && expectedVersion !== currentVersion) {
      await client.query('ROLLBACK');
      const latest = await pool.query('SELECT data, version FROM app_state WHERE id = 1');
      return res.status(409).json({
        error: 'Someone else saved changes since you loaded this page. Refresh to get the latest version.',
        data: latest.rows[0]?.data,
        version: latest.rows[0]?.version,
      });
    }

    const newVersion = currentVersion + 1;
    await client.query(
      `INSERT INTO app_state (id, data, version, updated_at) VALUES (1, $1, $2, now())
       ON CONFLICT (id) DO UPDATE SET data = $1, version = $2, updated_at = now()`,
      [data, newVersion]
    );
    await client.query('COMMIT');
    res.json({ ok: true, version: newVersion });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Server error saving state.' });
  } finally {
    client.release();
  }
});

/* ---------------- Static frontend ---------------- */

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

migrate()
  .then(() => {
    app.listen(PORT, () => console.log(`Bridge PM app listening on port ${PORT}`));
  })
  .catch((e) => {
    console.error('Migration failed:', e);
    process.exit(1);
  });
