'use strict';

// Load .env or flowscope.env locally; on Render, process.env is injected directly
const path = require('path');
const fs   = require('fs');
const envFiles = ['.env', 'flowscope.env'];
for (const f of envFiles) {
  const p = path.join(__dirname, f);
  if (fs.existsSync(p)) { require('dotenv').config({ path: p }); break; }
}

const express        = require('express');
const session        = require('express-session');
const bcrypt         = require('bcryptjs');
const cors           = require('cors');
const connectDB      = require('./config/db');
const User           = require('./models/User');
const { fetchLivePrice } = require('./services/marketData');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ─────────────────────────────────────────────
   CONNECT TO MONGODB
───────────────────────────────────────────── */
connectDB();

/* ─────────────────────────────────────────────
   ADMIN SEED — create one admin if none exists
───────────────────────────────────────────── */
async function seedAdmin() {
  try {
    const exists = await User.findOne({ isAdmin: true });
    if (!exists) {
      const hash = await bcrypt.hash('admin123', 10);
      await User.create({
        username:     'admin',
        passwordHash: hash,
        isAdmin:      true
      });
      console.log('[SEED] Admin user created (username: admin)');
    }
  } catch (err) {
    console.error('[SEED] Admin seed error:', err.message);
  }
}

/* Run seed after DB connection is established */
const mongoose = require('mongoose');
mongoose.connection.once('open', seedAdmin);

/* ─────────────────────────────────────────────
   MIDDLEWARE
───────────────────────────────────────────── */
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret:            process.env.SESSION_SECRET || 'flowscope-fallback-secret',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge:   2 * 60 * 60 * 1000   // 2 hours
  }
}));

/* ─────────────────────────────────────────────
   AUTH MIDDLEWARE
───────────────────────────────────────────── */

/** Check if user has active trial (trialUsed=true AND now < trialEndsAt) */
function isTrialActive(user) {
  return user.trialUsed && user.trialEndsAt && new Date() < new Date(user.trialEndsAt);
}

/** Require authenticated session — API routes return JSON 401, page routes redirect */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return res.redirect('/login.html');
}

/** Require authenticated AND admin session — else 403 */
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.redirect('/login.html');
  }
  if (!req.session.isAdmin) {
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return res.status(403).send(
      '<!DOCTYPE html><html><head><meta charset="UTF-8">' +
      '<title>403 Forbidden</title>' +
      '<style>body{background:#0b0e17;color:#c8d0e7;font-family:system-ui;display:flex;' +
      'flex-direction:column;align-items:center;justify-content:center;min-height:100vh;gap:12px;}' +
      'h1{color:#ff1744;font-size:3rem;margin:0}p{color:#4a5270}a{color:#448aff}</style>' +
      '</head><body>' +
      '<h1>403</h1><p>Access Denied — Admin privileges required.</p>' +
      '<a href="/dashboard.html">← Back to Dashboard</a>' +
      '</body></html>'
    );
  }
  return next();
}

/* ─────────────────────────────────────────────
   AUTH API ROUTES
───────────────────────────────────────────── */

/** POST /api/login — authenticate user against MongoDB */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    req.session.userId   = user._id.toString();
    req.session.username = user.username;
    req.session.isAdmin  = user.isAdmin;
    /* Determine redirect for normal users based on subscription/trial */
    let redirect = '/dashboard.html';
    if (!user.isAdmin) {
      const hasAccess = user.hasSubscription || isTrialActive(user);
      redirect = hasAccess ? '/dashboard.html' : '/subscription.html';
    } else {
      redirect = '/admin-dashboard.html';
    }
    return res.json({ ok: true, isAdmin: user.isAdmin, redirect });
  } catch (err) {
    console.error('[LOGIN]', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

/** POST /api/register — create new user in MongoDB */
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }
  if (username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  try {
    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(409).json({ error: 'Username already taken.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ username, passwordHash });
    return res.json({ ok: true, message: 'Account created. You can now log in.' });
  } catch (err) {
    console.error('[REGISTER]', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

/** POST /api/logout */
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true, redirect: '/login.html' });
  });
});

/** GET /api/me — return current session info */
app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    userId:   req.session.userId,
    username: req.session.username,
    isAdmin:  req.session.isAdmin
  });
});

/* ─────────────────────────────────────────────
   ADMIN API ROUTES
───────────────────────────────────────────── */

/** GET /api/admin/users — return all users from MongoDB */
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}, {
      username:      1,
      isAdmin:       1,
      hasSubscription: 1,
      plan:          1,
      trialUsed:     1,
      trialStartedAt: 1,
      trialEndsAt:   1,
      createdAt:     1
    }).sort({ createdAt: -1 }).lean();
    return res.json({ ok: true, users });
  } catch (err) {
    console.error('[ADMIN/USERS]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

/** GET /api/admin/stats — return real summary counts from MongoDB */
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    const [totalUsers, adminCount, subscribedUsers, activeTrials, expiredTrials] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ isAdmin: true }),
      User.countDocuments({ hasSubscription: true }),
      User.countDocuments({ trialUsed: true, trialEndsAt: { $gt: now } }),
      User.countDocuments({ trialUsed: true, trialEndsAt: { $lte: now } })
    ]);
    const normalUsers = totalUsers - adminCount;
    return res.json({
      ok: true,
      totalUsers,
      adminCount,
      subscribedUsers,
      activeTrials,
      expiredTrials,
      normalUsers
    });
  } catch (err) {
    console.error('[ADMIN/STATS]', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
});

/* ─────────────────────────────────────────────
   PROTECTED ADMIN ROUTE
───────────────────────────────────────────── */
app.get('/admin-dashboard.html', requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

/* ─────────────────────────────────────────────
   PUBLIC + NORMAL-USER ROUTES
───────────────────────────────────────────── */
/** Middleware: require active subscription OR active trial (admin exempt) */
async function requireAccess(req, res, next) {
  if (req.session.isAdmin) return next();
  try {
    const user = await User.findById(req.session.userId);
    if (!user) return res.redirect('/login.html');
    if (user.hasSubscription || isTrialActive(user)) return next();
    return res.redirect('/subscription.html');
  } catch (err) {
    return res.redirect('/subscription.html');
  }
}

app.get('/dashboard.html', requireAuth, requireAccess, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

/* login.html, register.html, subscription.html — public (no auth required) */
app.get('/login.html',        (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register.html',     (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/subscription.html', (req, res) => res.sendFile(path.join(__dirname, 'subscription.html')));

/* Root redirect */
app.get('/', async (req, res) => {
  if (req.session && req.session.userId) {
    if (req.session.isAdmin) return res.redirect('/admin-dashboard.html');
    try {
      const user = await User.findById(req.session.userId);
      if (user && (user.hasSubscription || isTrialActive(user))) {
        return res.redirect('/dashboard.html');
      }
    } catch (_) {}
    return res.redirect('/subscription.html');
  }
  res.redirect('/login.html');
});

/* ─────────────────────────────────────────────
   SUBSCRIPTION / TRIAL API ROUTES
───────────────────────────────────────────── */

/** POST /api/trial/activate — activate 12-hour free trial (once per user) */
app.post('/api/trial/activate', requireAuth, async (req, res) => {
  if (req.session.isAdmin) {
    return res.status(403).json({ error: 'Admin accounts do not use trials.' });
  }
  try {
    const user = await User.findById(req.session.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (user.trialUsed) {
      return res.status(409).json({ error: 'Free trial already used.' });
    }
    const now = new Date();
    user.trialUsed      = true;
    user.trialStartedAt = now;
    user.trialEndsAt    = new Date(now.getTime() + 12 * 60 * 60 * 1000); // +12 hours
    await user.save();
    return res.json({ ok: true, redirect: '/dashboard.html', trialEndsAt: user.trialEndsAt });
  } catch (err) {
    console.error('[TRIAL]', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

/** GET /api/subscription/status — return current user subscription/trial state */
app.get('/api/subscription/status', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const trialActive = isTrialActive(user);
    return res.json({
      hasSubscription: user.hasSubscription,
      plan:            user.plan,
      trialUsed:       user.trialUsed,
      trialActive,
      trialEndsAt:     user.trialEndsAt
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error.' });
  }
});

/* ─────────────────────────────────────────────
   MARKET DATA API
───────────────────────────────────────────── */

/** GET /api/market/live — returns real-time XAUUSD (Gold) price, no auth required */
app.get('/api/market/live', async (req, res) => {
  try {
    const data = await fetchLivePrice();
    return res.json({ ok: true, ...data });
  } catch (err) {
    console.error('[MARKET/LIVE]', err.message);
    return res.status(503).json({ ok: false, error: 'Market data temporarily unavailable.' });
  }
});

/* Static assets — no auth needed */
app.use(express.static(__dirname, {
  index: false,
  dotfiles: 'deny'
}));

/* 404 fallback */
app.use((req, res) => {
  res.status(404).send(
    '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>404</title>' +
    '<style>body{background:#0b0e17;color:#c8d0e7;font-family:system-ui;display:flex;' +
    'flex-direction:column;align-items:center;justify-content:center;min-height:100vh;gap:12px;}' +
    'h1{color:#448aff;font-size:3rem;margin:0}a{color:#448aff}</style>' +
    '</head><body><h1>404</h1><p>Page not found.</p><a href="/">← Home</a></body></html>'
  );
});

/* ─────────────────────────────────────────────
   START
───────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`FlowScope server running on http://localhost:${PORT}`);
  console.log(`Auth routes: POST /api/login, POST /api/register, POST /api/logout, GET /api/me`);
  console.log(`Admin route: GET /admin-dashboard.html  [requireAuth + requireAdmin]`);
  console.log(`Public routes: /login.html, /register.html`);
});
