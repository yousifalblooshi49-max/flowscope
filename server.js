'use strict';

require('dotenv').config({ path: require('path').join(__dirname, 'flowscope.env') });

const express        = require('express');
const session        = require('express-session');
const bcrypt         = require('bcryptjs');
const path           = require('path');
const cors           = require('cors');
const connectDB      = require('./config/db');
const User           = require('./models/User');

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

/** Require authenticated session — else redirect to /login.html */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login.html');
}

/** Require authenticated AND admin session — else 403 */
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login.html');
  }
  if (!req.session.isAdmin) {
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
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/subscription.html');
  }

  if (req.session.user.role === 'admin') {
    return res.redirect('/admin-dashboard.html');
  }

  if (req.session.user.hasAccess) {
    return res.redirect('/dashboard.html');
  }

  return res.redirect('/subscription.html');
});

/* ─────────────────────────────────────────────
   MARKET DATA ROUTES
───────────────────────────────────────────── */

app.get('/api/market/candles', async (req, res) => {
  try {
    const symbol = 'GC=F'; // Gold Futures
    const interval = req.query.interval || '5m';

    const rangeMap = {
      '1m': '1d',
      '5m': '5d',
      '15m': '5d',
      '30m': '1mo',
      '1h': '1mo'
    };

    const yahooIntervalMap = {
      '1m': '1m',
      '5m': '5m',
      '15m': '15m',
      '30m': '30m',
      '1h': '60m'
    };

    const range = rangeMap[interval] || '5d';
    const yInterval = yahooIntervalMap[interval] || '5m';

    const url = `https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?range=${range}&interval=${yInterval}`;

    const response = await fetch(url);
    const data = await response.json();

    const result = data.chart.result[0];
    const timestamps = result.timestamp;
    const quote = result.indicators.quote[0];

    const candles = timestamps.map((t, i) => ({
      time: t * 1000,
      open: quote.open[i],
      high: quote.high[i],
      low: quote.low[i],
      close: quote.close[i],
      volume: quote.volume[i] || 0
    }));

    res.json(candles);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch market data' });
  }
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
