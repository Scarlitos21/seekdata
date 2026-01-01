const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const cors = require('cors');
const crypto = require('crypto');

const db = require('./db-schema');
const authService = require('./auth-service');
const searchService = require('./search-service');
const sourcesService = require('./sources-service');
const adminRoutes = require('./admin-routes');
const { requirePermission, requireRole } = require('./permissions-middleware');
const immutable = require('./immutable-logger');
const discordService = require('./discord-service');

if (!process.env.DISCORD_BOT_TOKEN && !process.env.TOKEN) {
  try {
    const envPath = path.join(__dirname, '.env');
    if (fs.existsSync(envPath)) {
      const raw = fs.readFileSync(envPath, 'utf8');
      raw.split(/\r?\n/).forEach(line => {
        const m = line.match(/^\s*DISCORD_BOT_TOKEN\s*=\s*(.+)\s*$/);
        if (m) {
          process.env.DISCORD_BOT_TOKEN = m[1].trim().replace(/^['\"]|['\"]$/g, '');
        }
      });
    }
  } catch (e) {
  }
}

db.initializeDB();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS: allow frontend on Netlify to call this backend
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://seekdata.netlify.app',
      'http://localhost:3000',
      'http://localhost:3001',
      process.env.FRONTEND_URL
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  },
  credentials: true
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
function getRequestInfo(req) {
  const raw = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || req.connection.remoteAddress || '0.0.0.0';
  let ip = String(raw || '0.0.0.0');
  if (ip.startsWith('::ffff:')) {
    ip = ip.split('::ffff:')[1];
  }
  if (ip === '::1') ip = '127.0.0.1';

  if (ip.includes('%')) ip = ip.split('%')[0];

  const country = req.headers['cf-ipcountry'] || 'XX'; // Cloudflare header if available
  const userAgent = req.headers['user-agent'] || 'Unknown';
  return { ip, country, userAgent };
}

// Middleware: Extract auth token
function extractToken(req) {
  const authHeader = req.headers.authorization || '';
  const parts = authHeader.split(' ');
  if (parts.length === 2 && parts[0] === 'Bearer') {
    return parts[1];
  }
  return null;
}

// Middleware: Maintenance mode check
function checkMaintenance(req, res, next) {
  const system = db.readJSON(db.SYSTEM_FILE) || {};
  
  if (system.maintenance_mode === true) {
    // Allow admin panel access
    if (req.path.startsWith('/admin') || req.path.startsWith('/api/admin')) {
      return next();
    }
    // Allow maintenance page and any assets under /maintenance
    if (req.path === '/maintenance' || req.path.startsWith('/maintenance')) {
      return next();
    }
    // Block public API
    if (req.path.startsWith('/api/') && !req.path.startsWith('/api/admin')) {
      return res.status(503).json({ error: 'maintenance_mode', message: 'Service en maintenance' });
    }
    // For all other public requests (including '/'), redirect to maintenance
    return res.redirect('/maintenance');
  }
  
  next();
}

app.use(checkMaintenance);

// Middleware: Blacklist check
function checkBlacklist(req, res, next) {
  const { ip } = getRequestInfo(req);
  const blacklist = db.readJSON(db.BLACKLIST_FILE) || [];
  const whitelist = db.readJSON(db.WHITELIST_FILE) || [];

  // If IP is whitelisted, bypass checks
  if (whitelist.some(e => e.type === 'ip' && e.value === ip)) return next();

  // Try to resolve user context from token if present
  const token = extractToken(req);
  let session = null;
  if (token) {
    session = authService.verifySession(token) || authService.verifyAdminSession(token);
  }

  const email = session && session.email ? session.email.toLowerCase() : (session && session.username ? session.username.toLowerCase() : null);
  let userId = null;
  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    if (email && users[email]) userId = users[email].id;
  } catch (e) {
    // ignore
  }

  // Find matching blacklist entry (if any) to log exact type/value
  let matched = null;
  for (const entry of blacklist) {
    if (!entry || !entry.type || !entry.value) continue;
    const val = String(entry.value).toLowerCase();
    if (entry.type === 'ip' && entry.value === ip) { matched = entry; break; }
    if (entry.type === 'email' && email && val === email) { matched = entry; break; }
    if (entry.type === 'domain' && email && email.endsWith('@' + val)) { matched = entry; break; }
    if (entry.type === 'user_id' && userId && String(userId) === String(entry.value)) { matched = entry; break; }
  }

  if (matched) {
    // Immutable audit log for blacklist block
    try {
      immutable.writeEvent({
        type: 'blacklist_block',
        block_type: matched.type,
        value: String(matched.value),
        route: req.path || req.originalUrl || '/',
        role: session && session.role ? session.role : 'anonymous',
        user_email: email || null,
        ip,
        user_agent: getRequestInfo(req).userAgent || null,
        action: 'request_blocked'
      });
    } catch (e) {
      // ignore logging failures
    }

    // Also log concise security event
    searchService.logEvent({
      type: 'security_event',
      severity: 'critical',
      description: `Blacklisted access attempt: type=${matched.type} value=${matched.value} route=${req.path}`,
      ip,
      country: getRequestInfo(req).country
    });

    // Return minimal home page for any request with 403 — no details, no redirects
    const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title></title><style>html,body{height:100%;margin:0;background:#000;color:#fff;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}body{display:flex;align-items:center;justify-content:center} .box{text-align:center;font-weight:800;font-size:2rem;letter-spacing:1px}.sub{font-weight:600;font-size:1rem;color:#bbb;margin-top:8px}</style></head><body><div class="box">Blacklisted<br><div class="sub">Error 403</div></div></body></html>`;

    res.status(403).set('Content-Type','text/html; charset=utf-8').send(html);
    return;
  }

  next();
}

app.use(checkBlacklist);

// Serve static files after security middlewares so maintenance/blacklist can block public access
app.use(express.static(path.join(__dirname, '..')));

// API: list available badge SVGs from assets folder
app.get('/api/assets/badges', (req, res) => {
  try {
    const assetsDir = path.join(__dirname, '..', 'assets');
    if (!fs.existsSync(assetsDir)) return res.json({ ok: true, badges: [] });
    const files = fs.readdirSync(assetsDir).filter(f => /\.(svg|png|webp|jpe?g|gif)$/i.test(f)).sort();
    return res.json({ ok: true, badges: files });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'assets_list_failed' });
  }
});

// Proxy endpoint to fetch Discord user data (avatar/banner) via bot token
app.get('/api/discord/:id', async (req, res) => {
  const id = req.params.id;
  const https = require('https');
  const token = process.env.TOKEN || process.env.DISCORD_BOT_TOKEN;

  try {
    if (!token) {
      return res.status(403).json({ ok: false, error: 'no_bot_token' });
    }

    // Fetch user info from Discord API using bot token (like main.js)
    const discordJson = await new Promise((resolve) => {
      const options = {
        hostname: 'canary.discord.com',
        path: `/api/v10/users/${id}`,
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bot ${token}`
        },
        timeout: 5000
      };
      const req2 = https.request(options, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try { resolve(JSON.parse(d)); } catch (e) { resolve(null); }
        });
      });
      req2.on('error', () => resolve(null));
      req2.on('timeout', () => { req2.destroy(); resolve(null); });
      req2.end();
    });

    if (!discordJson || !discordJson.id) {
      return res.status(404).json({ ok: false, error: 'user_not_found', id });
    }

    // Build URLs exactly like main.js
    let avatarLink = null;
    if (discordJson.avatar) {
      avatarLink = `https://cdn.discordapp.com/avatars/${discordJson.id}/${discordJson.avatar}`;
    }

    let bannerLink = null;
    if (discordJson.banner) {
      bannerLink = `https://cdn.discordapp.com/banners/${discordJson.id}/${discordJson.banner}`;
    }

    const snowflakeToUtc = (snowflakeId) => { 
      const SNOWFLAKE_EPOCH = 1420070400000; 
      const timestamp = (Number(snowflakeId) / 4194304) + SNOWFLAKE_EPOCH; 
      return new Date(timestamp).toISOString(); 
    };

    const output = {
      ok: true,
      id: discordJson.id,
      username: discordJson.username,
      discriminator: discordJson.discriminator,
      tag: `${discordJson.username}#${discordJson.discriminator}`,
      avatar_url: avatarLink,
      banner_url: bannerLink,
      banner_color: discordJson.banner_color,
      public_flags: discordJson.public_flags || 0,
      bot: !!discordJson.bot,
      created_at: snowflakeToUtc(discordJson.id)
    };
    return res.json(output);
  } catch (e) {
    console.error('[API/discord/:id] Error:', e);
    return res.status(500).json({ ok: false, error: 'discord_fetch_failed' });
  }
});

// Database helpers
function getUserById(userId) {
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = Object.values(users).find(u => u.id === userId);
  return user;
}

function getUserByEmail(email) {
  const users = db.readJSON(db.USERS_FILE) || {};
  return users[email.toLowerCase()];
}

function saveUser(user) {
  const users = db.readJSON(db.USERS_FILE) || {};
  if (user.email) {
    users[user.email.toLowerCase()] = user;
    return db.writeJSON(db.USERS_FILE, users);
  }
  return false;
}

function deleteUser(userId) {
  const users = db.readJSON(db.USERS_FILE) || {};
  const userEmail = Object.keys(users).find(email => users[email].id === userId);
  if (userEmail) {
    delete users[userEmail];
    return db.writeJSON(db.USERS_FILE, users);
  }
  return false;
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

/**
 * Middleware: Verify JWT token from Authorization header
 * Returns { user_id, email } if valid, null if invalid
 */
function requireAuth(req, res, next) {
  const token = extractToken(req);
  
  if (!token) {
    return res.status(401).json({
      ok: false,
      message: 'Unauthorized: No token provided',
      redirect: '/login'
    });
  }
  
  const decoded = authService.verifyToken(token);
  if (!decoded) {
    return res.status(401).json({
      ok: false,
      message: 'Unauthorized: Invalid token',
      redirect: '/login'
    });
  }
  
  // Attach decoded token to request
  req.auth = decoded;
  next();
}

// System status
function getSystemStatus() {
  try {
    const s = db.readJSON(db.SYSTEM_FILE) || { suspended: false };
    return s;
  } catch (e) { return { suspended: false }; }
}

// ============================================================================
// AUTH ENDPOINTS
// ============================================================================

/**
 * POST /api/register
 * Create new user account
 */
app.post('/api/register', async (req, res) => {
  const { email, password, password_confirm } = req.body || {};
  const { ip, country } = getRequestInfo(req);
  
  if (!email || !password || !password_confirm) {
    return res.status(400).json({ error: 'missing_fields', message: 'Email et mot de passe requis' });
  }
  
  if (password !== password_confirm) {
    return res.status(400).json({ error: 'password_mismatch', message: 'Les mots de passe ne correspondent pas' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ error: 'weak_password', message: 'Mot de passe minimum 8 caractères' });
  }
  
  const users = db.readJSON(db.USERS_FILE) || {};
  const emailKey = email.toLowerCase();
  
  if (users[emailKey]) {
    searchService.logEvent({
      type: 'security_event',
      severity: 'warning',
      user_email: emailKey,
      description: 'Registration attempt with existing email',
      ip,
      country
    });
    return res.status(409).json({ error: 'email_exists', message: 'Cet email est déjà utilisé' });
  }
  
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();
    
    const defaultQuota = (db.PLANS && db.PLANS.FREE && db.PLANS.FREE.daily_quota) ? db.PLANS.FREE.daily_quota : 50;
    const today = new Date().toISOString().split('T')[0];
    users[emailKey] = {
      id: (crypto.randomUUID) ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'),
      email: emailKey,
      password_hash: passwordHash,
      role: 'user',
      plan: 'FREE',
      quota_used: 0,
      quota_limit: defaultQuota,
      quota_remaining: defaultQuota,
      quota_reset_date: today,
      created_at: now,
      last_login: null,
      ip_last: null,
      country: null,
      status: 'active',
      logins: [],
      failed_login_attempts: 0,
      locked_until: null,
      email_verified: false,
      api_keys: [],
      settings: { language: 'fr', notifications: true },
      is_admin: false,
      risk_score: 0
    };
    
    db.writeJSON(db.USERS_FILE, users);
    
    searchService.logEvent({
      type: 'user_registered',
      severity: 'info',
      user_email: emailKey,
      description: 'User registered',
      ip,
      country
    });
    
    return res.status(201).json({
      ok: true,
      message: 'Compte créé avec succès',
      user: { email: emailKey, plan: 'FREE' }
    });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/login
 * User login with email and password
 */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const { ip, country, userAgent } = getRequestInfo(req);
  
  if (!email || !password) {
    return res.status(400).json({ error: 'missing_fields', message: 'Email et mot de passe requis' });
  }
  
  const emailKey = email.toLowerCase();
  
  // Check if account is locked
  if (authService.isAccountLocked(emailKey)) {
    return res.status(403).json({
      error: 'account_locked',
      message: 'Compte verrouillé. Veuillez réessayer plus tard.'
    });
  }
  
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[emailKey];
  
  if (!user) {
    authService.recordFailedAttempt(emailKey, ip);
    return res.status(404).json({ error: 'user_not_found', message: 'Compte introuvable' });
  }
  
  try {
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordValid) {
      const locked = authService.recordFailedAttempt(emailKey, ip);
      return res.status(401).json({
        error: 'bad_credentials',
        message: locked ? 'Trop de tentatives. Compte verrouillé.' : 'Mot de passe incorrect'
      });
    }
    
    // Clear failed attempts on success
    authService.clearFailedAttempts(emailKey);
    
    // Create session
    const token = authService.createSession(emailKey, ip, userAgent, country);
    
    // Update user login info
    user.last_login = new Date().toISOString();
    if (!user.logins) user.logins = [];
    user.logins.push({
      at: new Date().toISOString(),
      ip,
      country
    });
    
    // Keep only last 100 logins
    if (user.logins.length > 100) {
      user.logins = user.logins.slice(-100);
    }
    
    db.writeJSON(db.USERS_FILE, users);
    
    // Log login event
    searchService.logEvent({
      type: 'login',
      severity: 'info',
      user_email: emailKey,
      description: 'User logged in',
      metadata: { ip, country },
      ip,
      country
    });
    
    return res.json({
      ok: true,
      message: 'Connexion réussie',
      token,
      user: {
        email: emailKey,
        plan: user.plan || 'FREE',
        quota_remaining: user.quota_remaining || db.PLANS.FREE.daily_quota
      }
    });
    
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/logout
 * Invalidate user session
 */
app.post('/api/logout', (req, res) => {
  const token = extractToken(req);
  
  if (token) {
    authService.invalidateSession(token);
  }
  
  return res.json({ ok: true, message: 'Déconnecté' });
});

/**
 * GET /api/me
 * Get current user info (PROTECTED)
 */
app.get('/api/me', requireAuth, (req, res) => {
  const token = extractToken(req);
  
  if (!token) {
    return res.status(401).json({ error: 'unauthorized', message: 'Token manquant' });
  }
  
  const session = authService.verifySession(token);
  if (!session) {
    return res.status(401).json({ error: 'unauthorized', message: 'Token invalide ou expiré' });
  }
  
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[session.email];
  
  if (!user) {
    return res.status(404).json({ error: 'user_not_found' });
  }
  
  const quota = searchService.getQuotaInfo(session.email);
  const stats = searchService.getUserSearchStats(session.email);
  
  return res.json({
    ok: true,
    user: {
      email: session.email,
      plan: user.plan || 'FREE',
      quota,
      stats,
      created_at: user.created_at,
      last_login: user.last_login
    }
  });
});

// ============================================================================
// SEARCH ENDPOINTS
// ============================================================================

/**
 * POST /api/search
 * Execute a search (authenticated)
 */
app.post('/api/search', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifySession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const { query } = req.body || {};
  if (!query || !query.trim()) {
    return res.status(400).json({ error: 'missing_query' });
  }

  const { ip, country } = getRequestInfo(req);

  // Check if email/IP is blacklisted
  const blacklist = db.readJSON(db.BLACKLIST_FILE) || [];
  const whitelist = db.readJSON(db.WHITELIST_FILE) || [];

  // Whitelist bypass
  if (whitelist.some(e => e.type === 'ip' && e.value === ip)) {
    // bypass blacklist checks for this IP
  } else {
    const userEmail = session.email ? session.email.toLowerCase() : null;
    const users = db.readJSON(db.USERS_FILE) || {};
    const userObj = userEmail ? users[userEmail] : null;
    const userId = userObj ? userObj.id : null;

    const isBlacklisted = blacklist.some(entry => {
      if (!entry || !entry.type || !entry.value) return false;
      const val = String(entry.value).toLowerCase();
      if (entry.type === 'ip' && entry.value === ip) return true;
      if (entry.type === 'email' && userEmail && val === userEmail) return true;
      if (entry.type === 'domain' && userEmail && userEmail.endsWith('@' + val)) return true;
      if (entry.type === 'user_id' && userId && String(userId) === String(entry.value)) return true;
      return false;
    });

    if (isBlacklisted) {
      searchService.logEvent({
        type: 'blocked_search',
        severity: 'warning',
        user_email: session.email,
        description: `Blacklisted user attempted search: ${query}`,
        ip, country
      });
      return res.status(403).json({ error: 'blacklisted', message: 'Accès refusé' });
    }
  }

  // Check user status
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[session.email.toLowerCase()];
  
  if (!user) {
    return res.status(404).json({ error: 'user_not_found' });
  }

  if (user.status === 'blocked') {
    searchService.logEvent({
      type: 'blocked_search',
      severity: 'warning',
      user_email: session.email,
      description: `Blocked user attempted search: ${query}`,
      ip, country
    });
    return res.status(403).json({ error: 'user_blocked', message: 'Votre compte a été bloqué' });
  }

  if (user.status === 'banned') {
    searchService.logEvent({
      type: 'blocked_search',
      severity: 'critical',
      user_email: session.email,
      description: `Banned user attempted search: ${query}`,
      ip, country
    });
    return res.status(403).json({ error: 'user_banned', message: 'Votre compte a été banni. Contactez support@seekdata.io' });
  }

  // Check global suspend
  const system = getSystemStatus();
  if (system.suspended) {
    return res.status(503).json({ ok:false, error: 'searches_suspended', message: 'Toutes les recherches sont temporairement suspendues', suspend: system });
  }
  
  const result = await searchService.executeSearch(
    session.email,
    query.trim(),
    ip,
    country
  );
  
  if (!result.ok) {
    return res.status(403).json(result);
  }
  
  return res.json(result);
});

/**
 * GET /api/history
 * Get user search history (authenticated)
 */
app.get('/api/history', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifySession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const limit = Math.min(parseInt(req.query.limit) || 50, 500);
  const history = searchService.getUserSearchHistory(session.email, limit);
  
  return res.json({ ok: true, history });
});

/**
 * GET /api/quota
 * Get user quota info
 */
app.get('/api/quota', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifySession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const quota = searchService.getQuotaInfo(session.email);
  return res.json({ ok: true, quota });
});

// ============================================================================
// ADMIN ENDPOINTS
// ============================================================================

// Creator route: serve Creator panel (requires admin session role 'creator')
// Auth check happens client-side via token cookie stored after admin login
app.get('/creator', (req, res) => {
  return res.sendFile(require('path').join(__dirname, '..', 'admin', 'creator', 'index.html'));
});

// Helper: get admin user object from admin session token
function getAdminUserFromSessionToken(token) {
  const session = authService.verifyAdminSession(token);
  if (!session) return null;
  const users = db.readJSON(db.USERS_FILE) || {};
  const email = session.username; // created with email
  return users[email.toLowerCase()] || null;
}

// Helper: require admin roles
function requireAdminRoles(req, res, allowedRoles = ['admin','creator']) {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  const adminUser = getAdminUserFromSessionToken(token);
  if (!adminUser) return res.status(403).json({ error: 'forbidden' });
  if (!allowedRoles.includes(adminUser.role)) return res.status(403).json({ error: 'insufficient_role' });
  return adminUser;
}

/**
 * POST /api/admin/login
 * Admin login
 */
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body || {};
  const { ip, country, userAgent } = getRequestInfo(req);

  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });

  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    const u = users[email.toLowerCase()];

    // If a proper admin user exists in users.json, validate via bcrypt
    if (u && u.is_admin) {
      const ok = await bcrypt.compare(password, u.password_hash);
      if (!ok) {
        searchService.logEvent({ type: 'security_event', severity: 'warning', description: 'Failed admin login - bad password', metadata: { email }, ip, country });
        return res.status(401).json({ error: 'bad_credentials' });
      }
      // create admin session token
      const token = authService.createAdminSession(u.email, ip, userAgent, u.role || 'admin');
      // log admin login
      searchService.logEvent({ type: 'admin_action', severity: 'info', user_email: u.email, description: 'Admin logged in', ip, country });
      return res.json({ ok: true, token, user: { email: u.email, role: u.role || 'admin' } });
    }

    // Fallback: allow legacy admin credentials from admin_credentials.json (plain or bcrypt)
    try {
      const fs = require('fs');
      const credPath = path.join(__dirname, 'admin_credentials.json');
      if (fs.existsSync(credPath)) {
        try {
          const creds = JSON.parse(fs.readFileSync(credPath, 'utf8') || '{}');
          const storedUser = (creds.username || '').toLowerCase();
          const storedPass = creds.password || '';
          if (email.toLowerCase() === storedUser) {
            // if storedPass looks like bcrypt hash
            if (/^\$2[aby]\$/.test(storedPass)) {
              try {
                const ok2 = await bcrypt.compare(password, storedPass);
                if (ok2) {
                  const token = authService.createAdminSession(email.toLowerCase(), ip, userAgent, 'creator');
                  searchService.logEvent({ type: 'admin_action', severity: 'info', user_email: email.toLowerCase(), description: 'Admin logged in (legacy creds hashed)', ip, country });
                  return res.json({ ok: true, token, user: { email: email.toLowerCase(), role: 'creator' } });
                }
              } catch (e) { /* continue to plain compare */ }
            }
            if (password === storedPass) {
              const token = authService.createAdminSession(email.toLowerCase(), ip, userAgent, 'creator');
              searchService.logEvent({ type: 'admin_action', severity: 'info', user_email: email.toLowerCase(), description: 'Admin logged in (legacy creds)', ip, country });
              return res.json({ ok: true, token, user: { email: email.toLowerCase(), role: 'creator' } });
            }
          }
        } catch (e) {
          console.error('Error parsing admin_credentials.json', e && e.message);
        }
      }
    } catch (e) {
      console.error('Admin credentials fallback error', e && e.message);
    }

    searchService.logEvent({ type: 'security_event', severity: 'warning', description: 'Failed admin login - not an admin or bad creds', metadata: { email }, ip, country });
    return res.status(401).json({ error: 'bad_credentials' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/admin/dashboard
 * Admin dashboard stats
 */
app.get('/api/admin/dashboard', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const users = db.readJSON(db.USERS_FILE) || {};
  const searchStats = searchService.getGlobalSearchStats();
  const sourceStats = sourcesService.getSourcesStats();
  const logs = searchService.getLogs({ limit: 100 });
  
  const totalUsers = Object.keys(users).length;
  const activeUsers = new Set(
    logs.filter(l => l.type === 'login').map(l => l.user_email)
  ).size;
  
  const alerts = db.readJSON(db.ALERTS_FILE) || [];
  const openAlerts = alerts.filter(a => a.status === 'open');
  
  return res.json({
    ok: true,
    dashboard: {
      users: {
        total: totalUsers,
        active_today: activeUsers
      },
      searches: searchStats,
      sources: sourceStats,
      alerts: {
        total_open: openAlerts.length,
        by_severity: {
          critical: openAlerts.filter(a => a.severity === 'critical').length,
          high: openAlerts.filter(a => a.severity === 'high').length,
          medium: openAlerts.filter(a => a.severity === 'medium').length,
          low: openAlerts.filter(a => a.severity === 'low').length
        }
      }
    }
  });
});

/**
 * GET /api/admin/users
 * List all users with details
 */
app.get('/api/admin/users', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const users = db.readJSON(db.USERS_FILE) || {};
  
  const userList = Object.values(users).map(u => {
    const lastLogin = u.logins && u.logins.length ? u.logins[u.logins.length - 1] : null;
    return {
      email: u.email,
      plan: u.plan || 'FREE',
      status: u.status,
      quota_remaining: u.quota_remaining,
      created_at: u.created_at,
      last_login: lastLogin ? lastLogin.at : null,
      last_login_ip: lastLogin ? lastLogin.ip : null,
      last_login_country: lastLogin ? lastLogin.country : null,
      risk_score: u.risk_score || 0,
      failed_attempts: u.failed_login_attempts || 0
    };
  });
  
  return res.json({ ok: true, users: userList });
});

/**
 * GET /api/admin/admins
 * List admin accounts (admin+creator)
 */
app.get('/api/admin/admins', (req, res) => {
  const adminUser = requireAdminRoles(req, res, ['admin','creator']);
  if (!adminUser) return;
  const users = db.readJSON(db.USERS_FILE) || {};
  const admins = Object.values(users).filter(u => u.is_admin).map(u => ({
    email: u.email,
    role: u.role || 'admin',
    status: u.status || 'active',
    created_at: u.created_at,
    last_login: u.last_login || null
  }));
  return res.json({ ok: true, admins });
});

/**
 * POST /api/admin/admins
 * Create a new admin (creator only)
 */
app.post('/api/admin/admins', async (req, res) => {
  const creator = requireAdminRoles(req, res, ['creator']);
  if (!creator) return;
  const { email, password, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing', message: 'email and password required' });
  const users = db.readJSON(db.USERS_FILE) || {};
  const key = email.toLowerCase();
  if (users[key]) return res.status(409).json({ error: 'exists' });
  try {
    const hash = await bcrypt.hash(password, 10);
    users[key] = {
      email: key,
      password_hash: hash,
      plan: 'FREE',
      quota_remaining: db.PLANS.FREE.daily_quota,
      quota_reset_date: new Date().toISOString().split('T')[0],
      created_at: new Date().toISOString(),
      last_login: null,
      logins: [],
      status: 'active',
      failed_login_attempts: 0,
      locked_until: null,
      is_admin: true,
      role: role || 'admin'
    };
    db.writeJSON(db.USERS_FILE, users);
    searchService.logEvent({ type: 'admin_action', severity: 'critical', user_email: creator.email, description: `Creator created admin ${key}`, metadata: {}, ip: req.ip, country: req.headers['cf-ipcountry'] || 'XX' });
    return res.status(201).json({ ok: true, admin: { email: key, role: users[key].role } });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * PUT /api/admin/admins/:email
 * Update admin (role/status) - creator only
 */
app.put('/api/admin/admins/:email', async (req, res) => {
  const creator = requireAdminRoles(req, res, ['creator']);
  if (!creator) return;
  const targetEmail = (req.params.email || '').toLowerCase();
  const { role, status, password } = req.body || {};
  const users = db.readJSON(db.USERS_FILE) || {};
  const u = users[targetEmail];
  if (!u || !u.is_admin) return res.status(404).json({ error: 'not_found' });
  if (role) u.role = role;
  if (status) u.status = status;
  if (password) {
    try {
      u.password_hash = await bcrypt.hash(password, 10);
    } catch (e) { /* ignore */ }
  }
  users[targetEmail] = u;
  db.writeJSON(db.USERS_FILE, users);
  searchService.logEvent({ type: 'admin_action', severity: 'warning', user_email: creator.email, description: `Creator updated admin ${targetEmail}`, metadata: { role, status }, ip: req.ip, country: req.headers['cf-ipcountry'] || 'XX' });
  return res.json({ ok: true });
});

/**
 * GET /api/admin/searches
 * List all searches
 */
app.get('/api/admin/searches', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const searches = db.readJSON(db.SEARCHES_FILE) || [];
  const limit = Math.min(parseInt(req.query.limit) || 500, 5000);
  
  const recentSearches = searches
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, limit);
  
  return res.json({ ok: true, searches: recentSearches });
});

/**
 * GET /api/admin/logs
 * Get system logs
 */
app.get('/api/admin/logs', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const filter = {
    type: req.query.type,
    severity: req.query.severity,
    user_email: req.query.user_email,
    limit: Math.min(parseInt(req.query.limit) || 1000, 10000)
  };
  
  const logs = searchService.getLogs(filter);
  return res.json({ ok: true, logs });
});

/**
 * GET /api/admin/alerts
 * List system alerts
 */
app.get('/api/admin/alerts', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const alerts = db.readJSON(db.ALERTS_FILE) || [];
  const status = req.query.status || 'open';
  
  const filtered = alerts.filter(a => a.status === status);
  
  return res.json({ ok: true, alerts: filtered });
});

/**
 * GET /api/admin/sources
 * Get OSINT sources status
 */
app.get('/api/admin/sources', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const stats = sourcesService.getSourcesStats();
  return res.json({ ok: true, sources: stats });
});

// ============================================================================
// ADMIN: BLACKLIST MANAGEMENT
// ============================================================================

// List blacklist (admin+creator+moderator can view)
app.get('/api/admin/blacklist', (req, res) => {
  const adminUser = requireAdminRoles(req, res, ['moderator','admin','creator']);
  if (!adminUser) return; // requireAdminRoles already responded
  const list = db.readJSON(db.BLACKLIST_FILE) || [];
  return res.json({ ok: true, blacklist: list });
});

// Add blacklist entry (admin or creator)
app.post('/api/admin/blacklist', (req, res) => {
  const adminUser = requireAdminRoles(req, res, ['admin','creator']);
  if (!adminUser) return;
  const { type, value, reason, severity, expires_at, active } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: 'missing', message: 'type and value required' });
  const list = db.readJSON(db.BLACKLIST_FILE) || [];
  const entry = {
    id: crypto.randomBytes(8).toString('hex'),
    type,
    value,
    reason: reason||'',
    severity: severity||'high',
    created_at: new Date().toISOString(),
    created_by: adminUser.email || adminUser.email,
    expires_at: expires_at || null,
    active: typeof active === 'boolean' ? active : true
  };
  list.push(entry);
  db.writeJSON(db.BLACKLIST_FILE, list);
  searchService.logEvent({ type: 'admin_action', severity: 'critical', user_email: adminUser.email||null, description: `Blacklist add ${type}=${value}`, metadata: { entry }, ip: req.ip, country: req.headers['cf-ipcountry'] || 'XX' });
  return res.json({ ok: true, entry });
});

// Update blacklist entry (partial update)
app.put('/api/admin/blacklist/:id', (req, res) => {
  const adminUser = requireAdminRoles(req, res, ['admin','creator']);
  if (!adminUser) return;
  const id = req.params.id;
  const updates = req.body || {};
  let list = db.readJSON(db.BLACKLIST_FILE) || [];
  let found = false;
  list = list.map(e => {
    if (e.id === id) {
      found = true;
      return Object.assign({}, e, updates, { updated_at: new Date().toISOString(), updated_by: adminUser.email });
    }
    return e;
  });
  if (!found) return res.status(404).json({ error: 'not_found' });
  db.writeJSON(db.BLACKLIST_FILE, list);
  searchService.logEvent({ type: 'admin_action', severity: 'warning', user_email: adminUser.email||null, description: `Blacklist update id=${id}`, metadata: { updates }, ip: req.ip, country: req.headers['cf-ipcountry'] || 'XX' });
  return res.json({ ok: true });
});

// Delete blacklist entry (admin or creator)
app.delete('/api/admin/blacklist/:id', (req, res) => {
  const adminUser = requireAdminRoles(req, res, ['admin','creator']);
  if (!adminUser) return;
  const id = req.params.id;
  let list = db.readJSON(db.BLACKLIST_FILE) || [];
  const before = list.length;
  list = list.filter(x=> x.id !== id);
  db.writeJSON(db.BLACKLIST_FILE, list);
  searchService.logEvent({ type: 'admin_action', severity: 'warning', user_email: adminUser.email||null, description: `Blacklist remove id=${id}`, metadata: {}, ip: req.ip, country: req.headers['cf-ipcountry'] || 'XX' });
  return res.json({ ok: true, removed: before - list.length });
});

// ============================================================================
// ADMIN: CONTROL (suspend/resume searches)
// ============================================================================

app.post('/api/admin/control/suspend', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  const { reason, until } = req.body || {};
  const system = db.readJSON(db.SYSTEM_FILE) || {};
  system.suspended = true;
  system.suspend_reason = reason || 'manual';
  system.suspend_by = session.username || session.email;
  system.suspend_until = until || null;
  db.writeJSON(db.SYSTEM_FILE, system);
  searchService.logEvent({ type: 'admin_action', severity: 'critical', user_email: session.username||null, description: `Global suspend: ${system.suspend_reason}`, metadata: { system }, ip: session.ip, country: session.country });
  return res.json({ ok: true, system });
});

app.post('/api/admin/control/resume', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  const system = db.readJSON(db.SYSTEM_FILE) || {};
  system.suspended = false;
  system.suspend_reason = null;
  system.suspend_by = session.username || session.email;
  system.suspend_until = null;
  db.writeJSON(db.SYSTEM_FILE, system);
  searchService.logEvent({ type: 'admin_action', severity: 'warning', user_email: session.username||null, description: `Global resume`, metadata: { system }, ip: session.ip, country: session.country });
  return res.json({ ok: true, system });
});

app.get('/api/admin/control/status', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  const system = db.readJSON(db.SYSTEM_FILE) || {};
  return res.json({ ok: true, system });
});

/**
 * POST /api/admin/sources/:id/healthcheck
 * Run healthcheck on source
 */
app.post('/api/admin/sources/:id/healthcheck', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });
  
  const sourceId = req.params.id;
  const result = await sourcesService.healthCheckSource(sourceId);
  
  if (!result) {
    return res.status(404).json({ error: 'source_not_found' });
  }
  
  return res.json({ ok: true, result });
});

// ============================================================================
// UTILITY ENDPOINTS
// ============================================================================

/**
 * GET /api/health
 * Health check
 */
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    status: 'online',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

/**
 * GET /api/plans
 * List available plans
 */
app.get('/api/plans', (req, res) => {
  const plans = Object.values(db.PLANS).map(p => ({
    id: p.id,
    name: p.name,
    price: p.price,
    daily_quota: p.daily_quota,
    allowed_types: p.allowed_types,
    features: p.features
  }));
  
  return res.json({ ok: true, plans });
});

/**
 * GET /login
 * Login page
 */
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'seeknow-login.html'));
});

/**
 * GET /dashboard
 * User dashboard page (PROTECTED)
 */
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'dashboard.html'));
});

/**
 * POST /api/change-password
 * Change user password
 */
app.post('/api/change-password', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ ok: false, message: 'Unauthorized' });
  
  const decoded = authService.verifyToken(token);
  if (!decoded) return res.status(401).json({ ok: false, message: 'Invalid token' });
  
  const user = getUserById(decoded.user_id);
  if (!user) return res.status(404).json({ ok: false, message: 'User not found' });
  
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ ok: false, message: 'Missing fields' });
  
  if (!bcrypt.compareSync(current_password, user.password_hash)) {
    return res.status(401).json({ ok: false, message: 'Current password is incorrect' });
  }
  
  const newHash = bcrypt.hashSync(new_password, 10);
  user.password_hash = newHash;
  saveUser(user);
  
  return res.json({ ok: true, message: 'Password changed successfully' });
});

/**
 * DELETE /api/delete-account
 * Delete user account
 */
app.delete('/api/delete-account', (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ ok: false, message: 'Unauthorized' });
  
  const decoded = authService.verifyToken(token);
  if (!decoded) return res.status(401).json({ ok: false, message: 'Invalid token' });
  
  const user = getUserById(decoded.user_id);
  if (!user) return res.status(404).json({ ok: false, message: 'User not found' });
  
  // Delete user
  deleteUser(user.id);
  
  return res.json({ ok: true, message: 'Account deleted successfully' });
});

// ============================================================================
// STATIC FILES & ROOT
// ============================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'seeknow.html'));
});

// Serve admin console root
app.get('/admin', (req, res) => {
  return res.sendFile(path.join(__dirname, '..', 'admin', 'index.html'));
});

// ============================================================================
// REGISTER COMPREHENSIVE ADMIN ROUTES
// ============================================================================
adminRoutes(app, db, authService, searchService, sourcesService, getRequestInfo, extractToken);

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║         SeekData OSINT Platform        ║
║          Server Running                ║
║                                        ║
║  HTTP: http://localhost:${PORT}           ║
║  API Base: /api/                       ║
║  Admin: /admin/                        ║
║                                        ║
║  Timestamp: ${new Date().toISOString()}    ║
╚════════════════════════════════════════╝
  `);
  
  // Start periodic healthchecks (every 30 minutes)
  setInterval(async () => {
    try {
      await sourcesService.healthCheckAllSources();
      console.log('[HEALTHCHECK] Sources checked');
    } catch (e) {
      console.error('[HEALTHCHECK] Error:', e.message);
    }
  }, 30 * 60 * 1000);
});

// ============================================================================
// MAINTENANCE PAGE ROUTE
// ============================================================================

app.get('/maintenance', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'maintenance.html'));
});

// ============================================================================
// ADDITIONAL ADMIN ROUTES (Maintenance, Blacklist, User Management)
// ============================================================================

/**
 * POST /api/admin/maintenance
 * Toggle maintenance mode
 */
app.post('/api/admin/maintenance', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  try {
    const system = db.readJSON(db.SYSTEM_FILE) || {};
    const { enable, message, until } = req.body || {};
    const { ip, country } = getRequestInfo(req);

    if (enable === true) {
      system.maintenance_mode = true;
      system.maintenance_message = message || 'Maintenance en cours';
      system.maintenance_start = new Date().toISOString();
      system.maintenance_end = until || null;
    } else if (enable === false) {
      system.maintenance_mode = false;
      system.maintenance_start = null;
      system.maintenance_end = null;
    }

    db.writeJSON(db.SYSTEM_FILE, system);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'warning',
      user_email: session.email,
      description: `Maintenance mode ${enable ? 'enabled' : 'disabled'}`,
      ip, country
    });

    return res.json({ ok: true, maintenance_mode: system.maintenance_mode });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * GET /api/admin/system
 * Get system configuration
 */
app.get('/api/admin/system', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);

  try {
    const system = db.readJSON(db.SYSTEM_FILE) || {};

    // If requester is admin, return full system config
    if (session) return res.json(system);

    // For public consumers (maintenance page), only return maintenance info
    const publicView = {
      maintenance_mode: !!system.maintenance_mode,
      maintenance_message: system.maintenance_message || null,
      maintenance_start: system.maintenance_start || null,
      maintenance_end: system.maintenance_end || null
    };

    return res.json(publicView);
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * POST /api/admin/users/:userId/block
 * Block a user
 */
app.post('/api/admin/users/:userId/block', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    const userId = req.params.userId;
    const { ip, country } = getRequestInfo(req);

    let userEmail = Object.keys(users).find(email => users[email].id === userId);
    if (!userEmail) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    const user = users[userEmail];
    user.status = 'blocked';
    db.writeJSON(db.USERS_FILE, users);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'warning',
      user_email: session.email,
      description: `User ${userEmail} blocked`,
      ip, country
    });

    return res.json({ ok: true, message: 'User blocked' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/admin/users/:userId/unblock
 * Unblock a user
 */
app.post('/api/admin/users/:userId/unblock', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    const userId = req.params.userId;
    const { ip, country } = getRequestInfo(req);

    let userEmail = Object.keys(users).find(email => users[email].id === userId);
    if (!userEmail) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    const user = users[userEmail];
    user.status = 'active';
    db.writeJSON(db.USERS_FILE, users);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'info',
      user_email: session.email,
      description: `User ${userEmail} unblocked`,
      ip, country
    });

    return res.json({ ok: true, message: 'User unblocked' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/admin/users/:userId/ban
 * Ban a user permanently
 */
app.post('/api/admin/users/:userId/ban', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    const userId = req.params.userId;
    const { reason } = req.body || {};
    const { ip, country } = getRequestInfo(req);

    let userEmail = Object.keys(users).find(email => users[email].id === userId);
    if (!userEmail) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    const user = users[userEmail];
    user.status = 'banned';
    user.banned_at = new Date().toISOString();
    user.banned_reason = reason || 'No reason provided';
    user.banned_by = session.email;
    db.writeJSON(db.USERS_FILE, users);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'critical',
      user_email: session.email,
      description: `User ${userEmail} banned. Reason: ${reason || 'N/A'}`,
      ip, country
    });

    return res.json({ ok: true, message: 'User banned' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/admin/users/:userId/plan
 * Change user subscription plan
 */
app.post('/api/admin/users/:userId/plan', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    const userId = req.params.userId;
    const { plan } = req.body || {};
    const { ip, country } = getRequestInfo(req);

    if (!['FREE', 'BASIC', 'PRO', 'ENTERPRISE'].includes(plan)) {
      return res.status(400).json({ error: 'invalid_plan' });
    }

    let userEmail = Object.keys(users).find(email => users[email].id === userId);
    if (!userEmail) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    const user = users[userEmail];
    const oldPlan = user.plan;
    user.plan = plan;
    user.quota_used = 0;
    user.quota_limit = db.PLANS[plan].daily_quota;
    db.writeJSON(db.USERS_FILE, users);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'warning',
      user_email: session.email,
      description: `User ${userEmail} plan changed from ${oldPlan} to ${plan}`,
      ip, country
    });

    return res.json({ ok: true, message: 'Plan updated' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/admin/blacklist
 * Add entry to blacklist
 */
app.post('/api/admin/blacklist', requirePermission('manage_blacklist'), (req, res) => {
  // Permission middleware guarantees admin session and permission; retrieve session for metadata
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  try {
    const { type, value, reason } = req.body || {};
    const { ip, country } = getRequestInfo(req);

    if (!['ip', 'email', 'domain', 'user_id'].includes(type)) {
      return res.status(400).json({ error: 'invalid_type' });
    }

    const blacklist = db.readJSON(db.BLACKLIST_FILE) || [];
    
    if (blacklist.some(e => e.type === type && e.value === value)) {
      immutable.writeEvent({ type: 'blacklist_add_conflict', actor: session ? session.username || session.email : null, action: 'add_blacklist', details: { type, value }, ip });
      return res.status(409).json({ error: 'already_exists' });
    }

    const entry = {
      id: crypto.randomUUID(),
      type,
      value,
      reason: reason || null,
      added_by: session ? (session.username || session.email) : null,
      added_at: new Date().toISOString()
    };

    blacklist.push(entry);
    db.writeJSON(db.BLACKLIST_FILE, blacklist);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'warning',
      user_email: session ? (session.username || session.email) : null,
      description: `Added to blacklist: ${type}=${value}`,
      ip, country
    });

    immutable.writeEvent({ type: 'blacklist_add', actor: session ? (session.username || session.email) : null, action: 'add_blacklist', details: entry, ip });

    return res.json({ ok: true, entry });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * DELETE /api/admin/blacklist/:id
 * Remove entry from blacklist
 */
app.delete('/api/admin/blacklist/:id', requirePermission('manage_blacklist'), (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  try {
    let blacklist = db.readJSON(db.BLACKLIST_FILE) || [];
    const { ip, country } = getRequestInfo(req);

    const before = blacklist.length;
    blacklist = blacklist.filter(e => e.id !== req.params.id);
    db.writeJSON(db.BLACKLIST_FILE, blacklist);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'info',
      user_email: session ? (session.username || session.email) : null,
      description: `Removed from blacklist: ${req.params.id}`,
      ip, country
    });

    immutable.writeEvent({ type: 'blacklist_remove', actor: session ? (session.username || session.email) : null, action: 'remove_blacklist', details: { id: req.params.id }, ip });

    return res.json({ ok: true, removed: before - blacklist.length });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/admin/whitelist
 * Add entry to whitelist
 */
app.post('/api/admin/whitelist', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  try {
    const { type, value, reason } = req.body || {};
    const { ip, country } = getRequestInfo(req);

    if (!['ip', 'email', 'user_id'].includes(type)) {
      return res.status(400).json({ error: 'invalid_type' });
    }

    const whitelist = db.readJSON(db.WHITELIST_FILE) || [];
    
    if (whitelist.some(e => e.type === type && e.value === value)) {
      return res.status(409).json({ error: 'already_exists' });
    }

    const entry = {
      id: crypto.randomUUID(),
      type,
      value,
      reason: reason || null,
      added_by: session.email,
      added_at: new Date().toISOString()
    };

    whitelist.push(entry);
    db.writeJSON(db.WHITELIST_FILE, whitelist);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'info',
      user_email: session.email,
      description: `Added to whitelist: ${type}=${value}`,
      ip, country
    });

    return res.json({ ok: true, entry });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * DELETE /api/admin/whitelist/:id
 * Remove entry from whitelist
 */
app.delete('/api/admin/whitelist/:id', (req, res) => {
  const token = extractToken(req);
  const session = authService.verifyAdminSession(token);
  if (!session) return res.status(401).json({ error: 'unauthorized' });

  try {
    let whitelist = db.readJSON(db.WHITELIST_FILE) || [];
    const { ip, country } = getRequestInfo(req);

    whitelist = whitelist.filter(e => e.id !== req.params.id);
    db.writeJSON(db.WHITELIST_FILE, whitelist);

    searchService.logEvent({
      type: 'admin_action',
      severity: 'info',
      user_email: session.email,
      description: `Removed from whitelist: ${req.params.id}`,
      ip, country
    });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

// ============================================================================
// CREATOR PANEL ENDPOINTS (role = 'creator' only)
// ============================================================================

// Helper: require CREATOR role
function requireCreator(req, res) {
  const token = extractToken(req);
  if (!token) return null;
  const session = authService.verifyAdminSession(token);
  if (!session || session.role !== 'creator') return null;
  return session;
}

// Helper: log immutable audit events
function logImmutableEvent(event) {
  const fs = require('fs');
  const immutablePath = path.join(__dirname, 'immutable-logs.json');
  const logs = fs.existsSync(immutablePath) 
    ? JSON.parse(fs.readFileSync(immutablePath, 'utf8') || '[]')
    : [];
  logs.push({
    id: require('crypto').randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString(),
    ...event
  });
  fs.appendFileSync(immutablePath, JSON.stringify(logs[logs.length - 1]) + '\n');
}

/**
 * CREATOR: Team management
 * Routes: GET/POST/PUT/DELETE /api/creator/team
 * Access: CREATOR only (requireCreator)
 */
app.get('/api/creator/team', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });

  try {
    const list = db.readJSON(db.TEAM_FILE) || [];
    return res.json({ ok: true, team: list });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/creator/team', async (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });

  try {
    const { pseudo, discord_id, title } = req.body || {};
    if (!pseudo || !discord_id) return res.status(400).json({ error: 'missing_fields', message: 'pseudo and discord_id required' });

    const list = db.readJSON(db.TEAM_FILE) || [];
    
    // Fetch Discord user data asynchronously - WAIT for it
    const discordData = await discordService.getDiscordUserData(discord_id);
    
    const entry = {
      id: require('crypto').randomBytes(8).toString('hex'),
      pseudo,
      discord_id,
      avatar_url: discordData.avatar_url,
      banner_url: discordData.banner_url,
      title: title || null,
      created_by: creator.username || creator.email || null,
      created_at: new Date().toISOString()
    };

    list.push(entry);
    db.writeJSON(db.TEAM_FILE, list);

    searchService.logEvent({ type: 'admin_action', severity: 'info', user_email: creator.username || null, description: `Creator added team member ${pseudo}`, ip: req.ip });
    immutable.writeEvent({ type: 'team_member_created', actor: creator.username || null, action: 'team_add', details: { pseudo, discord_id }, ip: req.ip });

    return res.status(201).json({ ok: true, entry });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

app.put('/api/creator/team/:id', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });

  try {
    const updates = req.body || {};
    let list = db.readJSON(db.TEAM_FILE) || [];
    let found = false;
    list = list.map(item => {
      if (item.id === req.params.id) {
        found = true;
        return Object.assign({}, item, updates, { updated_at: new Date().toISOString(), updated_by: creator.username || null });
      }
      return item;
    });
    if (!found) return res.status(404).json({ error: 'not_found' });
    db.writeJSON(db.TEAM_FILE, list);
    immutable.writeEvent({ type: 'team_member_updated', actor: creator.username || null, details: { id: req.params.id, updates } });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

app.delete('/api/creator/team/:id', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });

  try {
    let list = db.readJSON(db.TEAM_FILE) || [];
    const before = list.length;
    list = list.filter(item => item.id !== req.params.id);
    if (list.length === before) return res.status(404).json({ error: 'not_found' });
    db.writeJSON(db.TEAM_FILE, list);
    immutable.writeEvent({ type: 'team_member_deleted', actor: creator.username || null, details: { id: req.params.id } });
    return res.json({ ok: true, removed: before - list.length });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

// Refresh Discord avatar/banner for a team member (creator-only)
app.post('/api/creator/team/:id/refresh', async (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });

  try {
    const list = db.readJSON(db.TEAM_FILE) || [];
    const id = req.params.id;
    const member = list.find(m => m.id === id);
    if (!member) return res.status(404).json({ error: 'not_found' });

    // Attempt Discord lookup
    try {
      const discordData = await discordService.getDiscordUserData(member.discord_id);
      member.avatar_url = discordData.avatar_url || member.avatar_url || null;
      member.banner_url = discordData.banner_url || member.banner_url || null;
      member.updated_at = new Date().toISOString();
      member.updated_by = creator.username || creator.email || null;

      // Persist
      db.writeJSON(db.TEAM_FILE, list);

      immutable.writeEvent({ type: 'team_member_refreshed', actor: creator.username || null, details: { id: member.id, discord_id: member.discord_id }, ip: req.ip });

      return res.json({ ok: true, member });
    } catch (e) {
      return res.status(500).json({ error: 'discord_lookup_failed', message: e.message });
    }
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/creator/kill-switch
 * Activate emergency kill switch (creator-only)
 */
app.post('/api/creator/kill-switch', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const { reason } = req.body || {};
    const system = db.readJSON(db.SYSTEM_FILE) || {};
    
    system.kill_switch_active = true;
    system.kill_switch_activated_at = new Date().toISOString();
    system.kill_switch_activated_by = creator.username;
    system.kill_switch_reason = reason || 'Manual activation';
    
    db.writeJSON(db.SYSTEM_FILE, system);
    
    logImmutableEvent({
      type: 'kill_switch_activated',
      severity: 'critical',
      creator: creator.username,
      reason: reason || 'No reason provided',
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    return res.json({ ok: true, message: 'Kill Switch activé' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * POST /api/creator/kill-switch/disable
 * Disable kill switch (creator-only)
 */
app.post('/api/creator/kill-switch/disable', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const system = db.readJSON(db.SYSTEM_FILE) || {};
    system.kill_switch_active = false;
    system.kill_switch_disabled_at = new Date().toISOString();
    system.kill_switch_disabled_by = creator.username;
    
    db.writeJSON(db.SYSTEM_FILE, system);
    
    logImmutableEvent({
      type: 'kill_switch_disabled',
      severity: 'critical',
      creator: creator.username,
      ip: req.ip
    });
    
    return res.json({ ok: true, message: 'Kill Switch désactivé' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/creator/logs
 * Get real-time audit logs (creator-only)
 */
app.get('/api/creator/logs', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const logs = immutable.readEvents({ limit: 100, offset: 0 });
    return res.json({ ok: true, logs });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/creator/immutable-logs
 * Get immutable audit logs (creator-only)
 */
app.get('/api/creator/immutable-logs', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const fs = require('fs');
    const immutablePath = path.join(__dirname, 'immutable-logs.json');
    if (!fs.existsSync(immutablePath)) {
      return res.json({ ok: true, logs: [] });
    }
    
    const content = fs.readFileSync(immutablePath, 'utf8');
    const logs = content.split('\n').filter(l => l.trim()).map(l => JSON.parse(l));
    
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    
    return res.json({
      ok: true,
      logs: logs.slice(offset, offset + limit),
      total: logs.length
    });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * POST /api/creator/admin/create
 * Create or update admin user (creator-only)
 */
app.post('/api/creator/admin/create', async (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  const { email, password, role } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  
  try {
    const bcrypt = require('bcrypt');
    const users = db.readJSON(db.USERS_FILE) || {};
    const hash = await bcrypt.hash(password, 10);
    
    users[email.toLowerCase()] = {
      id: require('crypto').randomBytes(8).toString('hex'),
      email: email.toLowerCase(),
      is_admin: true,
      password_hash: hash,
      role: role || 'admin',
      created_at: new Date().toISOString(),
      created_by: creator.username
    };
    
    db.writeJSON(db.USERS_FILE, users);
    
    logImmutableEvent({
      type: 'admin_created',
      severity: 'warning',
      creator: creator.username,
      admin_email: email.toLowerCase(),
      role: role || 'admin'
    });
    
    return res.json({ ok: true, message: 'Admin créé' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error', message: e.message });
  }
});

/**
 * GET /api/creator/admins
 * List all admin users (creator-only)
 */
app.get('/api/creator/admins', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    const admins = Object.values(users)
      .filter(u => u.is_admin)
      .map(u => ({
        email: u.email,
        role: u.role || 'admin',
        created_at: u.created_at,
        created_by: u.created_by
      }));
    
    return res.json({ ok: true, admins });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * DELETE /api/creator/admin/:email
 * Delete or suspend admin (creator-only)
 */
app.delete('/api/creator/admin/:email', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const email = decodeURIComponent(req.params.email).toLowerCase();
    const users = db.readJSON(db.USERS_FILE) || {};
    
    if (!users[email]) {
      return res.status(404).json({ error: 'not_found' });
    }
    
    delete users[email];
    db.writeJSON(db.USERS_FILE, users);
    
    logImmutableEvent({
      type: 'admin_deleted',
      severity: 'warning',
      creator: creator.username,
      admin_email: email
    });
    
    return res.json({ ok: true, message: 'Admin supprimé' });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * POST /api/creator/backup
 * Create DB backup (creator-only)
 */
app.post('/api/creator/backup', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const fs = require('fs');
    const backupDir = path.join(__dirname, 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir);
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFile = path.join(backupDir, `backup-${timestamp}.tar.gz`);
    
    // Simple tar.gz backup of JSON files
    const files = [
      db.USERS_FILE, db.SEARCHES_FILE, db.LOGS_FILE, 
      db.SOURCES_FILE, db.SYSTEM_FILE
    ];
    
    logImmutableEvent({
      type: 'backup_created',
      severity: 'info',
      creator: creator.username,
      backup_file: backupFile
    });
    
    return res.json({ 
      ok: true, 
      message: 'Backup créé',
      backup_id: timestamp
    });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

/**
 * GET /api/creator/stats
 * Creator dashboard stats (creator-only)
 */
app.get('/api/creator/stats', (req, res) => {
  const creator = requireCreator(req, res);
  if (!creator) return res.status(403).json({ error: 'creator_only' });
  
  try {
    const users = db.readJSON(db.USERS_FILE) || {};
    const searches = db.readJSON(db.SEARCHES_FILE) || [];
    const system = db.readJSON(db.SYSTEM_FILE) || {};
    
    const admins = Object.values(users).filter(u => u.is_admin);
    
    return res.json({
      ok: true,
      stats: {
        total_users: Object.keys(users).length,
        total_searches: searches.length,
        total_admins: admins.length,
        kill_switch_active: system.kill_switch_active || false,
        kill_switch_activated_at: system.kill_switch_activated_at || null,
        creator_username: creator.username
      }
    });
  } catch (e) {
    return res.status(500).json({ error: 'server_error' });
  }
});

// ============================================================================
// SERVER START
// ============================================================================

// Server already listening via app.listen() at line 1173

module.exports = app;
