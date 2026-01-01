/**
 * ============================================================================
 * COMPREHENSIVE ADMIN PANEL API ENDPOINTS
 * SeekData - Production-Grade OSINT Admin Panel
 * ============================================================================
 */

module.exports = function registerAdminRoutes(app, db, authService, searchService, sourcesService, getRequestInfo, extractToken) {

  // Require admin and optional role check
  function requireAdmin(req, res) {
    const token = extractToken(req);
    if (!token) return null;
    const session = authService.verifyAdminSession(token);
    if (!session) return null;
    return session;
  }

  // ===== ADMIN AUTH =====
  app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body || {};
    const { ip, country, userAgent } = getRequestInfo(req);

    if (!email || !password) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const emailKey = email.toLowerCase();
    const users = db.readJSON(db.USERS_FILE) || {};
    const user = users[emailKey];

    // If we have a real admin user in users.json, validate via bcrypt
    if (user && user.is_admin) {
      try {
        const bcrypt = require('bcrypt');
        const passwordValid = await bcrypt.compare(password, user.password_hash);

        if (!passwordValid) {
          searchService.logEvent({
            type: 'admin_login_failed',
            severity: 'warning',
            user_email: emailKey,
            description: 'Failed admin login attempt',
            ip, country
          });
          return res.status(401).json({ error: 'bad_credentials' });
        }

        const token = authService.createAdminSession(emailKey, ip, userAgent, user.role || 'admin');

        searchService.logEvent({
          type: 'admin_login',
          severity: 'warning',
          user_email: emailKey,
          description: 'Admin logged in',
          ip, country
        });

        return res.json({ ok: true, token, user: { email: emailKey, role: user.role || 'admin' } });
      } catch (e) {
        return res.status(500).json({ error: 'server_error', message: e.message });
      }
    }

    // Fallback: if no admin user in users.json, allow simple admin_credentials.json (legacy)
    try {
      const fs = require('fs');
      const path = require('path');
      const credFile = path.join(__dirname, 'admin_credentials.json');
      if (fs.existsSync(credFile)) {
        try {
          const adminCreds = JSON.parse(fs.readFileSync(credFile, 'utf8') || '{}');
          if (adminCreds && adminCreds.username && adminCreds.password) {
            const credUser = (adminCreds.username || '').toLowerCase();
            const credPass = adminCreds.password || '';
            if (emailKey === credUser) {
              // If stored password looks like a bcrypt hash, use bcrypt.compare
              if (/^\$2[aby]\$/.test(credPass)) {
                try {
                  const bcrypt = require('bcrypt');
                  const ok = await bcrypt.compare(password, credPass);
                  if (ok) {
                    const token = authService.createAdminSession(emailKey, ip, userAgent, 'creator');
                    searchService.logEvent({ type: 'admin_login', severity: 'warning', user_email: emailKey, description: 'Admin logged in (legacy creds hashed)', ip, country });
                    return res.json({ ok: true, token, user: { email: emailKey, role: 'creator' } });
                  }
                } catch (e) { /* continue to plain compare fallback */ }
              }

              // Plain text compare
              if (password === credPass) {
                const token = authService.createAdminSession(emailKey, ip, userAgent, 'creator');
                searchService.logEvent({ type: 'admin_login', severity: 'warning', user_email: emailKey, description: 'Admin logged in (legacy creds)', ip, country });
                return res.json({ ok: true, token, user: { email: emailKey, role: 'creator' } });
              }
            }
          }
        } catch (e) {
          console.error('admin_credentials.json parse error', e && e.message);
        }
      }
    } catch (e) {
      console.error('admin credentials fallback error', e && e.message);
    }

    return res.status(401).json({ error: 'bad_credentials' });
  });

  // ===== ADMIN STATS & OVERVIEW =====
  app.get('/api/admin/stats', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const users = db.readJSON(db.USERS_FILE) || {};
      const searches = db.readJSON(db.SEARCHES_FILE) || [];
      const logs = searchService.getLogs({ limit: 10000 });
      const blacklist = db.readJSON(db.BLACKLIST_FILE) || [];

      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const yesterday = new Date(today);
      yesterday.setDate(yesterday.getDate() - 1);

      const searches_24h = searches.filter(s => new Date(s.created_at) >= yesterday).length;
      const active_today = Object.values(users).filter(u => {
        const lastLogin = u.last_login ? new Date(u.last_login) : null;
        return lastLogin && lastLogin >= today;
      }).length;

      const blocked_requests = logs.filter(l => l.type === 'blocked' || l.description.includes('blocked')).length;
      const security_alerts = logs.filter(l => l.severity === 'critical').length;

      const sources = db.readJSON(db.SOURCES_FILE) || db.DEFAULT_SOURCES;
      const api_health = Object.values(sources).filter(s => s.status === 'online').length;

      return res.json({
        ok: true,
        total_users: Object.keys(users).length,
        active_today,
        searches_24h,
        blocked_requests,
        security_alerts,
        api_health,
        blacklist_size: blacklist.length
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== USER MANAGEMENT =====
  app.get('/api/admin/users', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const users = db.readJSON(db.USERS_FILE) || {};
      let userList = Object.values(users);

      // Filter by search query
      const search = (req.query.search || '').toLowerCase();
      if (search) {
        userList = userList.filter(u =>
          u.email.includes(search) || (u.last_ip && u.last_ip.includes(search))
        );
      }

      // Filter by status
      const status = req.query.status;
      if (status) {
        userList = userList.filter(u => (u.status || 'active') === status);
      }

      // Remove password hashes and sensitive data
      userList = userList.map(u => ({
        id: u.id,
        email: u.email,
        plan: u.plan || 'FREE',
        status: u.status || 'active',
        created_at: u.created_at,
        last_login: u.last_login,
        last_ip: u.last_ip,
        quota_used: u.quota_used || 0,
        quota_limit: db.PLANS[u.plan || 'FREE']?.daily_quota || 0
      }));

      return res.json({
        ok: true,
        users: userList.slice(0, 100)
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.get('/api/admin/users/:userId', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const users = db.readJSON(db.USERS_FILE) || {};
      const user = Object.values(users).find(u => u.id === req.params.userId);

      if (!user) {
        return res.status(404).json({ error: 'user_not_found' });
      }

      return res.json({
        ok: true,
        user: {
          id: user.id,
          email: user.email,
          plan: user.plan || 'FREE',
          status: user.status || 'active',
          created_at: user.created_at,
          last_login: user.last_login,
          last_ip: user.last_ip,
          quota_used: user.quota_used || 0,
          quota_limit: db.PLANS[user.plan || 'FREE']?.daily_quota || 0,
          logins: user.logins || []
        }
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.post('/api/admin/users/:userId/block', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const users = db.readJSON(db.USERS_FILE) || {};
      const userEntry = Object.entries(users).find(([_, u]) => u.id === req.params.userId);

      if (!userEntry) {
        return res.status(404).json({ error: 'user_not_found' });
      }

      const [email, user] = userEntry;
      user.status = 'blocked';
      users[email] = user;
      db.writeJSON(db.USERS_FILE, users);

      // Invalidate existing sessions for this user so effect is immediate
      try { authService.invalidateSessionsForEmail(email); } catch (e) {}

      searchService.logEvent({
        type: 'admin_action',
        severity: 'warning',
        user_email: (admin.email || admin.username),
        description: `Blocked user ${email}`,
        ip: admin.ip,
        country: admin.country
      });

      return res.json({ ok: true, message: 'User blocked' });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.post('/api/admin/users/:userId/ban', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const users = db.readJSON(db.USERS_FILE) || {};
      const userEntry = Object.entries(users).find(([_, u]) => u.id === req.params.userId);

      if (!userEntry) {
        return res.status(404).json({ error: 'user_not_found' });
      }

      const [email, user] = userEntry;
      user.status = 'banned';
      users[email] = user;
      db.writeJSON(db.USERS_FILE, users);

      // Invalidate active sessions for this user immediately
      try { authService.invalidateSessionsForEmail(email); } catch (e) {}

      searchService.logEvent({
        type: 'admin_action',
        severity: 'critical',
        user_email: (admin.email || admin.username),
        description: `Banned user ${email}`,
        ip: admin.ip,
        country: admin.country
      });

      return res.json({ ok: true, message: 'User banned' });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.put('/api/admin/users/:userId/plan', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    const { plan } = req.body || {};
    if (!plan || !db.PLANS[plan]) {
      return res.status(400).json({ error: 'invalid_plan' });
    }

    try {
      const users = db.readJSON(db.USERS_FILE) || {};
      const userEntry = Object.entries(users).find(([_, u]) => u.id === req.params.userId);

      if (!userEntry) {
        return res.status(404).json({ error: 'user_not_found' });
      }

      const [email, user] = userEntry;
      const oldPlan = user.plan;
      user.plan = plan;
      user.quota_limit = db.PLANS[plan].daily_quota;
      users[email] = user;
      db.writeJSON(db.USERS_FILE, users);

      searchService.logEvent({
        type: 'admin_action',
        severity: 'info',
        user_email: (admin.email || admin.username),
        description: `Changed user ${email} plan from ${oldPlan} to ${plan}`,
        ip: admin.ip,
        country: admin.country
      });

      return res.json({ ok: true, message: `Plan changed to ${plan}` });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== SEARCH MANAGEMENT =====
  app.get('/api/admin/searches', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const searches = db.readJSON(db.SEARCHES_FILE) || [];
      let filtered = searches;

      // Filter by email
      const email = req.query.email;
      if (email) {
        filtered = filtered.filter(s => s.user_email === email);
      }

      // Filter by type
      const type = req.query.type;
      if (type) {
        filtered = filtered.filter(s => s.query_type === type);
      }

      // Filter by status
      const status = req.query.status;
      if (status) {
        filtered = filtered.filter(s => s.status === status);
      }

      const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
      const result = filtered
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
        .slice(0, limit);

      return res.json({
        ok: true,
        searches: result
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.delete('/api/admin/searches/:searchId', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const searches = db.readJSON(db.SEARCHES_FILE) || [];
      const filtered = searches.filter(s => s.id !== req.params.searchId);

      if (filtered.length === searches.length) {
        return res.status(404).json({ error: 'search_not_found' });
      }

      db.writeJSON(db.SEARCHES_FILE, filtered);

      searchService.logEvent({
        type: 'admin_action',
        severity: 'info',
        user_email: (admin.email || admin.username),
        description: `Deleted search ${req.params.searchId}`,
        ip: admin.ip,
        country: admin.country
      });

      return res.json({ ok: true, message: 'Search deleted' });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== SUBSCRIPTIONS =====
  app.get('/api/admin/subscriptions', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const users = db.readJSON(db.USERS_FILE) || {};
      const plans = Object.values(users).reduce((acc, u) => {
        const plan = u.plan || 'FREE';
        acc[plan] = (acc[plan] || 0) + 1;
        return acc;
      }, {});

      return res.json({
        ok: true,
        free_count: plans['FREE'] || 0,
        starter_count: plans['STARTER'] || 0,
        pro_count: plans['PRO'] || 0,
        enterprise_count: plans['ENTERPRISE'] || 0,
        total: Object.values(users).length
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== BLACKLIST/WHITELIST =====
  app.get('/api/admin/blacklist', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const blacklist = db.readJSON(db.BLACKLIST_FILE) || [];
      return res.json({ ok: true, list: blacklist });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.post('/api/admin/blacklist', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    const { type, value, reason } = req.body || {};
    if (!type || !value) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    try {
      const blacklist = db.readJSON(db.BLACKLIST_FILE) || [];
      const entry = {
        id: `bl_${Date.now()}`,
        type,
        value,
        reason: reason || '',
        added_at: new Date().toISOString(),
        added_by: (admin.email || admin.username)
      };

      blacklist.push(entry);
      db.writeJSON(db.BLACKLIST_FILE, blacklist);

      searchService.logEvent({
        type: 'admin_action',
        severity: 'info',
        user_email: (admin.email || admin.username),
        description: `Added to blacklist: ${type} = ${value}`,
        ip: admin.ip,
        country: admin.country
      });

      try {
        const immutable = require('./immutable-logger');
        immutable.writeEvent({
          type: 'blacklist_add',
          block_type: type,
          value: String(value),
          added_by: (admin.email || admin.username),
          ip: admin.ip || null,
          action: 'blacklist_add'
        });
      } catch (e) {
        // ignore
      }

      return res.status(201).json({ ok: true, entry });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.delete('/api/admin/blacklist/:entryId', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const blacklist = db.readJSON(db.BLACKLIST_FILE) || [];
      const filtered = blacklist.filter(e => e.id !== req.params.entryId);

      if (filtered.length === blacklist.length) {
        return res.status(404).json({ error: 'entry_not_found' });
      }

      db.writeJSON(db.BLACKLIST_FILE, filtered);

      searchService.logEvent({
        type: 'admin_action',
        severity: 'info',
        user_email: (admin.email || admin.username),
        description: `Removed from blacklist: ${req.params.entryId}`,
        ip: admin.ip,
        country: admin.country
      });

      try {
        const immutable = require('./immutable-logger');
        immutable.writeEvent({
          type: 'blacklist_remove',
          entry_id: req.params.entryId,
          removed_by: (admin.email || admin.username),
          ip: admin.ip || null,
          action: 'blacklist_remove'
        });
      } catch (e) {
        // ignore
      }

      return res.json({ ok: true, message: 'Entry removed' });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // Whitelist same as blacklist
  app.get('/api/admin/whitelist', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const whitelist = db.readJSON(db.WHITELIST_FILE) || [];
      return res.json({ ok: true, list: whitelist });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.post('/api/admin/whitelist', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    const { type, value, reason } = req.body || {};
    if (!type || !value) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    try {
      const whitelist = db.readJSON(db.WHITELIST_FILE) || [];
      const entry = {
        id: `wl_${Date.now()}`,
        type,
        value,
        reason: reason || '',
        added_at: new Date().toISOString(),
        added_by: (admin.email || admin.username)
      };

      whitelist.push(entry);
      db.writeJSON(db.WHITELIST_FILE, whitelist);

      searchService.logEvent({
        type: 'admin_action',
        severity: 'info',
        user_email: (admin.email || admin.username),
        description: `Added to whitelist: ${type} = ${value}`,
        ip: admin.ip,
        country: admin.country
      });

      return res.status(201).json({ ok: true, entry });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.delete('/api/admin/whitelist/:entryId', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const whitelist = db.readJSON(db.WHITELIST_FILE) || [];
      const filtered = whitelist.filter(e => e.id !== req.params.entryId);

      if (filtered.length === whitelist.length) {
        return res.status(404).json({ error: 'entry_not_found' });
      }

      db.writeJSON(db.WHITELIST_FILE, filtered);

      searchService.logEvent({
        type: 'admin_action',
        severity: 'info',
        user_email: (admin.email || admin.username),
        description: `Removed from whitelist: ${req.params.entryId}`,
        ip: admin.ip,
        country: admin.country
      });

      return res.json({ ok: true, message: 'Entry removed' });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== LOGS =====
  app.get('/api/admin/logs', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const filter = {
        type: req.query.type || null,
        severity: req.query.severity || null,
        user_email: req.query.user || null,
        limit: Math.min(parseInt(req.query.limit) || 500, 5000)
      };

      const logs = searchService.getLogs(filter);
      return res.json({ ok: true, logs });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== BLACKLIST LOGS (immutable) =====
  app.get('/api/admin/blacklist-logs', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const immutable = require('./immutable-logger');
      const limit = Math.min(parseInt(req.query.limit) || 200, 2000);
      const events = immutable.readEvents({ limit });
      // Filter only blacklist-related events
      const list = events.filter(e => e && (e.type === 'blacklist_block' || e.type === 'blacklist_add' || e.type === 'blacklist_remove'));
      return res.json({ ok: true, logs: list });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.post('/api/admin/logs/clear', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      db.writeJSON(db.LOGS_FILE, []);

      searchService.logEvent({
        type: 'admin_action',
        severity: 'critical',
        user_email: admin.email,
        description: `Cleared all logs`,
        ip: admin.ip,
        country: admin.country
      });

      return res.json({ ok: true, message: 'Logs cleared' });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== ALERTS =====
  app.get('/api/admin/alerts', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const alerts = db.readJSON(db.ALERTS_FILE) || [];
      const status = req.query.status || 'open';
      const filtered = status ? alerts.filter(a => a.status === status) : alerts;

      return res.json({
        ok: true,
        alerts: filtered.slice(0, 50)
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== SOURCES =====
  app.get('/api/admin/sources', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const sources = db.readJSON(db.SOURCES_FILE) || db.DEFAULT_SOURCES;
      return res.json({
        ok: true,
        sources: Object.values(sources)
      });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== SYSTEM ACTIONS =====
  app.post('/api/admin/backup', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });

    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupDir = path.join(__dirname, 'backups');
      if (!require('fs').existsSync(backupDir)) {
        require('fs').mkdirSync(backupDir, { recursive: true });
      }

      const files = ['users.json', 'searches.json', 'logs.json', 'blacklist.json', 'whitelist.json', 'alerts.json'];
      files.forEach(file => {
        const src = path.join(__dirname, file);
        const dst = path.join(backupDir, `${timestamp}_${file}`);
        if (require('fs').existsSync(src)) {
          require('fs').copyFileSync(src, dst);
        }
      });

      searchService.logEvent({
        type: 'admin_action',
        severity: 'info',
        user_email: admin.email,
        description: `Database backup created`,
        ip: admin.ip,
        country: admin.country
      });

      return res.json({ ok: true, message: `Backup created at ${timestamp}` });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== PATCH NOTES (public read, admin write owner only) =====
  app.get('/api/patch-notes', (req, res) => {
    try {
      const fs = require('fs');
      const path = require('path');
      const file = path.join(__dirname, 'patch_notes.json');
      if (!fs.existsSync(file)) return res.json([]);
      const content = fs.readFileSync(file, 'utf8') || '[]';
      const notes = JSON.parse(content);
      return res.json(Array.isArray(notes) ? notes.sort((a,b)=> new Date(b.date)-new Date(a.date)) : []);
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.post('/api/admin/patch-notes', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });
    // only owner/creator can post
    if (!admin.role || admin.role !== 'creator') return res.status(403).json({ error: 'forbidden' });

    const { title, body, version, date } = req.body || {};
    if (!title || !body) return res.status(400).json({ error: 'missing_fields' });

    try {
      const fs = require('fs');
      const path = require('path');
      const file = path.join(__dirname, 'patch_notes.json');
      let notes = [];
      if (fs.existsSync(file)) {
        try { notes = JSON.parse(fs.readFileSync(file, 'utf8') || '[]'); } catch(e){ notes = []; }
      }
      const note = { id: `pn_${Date.now()}`, title, body, version: version || null, date: date || new Date().toISOString(), added_by: admin.email || admin.username };
      notes.push(note);
      fs.writeFileSync(file, JSON.stringify(notes, null, 2), 'utf8');
      return res.status(201).json({ ok: true, note });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  // ===== TEAM LIST (public) + admin management =====
  app.get('/api/team', (req, res) => {
    try {
      const fs = require('fs');
      const path = require('path');
      const file = path.join(__dirname, 'team.json');
      if (!fs.existsSync(file)) return res.json([]);
      const content = fs.readFileSync(file, 'utf8') || '[]';
      const team = JSON.parse(content);
      return res.json(Array.isArray(team) ? team : []);
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.post('/api/admin/team', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });
    // Allow both 'creator' and 'admin' roles to manage team
    if (!admin.role || (admin.role !== 'creator' && admin.role !== 'admin')) return res.status(403).json({ error: 'forbidden' });

    const { username, discord_id, avatar, banner, role } = req.body || {};
    if (!username || !discord_id) return res.status(400).json({ error: 'missing_fields' });

    try {
      const fs = require('fs');
      const path = require('path');
      const file = path.join(__dirname, 'team.json');
      let team = [];
      if (fs.existsSync(file)) {
        try { team = JSON.parse(fs.readFileSync(file, 'utf8') || '[]'); } catch (e) { team = []; }
      }
      const member = { id: `tm_${Date.now()}`, username, discord_id, avatar: avatar || null, banner: banner || null, role: role || '' };
      team.push(member);
      fs.writeFileSync(file, JSON.stringify(team, null, 2), 'utf8');
      return res.status(201).json({ ok: true, member });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

  app.delete('/api/admin/team/:id', (req, res) => {
    const admin = requireAdmin(req, res);
    if (!admin) return res.status(401).json({ error: 'unauthorized' });
    // Allow both 'creator' and 'admin' roles to manage team
    if (!admin.role || (admin.role !== 'creator' && admin.role !== 'admin')) return res.status(403).json({ error: 'forbidden' });

    try {
      const fs = require('fs');
      const path = require('path');
      const file = path.join(__dirname, 'team.json');
      let team = [];
      if (fs.existsSync(file)) {
        try { team = JSON.parse(fs.readFileSync(file, 'utf8') || '[]'); } catch (e) { team = []; }
      }
      const filtered = team.filter(m => m.id !== req.params.id);
      fs.writeFileSync(file, JSON.stringify(filtered, null, 2), 'utf8');
      return res.json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: 'server_error', message: e.message });
    }
  });

};
