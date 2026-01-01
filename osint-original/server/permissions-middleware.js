const fs = require('fs');
const path = require('path');
const authService = require('./auth-service');
const db = require('./db-schema');
const immutable = require('./immutable-logger');

function extractTokenFromHeader(req) {
  const h = req.headers.authorization || '';
  const parts = h.split(' ');
  if (parts.length === 2 && parts[0] === 'Bearer') return parts[1];
  return null;
}

function requireRole(requiredRole) {
  return (req, res, next) => {
    const token = extractTokenFromHeader(req);
    if (!token) return res.status(401).json({ error: 'unauthorized' });
    const session = authService.verifyAdminSession(token);
    if (!session) return res.status(401).json({ error: 'unauthorized' });
    // session.role may be present; fallback to users.json
    const role = (session.role || session.role || '').toUpperCase();
    if (role === requiredRole.toUpperCase()) return next();
    // Not allowed
    immutable.writeEvent({ type: 'access_denied', actor: session.username || session.email || null, action: `requireRole:${requiredRole}`, reason: 'insufficient_role', ip: req.ip });
    return res.status(403).json({ error: 'insufficient_role' });
  };
}

function requirePermission(permission) {
  return (req, res, next) => {
    const token = extractTokenFromHeader(req);
    if (!token) {
      immutable.writeEvent({ type: 'access_denied', actor: null, action: permission, reason: 'no_token', ip: req.ip });
      return res.status(401).json({ error: 'unauthorized' });
    }

    const adminSession = authService.verifyAdminSession(token);
    if (!adminSession) {
      immutable.writeEvent({ type: 'access_denied', actor: null, action: permission, reason: 'invalid_admin_session', ip: req.ip });
      return res.status(401).json({ error: 'unauthorized' });
    }

    // Creator bypass
    if ((adminSession.role || '').toLowerCase() === 'creator' || (adminSession.role || '').toLowerCase() === 'root') {
      return next();
    }

    // Load permissions map
    let perms = {};
    try {
      perms = JSON.parse(fs.readFileSync(path.join(__dirname, 'permissions.json'), 'utf8'));
    } catch (e) {
      console.error('permissions middleware: failed to load permissions.json', e && e.message);
      immutable.writeEvent({ type: 'system_error', message: 'permissions_load_failed', error: e && e.message });
      return res.status(500).json({ error: 'server_error' });
    }

    const users = db.readJSON(db.USERS_FILE) || {};
    const adminUser = users[(adminSession.username||adminSession.email||'').toLowerCase()] || null;
    const roleName = (adminUser && adminUser.role) ? adminUser.role.toUpperCase() : (adminSession.role || '').toUpperCase();

    const rolePerms = (perms.roles && perms.roles[roleName]) || {};
    const allowed = !!rolePerms[permission];

    if (allowed) return next();

    // Deny
    immutable.writeEvent({
      type: 'access_denied',
      actor: adminUser ? adminUser.email : (adminSession.username || adminSession.email || null),
      role: roleName,
      action: permission,
      reason: 'missing_permission',
      ip: req.ip
    });

    return res.status(403).json({ error: 'insufficient_permissions' });
  };
}

function requireSubscription(minPlan) {
  // minPlan expected like 'FREE','BASIC','PRO','ENTERPRISE'
  const tiers = { FREE: 0, BASIC: 1, PRO: 2, ENTERPRISE: 3 };
  const minTier = (minPlan || 'FREE').toUpperCase();
  return (req, res, next) => {
    const token = extractTokenFromHeader(req);
    if (!token) return res.status(401).json({ error: 'unauthorized' });
    const session = authService.verifySession(token);
    if (!session) return res.status(401).json({ error: 'unauthorized' });
    const users = db.readJSON(db.USERS_FILE) || {};
    const user = users[(session.email || '').toLowerCase()];
    const userPlan = (user && user.plan) ? (String(user.plan).toUpperCase()) : 'FREE';
    const userTier = (tiers[userPlan] !== undefined) ? tiers[userPlan] : 0;
    if (userTier >= (tiers[minTier] || 0)) return next();
    // insufficient plan
    immutable.writeEvent({ type: 'access_denied', actor: session.email || null, action: `requireSubscription:${minPlan}`, reason: 'insufficient_plan', ip: req.ip });
    return res.status(403).json({ error: 'upgrade_required', required: minPlan });
  };
}

module.exports = {
  requireRole,
  requirePermission,
  requireSubscription
};


