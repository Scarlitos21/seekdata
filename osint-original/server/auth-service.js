/**
 * Authentication Service
 * Handles JWT tokens, password verification, rate limiting, and security
 */

const crypto = require('crypto');
const db = require('./db-schema');

// In-memory stores for sessions (can be upgraded to Redis)
const sessions = new Map(); // token -> {email, created_at, expires_at, ip, user_agent}
const failedAttempts = new Map(); // email -> [{ip, timestamp}]
const adminSessions = new Map(); // admin_token -> {username, created_at, expires_at}

// Configuration
const CONFIG = {
  JWT_EXPIRY_HOURS: 24,
  ADMIN_SESSION_EXPIRY_HOURS: 8,
  MAX_FAILED_ATTEMPTS: 5,
  FAILED_ATTEMPT_WINDOW_MINUTES: 15,
  LOCK_DURATION_MINUTES: 30,
  SESSION_CHECK_INTERVAL_MS: 60000 // cleanup every minute
};

/**
 * Generate JWT-like token
 */
function generateToken(email) {
  const payload = {
    email: email.toLowerCase(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (CONFIG.JWT_EXPIRY_HOURS * 3600),
    jti: crypto.randomBytes(16).toString('hex')
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

/**
 * Generate admin token
 */
function generateAdminToken(username) {
  return crypto.randomBytes(32).toString('hex') + Date.now().toString(36);
}

/**
 * Verify and decode token
 */
function verifyToken(token) {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    if (decoded.exp < Math.floor(Date.now() / 1000)) {
      return null; // Expired
    }
    return decoded;
  } catch (e) {
    return null;
  }
}

/**
 * Create user session
 */
function createSession(email, ip, userAgent, countryCode = 'XX') {
  const token = generateToken(email);
  const payload = verifyToken(token);
  
  sessions.set(token, {
    email: email.toLowerCase(),
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + CONFIG.JWT_EXPIRY_HOURS * 3600000).toISOString(),
    ip,
    user_agent: userAgent,
    country: countryCode
  });

  return token;
}

/**
 * Create admin session
 */
function createAdminSession(username, ip, userAgent, role = 'admin') {
  const token = generateAdminToken(username);
  
  adminSessions.set(token, {
    username,
    role,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + CONFIG.ADMIN_SESSION_EXPIRY_HOURS * 3600000).toISOString(),
    ip,
    user_agent: userAgent
  });

  return token;
}

/**
 * Verify user session
 */
function verifySession(token) {
  if (!sessions.has(token)) return null;
  
  const session = sessions.get(token);
  if (new Date(session.expires_at) < new Date()) {
    sessions.delete(token);
    return null;
  }
  
  return session;
}

/**
 * Verify admin session
 */
function verifyAdminSession(token) {
  if (!adminSessions.has(token)) return null;
  
  const session = adminSessions.get(token);
  if (new Date(session.expires_at) < new Date()) {
    adminSessions.delete(token);
    return null;
  }
  
  return session;
}

/**
 * Invalidate session (logout)
 */
function invalidateSession(token) {
  sessions.delete(token);
}

/**
 * Invalidate all sessions for a given email (useful when banning/blocking)
 */
function invalidateSessionsForEmail(email) {
  if (!email) return;
  const target = email.toLowerCase();
  for (let [token, session] of sessions.entries()) {
    if (session && session.email && session.email.toLowerCase() === target) {
      sessions.delete(token);
    }
  }
}

/**
 * Check if user account is locked
 */
function isAccountLocked(email) {
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[email.toLowerCase()];
  
  if (!user) return false;
  if (!user.locked_until) return false;
  
  const lockTime = new Date(user.locked_until);
  if (lockTime < new Date()) {
    // Lock expired, unlock account
    user.locked_until = null;
    user.failed_login_attempts = 0;
    db.writeJSON(db.USERS_FILE, users);
    return false;
  }
  
  return true;
}

/**
 * Record failed login attempt
 */
function recordFailedAttempt(email, ip) {
  const now = Date.now();
  const windowMs = CONFIG.FAILED_ATTEMPT_WINDOW_MINUTES * 60000;
  
  if (!failedAttempts.has(email)) {
    failedAttempts.set(email, []);
  }
  
  const attempts = failedAttempts.get(email);
  attempts.push({ ip, timestamp: now });
  
  // Keep only recent attempts
  const recentAttempts = attempts.filter(a => now - a.timestamp < windowMs);
  failedAttempts.set(email, recentAttempts);
  
  // Check if should lock account
  if (recentAttempts.length >= CONFIG.MAX_FAILED_ATTEMPTS) {
    lockAccount(email);
    return true; // Account locked
  }
  
  // Update user data
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[email.toLowerCase()];
  if (user) {
    user.failed_login_attempts = recentAttempts.length;
    db.writeJSON(db.USERS_FILE, users);
  }
  
  return false; // Not locked yet
}

/**
 * Lock account after too many failed attempts
 */
function lockAccount(email) {
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[email.toLowerCase()];
  
  if (user) {
    const lockUntil = new Date(Date.now() + CONFIG.LOCK_DURATION_MINUTES * 60000);
    user.locked_until = lockUntil.toISOString();
    user.failed_login_attempts = 0;
    db.writeJSON(db.USERS_FILE, users);
    
    // Create security alert
    createSecurityAlert(
      email,
      'account_locked',
      'critical',
      'Compte verrouillé après trop de tentatives de connexion échouées'
    );
  }
}

/**
 * Clear failed attempts on successful login
 */
function clearFailedAttempts(email) {
  failedAttempts.delete(email);
  
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[email.toLowerCase()];
  if (user) {
    user.failed_login_attempts = 0;
    db.writeJSON(db.USERS_FILE, users);
  }
}

/**
 * Create security alert
 */
function createSecurityAlert(userEmail, type, severity, description) {
  const alerts = db.readJSON(db.ALERTS_FILE) || [];
  
  alerts.push({
    id: crypto.randomBytes(8).toString('hex'),
    type,
    severity,
    status: 'open',
    user_email: userEmail,
    title: `Security Alert: ${type}`,
    description,
    recommendation: 'Please review your account security settings',
    created_at: new Date().toISOString(),
    resolved_at: null,
    assigned_to: null
  });
  
  db.writeJSON(db.ALERTS_FILE, alerts);
}

/**
 * Cleanup expired sessions (run periodically)
 */
function cleanupExpiredSessions() {
  const now = new Date();
  
  for (let [token, session] of sessions.entries()) {
    if (new Date(session.expires_at) < now) {
      sessions.delete(token);
    }
  }
  
  for (let [token, session] of adminSessions.entries()) {
    if (new Date(session.expires_at) < now) {
      adminSessions.delete(token);
    }
  }
}

// Start periodic cleanup
setInterval(cleanupExpiredSessions, CONFIG.SESSION_CHECK_INTERVAL_MS);

module.exports = {
  // Configuration
  CONFIG,
  
  // Token generation
  generateToken,
  generateAdminToken,
  verifyToken,
  
  // Session management
  createSession,
  createAdminSession,
  verifySession,
  verifyAdminSession,
  invalidateSession,
  invalidateSessionsForEmail,
  
  // Account security
  isAccountLocked,
  recordFailedAttempt,
  lockAccount,
  clearFailedAttempts,
  
  // Alerts
  createSecurityAlert,
  
  // Maintenance
  cleanupExpiredSessions
};
