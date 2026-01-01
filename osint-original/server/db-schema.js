/**
 * SeekData Database Schema
 * Structure and initialization for all persistent data
 */

const fs = require('fs');
const path = require('path');

// Data file paths
const DATA_DIR = __dirname;
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SEARCHES_FILE = path.join(DATA_DIR, 'searches.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');
const SOURCES_FILE = path.join(DATA_DIR, 'sources.json');
const ALERTS_FILE = path.join(DATA_DIR, 'alerts.json');
const BLACKLIST_FILE = path.join(DATA_DIR, 'blacklist.json');
const WHITELIST_FILE = path.join(DATA_DIR, 'whitelist.json');
const SYSTEM_FILE = path.join(DATA_DIR, 'system.json');
const SUBSCRIPTIONS_FILE = path.join(DATA_DIR, 'subscriptions.json');
const TEAM_FILE = path.join(DATA_DIR, 'team.json');
const ADMIN_CRED_FILE = path.join(DATA_DIR, 'admin_credentials.json');
const IP_LOG_FILE = path.join(DATA_DIR, 'ip_logs.json');

// Plans definition
const PLANS = {
  FREE: { 
    id: 'FREE',
    name: 'Gratuit', 
    daily_quota: 5, 
    allowed_types: ['email'], 
    features: ['base_search', 'email_only'],
    price: 0
  },
  BASIC: { 
    id: 'BASIC',
    name: 'Basique', 
    daily_quota: 50, 
    allowed_types: ['email','username'], 
    features: ['extended_search', 'email_username'],
    price: 9.99
  },
  PRO: { 
    id: 'PRO',
    name: 'Pro', 
    daily_quota: 1000, 
    allowed_types: ['email','username','ip','domain'], 
    features: ['full_search', 'all_types', 'api_access'],
    price: 29.99
  },
  ENTERPRISE: {
    id: 'ENTERPRISE',
    name: 'Entreprise',
    daily_quota: 50000,
    allowed_types: ['email','username','ip','domain','phone'],
    features: ['full_search', 'all_types', 'api_access', 'priority_support', 'custom_sources'],
    price: 'custom'
  }
};

// Default OSINT sources
const DEFAULT_SOURCES = [
  {
    id: 'public_archives',
    name: 'Archives Publiques',
    type: 'database',
    url: 'https://archives.local/api/search',
    enabled: true,
    reliability: 0.95,
    avg_latency_ms: 250,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'email_db',
    name: 'Email Database',
    type: 'breach_db',
    url: 'https://emaildb.local/search',
    enabled: true,
    reliability: 0.98,
    avg_latency_ms: 180,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'username_index',
    name: 'Username Index',
    type: 'social_media',
    url: 'https://usernames.local/api/search',
    enabled: true,
    reliability: 0.92,
    avg_latency_ms: 320,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'ip_geolocation',
    name: 'IP Geolocation',
    type: 'network',
    url: 'https://geo.local/lookup',
    enabled: true,
    reliability: 0.99,
    avg_latency_ms: 100,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'domain_whois',
    name: 'Domain WHOIS',
    type: 'domain_registry',
    url: 'https://whois.local/api/domain',
    enabled: true,
    reliability: 0.97,
    avg_latency_ms: 200,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'leakcheck',
    name: 'LeakCheck (public)',
    type: 'leakcheck',
    url: 'https://leakcheck.net/api/public?key=49535f49545f5245414c4c595f4150495f4b4559&check={query}',
    enabled: true,
    reliability: 0.9,
    avg_latency_ms: 700,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'snusbase',
    name: 'Snusbase',
    type: 'snusbase',
    url: 'https://snusbase.example/api/search?query={query}',
    enabled: false,
    reliability: 0.9,
    avg_latency_ms: 800,
    last_check: new Date().toISOString(),
    status: 'offline'
  },
  {
    id: 'breachvip',
    name: 'BreachVIP',
    type: 'breachvip',
    url: 'https://breachvip.example/api/search?query={query}',
    enabled: false,
    reliability: 0.88,
    avg_latency_ms: 900,
    last_check: new Date().toISOString(),
    status: 'offline'
  },
  {
    id: 'redline',
    name: 'RedLine Dataset',
    type: 'redline',
    url: 'https://redline.example/api/search?query={query}',
    enabled: false,
    reliability: 0.75,
    avg_latency_ms: 1200,
    last_check: new Date().toISOString(),
    status: 'offline'
  },
  {
    id: 'local_databases',
    name: 'Local Databases (F:\\Databases)',
    type: 'localdb',
    path: 'F:\\Databases',
    enabled: true,
    reliability: 0.99,
    avg_latency_ms: 50,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'dark_web_index',
    name: 'Dark Web Index',
    type: 'darkweb',
    url: 'https://darkindex.local/search',
    enabled: false,
    reliability: 0.85,
    avg_latency_ms: 500,
    last_check: new Date().toISOString(),
    status: 'offline'
  },
  {
    id: 'phone_lookup',
    name: 'Phone Lookup',
    type: 'telecom',
    url: 'https://phone.local/api/search',
    enabled: true,
    reliability: 0.88,
    avg_latency_ms: 280,
    last_check: new Date().toISOString(),
    status: 'online'
  },
  {
    id: 'business_registry',
    name: 'Business Registry',
    type: 'commerce',
    url: 'https://business.local/search',
    enabled: true,
    reliability: 0.96,
    avg_latency_ms: 220,
    last_check: new Date().toISOString(),
    status: 'online'
  }
];

/**
 * User schema:
 * {
 *   email: string (key, lowercase),
 *   password_hash: string,
 *   plan: 'FREE'|'BASIC'|'PRO'|'ENTERPRISE',
 *   quota_remaining: number,
 *   quota_reset_date: ISO string,
 *   created_at: ISO string,
 *   last_login: ISO string,
 *   logins: Array<{at: ISO, ip: string, country: string}>,
 *   status: 'active'|'suspended'|'banned',
 *   failed_login_attempts: number,
 *   locked_until: ISO string|null,
 *   email_verified: boolean,
 *   api_keys: Array<{key: string, created_at: ISO, last_used: ISO, active: boolean}>,
 *   settings: Object,
 *   is_admin: boolean,
 *   risk_score: number (0-100)
 * }
 */

/**
 * Search log schema:
 * {
 *   id: string (uuid-like),
 *   user_email: string,
 *   query: string,
 *   query_type: 'email'|'username'|'ip'|'domain'|'phone',
 *   results_count: number,
 *   sources_queried: Array<string>,
 *   duration_ms: number,
 *   status: 'success'|'partial'|'failed',
 *   created_at: ISO string,
 *   ip: string,
 *   country: string,
 *   quota_used: number
 * }
 */

/**
 * Log entry schema (generic):
 * {
 *   id: string,
 *   type: 'login'|'search'|'admin_action'|'error'|'security_event'|'api_call',
 *   severity: 'info'|'warning'|'critical',
 *   user_email: string|null,
 *   description: string,
 *   metadata: Object,
 *   created_at: ISO string,
 *   ip: string,
 *   country: string,
 *   user_agent: string
 * }
 */

/**
 * Alert schema:
 * {
 *   id: string,
 *   type: 'abuse'|'quota_warning'|'source_issue'|'suspicious_activity'|'system_alert',
 *   severity: 'low'|'medium'|'high'|'critical',
 *   status: 'open'|'acknowledged'|'resolved',
 *   user_email: string|null,
 *   title: string,
 *   description: string,
 *   recommendation: string,
 *   created_at: ISO string,
 *   resolved_at: ISO string|null,
 *   assigned_to: string|null
 * }
 */

// Utility functions
function ensureFile(filepath, defaultData) {
  if (!fs.existsSync(filepath)) {
    fs.writeFileSync(filepath, JSON.stringify(defaultData, null, 2), 'utf8');
  }
}

function readJSON(filepath) {
  try {
    if (!fs.existsSync(filepath)) return null;
    const content = fs.readFileSync(filepath, 'utf8') || '';
    if (!content.trim()) return null;
    return JSON.parse(content);
  } catch (e) {
    console.error(`Error reading ${filepath}:`, e.message);
    return null;
  }
}

function writeJSON(filepath, data) {
  try {
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error(`Error writing ${filepath}:`, e.message);
    return false;
  }
}

// Initialize all data files
function initializeDB() {
  ensureFile(USERS_FILE, {});
  ensureFile(SEARCHES_FILE, []);
  ensureFile(LOGS_FILE, []);
  ensureFile(SOURCES_FILE, DEFAULT_SOURCES);
  ensureFile(ALERTS_FILE, []);
  ensureFile(BLACKLIST_FILE, []);
  ensureFile(WHITELIST_FILE, []);
  ensureFile(SUBSCRIPTIONS_FILE, {});
  ensureFile(TEAM_FILE, []);
  ensureFile(SYSTEM_FILE, { suspended: false, suspend_reason: null, suspend_by: null, suspend_until: null });
  ensureFile(IP_LOG_FILE, []);
  ensureFile(ADMIN_CRED_FILE, { 
    username: 'admin', 
    password: 'admin',
    created_at: new Date().toISOString(),
    last_login: null
  });
}

module.exports = {
  // File paths
  USERS_FILE,
  SEARCHES_FILE,
  LOGS_FILE,
  SOURCES_FILE,
  ALERTS_FILE,
  SUBSCRIPTIONS_FILE,
  TEAM_FILE,
  ADMIN_CRED_FILE,
  IP_LOG_FILE,
  BLACKLIST_FILE,
  WHITELIST_FILE,
  SYSTEM_FILE,
  
  // Data
  PLANS,
  DEFAULT_SOURCES,
  
  // Utilities
  readJSON,
  writeJSON,
  ensureFile,
  initializeDB
};
