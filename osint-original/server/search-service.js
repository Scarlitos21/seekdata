/**
 * Search Service
 * Handles search execution, quota management, logging, and statistics
 */

const crypto = require('crypto');
const db = require('./db-schema');
const sourcesService = require('./sources-service');
const { logToDiscord } = require('./discord-log');

/**
 * Check blacklist rules. Returns matched rule or null.
 */
function isBlacklisted({ value, type, email, ip, country, api_key, username }) {
  const list = db.readJSON(db.BLACKLIST_FILE) || [];
  const now = new Date();
  for (const entry of list) {
    try {
      if (entry.expires_at && new Date(entry.expires_at) < now) continue; // expired
      switch (entry.type) {
        case 'ip':
          if (ip && ip === entry.value) return entry;
          break;
        case 'country':
          if (country && country.toUpperCase() === entry.value.toUpperCase()) return entry;
          break;
        case 'asn':
          // ASN matching not implemented in local env
          break;
        case 'email':
          if (email && email.toLowerCase() === entry.value.toLowerCase()) return entry;
          break;
        case 'username':
          if (username && username.toLowerCase() === entry.value.toLowerCase()) return entry;
          break;
        case 'domain':
          if (value && type === 'domain' && value.toLowerCase() === entry.value.toLowerCase()) return entry;
          break;
        case 'apikey':
          if (api_key && api_key === entry.value) return entry;
          break;
        case 'user':
          if (email && email.toLowerCase() === entry.value.toLowerCase()) return entry;
          break;
        default:
          break;
      }
    } catch (e) { continue; }
  }
  return null;
}


/**
 * Determine search query type
 */
function detectQueryType(query) {
  const q = (query || '').trim().toLowerCase();
  
  // Email
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) return 'email';
  
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) {
    const parts = q.split('.');
    if (parts.every(p => parseInt(p) <= 255)) return 'ip';
  }
  
  // Domain
  if (/^[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$/.test(q)) return 'domain';
  
  // Phone (basic validation)
  if (/^(\+?1?[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$/.test(q)) return 'phone';
  
  // Username
  if (/^[a-zA-Z0-9_.-]{3,}$/.test(q) && !q.includes('.com') && !q.includes('.')) return 'username';
  
  return 'other';
}

/**
 * Check if user can perform this search type
 */
function canSearchType(userPlan, queryType) {
  const plan = db.PLANS[userPlan] || db.PLANS.FREE;
  return plan.allowed_types.includes(queryType);
}

/**
 * Check and update user quota
 */
function checkAndUpdateQuota(email, queryType) {
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[email.toLowerCase()];
  
  if (!user) return { ok: false, error: 'user_not_found' };
  
  const today = new Date().toISOString().split('T')[0];
  const plan = db.PLANS[user.plan] || db.PLANS.FREE;
  
  // Reset quota if new day
  if (user.quota_reset_date !== today) {
    user.quota_remaining = plan.daily_quota;
    user.quota_reset_date = today;
  }
  
  // Check quota
  if (user.quota_remaining <= 0) {
    return { ok: false, error: 'quota_exhausted', remaining: 0 };
  }
  
  // Deduct quota (some query types might cost more)
  const cost = queryType === 'phone' ? 2 : 1;
  user.quota_remaining = Math.max(0, user.quota_remaining - cost);
  user.last_search = new Date().toISOString();
  
  db.writeJSON(db.USERS_FILE, users);
  
  return {
    ok: true,
    remaining: user.quota_remaining,
    used: plan.daily_quota - user.quota_remaining
  };
}

/**
 * Get user quota info
 */
function getQuotaInfo(email) {
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[email.toLowerCase()];
  
  if (!user) return null;
  
  const today = new Date().toISOString().split('T')[0];
  const plan = db.PLANS[user.plan] || db.PLANS.FREE;
  
  // Reset if new day (for display purposes)
  if (user.quota_reset_date !== today) {
    return {
      plan: user.plan,
      daily_quota: plan.daily_quota,
      remaining: plan.daily_quota,
      used: 0,
      reset_date: today,
      percentage_used: 0
    };
  }
  
  const used = plan.daily_quota - user.quota_remaining;
  
  return {
    plan: user.plan,
    daily_quota: plan.daily_quota,
    remaining: user.quota_remaining,
    used,
    reset_date: user.quota_reset_date,
    percentage_used: Math.round((used / plan.daily_quota) * 100)
  };
}

/**
 * Execute a search
 */
async function executeSearch(email, query, ip, country = 'XX') {
  const queryType = detectQueryType(query);
  
  // Validate user plan
  const users = db.readJSON(db.USERS_FILE) || {};
  const user = users[email.toLowerCase()];
  
  if (!user) {
    return { ok: false, error: 'user_not_found' };
  }
  
  const userPlan = user.plan || 'FREE';
  
  if (!canSearchType(userPlan, queryType)) {
    return {
      ok: false,
      error: 'invalid_search_type',
      message: `Type de recherche '${queryType}' non autorisé pour le plan ${userPlan}`
    };
  }
  
  // Check quota
  const quotaCheck = checkAndUpdateQuota(email, queryType);
  if (!quotaCheck.ok) {
    return {
      ok: false,
      error: quotaCheck.error,
      message: 'Quota quotidien épuisé'
    };
  }

  // Blacklist check: block if matching rule
  const blk = isBlacklisted({ value: query, type: queryType, email, ip, country, username: null });
  if (blk) {
    // Log blocked attempt
    logEvent({
      type: 'block',
      severity: 'warning',
      user_email: email,
      description: `Search blocked by blacklist (${blk.type}): ${blk.value}`,
      metadata: { blacklist: blk },
      ip,
      country
    });
    return { ok: false, error: 'blacklisted', message: 'Cette recherche est bloquée par une règle de sécurité', rule: blk };
  }
  
  // Perform actual search
  const startTime = Date.now();
  const searchResults = await sourcesService.searchAllSources(query, queryType);
  const duration = Date.now() - startTime;
  
  // Log search
  const searchId = crypto.randomBytes(8).toString('hex');
  const searches = db.readJSON(db.SEARCHES_FILE) || [];
  
  searches.push({
    id: searchId,
    user_email: email.toLowerCase(),
    query: query.substring(0, 100), // Store truncated query for privacy
    query_type: queryType,
    results_count: searchResults.total_results,
    sources_queried: searchResults.sources_queried.map(s => s.id),
    duration_ms: duration,
    status: searchResults.total_results > 0 ? 'success' : 'partial',
    created_at: new Date().toISOString(),
    ip,
    country,
    quota_used: queryType === 'phone' ? 2 : 1
  });
  
  db.writeJSON(db.SEARCHES_FILE, searches);
  
  // Log generic event
  logEvent({
    type: 'search',
    severity: 'info',
    user_email: email,
    description: `Search executed: ${queryType} - ${searchResults.total_results} results`,
    metadata: {
      query_type: queryType,
      results_count: searchResults.total_results,
      duration_ms: duration,
      sources_count: searchResults.sources_queried.length
    },
    ip,
    country
  });
  
  return {
    ok: true,
    search_id: searchId,
    results: searchResults.results,
    total_results: searchResults.total_results,
    sources_queried: searchResults.sources_queried,
    duration_ms: duration,
    quota_remaining: quotaCheck.remaining
  };
}

/**
 * Get user search history
 */
function getUserSearchHistory(email, limit = 100) {
  const searches = db.readJSON(db.SEARCHES_FILE) || [];
  
  return searches
    .filter(s => s.user_email === email.toLowerCase())
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, limit)
    .map(s => ({
      id: s.id,
      query_type: s.query_type,
      results_count: s.results_count,
      duration_ms: s.duration_ms,
      created_at: s.created_at
    }));
}

/**
 * Get search statistics for a user
 */
function getUserSearchStats(email) {
  const searches = db.readJSON(db.SEARCHES_FILE) || [];
  const userSearches = searches.filter(s => s.user_email === email.toLowerCase());
  
  if (userSearches.length === 0) {
    return {
      total_searches: 0,
      successful_searches: 0,
      total_results: 0,
      avg_duration_ms: 0,
      by_type: {}
    };
  }
  
  const byType = {};
  let totalDuration = 0;
  let totalResults = 0;
  let successCount = 0;
  
  for (const search of userSearches) {
    // By type
    if (!byType[search.query_type]) {
      byType[search.query_type] = { count: 0, total_results: 0 };
    }
    byType[search.query_type].count++;
    byType[search.query_type].total_results += search.results_count;
    
    // Aggregates
    totalDuration += search.duration_ms;
    totalResults += search.results_count;
    if (search.status === 'success') successCount++;
  }
  
  return {
    total_searches: userSearches.length,
    successful_searches: successCount,
    success_rate: Number((successCount / userSearches.length * 100).toFixed(1)),
    total_results: totalResults,
    avg_results_per_search: Number((totalResults / userSearches.length).toFixed(1)),
    avg_duration_ms: Math.round(totalDuration / userSearches.length),
    by_type: byType
  };
}

/**
 * Get global search statistics (admin)
 */
function getGlobalSearchStats() {
  const searches = db.readJSON(db.SEARCHES_FILE) || [];
  const users = db.readJSON(db.USERS_FILE) || {};
  
  if (searches.length === 0) {
    return {
      total_searches: 0,
      total_results: 0,
      avg_duration_ms: 0,
      active_users: 0,
      by_type: {}
    };
  }
  
  const today = new Date().toISOString().split('T')[0];
  const todaySearches = searches.filter(s => s.created_at.startsWith(today));
  const activeUsers = new Set(todaySearches.map(s => s.user_email)).size;
  
  const byType = {};
  let totalDuration = 0;
  let totalResults = 0;
  
  for (const search of searches) {
    // By type
    if (!byType[search.query_type]) {
      byType[search.query_type] = { count: 0, total_results: 0 };
    }
    byType[search.query_type].count++;
    byType[search.query_type].total_results += search.results_count;
    
    totalDuration += search.duration_ms;
    totalResults += search.results_count;
  }
  
  return {
    total_searches: searches.length,
    searches_today: todaySearches.length,
    total_results: totalResults,
    avg_duration_ms: Math.round(totalDuration / searches.length),
    active_users_today: activeUsers,
    total_unique_users: new Set(searches.map(s => s.user_email)).size,
    by_type: byType
  };
}

/**
 * Log generic event
 */
function logEvent(eventData) {
  let logs = db.readJSON(db.LOGS_FILE);
  // Ensure logs is an array (fix for when readJSON returns {} instead of [])
  if (!Array.isArray(logs)) {
    logs = [];
  }
  
  logs.push({
    id: crypto.randomBytes(8).toString('hex'),
    type: eventData.type || 'event',
    severity: eventData.severity || 'info',
    user_email: eventData.user_email || null,
    description: eventData.description || '',
    metadata: eventData.metadata || {},
    created_at: new Date().toISOString(),
    ip: eventData.ip || '0.0.0.0',
    country: eventData.country || 'XX',
    user_agent: eventData.user_agent || 'Unknown'
  });
  
  // Keep last 10000 logs only
  if (logs.length > 10000) {
    logs.splice(0, logs.length - 10000);
  }
  
  db.writeJSON(db.LOGS_FILE, logs);
  // Send critical or important events to Discord webhook if configured
  try {
    const notifyTypes = new Set(['user_registered','login','security_event','admin_action','block','search']);
    if (notifyTypes.has(eventData.type) || eventData.severity === 'critical') {
      // Avoid sending huge payloads
      const small = {
        type: eventData.type,
        user_email: eventData.user_email,
        ip: eventData.ip,
        description: eventData.description,
        metadata: eventData.metadata || {}
      };
      logToDiscord(small);
    }
  } catch (e) { /* ignore */ }
}

/**
 * Get logs with filtering
 */
function getLogs(filter = {}) {
  let logs = db.readJSON(db.LOGS_FILE);
  // Ensure logs is an array
  if (!Array.isArray(logs)) {
    logs = [];
  }
  
  if (filter.type) logs = logs.filter(l => l.type === filter.type);
  if (filter.severity) logs = logs.filter(l => l.severity === filter.severity);
  if (filter.user_email) logs = logs.filter(l => l.user_email === filter.user_email);
  if (filter.ip) logs = logs.filter(l => l.ip === filter.ip);
  
  const limit = filter.limit || 1000;
  return logs.slice(-limit).reverse();
}

module.exports = {
  // Query analysis
  detectQueryType,
  canSearchType,
  
  // Quota management
  checkAndUpdateQuota,
  getQuotaInfo,
  
  // Search execution
  executeSearch,
  getUserSearchHistory,
  getUserSearchStats,
  getGlobalSearchStats,
  
  // Logging
  logEvent,
  getLogs
};
