/**
 * OSINT Sources Management Service
 * Manages source health, reliability, latency, and search functionality
 */

const crypto = require('crypto');
const db = require('./db-schema');
const fs = require('fs');
const path = require('path');

// Use global fetch if available (Node 18+), otherwise try to require node-fetch if present
const _fetch = (typeof fetch !== 'undefined') ? fetch : (typeof globalThis.fetch !== 'undefined' ? globalThis.fetch : null);

/**
 * Initialize sources from database or defaults
 */
function getSources() {
  let sources = db.readJSON(db.SOURCES_FILE);
  if (!sources || sources.length === 0) {
    sources = db.DEFAULT_SOURCES;
    db.writeJSON(db.SOURCES_FILE, sources);
  }
  return sources;
}

/**
 * Get enabled sources only
 */
function getEnabledSources() {
  return getSources().filter(s => s.enabled);
}

/**
 * Get source by ID
 */
function getSourceById(sourceId) {
  const sources = getSources();
  return sources.find(s => s.id === sourceId);
}

/**
 * Perform healthcheck on a source
 */
async function healthCheckSource(sourceId) {
  const source = getSourceById(sourceId);
  if (!source) return null;
  
  const startTime = Date.now();
  const now = new Date().toISOString();
  
  try {
    // Simulate API call (in production, make real HTTP request)
    const delay = Math.random() * 300 + 100; // 100-400ms
    await new Promise(resolve => setTimeout(resolve, delay));
    
    // Simulate occasional failures (90% success rate)
    const success = Math.random() > 0.1;
    
    if (success) {
      const latency = Date.now() - startTime;
      
      // Update source status
      source.last_check = now;
      source.status = 'online';
      
      // Update average latency (moving average)
      source.avg_latency_ms = Math.round(
        (source.avg_latency_ms * 0.7) + (latency * 0.3)
      );
      
      // Update reliability (maintain 0.85-0.99 range)
      source.reliability = Math.min(
        0.99,
        source.reliability + 0.01
      );
      
      saveSources();
      return { status: 'online', latency, reliability: source.reliability };
    } else {
      source.last_check = now;
      source.status = 'degraded';
      source.reliability = Math.max(0.7, source.reliability - 0.05);
      
      saveSources();
      return { status: 'degraded', error: 'Source returned error' };
    }
  } catch (e) {
    source.last_check = now;
    source.status = 'offline';
    source.reliability = Math.max(0.5, source.reliability - 0.1);
    
    saveSources();
    return { status: 'offline', error: e.message };
  }
}

/**
 * Perform healthchecks on all sources
 */
async function healthCheckAllSources() {
  const sources = getSources();
  const results = [];
  
  for (const source of sources) {
    const result = await healthCheckSource(source.id);
    results.push({
      id: source.id,
      name: source.name,
      ...result
    });
  }
  
  return results;
}

/**
 * Simulate search on a source
 */
async function searchSource(sourceId, query, queryType) {
  const source = getSourceById(sourceId);
  if (!source) return { status: 'not_found', results: [] };
  if (!source.enabled) return { status: 'disabled', results: [] };
  
  const startTime = Date.now();
  
  try {
    // Simulate API call with realistic latency
    const baseLatency = source.avg_latency_ms || 200;
    const jitter = Math.random() * 50 - 25; // ±25ms
    const delay = Math.max(50, baseLatency + jitter);
    
    await new Promise(resolve => setTimeout(resolve, delay));
    
    // Simulate realistic result counts based on query type
    let resultCount = 0;
    switch (queryType) {
      case 'email':
        resultCount = Math.random() > 0.4 ? Math.floor(Math.random() * 50) + 1 : 0;
        break;
      case 'username':
        resultCount = Math.random() > 0.3 ? Math.floor(Math.random() * 100) + 1 : 0;
        break;
      case 'ip':
        resultCount = Math.random() > 0.5 ? Math.floor(Math.random() * 30) + 1 : 0;
        break;
      case 'domain':
        resultCount = Math.random() > 0.4 ? Math.floor(Math.random() * 40) + 1 : 0;
        break;
      default:
        resultCount = Math.floor(Math.random() * 20);
    }
    
    const latency = Date.now() - startTime;
    
    // Generate mock results
    const results = [];
    for (let i = 0; i < resultCount; i++) {
      results.push({
        id: crypto.randomBytes(4).toString('hex'),
        source: source.id,
        type: queryType,
        data: `Result ${i + 1} from ${source.name}`,
        confidence: Math.round(Math.random() * 100) + 70,
        timestamp: new Date().toISOString()
      });
    }
    
    return {
      status: 'success',
      source: source.id,
      results_count: resultCount,
      latency,
      results
    };
    
  } catch (e) {
    return {
      status: 'error',
      source: source.id,
      results: [],
      error: e.message
    };
  }
}

/**
 * Perform search across multiple sources
 */
async function searchAllSources(query, queryType) {
  const sources = getEnabledSources();
  const results = await Promise.all(
    sources.map(s => searchSource(s.id, query, queryType))
  );
  
  // Aggregate results
  const allResults = [];
  const sourceStats = [];
  
  for (const result of results) {
    if (result.status === 'success') {
      allResults.push(...(result.results || []));
      sourceStats.push({
        id: result.source,
        count: result.results_count,
        latency: result.latency
      });
    }
  }
  
  return {
    total_results: allResults.length,
    results: allResults.slice(0, 100), // Limit to 100 top results
    sources_queried: sourceStats,
    aggregated_latency: sourceStats.length > 0 
      ? Math.round(sourceStats.reduce((a, b) => a + b.latency, 0) / sourceStats.length)
      : 0
  };
}

/**
 * Get source statistics for admin
 */
function getSourcesStats() {
  const sources = getSources();
  
  const stats = {
    total: sources.length,
    enabled: sources.filter(s => s.enabled).length,
    online: sources.filter(s => s.status === 'online').length,
    degraded: sources.filter(s => s.status === 'degraded').length,
    offline: sources.filter(s => s.status === 'offline').length,
    avg_reliability: Number((sources.reduce((a, b) => a + b.reliability, 0) / sources.length).toFixed(2)),
    avg_latency: Math.round(sources.reduce((a, b) => a + b.avg_latency_ms, 0) / sources.length),
    sources: sources.map(s => ({
      id: s.id,
      name: s.name,
      type: s.type,
      enabled: s.enabled,
      status: s.status,
      reliability: s.reliability,
      avg_latency_ms: s.avg_latency_ms,
      last_check: s.last_check
    }))
  };
  
  return stats;
}

/**
 * Save sources to file
 */
function saveSources() {
  const sources = getSources();
  db.writeJSON(db.SOURCES_FILE, sources);
}

/**
 * Update source configuration
 */
function updateSource(sourceId, updates) {
  const sources = getSources();
  const source = sources.find(s => s.id === sourceId);
  
  if (source) {
    Object.assign(source, updates);
    saveSources();
    return source;
  }
  
  return null;
}

module.exports = {
  // Source management
  getSources,
  getEnabledSources,
  getSourceById,
  updateSource,
  saveSources,
  
  // Health checks
  healthCheckSource,
  healthCheckAllSources,
  
  // Searching
  searchSource,
  searchAllSources,
  
  // Statistics
  getSourcesStats
};
