#!/usr/bin/env node

/**
 * SeekData Admin Panel - API Test Suite
 * Validates all admin endpoints are functioning correctly
 */

const http = require('http');

const ADMIN_EMAIL = 'admin';
const ADMIN_PASSWORD = 'admin';
const API_BASE = 'http://localhost:3000';

let adminToken = null;

// Test results
const results = {
  passed: [],
  failed: []
};

// HTTP request helper
async function makeRequest(method, path, body = null, token = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_BASE);
    const options = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    if (token) {
      options.headers['Authorization'] = `Bearer ${token}`;
    }

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const response = {
            status: res.statusCode,
            body: data ? JSON.parse(data) : null
          };
          resolve(response);
        } catch (e) {
          resolve({
            status: res.statusCode,
            body: data
          });
        }
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(JSON.stringify(body));
    }

    req.end();
  });
}

// Test runner
async function test(name, fn) {
  try {
    await fn();
    results.passed.push(name);
    console.log(`✓ ${name}`);
  } catch (error) {
    results.failed.push({ name, error: error.message });
    console.log(`✗ ${name}: ${error.message}`);
  }
}

// Run tests
async function runTests() {
  console.log(`
╔════════════════════════════════════════╗
║   SeekData Admin API Test Suite        ║
║                                        ║
║  Testing all endpoints for admin panel ║
╚════════════════════════════════════════╝
`);

  // Test 1: Admin Login
  await test('Admin Login', async () => {
    const response = await makeRequest('POST', '/api/admin/login', {
      email: ADMIN_EMAIL,
      password: ADMIN_PASSWORD
    });

    if (response.status !== 200 || !response.body.token) {
      throw new Error(`Expected 200 with token, got ${response.status}`);
    }

    adminToken = response.body.token;
  });

  // Test 2: Get Stats
  await test('GET /api/admin/stats', async () => {
    const response = await makeRequest('GET', '/api/admin/stats', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!response.body.total_users) throw new Error('Missing total_users in response');
  });

  // Test 3: List Users
  await test('GET /api/admin/users', async () => {
    const response = await makeRequest('GET', '/api/admin/users', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!Array.isArray(response.body.users)) throw new Error('Expected array of users');
  });

  // Test 4: List Searches
  await test('GET /api/admin/searches', async () => {
    const response = await makeRequest('GET', '/api/admin/searches', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!Array.isArray(response.body.searches)) throw new Error('Expected array of searches');
  });

  // Test 5: Get Subscriptions
  await test('GET /api/admin/subscriptions', async () => {
    const response = await makeRequest('GET', '/api/admin/subscriptions', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (response.body.total === undefined) throw new Error('Missing total in response');
  });

  // Test 6: Get Blacklist
  await test('GET /api/admin/blacklist', async () => {
    const response = await makeRequest('GET', '/api/admin/blacklist', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!Array.isArray(response.body.list)) throw new Error('Expected array of blacklist entries');
  });

  // Test 7: Add Blacklist Entry
  await test('POST /api/admin/blacklist', async () => {
    const response = await makeRequest('POST', '/api/admin/blacklist', {
      type: 'ip',
      value: '192.168.1.1',
      reason: 'Test entry'
    }, adminToken);
    if (response.status !== 201) throw new Error(`Expected 201, got ${response.status}`);
    if (!response.body.entry) throw new Error('Missing entry in response');
  });

  // Test 8: Get Whitelist
  await test('GET /api/admin/whitelist', async () => {
    const response = await makeRequest('GET', '/api/admin/whitelist', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!Array.isArray(response.body.list)) throw new Error('Expected array of whitelist entries');
  });

  // Test 9: Get Logs
  await test('GET /api/admin/logs', async () => {
    const response = await makeRequest('GET', '/api/admin/logs', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!Array.isArray(response.body.logs)) throw new Error('Expected array of logs');
  });

  // Test 10: Get Alerts
  await test('GET /api/admin/alerts', async () => {
    const response = await makeRequest('GET', '/api/admin/alerts', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!Array.isArray(response.body.alerts)) throw new Error('Expected array of alerts');
  });

  // Test 11: Get Sources
  await test('GET /api/admin/sources', async () => {
    const response = await makeRequest('GET', '/api/admin/sources', null, adminToken);
    if (response.status !== 200) throw new Error(`Expected 200, got ${response.status}`);
    if (!Array.isArray(response.body.sources)) throw new Error('Expected array of sources');
  });

  // Test 12: Unauthorized access (no token)
  await test('Unauthorized Access (no token)', async () => {
    const response = await makeRequest('GET', '/api/admin/stats', null, null);
    if (response.status !== 401) throw new Error(`Expected 401, got ${response.status}`);
  });

  // Test 13: Invalid login
  await test('Invalid Login (bad password)', async () => {
    const response = await makeRequest('POST', '/api/admin/login', {
      email: ADMIN_EMAIL,
      password: 'wrongpassword'
    });
    if (response.status !== 401) throw new Error(`Expected 401, got ${response.status}`);
  });

  // Results
  console.log(`
╔════════════════════════════════════════╗
║         Test Results                   ║
╚════════════════════════════════════════╝

✓ PASSED: ${results.passed.length}
✗ FAILED: ${results.failed.length}

Tests Passed:
${results.passed.map(t => `  ✓ ${t}`).join('\n')}

${results.failed.length > 0 ? `\nTests Failed:\n${results.failed.map(t => `  ✗ ${t.name}: ${t.error}`).join('\n')}` : ''}

${results.failed.length === 0 ? '🎉 ALL TESTS PASSED!' : '❌ Some tests failed'}
`);

  process.exit(results.failed.length > 0 ? 1 : 0);
}

// Run
runTests().catch(console.error);
