const http = require('http');

function makeRequest(method, path, body) {
  return new Promise((resolve) => {
    const opts = {
      hostname: 'localhost',
      port: 3000,
      path,
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch(e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', (err) => {
      resolve({ status: 0, error: err.message });
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function test() {
  console.log('\n=== Testing Registration & Login ===\n');

  // Test registration
  console.log('1. Registering test@example.com...');
  const regRes = await makeRequest('POST', '/api/register', {
    email: 'test@example.com',
    password: 'Test1234',
    password_confirm: 'Test1234'
  });
  console.log(`   Status: ${regRes.status}`);
  console.log(`   Response:`, regRes.body);

  // Test login
  console.log('\n2. Logging in as test@example.com...');
  const loginRes = await makeRequest('POST', '/api/login', {
    email: 'test@example.com',
    password: 'Test1234'
  });
  console.log(`   Status: ${loginRes.status}`);
  console.log(`   Response:`, loginRes.body);

  process.exit(0);
}

test().catch(console.error);
