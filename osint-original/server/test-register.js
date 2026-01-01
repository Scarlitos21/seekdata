const http = require('http');

const opts = {
  hostname: 'localhost',
  port: 3000,
  path: '/api/register',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
};

const req = http.request(opts, (res) => {
  let data = '';
  res.on('data', (chunk) => data += chunk);
  res.on('end', () => {
    console.log('Status:', res.statusCode);
    console.log('Response:', data);
    process.exit(0);
  });
});

req.on('error', (err) => {
  console.error('Error:', err.message);
  process.exit(1);
});

const body = JSON.stringify({
  email: 'testuser50@test.com',
  password: 'Test1234',
  password_confirm: 'Test1234'
});

console.log('Sending registration request...');
req.write(body);
req.end();
