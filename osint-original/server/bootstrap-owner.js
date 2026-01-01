const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

async function run() {
  const usersFile = path.join(__dirname, 'users.json');
  let users = {};
  try {
    users = JSON.parse(fs.readFileSync(usersFile, 'utf8')) || {};
  } catch (e) {
    users = {};
  }

  const anyAdmin = Object.values(users).some(u => u.is_admin || u.role === 'creator' || u.role === 'admin');
  if (anyAdmin) {
    console.log('Admin already exists; aborting bootstrap.');
    return;
  }

  const email = 'admin';
  const password = 'admin';
  const now = new Date().toISOString();
  const id = (crypto.randomUUID) ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  const hash = await bcrypt.hash(password, 10);

  users[email] = {
    id,
    email,
    password_hash: hash,
    role: 'creator',
    plan: 'free',
    quota_used: 0,
    quota_limit: 50,
    created_at: now,
    last_login: null,
    ip_last: null,
    country: null,
    status: 'active',
    logins: [],
    is_admin: true
  };

  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), 'utf8');
  console.log('Bootstrap creator created:', email);
}

run().catch(e=>{ console.error('Error creating bootstrap owner:', e); process.exit(1); });
