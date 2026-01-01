const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const cors = require('cors');

const DATA_FILE = path.join(__dirname, 'users.json');
const LOG_FILE = path.join(__dirname, 'account_logs.json');
const PORT = process.env.PORT || 3000;

const GENERIC_LOG_FILE = path.join(__dirname, 'logs.json');
const ADMIN_CRED_FILE = path.join(__dirname, 'admin_credentials.json');

function loadUsers(){
  try{ return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')||'{}') }catch(e){ return {} }
}
function saveUsers(u){ fs.writeFileSync(DATA_FILE, JSON.stringify(u, null, 2), 'utf8') }

const app = express();
app.use(cors());
app.use(express.json());
// serve frontend static files (parent folder)
app.use(express.static(path.join(__dirname, '..')));
const adminTokens = new Set();
// user session tokens: token -> email
const userTokens = new Map();

// plan definitions
const PLANS = {
  FREE: { daily: 5, allowed: ['email'], note: 'Recherche email uniquement, bases locales' },
  BASIC: { daily: 50, allowed: ['email','username'], note: 'Email, username, bases locales étendues' },
  PRO: { daily: 1000, allowed: ['email','username','ip','domain'], note: 'Accès complet' }
};


function getIP(req){
  return req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '0.0.0.0';
}

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error: 'missing' });
  const users = loadUsers();
  const key = email.toLowerCase();
  if(users[key]) return res.status(409).json({ error: 'exists' });
  const saltRounds = 10;
  const hash = await bcrypt.hash(password, saltRounds);
  const now = new Date().toISOString();
  const ip = getIP(req);
  // default new user on FREE plan
  users[key] = { email: key, pw_hash: hash, created_at: now, created_ip: ip, logins: [], plan: 'FREE', quota_remaining: PLANS.FREE.daily, quota_reset: (new Date()).toISOString().slice(0,10) };
  saveUsers(users);

  try{
    const logs = fs.existsSync(LOG_FILE) ? JSON.parse(fs.readFileSync(LOG_FILE,'utf8')||'[]') : [];
    logs.push({ email: key, pw_hash: hash, ip, created_at: now });
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2), 'utf8');
  }catch(e){
    // fallback: append newline
    try{ fs.appendFileSync(LOG_FILE, JSON.stringify({ email: key, pw_hash: hash, ip, created_at: now }) + '\n'); }catch(e2){}
  }
  return res.json({ ok: true });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error: 'missing' });
  const users = loadUsers();
  const key = email.toLowerCase();
  const u = users[key];
  if(!u) return res.status(404).json({ error: 'not-found' });
  const ok = await bcrypt.compare(password, u.pw_hash);
  if(!ok) return res.status(401).json({ error: 'bad-credentials' });
  const now = new Date().toISOString();
  const ip = getIP(req);
  u.logins.push({ at: now, ip });
  saveUsers(users);
  // log login event
  try{
    const logs = fs.existsSync(LOG_FILE) ? JSON.parse(fs.readFileSync(LOG_FILE,'utf8')||'[]') : [];
    logs.push({ email: key, event: 'login', ip, at: now });
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2), 'utf8');
  }catch(e){}
  // Generate token for client session
  const token = Buffer.from(Math.random().toString()).toString('base64').substring(0, 32);
  userTokens.set(token, key);
  return res.json({ 
    ok: true, 
    token,
    user: { email: key, plan: u.plan, quota_remaining: u.quota_remaining, last_logins: u.logins.slice(-5) }
  });
});

// Generic logging endpoint: accept structured events and persist to logs.json
app.post('/api/logs', (req, res) => {
  const ev = req.body || {};
  if(!ev || !ev.event) return res.status(400).json({ error: 'missing_event' });
  const entry = Object.assign({}, ev, { at: new Date().toISOString(), ip: getIP(req) });
  try{
    const logs = fs.existsSync(GENERIC_LOG_FILE) ? JSON.parse(fs.readFileSync(GENERIC_LOG_FILE,'utf8')||'[]') : [];
    logs.push(entry);
    fs.writeFileSync(GENERIC_LOG_FILE, JSON.stringify(logs, null, 2), 'utf8');
    return res.json({ ok: true });
  }catch(e){
    return res.status(500).json({ error: 'write_failed' });
  }
});

// Admin login (reads local admin_credentials.json and returns a token)
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if(!username || !password) return res.status(400).json({ error: 'missing' });
  try{
    const creds = fs.existsSync(ADMIN_CRED_FILE) ? JSON.parse(fs.readFileSync(ADMIN_CRED_FILE,'utf8')||'{}') : {};
    // Log attempt (local dev only)
    console.log(`[admin-login] attempt username=${String(username)}`);
    if(creds.username === username && creds.password === password){
      const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
      adminTokens.add(token);
      console.log(`[admin-login] success username=${username}`);
      return res.json({ ok: true, token });
    }
    console.log(`[admin-login] failed username=${username}`);
    return res.status(401).json({ error: 'bad_credentials', message: 'Identifiants invalides' });
  }catch(e){
    return res.status(500).json({ error: 'server_error' });
  }
});


// current user info
app.get('/api/me', (req, res) =>{
  const hdr = req.headers.authorization || '';
  const parts = hdr.split(' ');
  const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : null;
  if(!token || !userTokens.has(token)) return res.status(401).json({ error: 'unauthorized' });
  const email = userTokens.get(token);
  const users = loadUsers();
  const u = users[email];
  if(!u) return res.status(404).json({ error: 'not-found' });
  return res.json({ ok:true, user: { email: u.email, plan: u.plan || 'FREE', quota_remaining: u.quota_remaining, quota_reset: u.quota_reset } });
});
// Fetch logs (admin only) - requires Authorization: Bearer <token>
app.get('/api/logs', (req, res) => {
  const hdr = req.headers.authorization || '';
  const parts = hdr.split(' ');
  const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : null;
  if(!token || !adminTokens.has(token)) return res.status(401).json({ error: 'unauthorized' });
  try{
    const logs = fs.existsSync(GENERIC_LOG_FILE) ? JSON.parse(fs.readFileSync(GENERIC_LOG_FILE,'utf8')||'[]') : [];
    return res.json({ ok: true, logs });
  }catch(e){
    return res.status(500).json({ error: 'read_failed' });
  }
});

// Admin: list users (sanitized)
app.get('/api/users', (req, res) => {
  const hdr = req.headers.authorization || '';
  const parts = hdr.split(' ');
  const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : null;
  if(!token || !adminTokens.has(token)) return res.status(401).json({ error: 'unauthorized' });
  try{
    const users = loadUsers();
    const list = Object.values(users).map(u=>({ email: u.email, plan: u.plan || 'FREE', created_at: u.created_at, quota_remaining: u.quota_remaining || 0, last_login: (u.logins && u.logins.length)? u.logins.slice(-1)[0] : null }));
    return res.json({ ok:true, users: list });
  }catch(e){ return res.status(500).json({ error:'read_failed' }); }
});

// perform search with plan enforcement
app.post('/api/search', (req, res) =>{
  const hdr = req.headers.authorization || '';
  const parts = hdr.split(' ');
  const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : null;
  if(!token || !userTokens.has(token)) return res.status(401).json({ error: 'unauthorized' });
  const email = userTokens.get(token);
  const users = loadUsers();
  const u = users[email];
  if(!u) return res.status(404).json({ error: 'not-found' });
  const q = (req.body && req.body.query || '').trim();
  if(!q) return res.status(400).json({ error: 'missing_query' });
  // determine type
  const isEmail = q.includes('@');
  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(q);
  const isDomain = !isEmail && q.includes('.') ;
  const isUsername = /^[a-zA-Z0-9_\-]{2,}$/.test(q) && !isEmail && !isIp && !isDomain;
  const type = isEmail ? 'email' : isIp ? 'ip' : isDomain ? 'domain' : isUsername ? 'username' : 'other';
  const plan = u.plan || 'FREE';
  const allowed = PLANS[plan].allowed;
  if(!allowed.includes(type)){
    return res.status(403).json({ error: 'forbidden', message: 'Cette recherche nécessite un plan supérieur' });
  }
  // check quota
  const today = (new Date()).toISOString().slice(0,10);
  if(!u.quota_reset || u.quota_reset !== today){ u.quota_remaining = PLANS[plan].daily; u.quota_reset = today; }
  if(u.quota_remaining <= 0) return res.status(403).json({ error: 'quota_exhausted', message: 'Quota quotidien épuisé' });
  // perform simple local DB search
  let results = [];
  try{
    const dbPath = path.join(__dirname, '..', 'db.json');
    if(fs.existsSync(dbPath)){
      const list = JSON.parse(fs.readFileSync(dbPath,'utf8')||'[]');
      const ql = q.toLowerCase();
      results = (list || []).filter(i => JSON.stringify(i).toLowerCase().includes(ql)).slice(0,50);
    }
  }catch(e){ results = []; }
  // decrement quota and save
  u.quota_remaining = (u.quota_remaining || PLANS[plan].daily) - 1;
  users[email] = u; saveUsers(users);
  // log search
  try{
    const logs = fs.existsSync(GENERIC_LOG_FILE) ? JSON.parse(fs.readFileSync(GENERIC_LOG_FILE,'utf8')||'[]') : [];
    logs.push({ email, event: 'search', query: q, type, results: results.length, at: new Date().toISOString(), ip: getIP(req) });
    fs.writeFileSync(GENERIC_LOG_FILE, JSON.stringify(logs, null, 2), 'utf8');
  }catch(e){}
  return res.json({ ok:true, results, quota_remaining: u.quota_remaining });
});

// user history
app.get('/api/history', (req, res) =>{
  const hdr = req.headers.authorization || '';
  const parts = hdr.split(' ');
  const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : null;
  if(!token || !userTokens.has(token)) return res.status(401).json({ error: 'unauthorized' });
  const email = userTokens.get(token);
  try{
    const logs = fs.existsSync(GENERIC_LOG_FILE) ? JSON.parse(fs.readFileSync(GENERIC_LOG_FILE,'utf8')||'[]') : [];
    const userLogs = logs.filter(l=> l.email === email && l.event === 'search').slice(-200).reverse();
    return res.json({ ok:true, history: userLogs });
  }catch(e){ return res.status(500).json({ error:'read_failed' }); }
});

// Simple health
app.get('/api/health', (req,res)=>res.json({ ok:true }));

// Serve site root: redirect / to the main SEEKDATA page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'seeknow.html'));
});

app.listen(PORT, ()=> console.log(`NOIRSCAN sim server running on http://localhost:${PORT}`));
