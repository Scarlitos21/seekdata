const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

async function initAdmin() {
  const usersFile = path.join(__dirname, 'users.json');
  
  // Generate hash for "admin"
  const hash = await bcrypt.hash('admin', 10);
  console.log('Generated password hash:', hash);
  
  const admin = {
    "admin": {
      "id": "admin-001",
      "email": "admin",
      "password_hash": hash,
      "role": "admin",
      "plan": "ENTERPRISE",
      "quota_used": 0,
      "quota_limit": 50000,
      "created_at": new Date().toISOString(),
      "last_login": null,
      "ip_last": null,
      "country": null,
      "status": "active",
      "logins": [],
      "failed_login_attempts": 0,
      "locked_until": null,
      "email_verified": true,
      "api_keys": [],
      "settings": {
        "language": "fr",
        "notifications": true
      },
      "is_admin": true,
      "risk_score": 0
    }
  };
  
  // Write to file
  fs.writeFileSync(usersFile, JSON.stringify(admin, null, 2), 'utf8');
  console.log('✓ Admin account created in users.json');
  console.log('Credentials: admin / admin');
  
  // Verify the hash works
  const test = await bcrypt.compare('admin', hash);
  console.log('Password verification:', test ? '✓ WORKS' : '✗ FAILED');
}

initAdmin().catch(console.error);
