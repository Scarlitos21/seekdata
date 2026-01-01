const bcrypt = require('bcrypt');

async function test() {
  const password = 'admin';
  const hash = await bcrypt.hash(password, 10);
  console.log('Generated hash:', hash);
  
  // Test it
  const valid = await bcrypt.compare(password, hash);
  console.log('Hash verification:', valid ? 'VALID ✓' : 'INVALID ✗');
}

test();
