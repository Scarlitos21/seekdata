const bcrypt = require('bcrypt');

async function generateHash() {
  const hash = await bcrypt.hash('admin', 10);
  console.log('Hash for "admin":', hash);
}

generateHash();
