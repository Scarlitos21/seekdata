const fs = require('fs');
const path = require('path');

const LOG_PATH = path.join(__dirname, 'immutable-logs.ndjson');

function writeEvent(event) {
  try {
    const line = JSON.stringify(Object.assign({ timestamp: new Date().toISOString() }, event));
    fs.appendFileSync(LOG_PATH, line + '\n', { encoding: 'utf8', mode: 0o600 });
    return true;
  } catch (e) {
    console.error('immutable-logger write error', e && e.message);
    return false;
  }
}

function readEvents(opts = {}) {
  try {
    if (!fs.existsSync(LOG_PATH)) return [];
    const content = fs.readFileSync(LOG_PATH, 'utf8');
    const lines = content.split('\n').filter(l => l.trim());
    const items = lines.map(l => {
      try { return JSON.parse(l); } catch (e) { return null; }
    }).filter(Boolean);
    const offset = opts.offset || 0;
    const limit = opts.limit || 100;
    return items.slice(offset, offset + limit);
  } catch (e) {
    console.error('immutable-logger read error', e && e.message);
    return [];
  }
}

module.exports = {
  writeEvent,
  readEvents,
  LOG_PATH
};
