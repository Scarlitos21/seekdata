const https = require('https');
const url = require('url');

function postWebhook(webhookUrl, bodyObj) {
  try {
    const parsed = url.parse(webhookUrl);
    const data = JSON.stringify(bodyObj);
    const options = {
      hostname: parsed.hostname,
      path: parsed.path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {
      // consume response to avoid memory leak
      res.on('data', () => {});
    });
    req.on('error', (e) => { /* silent */ });
    req.write(data);
    req.end();
  } catch (e) {
    // ignore
  }
}

function logToDiscord(eventData) {
  const webhook = process.env.DISCORD_WEBHOOK_URL;
  if (!webhook) return;

  const title = eventData.title || (eventData.type || 'event');
  const contentLines = [];
  if (eventData.user_email) contentLines.push(`User: ${eventData.user_email}`);
  if (eventData.ip) contentLines.push(`IP: ${eventData.ip}`);
  if (eventData.description) contentLines.push(`${eventData.description}`);
  if (eventData.metadata) {
    try { contentLines.push(`Meta: ${JSON.stringify(eventData.metadata)}`); } catch(e){}
  }

  const body = { content: `**${title}**\n${contentLines.join('\n')}` };
  postWebhook(webhook, body);
}

module.exports = { logToDiscord };
