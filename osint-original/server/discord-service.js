/**
 * Discord Service
 * Fetches user avatar and banner from Discord API (public data)
 */

const https = require('https');

const DISCORD_API_BASE = 'https://discord.com/api/v10';

/**
 * Fetch Discord user public data (avatar + banner)
 * Uses Discord API public endpoint - no auth token required
 */
async function getDiscordUserData(userId) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'discord.com',
      path: `/api/v10/users/${userId}`,
      method: 'GET',
      headers: {
        'User-Agent': 'SeekData/1.0'
      },
      timeout: 5000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const user = JSON.parse(data);
            const avatar_url = user.avatar 
              ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.webp?size=1024`
              : `https://cdn.discordapp.com/embed/avatars/${(parseInt(user.discriminator) || 0) % 5}.png`;
            const banner_url = user.banner
              ? `https://cdn.discordapp.com/banners/${user.id}/${user.banner}.webp?size=1024`
              : null;
            resolve({ avatar_url, banner_url, success: true });
          } else {
            // Fallback: generate default Discord avatar URL
            const defaultAvatar = `https://cdn.discordapp.com/embed/avatars/${(parseInt(userId) % 5)}.png`;
            resolve({ avatar_url: defaultAvatar, banner_url: null, success: false });
          }
        } catch (e) {
          // Fallback on parse error
          const defaultAvatar = `https://cdn.discordapp.com/embed/avatars/${(parseInt(userId) % 5)}.png`;
          resolve({ avatar_url: defaultAvatar, banner_url: null, success: false });
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      const defaultAvatar = `https://cdn.discordapp.com/embed/avatars/${(parseInt(userId) % 5)}.png`;
      resolve({ avatar_url: defaultAvatar, banner_url: null, success: false });
    });

    req.on('error', () => {
      const defaultAvatar = `https://cdn.discordapp.com/embed/avatars/${(parseInt(userId) % 5)}.png`;
      resolve({ avatar_url: defaultAvatar, banner_url: null, success: false });
    });

    req.end();
  });
}

module.exports = {
  getDiscordUserData
};
