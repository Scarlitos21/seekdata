// Creator Panel JavaScript
(async function(){
  function extractToken(){
    const m = document.cookie.match(/token=([^;]+)/);
    if (m && m[1]) return m[1];
    const s = sessionStorage.getItem('admin_token');
    if (s) return s;
    return null;
  }

  const token = extractToken();
  if (!token) {
    document.body.innerHTML = '<div style="color:#f00;padding:40px">Token admin introuvable. Connectez-vous via le panneau <a href="/admin/">admin</a>.</div>';
    return;
  }

  async function api(path, opts={}){
    opts.headers = Object.assign({}, opts.headers || {}, { 'Authorization': 'Bearer '+token, 'Content-Type':'application/json' });
    const res = await fetch(path, opts);
    const data = await res.json();
    if (res.status === 401 || res.status === 403) {
      throw new Error(data.error || 'unauthorized_or_forbidden');
    }
    if (!res.ok) throw new Error(data.message || data.error || 'API error');
    return data;
  }

  // Notifications system
  const notifications = [];
  function addNotification(msg, type='info') {
    const id = Date.now();
    notifications.push({ id, msg, type, time: new Date().toLocaleTimeString() });
    renderNotifications();
    setTimeout(() => {
      notifications.splice(notifications.findIndex(n => n.id === id), 1);
      renderNotifications();
    }, 4000);
  }

  function renderNotifications() {
    const container = document.getElementById('notifications');
    if (!container) return;
    container.innerHTML = notifications.map(n => 
      `<div class="notif notif-${n.type}">
        <span>${n.msg}</span>
        <span class="notif-time">${n.time}</span>
      </div>`
    ).join('');
  }

  // Show Discord profile card for a given Discord ID
  window.showProfile = async (discordId) => {
    const modal = document.getElementById('profile-card-modal');
    if (!modal) return;
    modal.style.display = 'flex';

    try {
      const res = await fetch('/api/discord/' + encodeURIComponent(discordId));
      if (!res.ok) {
        addNotification('Profil non trouvé', 'error');
        modal.style.display = 'none';
        return;
      }
      const data = await res.json();
      if (!data.ok) {
        addNotification('Erreur récupération profil: ' + data.error, 'error');
        modal.style.display = 'none';
        return;
      }

      // Fill profile card
      const banner = document.getElementById('profile-banner');
      const avatar = document.getElementById('profile-avatar');
      const tag = document.getElementById('profile-tag');
      const id = document.getElementById('profile-id');
      const badges = document.getElementById('profile-badges');

      // Banner
      if (data.banner_url) {
        banner.style.backgroundImage = `url('${data.banner_url}')`;
      } else if (data.banner_color) {
        banner.style.background = data.banner_color;
      }

      // Avatar
      if (data.avatar_url) {
        avatar.src = data.avatar_url;
      }

      // Tag (username#discriminator)
      tag.innerText = data.tag || data.username || 'Utilisateur';

      // ID (hidden per user request)
      id.style.display = 'none';

      // Discord badges (public_flags)
      const badgesList = [];
      if (data.public_flags) {
        const flagMap = {
          1: '🏠 Staff',
          2: '🎮 Partner',
          4: '⭐ HypeSquad',
          8: '🌟 BugHunter',
          64: '🚀 Early Adopter',
          128: '🎓 Team User',
          256: '❤️ System',
          512: '🎨 HypeSquad Bravery',
          1024: '🎨 HypeSquad Brilliance',
          2048: '🎨 HypeSquad Balance',
          4096: '🔴 Early Verified Bot Developer',
          16384: '✅ Verified Bot',
          131072: '🌐 Active Developer'
        };
        let flags = data.public_flags;
        for (const [bit, label] of Object.entries(flagMap)) {
          if (flags & parseInt(bit)) {
            badgesList.push(`<span style="background:#1a3a1a;color:#88ff88;padding:6px 10px;border-radius:6px;font-size:0.8rem;font-weight:600;display:inline-flex;align-items:center;gap:6px">${label}</span>`);
          }
        }
      }
      badges.innerHTML = badgesList.length > 0 ? badgesList.join('') : '<span style="color:#666;font-size:0.9rem">Aucun badge</span>';
    } catch (e) {
      addNotification('Erreur: ' + e.message, 'error');
      modal.style.display = 'none';
    }
  };

  // Close profile modal
  document.getElementById('profile-close').addEventListener('click', () => {
    document.getElementById('profile-card-modal').style.display = 'none';
  });


  // Load stats
  async function loadStats() {
    try {
      const data = await api('/api/creator/stats');
      if (data.ok) {
        const s = data.stats;
        document.getElementById('stats-box').innerHTML = `
          <div class="stat-box">
            <div class="label">Utilisateurs</div>
            <div class="value">${s.total_users}</div>
          </div>
          <div class="stat-box">
            <div class="label">Recherches</div>
            <div class="value">${s.total_searches}</div>
          </div>
          <div class="stat-box">
            <div class="label">Admins</div>
            <div class="value">${s.total_admins}</div>
          </div>
          <div class="stat-box">
            <div class="label">Kill Switch</div>
            <div class="value" style="color:${s.kill_switch_active ? '#ff8888' : '#88ff88'}">${s.kill_switch_active ? 'ACTIF' : 'inactif'}</div>
          </div>
        `;
      }
    } catch (e) {
      addNotification('Erreur stats: ' + e.message, 'error');
    }
  }

  // Load admins
  async function loadAdmins() {
    try {
      const data = await api('/api/creator/admins');
      if (data.ok) {
        const admins = data.admins || [];
        if (admins.length === 0) {
          document.getElementById('admins-list').innerHTML = '<div class="muted">Aucun admin</div>';
          return;
        }
        document.getElementById('admins-list').innerHTML = admins.map(a => 
          `<div style="padding:8px;border-bottom:1px solid #111;display:flex;justify-content:space-between">
            <span>${a.email}<br><span class="muted small">${a.role}</span></span>
            <button onclick="window.deleteAdmin('${a.email}')" class="btn-ghost" style="font-size:0.8rem;padding:4px 6px">×</button>
          </div>`
        ).join('');
      }
    } catch (e) {
      addNotification('Erreur admins: ' + e.message, 'error');
    }
  }

  // Delete admin
  window.deleteAdmin = async (email) => {
    if (!confirm('Supprimer cet admin ?')) return;
    try {
      const res = await api('/api/creator/admin/' + encodeURIComponent(email), { method: 'DELETE' });
      if (res.ok) {
        addNotification('✓ Admin supprimé', 'success');
        await refresh();
      }
    } catch (e) {
      addNotification('Erreur: ' + e.message, 'error');
    }
  };

  // Load audit logs - from /api/creator/logs
  async function loadLogs() {
    try {
      const data = await api('/api/creator/logs?limit=50');
      const logs = data.logs || [];
      if (logs.length === 0) {
        document.getElementById('audit-list').innerHTML = '<div class="muted">Aucun événement</div>';
        return;
      }
      document.getElementById('audit-list').innerHTML = logs.reverse().map(l => {
        const isCritical = l.type && (l.type.includes('kill') || l.type.includes('deleted'));
        const badge = l.type ? `<span class="log-badge">${l.type.replace(/_/g, ' ')}</span>` : '';
        const actor = l.actor ? `<span class="log-actor">${l.actor}</span>` : '';
        return `<div class="log-entry ${isCritical ? 'critical' : ''}">
          <div class="log-header">
            ${badge} ${actor}
            <span class="log-time">${new Date(l.timestamp).toLocaleTimeString()}</span>
          </div>
          ${l.action ? `<div class="log-action">${l.action}</div>` : ''}
        </div>`;
      }).join('');
    } catch (e) {
      addNotification('Erreur logs: ' + e.message, 'error');
    }
  }

  // Load team members with Discord avatars
  async function loadTeam() {
    try {
      const data = await api('/api/creator/team');
      const list = data.team || [];
      if (list.length === 0) {
        document.getElementById('team-list').innerHTML = '<div class="muted" style="padding:20px;text-align:center">Aucun membre d\'équipe</div>';
        return;
      }
      document.getElementById('team-list').innerHTML = list.map(t => {
        const avatar = t.avatar_url 
          ? `<img src="${t.avatar_url}" alt="${t.pseudo}" class="team-avatar" onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 80 80%22%3E%3Crect fill=%22%23222%22 width=%2280%22 height=%2280%22/%3E%3Ctext x=%2240%22 y=%2245%22 font-size=%2240%22 fill=%22%23666%22 text-anchor=%22middle%22 dominant-baseline=%22central%22%3E—%3C/text%3E%3C/svg%3E'">` 
          : `<div class="team-avatar-empty">?</div>`;
        const badges = Array.isArray(t.badges) ? t.badges : [];
        const badgesHTML = badges.length ? `<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">${badges.map((b,i)=>`<span class="badge badge-creator" style="padding:6px 10px;font-weight:800;font-size:0.85rem;display:inline-flex;align-items:center;gap:8px;border-radius:8px;border:1px solid #fff;color:#fff">${b.icon?`<img src="${b.icon}" style="width:18px;height:18px;filter:invert(1)">`:''}<span>${b.text}</span><button onclick="window.removeBadge('${t.id}',${i})" style="margin-left:8px;background:transparent;border:none;color:#ff8888;cursor:pointer">×</button></span>`).join('')}</div>` : '';

        return `<div class="team-card">
          ${avatar}
          <div class="team-info">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <div>
                <div class="team-pseudo">${t.pseudo}</div>
                ${t.title ? `<div class="team-title">${t.title}</div>` : ''}
                <div class="team-discord">🎮 ${t.discord_id}</div>
                ${badgesHTML}
              </div>
              <div style="display:flex;flex-direction:column;gap:6px">
                <button onclick="window.refreshMember('${t.id}')" class="btn-ghost" style="padding:6px 10px;font-size:0.85rem">↻ Rafraîchir déco</button>
                <button onclick="window.showProfile('${t.discord_id}')" class="btn-ghost" style="padding:6px 10px;font-size:0.85rem">👤 Profil</button>
                <button onclick="window.addBadge('${t.id}')" class="btn-ghost" style="padding:6px 10px;font-size:0.85rem">＋ Badge</button>
              </div>
            </div>
          </div>
          <div class="team-actions">
            <button onclick="window.deleteTeam('${t.id}')" class="btn-delete" title="Supprimer ce membre">Supprimer</button>
          </div>
        </div>`;
      }).join('');
    } catch (e) {
      addNotification('Erreur équipe: ' + e.message, 'error');
    }
  }
  
  // Delete team member
  window.deleteTeam = async (id) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce membre ?')) return;
    try {
      const res = await api('/api/creator/team/' + encodeURIComponent(id), { method: 'DELETE' });
      addNotification('Membre supprimé ✓', 'success');
      await loadTeam();
    } catch (e) {
      addNotification('Erreur suppression: ' + e.message, 'error');
    }
  }

  // Create team member with Discord API
  window.addTeamMember = async () => {
    try {
      const pseudo = prompt('Pseudo (obligatoire)');
      if (!pseudo) return;
      const discord_id = prompt('Discord ID (obligatoire - ex: 123456789)');
      if (!discord_id) return;
      const title = prompt('Titre (optionnel - ex: Owner, Admin)') || null;

      const payload = { pseudo, discord_id };
      if (title) payload.title = title;

      const res = await api('/api/creator/team', { method: 'POST', body: JSON.stringify(payload) });
      if (res.ok) {
        addNotification(`✓ Membre ${pseudo} ajouté (Avatar Discord chargé)`, 'success');
        await refresh();
      }
    } catch (e) {
      addNotification('Erreur création: ' + e.message, 'error');
    }
  };

  // Add badge to a team member (creator-only)
  // Helper to show badge picker modal and return selected filename or null/empty
  function niceLabelFromFilename(fname) {
    if (!fname) return '';
    const base = fname.replace(/\.[^.]+$/, '');
    return base.replace(/[-_]/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
  }

  function showBadgePicker() {
    return new Promise(async (resolve) => {
      const modal = document.getElementById('badge-picker');
      const container = document.getElementById('badge-options');
      const input = document.getElementById('badge-text');
      if (!modal || !container || !input) return resolve(null);
      modal.style.display = 'flex';
      container.innerHTML = 'Chargement...';
      input.value = '';
      const cleanup = () => {
        modal.style.display = 'none';
        container.innerHTML = '';
        input.value = '';
      };

      try {
        const res = await fetch('/api/assets/badges');
        const j = await res.json();
        const badges = (j && Array.isArray(j.badges)) ? j.badges : [];
        if (badges.length === 0) {
          container.innerHTML = '<div class="muted">Aucune icône disponible dans assets/</div>';
        } else {
          container.innerHTML = '';
          badges.forEach(fname => {
            const btn = document.createElement('button');
            btn.className = 'badge-option';
            btn.setAttribute('data-file', fname);
            btn.style.cssText = 'background:#111;border:1px solid #333;padding:8px;border-radius:8px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:6px;width:96px;height:96px';
            const img = document.createElement('img');
            img.src = '/assets/' + fname;
            img.style.width = '48px'; img.style.height = '48px'; img.style.display = 'block';
            img.onerror = () => { img.style.display = 'none'; };
            const lbl = document.createElement('div');
            lbl.style.fontSize = '0.85rem'; lbl.style.color = '#ddd'; lbl.style.textAlign = 'center'; lbl.style.maxWidth = '86px';
            lbl.innerText = niceLabelFromFilename(fname);
            btn.appendChild(img);
            btn.appendChild(lbl);
            btn.onclick = () => {
              const textVal = (input.value || '').trim() || niceLabelFromFilename(fname);
              cleanup();
              resolve({ file: fname, text: textVal });
            };
            container.appendChild(btn);
          });
        }
      } catch (e) {
        container.innerHTML = '<div class="muted">Erreur lors du chargement des icônes</div>';
      }

      document.getElementById('badge-none').onclick = () => { const t = (input.value||'').trim(); cleanup(); resolve({ file: '', text: t || null }); };
      document.getElementById('badge-cancel').onclick = () => { cleanup(); resolve(null); };
    });
  }

  window.addBadge = async (id) => {
    try {
      const result = await showBadgePicker();
      if (!result) return; // cancelled
      const iconFilename = result.file || '';
      const text = (result.text || '').trim();
      if (!text) return addNotification('Texte du badge requis', 'error');

      const iconPath = iconFilename ? `assets/${iconFilename}` : null;
      // fetch current team
      const data = await api('/api/creator/team');
      const team = data.team || [];
      const member = team.find(m=>m.id===id);
      if (!member) return addNotification('Membre introuvable', 'error');
      const badges = Array.isArray(member.badges) ? member.badges.slice() : [];
      const newBadge = { text: text, icon: iconPath };
      badges.push(newBadge);
      await api('/api/creator/team/' + encodeURIComponent(id), { method: 'PUT', body: JSON.stringify({ badges }) });
      addNotification('Badge ajouté ✓', 'success');
      await loadTeam();
    } catch (e) {
      addNotification('Erreur ajout badge: ' + e.message, 'error');
    }
  };

  // Remove badge from member
  window.removeBadge = async (id, index) => {
    if (!confirm('Supprimer ce badge ?')) return;
    try {
      const data = await api('/api/creator/team');
      const team = data.team || [];
      const member = team.find(m=>m.id===id);
      if (!member) return addNotification('Membre introuvable', 'error');
      const badges = Array.isArray(member.badges) ? member.badges.slice() : [];
      if (index < 0 || index >= badges.length) return addNotification('Index invalide', 'error');
      badges.splice(index,1);
      await api('/api/creator/team/' + encodeURIComponent(id), { method: 'PUT', body: JSON.stringify({ badges }) });
      addNotification('Badge supprimé ✓', 'success');
      await loadTeam();
    } catch (e) {
      addNotification('Erreur suppression badge: ' + e.message, 'error');
    }
  };

  // Refresh avatar/banner for member by calling server refresh endpoint
  window.refreshMember = async (id) => {
    try {
      const res = await api('/api/creator/team/' + encodeURIComponent(id) + '/refresh', { method: 'POST' });
      if (res.ok) {
        addNotification('Décorations rafraîchies ✓', 'success');
        await loadTeam();
      }
    } catch (e) {
      addNotification('Erreur rafraîchissement: ' + e.message, 'error');
    }
  };

  // Delete team member
  window.deleteTeam = async (id) => {
    if (!confirm('Supprimer ce membre de l\'équipe ?')) return;
    try {
      const res = await api('/api/creator/team/' + encodeURIComponent(id), { method: 'DELETE' });
      if (res.ok) {
        addNotification('✓ Membre supprimé', 'success');
        await refresh();
      }
    } catch (e) {
      addNotification('Erreur suppression: ' + e.message, 'error');
    }
  };

  // Refresh all
  async function refresh() {
    await Promise.all([loadStats(), loadLogs(), loadTeam(), loadAdmins()]);
  }

  // Kill switch
  document.getElementById('btn-kill-switch').addEventListener('click', async () => {
    if (!confirm('Activer le Kill Switch ?\nCela stoppera toutes les recherches.')) return;
    try {
      const res = await api('/api/creator/kill-switch', {
        method: 'POST',
        body: JSON.stringify({ reason: 'Manual activation from creator panel' })
      });
      if (res.ok) {
        addNotification('🔴 Kill Switch ACTIVÉ', 'critical');
        await refresh();
      }
    } catch (e) {
      addNotification('Erreur kill-switch: ' + e.message, 'error');
    }
  });

  // Disable kill switch
  document.getElementById('btn-disable-kill').addEventListener('click', async () => {
    try {
      const res = await api('/api/creator/kill-switch/disable', { method: 'POST' });
      if (res.ok) {
        addNotification('✓ Kill Switch désactivé', 'success');
        await refresh();
      }
    } catch (e) {
      addNotification('Erreur: ' + e.message, 'error');
    }
  });

  // DB Backup
  document.getElementById('btn-db-backup').addEventListener('click', async () => {
    try {
      const res = await api('/api/creator/backup', { method: 'POST' });
      if (res.ok) addNotification('💾 Backup créé: ' + res.backup_id, 'success');
    } catch (e) {
      addNotification('Erreur backup: ' + e.message, 'error');
    }
  });

  // Refresh button
  document.getElementById('btn-refresh').addEventListener('click', refresh);

  // New team member button
  document.getElementById('btn-new-team').addEventListener('click', window.addTeamMember);

  // Logout
  document.getElementById('btn-logout').addEventListener('click', () => {
    document.cookie = 'token=; Max-Age=0; path=/';
    location.href = '/admin/';
  });

  // Initial load
  renderNotifications();
  refresh();
  setInterval(refresh, 15000); // Auto-refresh every 15s
})();
