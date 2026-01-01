class AdminPanel {
  constructor() {
    this.token = sessionStorage.getItem('admin_token');
    this.user = sessionStorage.getItem('admin_user');
    this.apiBase = window.API_URL || 'https://seekdata-backend.onrender.com';
    this.init();
  }

  api(path, options = {}) {
    // Helper to build full API URL
    const url = this.apiBase + path;
    return fetch(url, options);
  }

  init() {
    this.checkAuth();
    this.setupNavigation();
    this.updateClock();
    setInterval(() => this.updateClock(), 1000);
    
    if (this.token) {
      this.loadOverview();
      this.setupEventListeners();
    }
  }

  checkAuth() {
    const authWall = document.getElementById('auth-wall');
    const adminPanel = document.getElementById('admin-panel');

    if (!this.token || !this.user) {
      authWall.classList.remove('hidden');
      adminPanel.classList.add('hidden');
      this.setupLoginForm();
      return;
    }

    authWall.classList.add('hidden');
    adminPanel.classList.remove('hidden');
    
    try {
      const userData = JSON.parse(this.user);
      document.getElementById('admin-email').textContent = userData.email;
    } catch (e) {
      //
    }
  }

  setupLoginForm() {
    const form = document.getElementById('login-form');
    const errorDiv = document.getElementById('auth-error');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const email = document.getElementById('email-input').value;
      const password = document.getElementById('password-input').value;

      try {
        const response = await this.api('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok && data.token) {
          sessionStorage.setItem('admin_token', data.token);
          sessionStorage.setItem('admin_user', JSON.stringify(data.user));
          window.location.reload();
        } else {
          errorDiv.textContent = data.error || 'Authentification échouée';
          errorDiv.classList.add('show');
        }
      } catch (err) {
        errorDiv.textContent = 'Erreur serveur';
        errorDiv.classList.add('show');
      }
    });
  }

  setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(btn => {
      btn.addEventListener('click', () => {
        const section = btn.dataset.section;
        this.switchSection(section);
      });
    });

    document.getElementById('logout-btn').addEventListener('click', () => {
      sessionStorage.clear();
      window.location.reload();
    });
  }

  switchSection(section) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

    // Show selected section
    const sectionEl = document.getElementById('section-' + section);
    if (sectionEl) sectionEl.classList.add('active');

    // Mark nav button as active
    document.querySelector(`[data-section="${section}"]`).classList.add('active');

    // Update title
    const titles = {
      overview: 'Overview',
      users: 'Gestion Utilisateurs',
      searches: 'Recherches',
      subscriptions: 'Abonnements',
      blacklist: 'Blacklist',
      whitelist: 'Whitelist',
      logs: 'Logs & Audit',
      apis: 'APIs & Sources',
      settings: 'Paramètres Système'
    };
    document.getElementById('section-title').textContent = titles[section] || section;

    // Load data
    switch (section) {
      case 'overview': this.loadOverview(); break;
      case 'users': this.loadUsers(); break;
      case 'searches': this.loadSearches(); break;
      case 'subscriptions': this.loadSubscriptions(); break;
      case 'blacklist': this.loadBlacklist(); break;
      case 'whitelist': this.loadWhitelist(); break;
      case 'logs': this.loadLogs(); break;
      case 'apis': this.loadAPIs(); break;
      case 'settings': this.loadSettings(); break;
      case 'patches': this.loadPatchNotes(); break;
      case 'team': this.loadTeam(); break;
    }
  }

  setupEventListeners() {
    // Users filters
    document.getElementById('users-search').addEventListener('input', () => this.loadUsers());
    document.getElementById('users-status-filter').addEventListener('change', () => this.loadUsers());

    // Searches filters
    document.getElementById('searches-email-filter').addEventListener('input', () => this.loadSearches());
    document.getElementById('searches-type-filter').addEventListener('change', () => this.loadSearches());

    // Subscriptions filter
    document.getElementById('subscriptions-plan-filter').addEventListener('change', () => this.loadSubscriptions());

    // Logs filters
    document.getElementById('logs-type-filter').addEventListener('change', () => this.loadLogs());
    document.getElementById('logs-severity-filter').addEventListener('change', () => this.loadLogs());
  }

  async makeRequest(method, url, body = null) {
    const options = {
      method,
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      }
    };

    if (body) options.body = JSON.stringify(body);

    const fullUrl = (typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'))) ? url : (this.apiBase + url);
    const response = await fetch(fullUrl, options);
    if (response.status === 401) {
      sessionStorage.clear();
      window.location.reload();
    }
    return response;
  }

  async loadOverview() {
    try {
      const res = await this.makeRequest('GET', '/api/admin/stats');
      const stats = await res.json();

      if (stats.ok || stats.total_users !== undefined) {
        document.getElementById('stat-total-users').textContent = stats.total_users || 0;
        document.getElementById('stat-active-today').textContent = stats.active_today || 0;
        document.getElementById('stat-searches-24h').textContent = stats.searches_24h || 0;
        document.getElementById('stat-security-alerts').textContent = stats.security_alerts || 0;
      }

      // Load recent activity
      const logsRes = await this.makeRequest('GET', '/api/admin/logs?limit=5');
      const logs = await logsRes.json();
      
      const activityList = document.getElementById('recent-activity');
      if (Array.isArray(logs)) {
        activityList.innerHTML = logs.map(log => `
          <div class="activity-item">
            <strong>${log.type}</strong> - ${log.description}
            <br><code>${new Date(log.timestamp).toLocaleString('fr-FR')}</code>
          </div>
        `).join('');
      }
    } catch (err) {
      console.error('Overview error:', err);
    }
  }

  async loadUsers() {
    try {
      const search = document.getElementById('users-search').value;
      const status = document.getElementById('users-status-filter').value;
      
      let url = '/api/admin/users?';
      if (search) url += `search=${encodeURIComponent(search)}&`;
      if (status) url += `status=${status}`;

      const res = await this.makeRequest('GET', url);
      const users = await res.json();

      const tbody = document.getElementById('users-tbody');
      if (!Array.isArray(users) || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">Aucun utilisateur</td></tr>';
        return;
      }

      tbody.innerHTML = users.map(u => `
        <tr>
          <td>${u.email}</td>
          <td>${u.plan || 'FREE'}</td>
          <td><code>${u.ip_created || 'N/A'}</code></td>
          <td>${u.last_login ? new Date(u.last_login).toLocaleString('fr-FR') : 'Jamais'}</td>
          <td>${u.status || 'active'}</td>
          <td>
            <div style="display:flex; gap:5px;">
              ${u.status === 'active' ? `<button class="action-btn danger" onclick="admin.blockUser('${u.id}')">Bloquer</button>` : `<button class="action-btn" onclick="admin.unblockUser('${u.id}')">Débloquer</button>`}
              <button class="action-btn danger" onclick="admin.banUser('${u.id}')">Bannir</button>
            </div>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Users error:', err);
    }
  }

  async loadSearches() {
    try {
      const email = document.getElementById('searches-email-filter').value;
      const type = document.getElementById('searches-type-filter').value;
      
      let url = '/api/admin/searches?';
      if (email) url += `email=${encodeURIComponent(email)}&`;
      if (type) url += `type=${type}`;

      const res = await this.makeRequest('GET', url);
      const searches = await res.json();

      const tbody = document.getElementById('searches-tbody');
      if (!Array.isArray(searches) || searches.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">Aucune recherche</td></tr>';
        return;
      }

      tbody.innerHTML = searches.map(s => `
        <tr>
          <td>${s.user_email}</td>
          <td><code>${s.query || ''}</code></td>
          <td>${s.query_type || 'N/A'}</td>
          <td>${s.source || 'N/A'}</td>
          <td>${new Date(s.created_at).toLocaleString('fr-FR')}</td>
          <td>
            <button class="action-btn" onclick="admin.blockSearch('${s.id}')">Bloquer</button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Searches error:', err);
    }
  }

  async loadSubscriptions() {
    try {
      const plan = document.getElementById('subscriptions-plan-filter').value;
      
      let url = '/api/admin/users?';
      if (plan) url += `plan=${plan}`;

      const res = await this.makeRequest('GET', url);
      const users = await res.json();

      const tbody = document.getElementById('subscriptions-tbody');
      if (!Array.isArray(users) || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">Aucun utilisateur</td></tr>';
        return;
      }

      tbody.innerHTML = users.map(u => `
        <tr>
          <td>${u.email}</td>
          <td>${u.plan || 'FREE'}</td>
          <td>${u.created_at ? new Date(u.created_at).toLocaleDateString('fr-FR') : 'N/A'}</td>
          <td>N/A</td>
          <td>${u.quota_used || 0} / ${u.quota_limit || 'Illimité'}</td>
          <td>
            <button class="action-btn" onclick="admin.changePlan('${u.id}')">Modifier</button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Subscriptions error:', err);
    }
  }

  async loadBlacklist() {
    try {
      const res = await this.makeRequest('GET', '/api/admin/blacklist');
      const data = await res.json();
      const items = (data && data.list) ? data.list : (Array.isArray(data) ? data : []);

      const container = document.getElementById('blacklist-items');
      if (!Array.isArray(items) || items.length === 0) {
        container.innerHTML = '<div style="color:#888; text-align:center; padding:30px;">Aucune entrée</div>';
      } else {
        container.innerHTML = items.map(item => `
        <div class="item-row">
          <div class="item-info">
            <div class="item-type">${item.type}</div>
            <div class="item-value">${item.value}</div>
          </div>
          <div class="item-actions">
            <button class="action-btn danger" onclick="admin.removeFromBlacklist('${item.id}')">Supprimer</button>
          </div>
        </div>
      `).join('');
      }

      // Load immutable blacklist logs as well
      this.loadBlacklistLogs();
    } catch (err) {
      console.error('Blacklist error:', err);
    }
  }

  async loadBlacklistLogs() {
    try {
      const res = await this.makeRequest('GET', '/api/admin/blacklist-logs?limit=200');
      const data = await res.json();
      const rows = (data && data.logs) ? data.logs : [];
      const tbody = document.getElementById('blacklist-logs-tbody');
      if (!Array.isArray(rows) || rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5">Aucun log de blacklist</td></tr>';
        return;
      }

      tbody.innerHTML = rows.map(r => `
        <tr>
          <td>${r.timestamp ? new Date(r.timestamp).toLocaleString('fr-FR') : ''}</td>
          <td>${r.type || ''}</td>
          <td><code>${r.block_type ? r.block_type+': '+(r.value||'') : (r.value||JSON.stringify(r))}</code></td>
          <td>${r.ip || ''}</td>
          <td>${r.user_email || r.added_by || r.removed_by || ''}</td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Blacklist logs error:', err);
    }
  }

  async addToBlacklist() {
    try {
      const type = document.getElementById('blacklist-type-input').value;
      const value = document.getElementById('blacklist-value-input').value.trim();
      if (!value) return alert('Veuillez saisir une valeur');
      const res = await this.makeRequest('POST', '/api/admin/blacklist', { type, value });
      const data = await res.json();
      if (res.ok) {
        this.loadBlacklist();
        document.getElementById('blacklist-value-input').value = '';
      } else {
        alert(data.error || 'Erreur');
      }
    } catch (err) {
      console.error('Add blacklist error:', err);
    }
  }

  async removeFromBlacklist(entryId) {
    if (!confirm('Supprimer cette entrée de la blacklist ?')) return;
    try {
      const res = await this.makeRequest('DELETE', `/api/admin/blacklist/${entryId}`);
      if (res.ok) this.loadBlacklist();
    } catch (err) {
      console.error('Remove blacklist error:', err);
    }
  }

  async loadWhitelist() {
    try {
      const res = await this.makeRequest('GET', '/api/admin/whitelist');
      const items = await res.json();

      const container = document.getElementById('whitelist-items');
      if (!Array.isArray(items) || items.length === 0) {
        container.innerHTML = '<div style="color:#888; text-align:center; padding:30px;">Aucune entrée</div>';
        return;
      }

      container.innerHTML = items.map(item => `
        <div class="item-row">
          <div class="item-info">
            <div class="item-type">${item.type}</div>
            <div class="item-value">${item.value}</div>
          </div>
          <div class="item-actions">
            <button class="action-btn" onclick="admin.removeFromWhitelist('${item.id}')">Supprimer</button>
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.error('Whitelist error:', err);
    }
  }

  async loadLogs() {
    try {
      const type = document.getElementById('logs-type-filter').value;
      const severity = document.getElementById('logs-severity-filter').value;
      
      let url = '/api/admin/logs?';
      if (type) url += `type=${type}&`;
      if (severity) url += `severity=${severity}`;

      const res = await this.makeRequest('GET', url);
      const logs = await res.json();

      const tbody = document.getElementById('logs-tbody');
      if (!Array.isArray(logs) || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5">Aucun log</td></tr>';
        return;
      }

      tbody.innerHTML = logs.map(log => `
        <tr>
          <td>${new Date(log.timestamp).toLocaleString('fr-FR')}</td>
          <td>${log.type}</td>
          <td>${log.severity || 'info'}</td>
          <td>${log.description}</td>
          <td><code>${log.ip || 'N/A'}</code></td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Logs error:', err);
    }
  }

  async loadAPIs() {
    try {
      const res = await this.makeRequest('GET', '/api/admin/sources');
      const sources = await res.json();

      const grid = document.getElementById('sources-grid');
      if (!Array.isArray(sources) || sources.length === 0) {
        grid.innerHTML = '<div style="color:#888;">Aucune source</div>';
        return;
      }

      grid.innerHTML = sources.map(s => `
        <div class="source-card">
          <div class="source-name">${s.name}</div>
          <div class="source-status ${s.status === 'online' ? 'online' : 'offline'}">
            ${s.status === 'online' ? '● Online' : '● Offline'}
          </div>
          <div class="source-info">Requêtes: ${s.requests_24h || 0}</div>
          <div class="source-info">Uptime: ${s.uptime || 'N/A'}%</div>
          <div class="source-info" style="margin-top:12px; font-size:11px;">
            ${s.last_check ? new Date(s.last_check).toLocaleString('fr-FR') : 'N/A'}
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.error('APIs error:', err);
    }
  }

  async loadSettings() {
    // Load settings
  }

  // Patch notes management
  async loadPatchNotes() {
    try {
      const res = await this.makeRequest('GET', '/api/patch-notes');
      const notes = await res.json();
      const list = document.getElementById('patch-list');
      if (!Array.isArray(notes) || notes.length === 0) {
        list.innerHTML = '<div style="color:#888">Aucune note</div>';
        return;
      }
      list.innerHTML = notes.map(n => `<div style="padding:8px 0;border-bottom:1px solid #111"><strong>${n.title}</strong> <div style="color:#aaa;font-size:0.9rem">${new Date(n.date).toLocaleString()}</div></div>`).join('');
    } catch (e) {
      console.error('Patch notes load error', e);
    }
  }

  async addPatchNote() {
    const title = document.getElementById('patch-title').value;
    const body = document.getElementById('patch-body').value;
    const version = document.getElementById('patch-version').value;
    if (!title || !body) { alert('Titre et corps requis'); return; }
    try {
      const res = await this.makeRequest('POST', '/api/admin/patch-notes', { title, body, version });
      if (res.ok) {
        alert('Note ajoutée');
        document.getElementById('patch-title').value = '';
        document.getElementById('patch-body').value = '';
        document.getElementById('patch-version').value = '';
        this.loadPatchNotes();
      } else {
        const err = await res.json(); alert(err.error || 'Erreur');
      }
    } catch (e) { console.error(e); alert('Erreur serveur'); }
  }

  // Team management
  async loadTeam() {
    try {
      const res = await this.makeRequest('GET', '/api/team');
      const team = await res.json();
      const container = document.getElementById('team-list');
      if (!Array.isArray(team) || team.length === 0) { container.innerHTML = '<div style="color:#888">Aucun membre</div>'; return; }
      container.innerHTML = team.map(m => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px;border-bottom:1px solid #111">
          <div>
            <strong>${m.username}</strong><div style="color:#aaa;font-size:0.9rem">ID: ${m.discord_id} • ${m.role || ''}</div>
          </div>
          <div>
            <button class="action-btn danger" onclick="admin.deleteTeamMember('${m.id}')">Supprimer</button>
          </div>
        </div>
      `).join('');
    } catch (e) { console.error('loadTeam', e); }
  }

  async addTeamMember() {
    const username = document.getElementById('team-username').value;
    const discord_id = document.getElementById('team-discord-id').value;
    const role = document.getElementById('team-role').value;
    if (!username || !discord_id) { alert('Pseudo et ID requis'); return; }
    try {
      const res = await this.makeRequest('POST', '/api/admin/team', { username, discord_id, role });
      if (res.ok) {
        alert('Membre ajouté');
        document.getElementById('team-username').value = '';
        document.getElementById('team-discord-id').value = '';
        document.getElementById('team-role').value = '';
        this.loadTeam();
      } else {
        const err = await res.json(); alert(err.error || 'Erreur');
      }
    } catch (e) { console.error(e); alert('Erreur serveur'); }
  }

  async deleteTeamMember(id) {
    if (!confirm('Supprimer ce membre ?')) return;
    try {
      const res = await this.makeRequest('DELETE', `/api/admin/team/${id}`);
      if (res.ok) this.loadTeam(); else { const err = await res.json(); alert(err.error || 'Erreur'); }
    } catch (e) { console.error(e); alert('Erreur'); }
  }

  // ADMIN ACTIONS
  async blockUser(userId) {
    if (!confirm('Bloquer cet utilisateur?')) return;
    
    try {
      const res = await this.makeRequest('POST', `/api/admin/users/${userId}/block`);
      if (res.ok) {
        alert('Utilisateur bloqué');
        this.loadUsers();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async blockSearch(searchId) {
    if (!confirm('Bloquer cette recherche?')) return;
    
    try {
      const res = await this.makeRequest('DELETE', `/api/admin/searches/${searchId}`);
      if (res.ok) {
        alert('Recherche bloquée');
        this.loadSearches();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async addToBlacklist() {
    const type = document.getElementById('blacklist-type-input').value;
    const value = document.getElementById('blacklist-value-input').value;

    if (!type || !value) {
      alert('Type et valeur requis');
      return;
    }

    try {
      const res = await this.makeRequest('POST', '/api/admin/blacklist', { type, value });
      if (res.ok) {
        document.getElementById('blacklist-value-input').value = '';
        this.loadBlacklist();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async removeFromBlacklist(id) {
    try {
      const res = await this.makeRequest('DELETE', `/api/admin/blacklist/${id}`);
      if (res.ok) this.loadBlacklist();
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async addToWhitelist() {
    const type = document.getElementById('whitelist-type-input').value;
    const value = document.getElementById('whitelist-value-input').value;

    if (!type || !value) {
      alert('Type et valeur requis');
      return;
    }

    try {
      const res = await this.makeRequest('POST', '/api/admin/whitelist', { type, value });
      if (res.ok) {
        document.getElementById('whitelist-value-input').value = '';
        this.loadWhitelist();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async removeFromWhitelist(id) {
    try {
      const res = await this.makeRequest('DELETE', `/api/admin/whitelist/${id}`);
      if (res.ok) this.loadWhitelist();
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async changePlan(userId) {
    const plans = ['FREE', 'BASIC', 'PRO', 'ENTERPRISE'];
    const plan = prompt(`Nouveau plan (${plans.join(', ')}):`);
    if (!plan) return;
    
    if (!plans.includes(plan.toUpperCase())) {
      alert('Plan invalide');
      return;
    }

    try {
      const res = await this.makeRequest('POST', `/api/admin/users/${userId}/plan`, { 
        plan: plan.toUpperCase() 
      });
      if (res.ok) {
        alert('Plan modifié avec succès');
        this.loadSubscriptions();
      }
    } catch (err) {
      console.error('Error:', err);
      alert('Erreur lors de la modification du plan');
    }
  }

  async triggerMaintenance() {
    try {
      // Get current system status
      const sysRes = await this.makeRequest('GET', '/api/admin/system');
      let system = {};
      if (sysRes && sysRes.ok) {
        try { system = await sysRes.json(); } catch (e) { system = {}; }
      }

      const currentlyOn = !!(system && system.maintenance_mode);

      if (currentlyOn) {
        if (!confirm('Le site est actuellement en maintenance. Voulez-vous désactiver la maintenance ?')) return;
        const res = await this.makeRequest('POST', '/api/admin/maintenance', { enable: false });
        if (res.ok) {
          alert('Mode maintenance désactivé');
          this.loadOverview();
        } else {
          alert('Erreur lors de la désactivation');
        }
        return;
      }

      // Enable maintenance: ask for message and duration
      const message = prompt('Message de maintenance (sera affiché aux utilisateurs):', 'Maintenance en cours');
      if (message === null) return;

      const minutes = prompt('Durée estimée (en minutes). Laisser vide pour indéfinie:','30');
      let untilDate = null;
      if (minutes && minutes.trim()) {
        const m = parseInt(minutes, 10);
        if (!isNaN(m) && m > 0) {
          untilDate = new Date(Date.now() + m * 60 * 1000).toISOString();
        }
      }

      const res = await this.makeRequest('POST', '/api/admin/maintenance', { enable: true, message, until: untilDate });
      if (res.ok) {
        alert('Mode maintenance activé');
        this.loadOverview();
      } else {
        alert("Erreur lors de l'activation de la maintenance");
      }
    } catch (err) {
      console.error('Error:', err);
      alert('Erreur lors de la requête de maintenance');
    }
  }

  async backupDB() {
    if (!confirm('Créer une sauvegarde de la base de données?')) return;

    try {
      const res = await this.makeRequest('POST', '/api/admin/backup');
      if (res.ok) alert('Backup créé avec succès');
    } catch (err) {
      console.error('Error:', err);
      alert('Erreur lors du backup');
    }
  }

  async clearLogs() {
    if (!confirm('Êtes-vous SÛR? Cette action est irréversible.')) return;
    if (!confirm('VRAIMENT supprimer TOUS les logs?')) return;

    try {
      const res = await this.makeRequest('DELETE', '/api/admin/logs');
      if (res.ok) {
        alert('Tous les logs ont été supprimés');
        this.loadLogs();
      }
    } catch (err) {
      console.error('Error:', err);
      alert('Erreur lors de la suppression des logs');
    }
  }

  async blockUser(userId) {
    if (!confirm('Bloquer cet utilisateur ?')) return;
    try {
      const res = await this.makeRequest('POST', `/api/admin/users/${userId}/block`);
      if (res.ok) {
        alert('Utilisateur bloqué');
        this.loadUsers();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async unblockUser(userId) {
    if (!confirm('Débloquer cet utilisateur ?')) return;
    try {
      const res = await this.makeRequest('POST', `/api/admin/users/${userId}/unblock`);
      if (res.ok) {
        alert('Utilisateur débloqué');
        this.loadUsers();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async banUser(userId) {
    const reason = prompt('Raison du bannissement:');
    if (reason === null) return;
    try {
      const res = await this.makeRequest('POST', `/api/admin/users/${userId}/ban`, { reason });
      if (res.ok) {
        alert('Utilisateur banni définitivement');
        this.loadUsers();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async blockSearch(searchId) {
    if (!confirm('Bloquer cette recherche ?')) return;
    try {
      const res = await this.makeRequest('POST', `/api/admin/searches/${searchId}/block`);
      if (res.ok) {
        alert('Recherche bloquée');
        this.loadSearches();
      }
    } catch (err) {
      console.error('Error:', err);
    }
  }

  async updateSetting(key, value) {
    try {
      const res = await this.makeRequest('POST', '/api/admin/settings', { [key]: value });
      if (res.ok) alert('Paramètre mis à jour');
    } catch (err) {
      console.error('Error:', err);
    }
  }

  loadLogs() {
    // Load logs from localStorage
    const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;
    
    // Reverse to show newest first
    const sortedLogs = [...logs].reverse();
    
    if (sortedLogs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5">Aucun log enregistré</td></tr>';
      return;
    }
    
    tbody.innerHTML = sortedLogs.map(log => {
      const date = new Date(log.timestamp);
      const timeStr = date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const dateStr = date.toLocaleDateString('fr-FR');
      
      // Determine severity based on event type
      let severity = 'info';
      if (log.event.includes('error') || log.event.includes('failed')) severity = 'warning';
      if (log.event.includes('blocked')) severity = 'critical';
      
      // Format description
      let desc = log.event;
      if (log.email) desc += ` (${log.email})`;
      if (log.query) desc += ` - Query: "${log.query}"`;
      if (log.reason) desc += ` - ${log.reason}`;
      
      return `
        <tr>
          <td>${dateStr} ${timeStr}</td>
          <td>${log.event}</td>
          <td><span class="severity-${severity}">${severity}</span></td>
          <td>${desc}</td>
          <td>${log.ip || 'N/A'}</td>
        </tr>
      `;
    }).join('');
  }

  updateClock() {
    const now = new Date();
    const time = now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const elem = document.getElementById('current-time');
    if (elem) elem.textContent = time;
  }
}

// Initialize
const admin = new AdminPanel()
