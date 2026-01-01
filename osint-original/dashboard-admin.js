/**
 * Dashboard Admin - Version localStorage
 * Gestion des utilisateurs, logs, et maintenance
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialiser l'admin
  initAdmin();
});

// ============================================================================
// INITIALISATION
// ============================================================================

function initAdmin() {
  setupNavigation();
  setupLogout();
  loadLogs();
  loadUsers();
}

// ============================================================================
// NAVIGATION PAR SECTIONS
// ============================================================================

function setupNavigation() {
  const navButtons = document.querySelectorAll('[data-section]');

  navButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();

      const section = btn.getAttribute('data-section');

      // Désactiver les autres boutons
      navButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Cacher tous les contenus
      document.querySelectorAll('[id^="section-"]').forEach(sec => {
        sec.style.display = 'none';
      });

      // Afficher la bonne section
      const sectionEl = document.getElementById(`section-${section}`);
      if (sectionEl) {
        sectionEl.style.display = 'block';

        // Charger les données selon la section
        if (section === 'logs') loadLogs();
        if (section === 'users') loadUsers();
        if (section === 'maintenance') loadMaintenanceStatus();
      }
    });
  });

  // Afficher la première section par défaut
  const firstBtn = navButtons[0];
  if (firstBtn) firstBtn.click();
}

// ============================================================================
// LOGS
// ============================================================================

function loadLogs() {
  const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');

  // Trier par date (plus récent en premier)
  const sortedLogs = [...logs].reverse();

  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;

  if (sortedLogs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#666;padding:20px;">Aucun log disponible</td></tr>';
    return;
  }

  tbody.innerHTML = sortedLogs.map(log => {
    const severity = getSeverity(log.event);
    const timestamp = new Date(log.timestamp).toLocaleString('fr-FR');
    const email = log.email || 'N/A';
    const details = getLogDetails(log);

    return `
      <tr class="log-row log-${severity}">
        <td><span class="severity-badge ${severity}">${severity.toUpperCase()}</span></td>
        <td>${log.event}</td>
        <td>${email}</td>
        <td>${details}</td>
        <td>${timestamp}</td>
      </tr>
    `;
  }).join('');
}

function getSeverity(event) {
  const severities = {
    'user_registered': 'info',
    'user_login': 'info',
    'login_failed': 'warning',
    'search_performed': 'info',
    'search_blocked': 'warning',
    'registration_error': 'critical',
    'user_logout': 'info'
  };
  return severities[event] || 'info';
}

function getLogDetails(log) {
  if (log.event === 'login_failed') {
    return `Raison: ${log.reason || 'Inconnue'}`;
  }
  if (log.event === 'search_performed') {
    return `Requête: "${log.query || 'N/A'}" - ${log.results_count || 0} résultats`;
  }
  if (log.event === 'registration_error') {
    return log.error || 'Erreur inconnue';
  }
  if (log.event === 'user_login') {
    return `IP: ${log.ip || 'N/A'}`;
  }
  return '';
}

// ============================================================================
// GESTION DES UTILISATEURS
// ============================================================================

function loadUsers() {
  const users = JSON.parse(localStorage.getItem('SeekData_users') || '{}');
  const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');

  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;

  if (Object.keys(users).length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#666;padding:20px;">Aucun utilisateur enregistré</td></tr>';
    return;
  }

  tbody.innerHTML = Object.entries(users).map(([email, user]) => {
    const lastLogin = logs
      .filter(log => log.email === email && log.event === 'user_login')
      .pop();

    const createdAt = new Date(user.created_at).toLocaleDateString('fr-FR');
    const lastLoginTime = lastLogin
      ? new Date(lastLogin.timestamp).toLocaleString('fr-FR')
      : 'Jamais';

    const searchCount = logs.filter(log => log.email === email && log.event === 'search_performed').length;

    return `
      <tr>
        <td>${escapeHtml(user.username || email)}</td>
        <td>${escapeHtml(email)}</td>
        <td>${createdAt}</td>
        <td>${lastLoginTime}</td>
        <td>${searchCount} recherches</td>
        <td>
          <button class="btn-small" onclick="blockUser('${email}')">Bloquer</button>
          <button class="btn-small" onclick="deleteUser('${email}')">Supprimer</button>
        </td>
      </tr>
    `;
  }).join('');
}

function blockUser(email) {
  const confirmed = confirm(`Bloquer l'utilisateur ${escapeHtml(email)} ?`);
  if (!confirmed) return;

  // Ajouter à une blacklist
  let blacklist = JSON.parse(localStorage.getItem('SeekData_blacklist') || '[]');
  if (!blacklist.includes(email)) {
    blacklist.push(email);
    localStorage.setItem('SeekData_blacklist', JSON.stringify(blacklist));
    alert(`Utilisateur ${email} bloqué`);
    loadUsers();
  }
}

function deleteUser(email) {
  const confirmed = confirm(`Supprimer définitivement l'utilisateur ${escapeHtml(email)} ?`);
  if (!confirmed) return;

  const users = JSON.parse(localStorage.getItem('SeekData_users') || '{}');
  delete users[email];
  localStorage.setItem('SeekData_users', JSON.stringify(users));

  addLog('user_deleted_by_admin', { email, deleted_by: 'admin' });
  alert(`Utilisateur ${email} supprimé`);
  loadUsers();
}

// ============================================================================
// MAINTENANCE
// ============================================================================

function loadMaintenanceStatus() {
  const maintenance = JSON.parse(localStorage.getItem('SeekData_maintenance') || '{"enabled":false,"message":""}');

  const toggle = document.getElementById('maintenance-toggle');
  const message = document.getElementById('maintenance-message');

  if (toggle) toggle.checked = maintenance.enabled;
  if (message) message.value = maintenance.message;
}

function toggleMaintenance() {
  const toggle = document.getElementById('maintenance-toggle');
  const message = document.getElementById('maintenance-message');

  if (!toggle || !message) return;

  const maintenance = {
    enabled: toggle.checked,
    message: message.value,
    toggledAt: new Date().toISOString()
  };

  localStorage.setItem('SeekData_maintenance', JSON.stringify(maintenance));

  addLog('maintenance_' + (maintenance.enabled ? 'enabled' : 'disabled'), {
    message: maintenance.message
  });

  alert(maintenance.enabled ? 'Mode maintenance ACTIVÉ' : 'Mode maintenance DÉSACTIVÉ');
}

// ============================================================================
// DÉCONNEXION
// ============================================================================

function setupLogout() {
  const logoutBtn = document.getElementById('admin-logout-btn') || document.querySelector('[onclick*="logout"]');

  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      sessionStorage.removeItem('seekdata_admin_token');
      window.location.href = 'index.html';
    });
  }
}

// ============================================================================
// UTILITAIRES
// ============================================================================

function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

function addLog(event, details = {}) {
  const log = { timestamp: new Date().toISOString(), event, ...details };
  const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');
  logs.push(log);
  if (logs.length > 500) logs.shift();
  localStorage.setItem('SeekData_logs', JSON.stringify(logs));
}
