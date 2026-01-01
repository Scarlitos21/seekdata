/**
 * Dashboard Utilisateur - Version localStorage
 * Affiche les vraies données (pas de fake data)
 */

document.addEventListener('DOMContentLoaded', () => {
  const userEmail = sessionStorage.getItem('seekdata_user');
  const token = sessionStorage.getItem('seekdata_token');

  // Vérifier l'authentification
  if (!userEmail || !token) {
    window.location.href = 'login.html';
    return;
  }

  // Initialiser le dashboard
  initDashboard(userEmail);
});

// ============================================================================
// INITIALISATION
// ============================================================================

function initDashboard(userEmail) {
  // Afficher les infos utilisateur
  displayUserInfo(userEmail);

  // Charger les données
  loadOverviewData(userEmail);
  loadSearchHistory();
  loadLoginHistory(userEmail);

  // Setup navigation
  setupNavigation();

  // Setup logout
  setupLogout(userEmail);
}

// ============================================================================
// INFOS UTILISATEUR
// ============================================================================

function displayUserInfo(userEmail) {
  const users = JSON.parse(localStorage.getItem('SeekData_users') || '{}');
  const user = users[userEmail];

  if (!user) return;

  const initials = userEmail.substring(0, 1).toUpperCase();
  const userName = user.username || userEmail;

  document.getElementById('user-name').textContent = userName;
  document.getElementById('user-avatar').textContent = initials;
  document.getElementById('current-user').textContent = userName;

  // created date and total logins
  const createdEl = document.getElementById('created-date');
  if(createdEl) createdEl.textContent = user.created_at ? new Date(user.created_at).toLocaleString('fr-FR') : '—';
  const totalLoginsEl = document.getElementById('total-logins');
  if(totalLoginsEl) totalLoginsEl.textContent = (user.logins || []).length;
}

// ============================================================================
// APERÇU (OVERVIEW)
// ============================================================================

function loadOverviewData(userEmail) {
  const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');
  const users = JSON.parse(localStorage.getItem('SeekData_users') || '{}');
  const user = users[userEmail];

  // Filtrer les logs de l'utilisateur actuel
  const userLogs = logs.filter(log => log.email === userEmail);
  const userSearches = userLogs.filter(log => log.event === 'search_performed');
  const userLogins = userLogs.filter(log => log.event === 'user_login');

  // Stats
  const totalSearches = userSearches.length;
  const searchesToday = userSearches.filter(log => {
    const logDate = new Date(log.timestamp).toDateString();
    const today = new Date().toDateString();
    return logDate === today;
  }).length;

  const lastSearch = userSearches.length > 0
    ? formatDate(userSearches[userSearches.length - 1].timestamp)
    : 'Aucune recherche';

  const lastLogin = userLogins.length > 0
    ? formatDate(userLogins[userLogins.length - 1].timestamp)
    : 'Jamais';

  // Afficher les stats
  document.getElementById('total-searches').textContent = totalSearches;
  document.getElementById('searches-today').textContent = searchesToday;
  document.getElementById('last-search-time').textContent = lastSearch;
  document.getElementById('last-login-time').textContent = lastLogin;
  document.getElementById('account-status').textContent = 'Actif';
  document.getElementById('account-status').style.color = '#4ade80';

  // Afficher plan
  const plan = user?.plan || 'FREE';
  document.getElementById('current-plan').textContent = plan;

  // Quotas selon le plan
  const quotas = {
    'FREE': { daily: 5, monthly: 50 },
    'PREMIUM': { daily: 100, monthly: 3000 },
    'PRO': { daily: -1, monthly: -1 } // Illimité
  };

  const quota = quotas[plan] || quotas['FREE'];
  const remaining = quota.daily === -1 ? '∞' : Math.max(0, quota.daily - searchesToday);
  document.getElementById('remaining-searches').textContent = remaining;
  document.getElementById('plan-status').textContent = `${plan} - Quota: ${remaining} requêtes restantes`;
}

// ============================================================================
// HISTORIQUE DE RECHERCHES
// ============================================================================

function loadSearchHistory() {
  const userEmail = sessionStorage.getItem('seekdata_user');
  const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');

  const userSearches = logs
    .filter(log => log.email === userEmail && log.event === 'search_performed')
    .reverse() // Plus récent en premier
    .slice(0, 10); // Dernières 10

  const tbody = document.getElementById('search-history-tbody');
  if (!tbody) return;

  if (userSearches.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#666;padding:20px;">Aucune recherche effectuée</td></tr>';
    return;
  }

  tbody.innerHTML = userSearches.map((log, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>${escapeHtml(log.query || '')}</td>
      <td>${log.results_count || '0'} résultats</td>
      <td>${formatDate(log.timestamp)}</td>
    </tr>
  `).join('');
}

// ============================================================================
// HISTORIQUE DE CONNEXIONS
// ============================================================================

function loadLoginHistory(userEmail) {
  const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');

  const userLogins = logs
    .filter(log => log.email === userEmail && log.event === 'user_login')
    .reverse()
    .slice(0, 10);

  const tbody = document.getElementById('login-history-tbody');
  if (!tbody) return;

  if (userLogins.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#666;padding:20px;">Aucune connexion enregistrée</td></tr>';
    return;
  }

  tbody.innerHTML = userLogins.map((log, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>${log.ip || 'N/A'}</td>
      <td>${formatDate(log.timestamp)}</td>
    </tr>
  `).join('');
}

// ============================================================================
// NAVIGATION PAR ONGLETS
// ============================================================================

function setupNavigation() {
  const navButtons = document.querySelectorAll('.nav-item[data-tab]');

  navButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();

      const tabName = btn.getAttribute('data-tab');

      // Désactiver les autres onglets
      navButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Cacher tous les contenus
      document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
      });

      // Afficher le bon contenu
      const tab = document.getElementById(`tab-${tabName}`);
      if (tab) {
        tab.classList.add('active');

        // Charger les données si nécessaire
        if (tabName === 'history') {
          loadSearchHistory();
          loadLoginHistory(sessionStorage.getItem('seekdata_user'));
        }
      }
    });
  });
}

// ============================================================================
// DÉCONNEXION
// ============================================================================

function setupLogout(userEmail) {
  const logoutBtn = document.getElementById('logout-btn');
  if (!logoutBtn) return;

  logoutBtn.addEventListener('click', (e) => {
    e.preventDefault();

    // Logger la déconnexion
    addLog('user_logout', { email: userEmail });

    // Supprimer la session
    sessionStorage.removeItem('seekdata_token');
    sessionStorage.removeItem('seekdata_user');

    // Rediriger
    window.location.href = 'index.html';
  });
}

// ============================================================================
// UTILITAIRES
// ============================================================================

function formatDate(isoString) {
  if (!isoString) return 'N/A';

  const date = new Date(isoString);
  const now = new Date();
  const diff = now - date;

  // Afficher "il y a X temps" pour les récentes
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'À l\'instant';
  if (minutes < 60) return `il y a ${minutes}m`;
  if (hours < 24) return `il y a ${hours}h`;
  if (days < 7) return `il y a ${days}j`;

  // Sinon afficher la date
  return date.toLocaleDateString('fr-FR', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

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
