/**
 * Dashboard User Interface - SECURE VERSION
 * Requires valid authentication token
 */

const TOKEN = sessionStorage.getItem('seekdata_token');

// ============================================================================
// INITIALIZATION & AUTH CHECK
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // No token = unauthorized
  if (!TOKEN) {
    showAccessDenied();
    return;
  }

  try {
    // Verify token is still valid
    const meRes = await fetch('/api/me', {
      headers: { 'Authorization': `Bearer ${TOKEN}` }
    });

    if (!meRes.ok) {
      // Token expired or invalid
      sessionStorage.removeItem('seekdata_token');
      showAccessDenied();
      return;
    }

    const meData = await meRes.json();
    if (!meData.user) {
      showAccessDenied();
      return;
    }

    // Token valid - initialize dashboard
    window.CURRENT_USER = meData.user;
    setupDashboard();

  } catch (err) {
    console.error('Auth check failed:', err);
    showAccessDenied();
  }
});

// ============================================================================
// SETUP & INITIALIZATION
// ============================================================================

function setupDashboard() {
  // Show dashboard
  const container = document.querySelector('.dashboard-container');
  if (container) container.style.display = 'grid';

  // Update user display
  updateUserDisplay();

  // Setup navigation
  setupNavigation();

  // Setup logout
  setupLogout();

  // Load initial data
  loadOverviewData();

  // Setup event listeners
  setupEventListeners();
}

// ============================================================================
// USER DISPLAY
// ============================================================================

function updateUserDisplay() {
  const user = window.CURRENT_USER;
  if (!user) return;

  const initials = (user.email || 'U').substring(0, 1).toUpperCase();
  document.getElementById('user-name').textContent = user.email;
  document.getElementById('user-plan').textContent = `Plan: ${user.plan || 'FREE'}`;
  document.getElementById('user-avatar').textContent = initials;

  // Update plan info
  updatePlanDisplay(user.plan);
}

function updatePlanDisplay(plan) {
  const planData = getPlanData(plan);
  document.getElementById('current-plan-display').textContent = plan;
  document.getElementById('plan-name').textContent = plan;
  document.getElementById('plan-price').textContent = planData.price;
  document.getElementById('plan-features').innerHTML = planData.features
    .map(f => `<li>${f}</li>`).join('');
}

function getPlanData(plan) {
  const plans = {
    FREE: {
      price: '0€/mois',
      features: [
        '✓ 5 recherches par jour',
        '✓ Email uniquement',
        '✗ Pas de monitoring temps réel'
      ]
    },
    STARTER: {
      price: '9€/mois',
      features: [
        '✓ Recherches illimitées',
        '✓ OSINT multi-sources',
        '✓ Analyse d\'IP',
        '✓ Support prioritaire'
      ]
    },
    PRO: {
      price: '29€/mois',
      features: [
        '✓ Tous les services Starter',
        '✓ API d\'intégration privée',
        '✓ Support 24/7 dédié',
        '✓ Rapports personnalisés'
      ]
    }
  };
  return plans[plan] || plans.FREE;
}

// ============================================================================
// NAVIGATION
// ============================================================================

function setupNavigation() {
  document.querySelectorAll('[data-tab]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const tabName = e.currentTarget.dataset.tab;
      switchTab(tabName);
    });
  });
}

function switchTab(tabName) {
  // Hide all tabs
  document.querySelectorAll('.tab-content').forEach(tab => {
    tab.classList.remove('active');
  });

  // Deactivate all nav items
  document.querySelectorAll('[data-tab]').forEach(btn => {
    btn.classList.remove('active');
  });

  // Show selected tab
  document.getElementById(`tab-${tabName}`).classList.add('active');
  document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

  // Update page title
  const titles = {
    overview: 'Aperçu',
    search: 'Rechercher',
    history: 'Historique',
    subscription: 'Abonnement',
    settings: 'Paramètres'
  };
  document.getElementById('page-title').textContent = titles[tabName];

  // Load tab-specific data
  if (tabName === 'overview') loadOverviewData();
  if (tabName === 'history') loadHistory();
}

// ============================================================================
// OVERVIEW DATA
// ============================================================================

async function loadOverviewData() {
  try {
    const res = await fetch('/api/me', {
      headers: { 'Authorization': `Bearer ${TOKEN}` }
    });

    if (!res.ok) throw new Error('Failed to load user data');

    const data = await res.json();
    const user = data.user;

    // Update stats
    const planData = getPlanData(user.plan || 'FREE');
    document.getElementById('current-plan-display').textContent = user.plan || 'FREE';
    
    const dailyQuota = user.quota?.daily_remaining || 5;
    const dailyLimit = user.quota?.daily_limit || 5;
    
    document.getElementById('remaining-searches').textContent = dailyQuota;
    document.getElementById('quota-used').textContent = dailyLimit - dailyQuota;
    document.getElementById('quota-total').textContent = dailyLimit;

    const pct = ((dailyLimit - dailyQuota) / dailyLimit) * 100;
    document.getElementById('quota-fill').style.width = Math.min(100, pct) + '%';

  } catch (err) {
    console.error('Overview load error:', err);
    showTabError('overview', 'Erreur lors du chargement des données');
  }
}

// ============================================================================
// SEARCH
// ============================================================================

function setupEventListeners() {
  const searchBtn = document.getElementById('search-submit');
  if (searchBtn) searchBtn.addEventListener('click', performSearch);
  
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);
  
  const changePwdBtn = document.getElementById('change-password-btn');
  if (changePwdBtn) changePwdBtn.addEventListener('click', changePassword);
  
  const deleteBtn = document.getElementById('delete-account-btn');
  if (deleteBtn) deleteBtn.addEventListener('click', confirmDeleteAccount);
}

async function performSearch() {
  const query = document.getElementById('search-query').value.trim();
  const type = document.getElementById('search-type').value;
  const msg = document.getElementById('search-message');

  if (!query) {
    showMessage(msg, 'Veuillez entrer une valeur à rechercher', 'error');
    return;
  }

  try {
    const res = await fetch('/api/search', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ type, query })
    });

    const data = await res.json();

    if (!res.ok) {
      showMessage(msg, data.message || 'Erreur lors de la recherche', 'error');
      return;
    }

    showMessage(msg, `Recherche effectuée: ${data.results?.length || 0} résultats`, 'success');

    const container = document.getElementById('search-results-container');
    const content = document.getElementById('search-results-content');

    if (data.results && data.results.length > 0) {
      content.innerHTML = `<pre>${JSON.stringify(data.results.slice(0, 5), null, 2)}</pre>`;
    } else {
      content.innerHTML = '<p>Aucun résultat trouvé.</p>';
    }

    container.style.display = 'block';

  } catch (err) {
    console.error('Search error:', err);
    showMessage(msg, 'Erreur: ' + err.message, 'error');
  }
}

// ============================================================================
// HISTORY
// ============================================================================

async function loadHistory() {
  try {
    const res = await fetch('/api/history', {
      headers: { 'Authorization': `Bearer ${TOKEN}` }
    });

    if (!res.ok) throw new Error('Failed to load history');

    const data = await res.json();
    const history = data.history || [];

    if (history.length === 0) {
      document.getElementById('history-tbody').innerHTML =
        '<tr><td colspan="5" style="text-align:center;color:rgba(255,255,255,0.5)">Aucune recherche effectuée</td></tr>';
      return;
    }

    const rows = history.map(item => `
      <tr>
        <td>${item.type}</td>
        <td>${maskValue(item.query)}</td>
        <td>${new Date(item.created_at).toLocaleString('fr-FR')}</td>
        <td>${item.source || '—'}</td>
        <td>${getStatusBadge(item.status)}</td>
      </tr>
    `).join('');

    document.getElementById('history-tbody').innerHTML = rows;

  } catch (err) {
    console.error('History load error:', err);
    showTabError('history', 'Erreur lors du chargement de l\'historique');
  }
}

function maskValue(val) {
  if (!val) return '—';
  if (val.includes('@')) {
    const [user, domain] = val.split('@');
    return user.substring(0, 3) + '***@' + domain;
  }
  return val.substring(0, 3) + '***';
}

function getStatusBadge(status) {
  const badges = {
    success: '✓',
    blocked: '🚫',
    error: '✗'
  };
  return badges[status] || '—';
}

// ============================================================================
// ACCOUNT SETTINGS
// ============================================================================

async function changePassword() {
  const current = document.getElementById('current-password').value;
  const newPwd = document.getElementById('new-password').value;
  const confirm = document.getElementById('confirm-password').value;

  if (!current || !newPwd || !confirm) {
    showError('Veuillez remplir tous les champs');
    return;
  }

  if (newPwd !== confirm) {
    showError('Les mots de passe ne correspondent pas');
    return;
  }

  if (newPwd.length < 8) {
    showError('Le mot de passe doit contenir au moins 8 caractères');
    return;
  }

  try {
    const res = await fetch('/api/change-password', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ current_password: current, new_password: newPwd })
    });

    const data = await res.json();

    if (!res.ok) {
      showError(data.message || 'Erreur lors du changement de mot de passe');
      return;
    }

    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';

    showSuccess('Mot de passe changé avec succès');

  } catch (err) {
    console.error('Password change error:', err);
    showError('Erreur: ' + err.message);
  }
}

function confirmDeleteAccount() {
  showConfirmation(
    'Supprimer le compte',
    'Cette action est irréversible. Êtes-vous sûr?',
    deleteAccount
  );
}

async function deleteAccount() {
  try {
    const res = await fetch('/api/delete-account', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${TOKEN}` }
    });

    if (!res.ok) throw new Error('Suppression impossible');

    sessionStorage.removeItem('seekdata_token');
    window.location.href = '/login';

  } catch (err) {
    console.error('Delete account error:', err);
    showError('Erreur: ' + err.message);
  }
}

// ============================================================================
// LOGOUT
// ============================================================================

function logout() {
  sessionStorage.removeItem('seekdata_token');
  window.location.href = '/login';
}

// ============================================================================
// UI UTILITIES
// ============================================================================

function showMessage(el, msg, type) {
  if (!el) return;
  el.textContent = msg;
  el.className = `search-message show ${type}`;
}

function showError(msg) {
  const msg_el = document.getElementById('search-message');
  showMessage(msg_el, msg, 'error');
}

function showSuccess(msg) {
  const msg_el = document.getElementById('search-message');
  showMessage(msg_el, msg, 'success');
}

function showTabError(tabName, msg) {
  const tab = document.getElementById(`tab-${tabName}`);
  if (tab) {
    tab.innerHTML = `<div style="padding:2rem;text-align:center;color:rgba(255,100,100,0.9)"><p>${msg}</p></div>`;
  }
}

function showConfirmation(title, msg, callback) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-message').textContent = msg;
  document.getElementById('confirmation-modal').style.display = 'flex';

  document.getElementById('modal-confirm').onclick = () => {
    document.getElementById('confirmation-modal').style.display = 'none';
    callback();
  };

  document.getElementById('modal-cancel').onclick = () => {
    document.getElementById('confirmation-modal').style.display = 'none';
  };
}

// ============================================================================
// ACCESS DENIED
// ============================================================================

function showAccessDenied() {
  document.body.innerHTML = `
    <div style="position:fixed;inset:0;background:#000;display:flex;align-items:center;justify-content:center;padding:1rem">
      <div style="background:rgba(255,255,255,0.04);border:1.5px solid rgba(255,100,100,0.3);border-radius:14px;padding:2.5rem;max-width:450px;text-align:center">
        <div style="font-size:3rem;margin-bottom:1rem">🔒</div>
        <h1 style="color:#fff;margin:0 0 0.5rem;font-size:1.6rem">Accès refusé</h1>
        <p style="color:rgba(255,255,255,0.7);margin:0 0 1.5rem">Veuillez vous connecter pour accéder au dashboard</p>
        <a href="/login" style="display:inline-block;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.08);color:#fff;padding:0.9rem 1.8rem;border-radius:8px;text-decoration:none;font-weight:600;transition:all 0.3s">
          Aller à la connexion
        </a>
      </div>
    </div>
  `;
}

function setupLogout() {
  // Already handled in setupEventListeners
}
