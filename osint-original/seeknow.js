// SEEKDATA: interactions, animations, simulated auth + client-side search demo

// ===== LOG SYSTEM =====
function addLog(event, details = {}) {
  const log = {
    timestamp: new Date().toISOString(),
    event,
    ...details
  };
  const logs = JSON.parse(localStorage.getItem('SeekData_logs') || '[]');
  logs.push(log);
  // Keep only last 500 logs
  if (logs.length > 500) logs.shift();
  localStorage.setItem('SeekData_logs', JSON.stringify(logs));
  console.log('[LOG]', log);
}

document.addEventListener('DOMContentLoaded', ()=>{
  // ===== SEARCH TAGS =====
  document.querySelectorAll('.search-tag').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const input = document.getElementById('search-input');
      if(!input) return;
      input.value = btn.textContent.trim();
      input.focus();
    });
  });

  // ===== SEARCH FORM WITH PROVIDERS =====
  const searchForm = document.getElementById('search-form');
  if(searchForm){
    searchForm.addEventListener('submit', async e=>{
      e.preventDefault();
      const input = document.getElementById('search-input');
      const provider = document.getElementById('search-provider')?.value || '';
      const query = (input && input.value.trim()) || '';
      
      if(!query){
        showSearchMessage('Veuillez entrer une requête.', 'error');
        return;
      }
      if(!provider){
        showSearchMessage('Veuillez sélectionner un provider.', 'error');
        return;
      }

      const token = sessionStorage.getItem('seekdata_token');
      const userEmail = sessionStorage.getItem('seekdata_user');

      if(!token){
        showSearchMessage('Veuillez vous connecter pour effectuer une recherche.', 'error');
        addLog('search_blocked', { reason: 'not_authenticated' });
        setTimeout(()=>{ window.location.href = 'login.html'; }, 800);
        return;
      }

      // Check if user has access to this provider based on plan
      const users = JSON.parse(localStorage.getItem('SeekData_users') || '{}');
      const user = users[userEmail];
      const plan = user?.plan || 'FREE';

      const canAccess = checkProviderAccess(provider, plan);
      if(!canAccess){
        showSearchMessage(`Accès refusé. Le provider "${provider}" nécessite un plan supérieur.`, 'error');
        addLog('search_blocked', { provider, query, reason: 'plan_restriction' });
        return;
      }

      // Perform search via provider
      const results = await performSearch(query, provider);
      addLog('search_performed', { provider, query, results_count: results.length });
      displayResults(results, query, provider);
    });
  }

  // ===== AUTH FORMS (login only) =====
  // ===== AUTH FORMS (login only) =====
  const loginForm = document.getElementById('login-form');
  const contactForm = document.getElementById('contact-form');

  if(loginForm){
    loginForm.addEventListener('submit', async e=>{
      e.preventDefault();
      const email = loginForm.querySelector('input[name="email"]')?.value.trim().toLowerCase() || '';
      const password = loginForm.querySelector('input[name="password"]')?.value || '';
      const msg = loginForm.querySelector('.form-msg');
      if(!msg) return;
      msg.textContent = '';
      if(!email || !password){
        msg.textContent = 'Veuillez remplir tous les champs.';
        msg.className = 'form-msg error';
        return;
      }
      try{
        // Use localStorage for local authentication
        const users = JSON.parse(localStorage.getItem('SeekData_users') || '{}');
        if(!users[email]){
          msg.textContent = 'Compte introuvable.';
          msg.className = 'form-msg error';
          return;
        }
        const hash = await sha256(password);
        if(hash!==users[email].pw_hash){
          msg.textContent = 'Mot de passe incorrect.';
          msg.className = 'form-msg error';
          return;
        }
        // Create token
        const token = 'token_' + btoa(email + ':' + Date.now());
        sessionStorage.setItem('seekdata_token', token);
        sessionStorage.setItem('seekdata_user', email);
        const ip = await fetchIP();
        const now = new Date().toISOString();
        users[email].logins.push({at:now, ip});
        localStorage.setItem('seekdata_users', JSON.stringify(users));
        msg.textContent = 'Connexion réussie.';
        msg.className = 'form-msg success';
        addLog('user_login', { email, ip });
        sendLog({ event: 'login', email, method: 'local', ip });
        loginForm.reset();
        // refresh header UI to show Dashboard
        setTimeout(()=>{ updateAuthUI(); }, 100);
      }catch(err){
        msg.textContent = 'Erreur lors de la connexion.';
        msg.className = 'form-msg error';
        console.error('Login error:', err);
      }
    });
  }

  // Replace auth buttons if user is logged in
  function updateAuthUI(){
    const navAuth = document.querySelector('.nav-auth');
    if(!navAuth) return;
    const token = sessionStorage.getItem('seekdata_token');
    if(token){
      // render Dashboard button + dropdown
      navAuth.innerHTML = `
        <div class="user-area">
          <button class="btn solid" id="open-dashboard">Dashboard</button>
          <div class="user-menu" id="user-menu" style="display:none;">
            <a href="/dashboard.html">Mon compte</a>
            <a href="/dashboard.html#subscription">Abonnement</a>
            <a href="/dashboard.html#history">Historique</a>
            <a href="#" id="logout-link">Déconnexion</a>
          </div>
        </div>`;
      const btn = document.getElementById('open-dashboard');
      const menu = document.getElementById('user-menu');
      btn.addEventListener('click', ()=> window.location.href = '/dashboard.html');
      btn.addEventListener('contextmenu', e=>{ e.preventDefault(); menu.style.display = menu.style.display === 'none' ? 'block' : 'none'; });
      document.getElementById('logout-link').addEventListener('click', e=>{ e.preventDefault(); sessionStorage.removeItem('seekdata_token'); sessionStorage.removeItem('seekdata_user'); updateAuthUI(); });
    } else {
      // ensure default (Logout was removed)
      // if nav-auth originally had buttons in markup, leave them as-is
      // no-op if already default
    }
  }
  // init auth UI on load
  updateAuthUI();

  if(contactForm){
    contactForm.addEventListener('submit', async e=>{
      e.preventDefault();
      const msg = contactForm.querySelector('.form-msg');
      const msgText = contactForm.querySelector('textarea[name="message"]')?.value.trim() || '';
      if(!msg) return;
      msg.textContent = '';
      if(!msgText){
        msg.textContent = 'Veuillez entrer un message.';
        msg.className = 'form-msg error';
        return;
      }
      const now = new Date().toISOString();
      const ip = await fetchIP();
      const messages = JSON.parse(localStorage.getItem('seekdata_messages') || '[]');
      messages.push({msg:msgText, at:now, ip});
      localStorage.setItem('seekdata_messages', JSON.stringify(messages));
      msg.textContent = 'Message envoyé avec succès (simulation).';
      msg.className = 'form-msg success';
      sendLog({ event: 'contact_message', message: msgText, ip, at: now });
      contactForm.reset();
    });
  }

  // ===== EYE ANIMATION (subtle wobble) =====
  const iris = document.querySelector('.iris');
  if(iris){
    let t = 0;
    setInterval(()=>{
      t += 0.03;
      const sx = 1 + Math.sin(t)*0.018;
      const sy = 1 + Math.cos(t)*0.012;
      iris.style.transform = `scale(${sx}, ${sy})`;
    }, 50);
  }

  // ===== BRAND LOGO HIGHLIGHT =====
  const brand = document.querySelector('.brand');
  if(brand){
    brand.addEventListener('mouseenter', e=>{
      brand.classList.add('glow');
      updateBrandPos(e);
    });
    brand.addEventListener('mousemove', e=> updateBrandPos(e));
    brand.addEventListener('mouseleave', ()=> brand.classList.remove('glow'));
  }
  function updateBrandPos(e){
    const r = brand.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * 100;
    const y = ((e.clientY - r.top) / r.height) * 100;
    brand.style.setProperty('--brand-x', x + '%');
    brand.style.setProperty('--brand-y', y + '%');
  }

  // ===== SMOOTH SCROLL =====
  document.querySelectorAll('a[href^="#"]').forEach(link=>{
    link.addEventListener('click', e=>{
      const href = link.getAttribute('href');
      if(href==='#') return;
      e.preventDefault();
      const target = document.querySelector(href);
      if(target){
        target.scrollIntoView({behavior:'smooth', block:'start'});
      }
    });
  });

  // ===== GRID MASK: compute where to cut the grid (below hero/account start)
  function setGridCut(){
    const loginSec = document.getElementById('login-section');
    const mask = document.querySelector('.grid-mask');
    if(!mask || !loginSec) return;
    const rect = loginSec.getBoundingClientRect();
    const top = window.scrollY + rect.top;
    // set css var on root in pixels
    document.documentElement.style.setProperty('--grid-cut', top + 'px');
  }
  setGridCut();
  window.addEventListener('resize', setGridCut);
  window.addEventListener('load', setGridCut);

});

function showSearchMessage(text, type){
  let msgEl = document.getElementById('search-msg');
  if(!msgEl) return;
  msgEl.textContent = text;
  msgEl.className = `search-msg ${type}`;
}

// ===== UTILITIES =====
async function fetchIP(){
  try{
    const res = await fetch('https://api.ipify.org?format=json');
    if(!res.ok) throw new Error();
    const j = await res.json();
    return j.ip || '0.0.0.0';
  }catch(e){
    return '0.0.0.0';
  }
}

async function sha256(message){
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b=>b.toString(16).padStart(2,'0')).join('');
}

// ===== CLIENT-SIDE SEARCH HELPERS (demo) =====
async function performSearch(query){
  // Require authentication for searches
  const token = sessionStorage.getItem('seekdata_token');
  if(!token){
    showSearchMessage('Veuillez vous connecter pour effectuer une recherche.', 'error');
    return [];
  }

  // Try server-side search if authenticated
  if(token){
    try{
      showSearchMessage('Chargement...', 'info');
      const backend = window.API_URL || 'https://seekdata-backend.onrender.com';
      const res = await fetch(`${backend}/api/search`, { method:'POST', headers: {'content-type':'application/json','authorization':'Bearer '+token}, body: JSON.stringify({ query }) });
      if(res.status === 401){ showSearchMessage('Non autorisé — veuillez vous connecter.', 'error'); return []; }
      if(res.status === 403){ const b = await res.json().catch(()=>({})); showSearchMessage(b && b.message ? b.message : 'Interdit', 'error'); return []; }
      const j = await res.json().catch(()=>({}));
      showSearchMessage('', 'info');
      return j.results || [];
    }catch(e){ /* fall through to local */ }
  }
  // If we reach here, server-side search failed — do not return local simulated results when searches are restricted
  return [];
}

// Best-effort log sender for client-side actions
function sendLog(payload){
  try{
    const backend = window.API_URL || 'https://seekdata-backend.onrender.com';
    fetch(backend + '/api/logs', {
      method: 'POST',
      headers: {'content-type':'application/json'},
      body: JSON.stringify(payload)
    }).catch(()=>{});
  }catch(e){/* ignore */}
}

// Determine provider access by plan
function checkProviderAccess(provider, plan){
  const access = {
    'FREE': ['leakcheck-email','leakcheck','roblox','steam','ipinfo'],
    'PREMIUM': ['leakcheck-email','leakcheck','roblox','steam','ipinfo','phoneinfo'],
    'STARTER': ['leakcheck-email','leakcheck','roblox','steam','ipinfo','phoneinfo','breachvip','redline'],
    'PRO': ['leakcheck-email','leakcheck','roblox','steam','ipinfo','phoneinfo','breachvip','redline','snusbase']
  };
  const allowed = access[plan] || access['FREE'];
  return allowed.includes(provider);
}

// performSearch: attempt to call backend endpoints if available; otherwise simulate minimal responses
async function performSearch(query, provider){
  // Prefer backend if available
  try{
    const backend = window.API_URL || null;
    if(backend){
      const res = await fetch(`${backend}/api/search`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({provider,query})});
      if(res.ok){
        const j = await res.json();
        return j.results || [];
      }
    }
  }catch(e){ /* ignore */ }

  // Local simulation for each provider
  const now = new Date().toISOString();
  const base = { provider, query, at: now };
  switch(provider){
    case 'ipinfo': return [{ provider:'ipinfo', title:`IP ${query}`, snippet:`IP lookup simulated: 1 result`, source:'ipinfo', at:now }];
    case 'roblox': return [{ provider:'roblox', title:`Roblox lookup ${query}`, snippet:'Profil public trouvé (simulé)', source:'roblox', at:now }];
    case 'steam': return [{ provider:'steam', title:`Steam lookup ${query}`, snippet:'Compte Steam simulé', source:'steam', at:now }];
    case 'phoneinfo': return [{ provider:'phoneinfo', title:`Phone ${query}`, snippet:'Données téléphone simulées', source:'phoneinfo', at:now }];
    case 'snusbase': return [{ provider:'snusbase', title:`Snusbase ${query}`, snippet:'Résultats Snusbase (premium) - doit être configuré', source:'snusbase', at:now }];
    case 'redline': return [{ provider:'redline', title:`redline ${query}`, snippet:'redline results (premium)', source:'redline', at:now }];
    case 'breachvip': return [{ provider:'breachvip', title:`BreachVIP ${query}`, snippet:'BreachVIP results (premium)', source:'breachvip', at:now }];
    case 'leakcheck-email':
    case 'leakcheck': return [{ provider:'leakcheck', title:`LeakCheck ${query}`, snippet:'LeakCheck findings (public)', source:'leakcheck', at:now }];
    default: return [{ provider:'unknown', title: query, snippet:'Aucun provider spécifique', source:'local', at:now }];
  }
}

function displayResults(items, query, provider){
  let container = document.getElementById('search-results');
  if(!container){
    container = document.createElement('div');
    container.id = 'search-results';
    container.className = 'cards-grid';
    const heroInner = document.querySelector('.hero-inner');
    if(heroInner) heroInner.appendChild(container);
  }
  container.innerHTML = '';
  if(!items || items.length===0){
    container.innerHTML = `<div class="card">Aucun résultat trouvé pour <strong>${escapeHtml(query)}</strong></div>`;
    return;
  }
  // Group results by provider and render provider-specific boxes
  const grouped = {};
  items.forEach(it=>{ const p = it.provider||provider||'unknown'; grouped[p]=grouped[p]||[]; grouped[p].push(it); });
  Object.entries(grouped).forEach(([p, arr])=>{
    const box = document.createElement('div');
    box.className = 'card';
    box.innerHTML = `<h3 style="margin-top:0">Résultats — ${escapeHtml(p)}</h3>`;
    arr.forEach(it=>{
      const row = document.createElement('div');
      row.style.padding = '10px 0';
      row.style.borderTop = '1px solid rgba(255,255,255,0.04)';
      row.innerHTML = `<div style="font-weight:700">${escapeHtml(it.title||it.id||'Résultat')}</div><div style="color:rgba(255,255,255,0.7)">${escapeHtml(it.snippet||JSON.stringify(it))}</div><div style="font-size:0.8rem;color:rgba(255,255,255,0.5);margin-top:6px">Source: ${escapeHtml(it.source||p)} • ${escapeHtml(it.at||'')}</div>`;
      box.appendChild(row);
    });
    container.appendChild(box);
  });
  const dl = document.createElement('div');
  dl.style.gridColumn = '1/-1';
  dl.style.textAlign = 'center';
  dl.innerHTML = `<button class="btn solid" id="download-results">Télécharger les résultats</button>`;
  container.appendChild(dl);
  document.getElementById('download-results').addEventListener('click', ()=> downloadResults(items, query));
}

function downloadResults(items, query){
  const lines = items.map(it => `Title: ${it.title || ''}\nSource: ${it.source || ''}\nDate: ${it.at || ''}\nSnippet: ${it.snippet || JSON.stringify(it)}\n---\n`);
  const blob = new Blob([`Results for ${query}\n\n` + lines.join('\n')], {type:'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `seekdata_results_${query.replace(/\W+/g,'_')}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function escapeHtml(s){return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"})[c]);}
