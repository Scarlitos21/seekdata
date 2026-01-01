// SEEKDATA (static-adapted): interactions, animations, simulated auth + client-side search demo

// ===== API CONFIGURATION =====
const API_URL = 'https://seekdata.onrender.com';

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

  // ===== SEARCH FORM =====
  const searchForm = document.getElementById('search-form');
  if(searchForm){
    searchForm.addEventListener('submit', async e=>{
      e.preventDefault();
      const input = document.getElementById('search-input');
      const provider = document.getElementById('search-provider')?.value || '';
      const query = (input && input.value.trim()) || '';
      
      if(!query){
        showSearchMessage('Veuillez entrer une requête de recherche.', 'error');
        return;
      }
      
      if(!provider){
        showSearchMessage('Veuillez sélectionner un provider.', 'error');
        return;
      }
      
      // Block searches from homepage when not authenticated
      const token = sessionStorage.getItem('seekdata_token');
      if(!token){
        showSearchMessage('Veuillez vous connecter pour effectuer une recherche.', 'error');
        setTimeout(()=>{ window.location.href = 'login.html'; }, 800);
        return;
      }

      const results = await performSearch(query, provider);
      displayResults(results, query, provider);
    });
  }

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

      // STATIC SITE: use localStorage-based accounts only (no server)
      try{
        const users = JSON.parse(localStorage.getItem('seekdata_users') || '{}');
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
        const ip = await fetchIP();
        const now = new Date().toISOString();
        users[email].logins = users[email].logins || [];
        users[email].logins.push({at:now, ip});
        localStorage.setItem('seekdata_users', JSON.stringify(users));
        msg.textContent = 'Connexion réussie (local).';
        msg.className = 'form-msg success';
        sendLog({ event: 'login', email, method: 'local', ip });
        loginForm.reset();
        setTimeout(()=>{ updateAuthUI(); }, 100);
      }catch(err){
        console.error('Login error (static):', err);
        msg.textContent = 'Erreur lors de la connexion.';
        msg.className = 'form-msg error';
      }
    });
  }

  // Replace auth buttons if user is logged in
  function updateAuthUI(){
    const navAuth = document.querySelector('.nav-auth');
    if(!navAuth) return;
    const token = sessionStorage.getItem('seekdata_token');
    if(token){
      navAuth.innerHTML = `
        <div class="user-area">
          <button class="btn solid" id="open-dashboard">Dashboard</button>
          <div class="user-menu" id="user-menu" style="display:none;">
            <a href="dashboard.html">Mon compte</a>
            <a href="dashboard.html#subscription">Abonnement</a>
            <a href="dashboard.html#history">Historique</a>
            <a href="#" id="logout-link">Déconnexion</a>
          </div>
        </div>`;
      const btn = document.getElementById('open-dashboard');
      const menu = document.getElementById('user-menu');
      btn.addEventListener('click', ()=> window.location.href = 'dashboard.html');
      btn.addEventListener('contextmenu', e=>{ e.preventDefault(); menu.style.display = menu.style.display === 'none' ? 'block' : 'none'; });
      document.getElementById('logout-link').addEventListener('click', e=>{ e.preventDefault(); sessionStorage.removeItem('seekdata_token'); sessionStorage.removeItem('seekdata_user'); updateAuthUI(); });
    }
  }
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

  function setGridCut(){
    const loginSec = document.getElementById('login-section');
    const mask = document.querySelector('.grid-mask');
    if(!mask || !loginSec) return;
    const rect = loginSec.getBoundingClientRect();
    const top = window.scrollY + rect.top;
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

// ===== CLIENT-SIDE SEARCH HELPERS =====
async function performSearch(query, provider = ''){
  try {
    showSearchMessage('Recherche en cours...', 'info');
    const token = sessionStorage.getItem('seekdata_token');
    
    const res = await fetch(API_URL + '/api/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ query, provider })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showSearchMessage(err.message || 'Erreur serveur', 'error');
      return [];
    }

    const data = await res.json();
    showSearchMessage('', '');
    return data.results || [];
  } catch (err) {
    console.error('Search error:', err);
    showSearchMessage('Erreur de connexion au serveur', 'error');
    return [];
  }
}

// Best-effort log sender for client-side actions — no external backend on Netlify
function sendLog(payload){
  try{ console.debug('Client log (static):', payload); }catch(e){}
}

function displayResults(items, query, provider = ''){
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
    container.innerHTML = `<div class="card">Aucun résultat trouvé pour <strong>${escapeHtml(query)}</strong> avec le provider <strong>${escapeHtml(provider)}</strong></div>`;
    return;
  }
  items.forEach(it =>{
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `<h3>${escapeHtml(it.title||'Résultat')}</h3><p>${escapeHtml(it.snippet||'')}</p><p style="font-size:0.85rem;color:rgba(255,255,255,0.6)">Provider: ${escapeHtml(provider)} • Source: ${escapeHtml(it.source||'N/A')} • ${escapeHtml(it.at||'')}</p>`;
    container.appendChild(card);
  });
  const dl = document.createElement('div');
  dl.style.gridColumn = '1/-1';
  dl.style.textAlign = 'center';
  dl.innerHTML = `<button class="btn solid" id="download-results">Télécharger les résultats</button>`;
  container.appendChild(dl);
  document.getElementById('download-results').addEventListener('click', ()=> downloadResults(items, query, provider));
}

function downloadResults(items, query, provider = ''){
  const lines = items.map(it => `Title: ${it.title || ''}\nSource: ${it.source || ''}\nDate: ${it.at || ''}\nSnippet: ${it.snippet || JSON.stringify(it)}\n---\n`);
  const blob = new Blob([`Results for ${query} (Provider: ${provider})\n\n` + lines.join('\n')], {type:'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `seekdata_results_${query.replace(/\W+/g,'_')}_${provider}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function escapeHtml(s){return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"})[c]);}
