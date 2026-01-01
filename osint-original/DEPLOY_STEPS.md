# Étapes de déploiement complet — Frontend (Netlify) + Admin (Local)

## ✅ Résumé rapide

Ton site **fonctionne 100% en client-side (localStorage)**. Aucun serveur nécessaire pour tester. Voici comment faire :

---

## 1) **Étape 1 : Générer le package frontend**

Depuis PowerShell, dans le dossier `c:\Users\userl\Documents\Forge Projet\osintlabs\Sites` :

```powershell
cd "c:\Users\userl\Documents\Forge Projet\osintlabs\Sites"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\build_deploy.ps1
```

Ça crée un dossier `deploy/` contenant :
- Tous les fichiers HTML (`index.html`, `login.html`, `register.html`, `features.html`, etc.)
- `seeknow.css` (fichier root)
- `assets/` (CSS, JS, images)
- `netlify.toml` (config Netlify)

---

## 2) **Étape 2 : Tester localement**

### Option A — Serveur HTTP simple (Python)

```powershell
# Navigue vers le dossier deploy
cd "c:\Users\userl\Documents\Forge Projet\osintlabs\Sites\deploy"

# Lance un serveur HTTP
python -m http.server 8000
# Accède à http://localhost:8000 dans le navigateur
```

### Option B — VS Code Live Server
- Installe l'extension "Live Server" dans VS Code
- Clic droit sur `deploy/index.html` → "Open with Live Server"
- Teste le site sur le port proposé (généralement http://127.0.0.1:5500)

---

## 3) **Étape 3 : Fonctionnalités principales testées**

### Créer un compte
1. Va sur `http://localhost:8000/register.html`
2. Remplis le formulaire → "Créer un compte"
3. Le compte est sauvegardé dans `localStorage` (browser storage)
4. Un log `user_registered` est enregistré

### Se connecter
1. Va sur `http://localhost:8000/login.html`
2. Rentre l'email et le mot de passe du compte créé
3. Token sauvegardé dans `sessionStorage` (durée de la session)
4. Un log `user_login` est enregistré

### Effectuer une recherche
1. Après connexion, va sur `http://localhost:8000` (home)
2. Tape une requête dans le champ "Rechercher"
3. Les résultats sont simulés côté client
4. Un log `search_performed` est enregistré

### Accéder à l'admin
1. Ouvre `c:\Users\userl\Documents\Forge Projet\osintlabs\Sites\osint-original\admin\index.html` directement dans le navigateur
2. Login admin (credentials simulés, utilise n'importe quoi pour les tests)
3. Voir la section **"Logs & Audit"** → affiche tous les logs depuis `localStorage` (user_registered, user_login, search_performed, etc.)

---

## 4) **Système de Logs expliqué**

Tous les logs sont stockés dans **`localStorage`** sous la clé `SeekData_logs` (tableau JSON).

### Types de logs enregistrés :
- **`user_registered`** — création de compte (email, username)
- **`user_login`** — connexion réussie (email, ip)
- **`login_failed`** — tentative échouée (email, reason: 'account_not_found' ou 'wrong_password')
- **`search_performed`** — recherche effectuée (query, results_count)
- **`search_blocked`** — recherche bloquée (pas authentifié)
- **`registration_error`** — erreur lors de l'inscription (email, error message)

### Voir les logs :
- **Dans l'admin panel** : section "Logs & Audit" (affiche les 500 derniers logs)
- **En console** : les logs sont affichés avec `[LOG]` dans la console du navigateur
- **En localStorage directement** : ouvre la console (F12) → "Application" → "Local Storage" → "SeekData_logs"

---

## 5) **Système d'authentification (localStorage)**

### Registration (register.html)
```
Email + Password → SHA256(password) → sauvegardé dans localStorage['SeekData_users']
Exemple : {email: {email, username, pw_hash, created_at, logins: [...]}}
```

### Login (login.html)
```
Email + Password → SHA256(password) → comparé avec pw_hash dans localStorage
Si match → sessionStorage['seekdata_token'] créé
Token utilisé pendant la session pour vérifier l'auth
```

---

## 6) **Déployer sur Netlify**

Quand tu es prêt(e) :

1. **Créer un compte Netlify** : https://app.netlify.com
2. **Uploader le package** :
   - Glisse-dépose le dossier `deploy/` sur https://app.netlify.com/drop
   - Ou connecte un repo GitHub
3. **Vérifier le domaine** :
   - Netlify te donne une URL : `https://votre-site.netlify.app`
   - Teste le login, register, et logs là-bas

---

## 7) **Fichiers importants**

| Fichier | Rôle |
|---------|------|
| `register.html` | Créer un compte (localStorage) |
| `login.html` | Se connecter (localStorage) |
| `seeknow.js` | Interactions frontend, logs |
| `seeknow.css` | Styles principaux |
| `admin/index.html` | Panel admin (affiche logs) |
| `admin/app.js` | Logique admin (loadLogs) |
| `build_deploy.ps1` | Script pour générer le package |

---

## 8) **Résolution des problèmes**

### "Le CSS ne charge pas"
→ Assure-toi que `seeknow.css` est dans le dossier `deploy/` (pas dans un sous-dossier)
→ Les liens HTML doivent être `<link href="seeknow.css?v=1" />`

### "Je ne peux pas me connecter après avoir créé un compte"
→ Vérifie que `localStorage` n'est pas vidé (par les paramètres de confidentialité du navigateur)
→ Ouvre la console (F12) et recherche les erreurs JavaScript

### "Les logs ne s'affichent pas dans l'admin"
→ Va dans Admin Panel → "Logs & Audit"
→ Les logs sont chargés depuis `localStorage['SeekData_logs']`
→ Assure-toi que tu as bien créé un compte et te connecté (ça crée des logs)

### "Le formulaire dit 'Erreur: ... is not valid JSON'"
→ C'était un bug qui a été fixé. Assure-toi que tu utilises les fichiers mis à jour.

---

## 9) **Prochaines étapes optionnelles**

### Pour un vrai backend (serveur Node.js + Render)
- Créer des routes `/api/register` et `/api/login` sur `server.js`
- Modifier `register.html` et `login.html` pour appeler l'API
- Déployer `server/` sur Render
- Les logs seraient alors stockés côté serveur (plus sécurisé)

### Pour protéger l'admin
- Ajouter une authentification JWT côté serveur
- Ou un Basic Auth simple (username/password)
- Voir le fichier `admin/app.js` pour l'implémentation

---

## 10) **Contact & Support**

Si tu as des questions sur le déploiement :
1. Vérifie que tous les fichiers sont dans `deploy/`
2. Teste localement d'abord (étape 2)
3. Puis déploie sur Netlify (étape 6)

---

**Status : ✅ Prêt à déployer**
Tous les fichiers (HTML, CSS, JS) sont à jour. Les logs fonctionnent. L'admin affiche les logs.

