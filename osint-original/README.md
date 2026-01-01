# SEEKDATA local dev

This workspace includes a lightweight Node server to persist admin logs and handle demo admin login.

Start the server and open the site:

```powershell
cd "c:\Users\userl\Documents\Forge Projet\osintlabs\Sites\osint-original\server"
npm install express bcrypt cors
node server.js
```

Then open:

- http://localhost:3000/seeknow.html (site)
- http://localhost:3000/admin/ (admin panel)

Admin credentials are stored in `server/admin_credentials.json`. Default: `admin` / `admin`.

Notes:
- This server is a minimal local demo. Do not expose it publicly.
- Logs are persisted to `server/logs.json`.
