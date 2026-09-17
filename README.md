# Cash Mode / LIVE Rewards — File Authentication

This build uses **no MongoDB and no external database**. Accounts are stored in `data/users.json` and active login sessions in `data/sessions.json`. Passwords are bcrypt-hashed.

## Render
Build: `npm install`
Start: `npm start`

Environment variables (optional):
- `ADMIN_USERNAME` (default `uk0wme`)
- `ADMIN_PASSWORD` (default `ilobyou`)
- `SESSION_SECRET` (recommended random secret)
- `AUTH_DATA_DIR` (use `/var/data` when a Render persistent disk is mounted)
- `FRONTEND_URL` (only needed for a separately hosted frontend)
- `COOKIE_SAMESITE` (`lax` for same-site; `none` for HTTPS cross-site frontend)

No `MONGO_URI` is required.

## Authentication endpoints
- `GET /health`
- `POST /api/auth/login`
- `GET /api/auth/status`
- `POST /api/auth/logout`
- `GET /api/users` (admin)
- `POST /api/users` (admin)
- `DELETE /api/users/:id` (admin)
