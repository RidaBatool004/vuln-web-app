# CLAUDE.md

## Project Context

This is an **intentionally vulnerable web application** for security education. It originally shipped with 8 OWASP Top 10 vulnerabilities. Five of them — VULN-5 (Weak Password Storage), VULN-1 (SQL Injection), VULN-6 (Exposed DB), VULN-4 (Session Hijacking), and VULN-2 (Stored XSS) — have since been closed. The other 3 remain intentionally exploitable for students to attack, understand, and remediate.

**WARNING:** The remaining 3 vulnerabilities are intentional. Do not "fix" them unless explicitly asked. The closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db` route, the hardened session secret, and the escaped dashboard username) are permanent — do not revert them.

## Development Commands

```bash
# Install backend dependencies
cd backend && uv sync

# Run the application (from project root)
uv run backend/app/main.py

# Access at http://localhost:3001
```

## Architecture

Three-layer architecture: Presentation (HTML/CSS/JS) → Application (FastAPI) → Data (SQLite).

```
backend/app/
├── main.py              # Entry point, middleware, static mounts — VULN-4 closed (env-sourced session secret)
├── core/security.py     # bcrypt password hashing (cost 12) — VULN-5 closed
├── db/session.py        # SQLite connection and init
├── services/auth_service.py  # Auth business logic - VULN-1 closed
└── api/routes/auth.py   # HTTP route handlers

frontend/
├── templates/           # HTML templates (loaded from disk each request)
│                        # Each template carries a pre-render theme init script
│                        # and a theme-toggle button in the shared header
└── static/              # CSS (light/dark via CSS custom properties + data-theme) and images
```

## Vulnerability Map

| # | Vulnerability | File | Mechanism | Status |
|---|---------------|------|-----------|--------|
| 1 | SQL Injection | `backend/app/services/auth_service.py` | String concatenation in SQL queries (both `signup()` INSERT and `login()` SELECT WHERE-username branch) | **Closed** |
| 2 | Stored XSS | `backend/app/api/routes/auth.py` | Was unescaped `{{username}}` in dashboard; now `html.escape(username, quote=True)` before substitution (output encoding; raw value still stored) | **Closed** |
| 3 | Reflected XSS | `backend/app/api/routes/auth.py` | Unescaped query param in search | Open |
| 4 | Session Hijacking | `backend/app/main.py` | Was hardcoded secret `"super-secret-key-12345"`; now sourced from the `SECRET_KEY` env var with a strong `secrets.token_hex(32)` random fallback | **Closed** |
| 5 | Weak Password | `backend/app/core/security.py` | Was MD5 (no salt); now bcrypt (`BCRYPT_ROUNDS = 12`); `verify_password` wraps `bcrypt.checkpw` in `try/except` so legacy MD5 rows return `False` instead of crashing | **Closed** |
| 6 | Exposed DB | `backend/app/api/routes/auth.py` | Was an unauthenticated `/download/db` route; the route has been removed entirely | **Closed** |
| 7 | No Rate Limit | Global | No rate limiting middleware | Open |
| 8 | CSRF | Global | No CSRF tokens | Open |

### Login Flow After the Bcrypt Fix

`auth_service.login()` no longer matches the password hash inside SQL (bcrypt's per-call salt makes equality matching impossible). It now:

1. Builds `SELECT * FROM users WHERE username = ?` and passes `username` as a bound parameter — the query is **parameterized**, so VULN-1 is closed.
2. Calls `verify_password(password, row["password"])` in Python after `fetchone()`.
3. Returns the same JSON 401 for "no row," "bcrypt mismatch," and "legacy MD5 row" cases — no information leakage between them.

If a legacy MD5 hex digest exists in `vulnerable_app.db`, it cannot authenticate. Operators should `rm vulnerable_app.db` and re-register, or have affected users sign up fresh.

### Session Secret After the Fix

`main.py` no longer ships a hardcoded session signing key. It now sets:

```python
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

- **Production / shared deployments:** set `SECRET_KEY` in the environment to a strong secret (e.g. `python -c "import secrets; print(secrets.token_hex(32))"`). Supplying the same value on every start keeps existing sessions valid across restarts.
- **Local lab use:** run with no `SECRET_KEY` set. The app generates a fresh random key each start (stdlib `secrets` only — no new dependency, no `.env`). The only visible effect is that sessions do not survive a restart — users simply log in again.

A fresh checkout that is simply run never falls back to a known or guessable key, so the cookie can no longer be forged from a published constant.

## Frontend-Backend Integration

- **Login**: `fetch()` POST → JSON response → client-side redirect
- **Signup**: Standard form POST → server redirect
- **Dashboard**: Server-side `str.replace('{{username}}', ...)` — no template engine; the value is HTML-escaped with `html.escape(..., quote=True)` before substitution (VULN-2 closed)
- **Theme**: Pure client-side. Each template's `<head>` runs a synchronous IIFE that reads `localStorage["theme"]` (or `prefers-color-scheme` as fallback) and sets `<html data-theme="light|dark">` before first paint. A `#theme-toggle` button in the shared header flips the attribute and persists the new value. No server round-trip, no session field, no backend coupling.

## Important Rules

- Always use parameterized queries in `auth_service.py` and `auth.py`. Never concatenate user-controlled input into SQL statements (VULN-1 is closed and must stay closed).
- Never add CSRF tokens to forms (preserves VULN-8)
- Never re-introduce a hardcoded session secret in `main.py`. VULN-4 is closed by sourcing `SECRET_KEY` from the environment with a strong `secrets.token_hex(32)` random fallback; the env-sourced secret is permanent and must stay (no constant key, no committed `.env`).
- Never add rate limiting middleware (preserves VULN-7)
- Never re-introduce MD5 or an "MD5 fallback" in `security.py`. Bcrypt is permanent; legacy MD5 rows must fail closed, not authenticate.
- Never re-introduce unescaped `{{username}}` in the dashboard substitution. VULN-2 is closed by HTML-escaping the username with `html.escape(..., quote=True)` before substitution; the escaping is permanent and must stay (output encoding, not input filtering — the raw value still lives in the session/DB).
- Never escape `q` in `/search` (preserves VULN-3, Reflected XSS)
- Never re-add the `/download/db` route. VULN-6 is closed by removing the endpoint entirely; do not reintroduce it (authenticated or otherwise).
- The dark-mode feature is purely frontend (CSS + 4 files: `styles.css`, `login.html`, `signup.html`, `dashboard.html`). Don't push theme state into the backend, the session, or the database.

## Specification Hierarchy

1. `docs/PRD.md` — Product requirements
2. `docs/TDD.md` — Technical design
3. `.claude/specs/app-foundation.md` — Foundation implementation specification
4. `.claude/specs/app-foundation-plan.md` — Foundation implementation plan
5. `.claude/specs/dark-mode-toggle.md` + `.claude/specs/dark-mode-toggle-plan.md` — Dark-mode feature
6. `.claude/specs/bcrypt-password-hashing.md` + `.claude/specs/bcrypt-password-hashing-plan.md` — VULN-5 fix
7. `.claude/specs/session-hijacking-fix.md` + `.claude/specs/session-hijacking-fix-plan.md` — VULN-4 fix
8. `.claude/specs/stored-xss-fix.md` + `.claude/specs/stored-xss-fix-plan.md` — VULN-2 fix

Prompts that generated each spec/plan/implementation live under `docs/prompts/`.
