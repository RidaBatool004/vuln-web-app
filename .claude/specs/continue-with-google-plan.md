# Implementation Plan — Continue with Google (OAuth 2.0)

**Version:** 1.1.0
**Last Updated:** 2026-06-19
**Target Release Tag:** v1.0.3
**Parent Spec:** [continue-with-google.md](./continue-with-google.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)

> **Changelog:** v1.1.0 removes JWT access/refresh tokens (no `core/tokens.py`, no `/auth/token/refresh`, no `JWT_SECRET`, no logout cookie-clearing). Google login establishes the existing signed-session cookie only. The plan drops from nine phases to seven.

---

## 0. Plan Overview

This plan implements [continue-with-google.md](./continue-with-google.md): OAuth 2.0 social login via Google, with auto-create/link and graceful "not configured" degradation for a fresh clone. The work is split into **seven phases**, ordered so the app **boots cleanly after every phase** (config and schema first; the user-visible routes/button only after their dependencies exist).

**Four implementation realities, baked into this plan:**

1. **`main.py` is NOT touched.** Authlib's Starlette client uses the *existing* `SessionMiddleware` to hold the OAuth `state`/`nonce`. The new routes are auto-discovered by the existing `include_router(router)`. So VULN-4/7/8 middleware wiring stays byte-for-byte. (This also means the OAuth `state` check — not the POST-only `CSRFMiddleware` — is the flow's CSRF defense.)
2. **Both OAuth routes are GETs.** `CSRFMiddleware` and `RateLimitMiddleware` are POST-scoped, so they correctly ignore the button click, the Google redirect, and the callback. No CSRF token on the button.
3. **One auth mechanism: the existing session.** Google login writes the same `request.session` keys as `login()` and sets no other cookie. `/welcome`/`/profile` gate identically for Google and password users. **No JWT.** `/logout` is unchanged (clearing the session is a complete logout).
4. **First schema change → in-place migration.** `init_db()` creates the full table for fresh DBs *and* `ALTER TABLE ADD COLUMN`s the four new fields for an existing `vulnerable_app.db`, so a v1.0.2 clone upgrades without losing rows.

Plus: **no committed secrets** — a stdlib `.env` loader (no `python-dotenv`) feeds `os.environ`; `.env` is git-ignored; `.env.example` ships placeholders. The "Continue with Google" button is always shown and degrades to a not-configured page.

### Phase Summary

| # | Phase | Files | Goal |
|---|-------|-------|------|
| 1 | Dependencies + config + `.env` | `pyproject.toml`, `backend/pyproject.toml`, `core/config.py` (new), `.env.example` (new), `.gitignore` | Add Authlib/httpx; stdlib `.env` loader; `is_google_configured()` |
| 2 | Schema + migration | `db/session.py` | New columns, nullable `password`, idempotent `ALTER TABLE` |
| 3 | OAuth client | `core/oauth.py` (new) | Guarded Authlib `google` OIDC registration |
| 4 | OAuth service | `services/oauth_service.py` (new) | Parameterized find-link-create + unique username |
| 5 | Routes | `api/routes/auth.py` | `GET /auth/google/login`, `GET /auth/google/callback` (session login) |
| 6 | Templates + CSS | `login.html`, `signup.html`, `oauth_not_configured.html` (new), `styles.css` | Button + divider + not-configured page |
| 7 | Docs + verification | `README.md`, `CLAUDE.md`, then walk spec §10 | Tables, setup section, integration subsection, rule, hierarchy |

### Files That MUST NOT Be Modified
`backend/app/main.py`, `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/services/auth_service.py` (the three existing functions), the existing `GET /logout` handler, `frontend/templates/dashboard.html`, `frontend/templates/profile.html`, `docs/*`, prior specs/plans.

### Vulnerability-Preservation Checklist (re-confirm after every phase)
VULN-1 parameterized SQL in `oauth_service.py`; VULN-2/3 no unescaped reflection (name/picture not rendered; not-configured page static); VULN-4 `main.py` untouched, Google users authenticated by the existing `SECRET_KEY`-signed session (no new key); VULN-5 `security.py` untouched, OAuth rows have NULL password; VULN-6 no `/download/db`; VULN-7 limiter untouched; VULN-8 CSRF middleware untouched, OAuth `state` is the flow's CSRF defense.

---

## Phase 1 — Dependencies, Config Loader, `.env`

### 1.1 Goal
Add the two dependencies and a stdlib config layer that loads `.env` (if present) and exposes the OAuth settings + `is_google_configured()`.

### 1.2 Dependency edits
Add to the `dependencies` array in **both** `pyproject.toml` and `backend/pyproject.toml`:
```toml
    "authlib>=1.3.0",
    "httpx>=0.27.0",
```
Then `uv sync`. (`httpx` is Authlib's HTTP client for the Starlette integration; `itsdangerous`, already present, signs the session.)

### 1.3 `backend/app/core/config.py` (new)
```python
"""Configuration + .env loading for the OAuth feature (stdlib only).

Loads a repo-root .env file (if present) into os.environ WITHOUT adding a
python-dotenv dependency, then exposes the Google OAuth settings.

Real environment variables always win over .env values, so a deployment
that sets GOOGLE_CLIENT_ID in the real environment is never overridden by
a stale .env. Importing this module is side-effect-light and never raises
when .env is absent -- a fresh clone with no config still boots.
"""

import os

# Repo root: climb from backend/app/core/config.py up three levels.
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_ENV_PATH = os.path.join(_BASE_DIR, ".env")


def _load_dotenv(path: str) -> None:
    """Minimal KEY=VALUE .env parser. Ignores blanks and # comments, strips
    surrounding quotes, and only sets keys not already in os.environ."""
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        # A broken/unreadable .env must not crash startup.
        pass


_load_dotenv(_ENV_PATH)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI", "http://localhost:3001/auth/google/callback"
)


def is_google_configured() -> bool:
    """True only when both the client id and secret are present."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
```

### 1.4 `.env.example` (new, committed)
```bash
# Continue with Google (OAuth 2.0) — copy to .env and fill in.
# Get these from Google Cloud Console → Google Auth Platform → Clients
# → OAuth 2.0 Client ID (Web application). See README "Continue with Google — Setup".
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
# Must EXACTLY match an Authorized redirect URI in the Google console:
GOOGLE_REDIRECT_URI=http://localhost:3001/auth/google/callback
```

### 1.5 `.gitignore`
Append `.env` (keep `.env.example` tracked). Verify it is not already covered; if a broad rule exists, add an explicit `!/.env.example` negation.

### 1.6 What NOT to change in Phase 1
- **DO NOT** import `python-dotenv` or any config library — stdlib only.
- **DO NOT** add a `JWT_SECRET` or any token-signing setting — there is no JWT in this feature.
- **DO NOT** read or require any secret at import time beyond the `os.environ.get` defaults; absence must be non-fatal.
- **DO NOT** touch `main.py`.

### 1.7 Phase 1 Verification
```bash
uv sync
grep -n 'authlib\|httpx' pyproject.toml backend/pyproject.toml
cd backend && uv run python -c "from app.core import config as c; print(c.is_google_configured())" && cd ..
git check-ignore .env
```
Expected: deps present; prints `False` (no creds yet); `.env` ignored.

---

## Phase 2 — Schema + Migration (`backend/app/db/session.py`)

### 2.1 Goal
Extend `users` with `google_id`/`name`/`picture`/`auth_provider`, make `password` nullable, and migrate an existing DB in place.

### 2.2 Edit — `init_db()`
Replace the `CREATE TABLE` body and add a migration step:
```python
def init_db():
    """Create/upgrade the users table.

    Fresh DBs get the full schema below. Pre-existing DBs (e.g. from v1.0.2)
    are migrated in place: any of the four OAuth columns that are missing are
    added with ALTER TABLE. Idempotent and row-preserving.
    """
    conn = get_db()
    # password is NULLABLE: OAuth-only accounts store NULL (no bcrypt hash);
    # local accounts keep their bcrypt string. google_id is UNIQUE but
    # nullable -- SQLite allows multiple NULLs, so local users coexist.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE,
            email         TEXT,
            password      TEXT,
            google_id     TEXT UNIQUE,
            name          TEXT,
            picture       TEXT,
            auth_provider TEXT DEFAULT 'local'
        )"""
    )

    # Migrate older DBs: add any missing OAuth columns without dropping rows.
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    migrations = {
        "google_id": "ALTER TABLE users ADD COLUMN google_id TEXT",
        "name": "ALTER TABLE users ADD COLUMN name TEXT",
        "picture": "ALTER TABLE users ADD COLUMN picture TEXT",
        "auth_provider": "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local'",
    }
    for column, ddl in migrations.items():
        if column not in existing:
            conn.execute(ddl)

    conn.commit()
    conn.close()
```

> **Note:** the migration adds `google_id` *without* the `UNIQUE` keyword — SQLite cannot add a `UNIQUE` column via `ALTER TABLE`. Fresh DBs still get `UNIQUE` from the `CREATE TABLE`. For migrated DBs, uniqueness is additionally guaranteed by the service always selecting by `google_id` before insert; optionally add `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL` after the loop for a partial unique index that tolerates multiple NULLs.

### 2.3 What NOT to change in Phase 2
- **DO NOT** drop/recreate the table or delete rows. Migration is additive only.
- **DO NOT** make `password` `NOT NULL`.
- **DO NOT** change `get_db()`.

### 2.4 Phase 2 Verification
```bash
rm -f vulnerable_app.db
cd backend && uv run python -c "from app.db.session import init_db; init_db()" && cd ..
sqlite3 vulnerable_app.db "PRAGMA table_info(users);"
```
Expected: the four new columns present; re-running `init_db()` adds nothing further; a migrated old DB keeps its rows and gains the columns.

---

## Phase 3 — OAuth Client (`backend/app/core/oauth.py`, new)

### 3.1 Goal
Register the Google OIDC provider on a module-level Authlib `OAuth()`, guarded so import never crashes without creds.

### 3.2 File
```python
"""Authlib OAuth client for Google (OpenID Connect).

Uses Google's discovery document so Authlib handles the authorization
endpoint, token endpoint, JWKS, and ID-token verification (signature +
iss/aud/exp/nonce) for us. The OAuth `state` parameter Authlib stores in
the session is the CSRF defense for the callback (the POST-only
CSRFMiddleware does not -- and should not -- touch these GET routes).
"""

from authlib.integrations.starlette_client import OAuth

from app.core import config

oauth = OAuth()

# Register unconditionally: with empty creds the object still imports fine;
# the route's is_google_configured() gate prevents an actual unconfigured
# redirect, so we never reach Google with blank credentials.
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=config.GOOGLE_CLIENT_ID,
    client_secret=config.GOOGLE_CLIENT_SECRET,
    client_kwargs={"scope": "openid email profile"},
)
```

### 3.3 What NOT to change
- **DO NOT** hardcode the client id/secret — read from `config`.
- **DO NOT** add `app.add_middleware(...)` here or in `main.py`; Authlib uses the existing `SessionMiddleware`.

### 3.4 Phase 3 Verification
```bash
cd backend && uv run python -c "from app.core.oauth import oauth; print(hasattr(oauth,'google'))" && cd ..
```
Expected: prints `True` (import succeeds with no creds).

---

## Phase 4 — OAuth Service (`backend/app/services/oauth_service.py`, new)

### 4.1 Goal
Resolve a Google identity to a `users` row (find by `google_id` → link by `email` → create), all parameterized.

### 4.2 File
```python
"""Find-or-create logic for Google sign-in.

Resolution order (all parameterized -- VULN-1 stays closed):
  1. Existing Google account  -> SELECT WHERE google_id = ?
  2. Existing local account   -> SELECT WHERE email = ?  (link it)
  3. New account              -> INSERT (password NULL, auth_provider 'google')

OAuth accounts store password = NULL: there is no weak hash to leak, and the
unchanged password login() fails closed for them (verify_password(pw, None)
returns False). bcrypt (VULN-5) is untouched.
"""

import re

from app.db.session import get_db


def _sanitize(base: str) -> str:
    """Reduce an email local-part / name to a safe username seed."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", (base or "").split("@")[0])
    return cleaned or "user"


def _unique_username(conn, base: str) -> str:
    """Return `base`, or base+N for the first N that is free (parameterized)."""
    candidate = base
    suffix = 1
    while conn.execute(
        "SELECT 1 FROM users WHERE username = ?", [candidate]
    ).fetchone():
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate


def find_or_create_google_user(google_id: str, email: str, name: str, picture: str):
    """Return a dict for the resolved/created user, or None if google_id or
    email is missing (caller treats None as 'missing user information')."""
    if not google_id or not email:
        return None

    conn = get_db()
    try:
        # 1) Returning Google user.
        row = conn.execute(
            "SELECT * FROM users WHERE google_id = ?", [google_id]
        ).fetchone()
        if row:
            # Refresh display fields opportunistically (parameterized).
            conn.execute(
                "UPDATE users SET name = ?, picture = ? WHERE id = ?",
                [name, picture, row["id"]],
            )
            conn.commit()
            return dict(row)

        # 2) Existing local account with the same email -> link it.
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", [email]
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE users SET google_id = ?, name = ?, picture = ?, "
                "auth_provider = ? WHERE id = ?",
                [google_id, name, picture, "google", row["id"]],
            )
            conn.commit()
            return dict(
                conn.execute("SELECT * FROM users WHERE id = ?", [row["id"]]).fetchone()
            )

        # 3) Brand-new Google account (password NULL).
        username = _unique_username(conn, _sanitize(email or name))
        cur = conn.execute(
            "INSERT INTO users (username, email, password, google_id, name, "
            "picture, auth_provider) VALUES (?, ?, NULL, ?, ?, ?, 'google')",
            [username, email, google_id, name, picture],
        )
        conn.commit()
        return dict(
            conn.execute(
                "SELECT * FROM users WHERE id = ?", [cur.lastrowid]
            ).fetchone()
        )
    finally:
        conn.close()
```

### 4.3 What NOT to change
- **DO NOT** concatenate any value into SQL — `?` placeholders only (VULN-1).
- **DO NOT** write a password hash for OAuth accounts — store `NULL`.
- **DO NOT** modify `auth_service.py`.

### 4.4 Phase 4 Verification
```bash
grep -n 'WHERE google_id = ?\|WHERE email = ?\|INSERT INTO users' backend/app/services/oauth_service.py
cd backend && uv run python -c "
from app.db.session import init_db; init_db()
from app.services.oauth_service import find_or_create_google_user as f
u = f('gid-1','t@x.com','Tester','http://p')
print(u['auth_provider'], u['password'] is None, u['username'])
print(f('gid-1','t@x.com','Tester','http://p')['id'] == u['id'])  # idempotent
" && cd ..
```
Expected: parameterized statements match; prints `google True t` then `True`.

---

## Phase 5 — Routes (`backend/app/api/routes/auth.py`)

### 5.1 Goal
Add two GET handlers. New imports: `config`, `oauth`, `oauth_service`. (No `JSONResponse`, no `tokens` — there is no refresh endpoint.)

### 5.2 Imports to add (top of file)
```python
from app.core import config
from app.core.oauth import oauth
from app.services import oauth_service
```

### 5.3 Handlers to add (near the other auth routes)
```python
@router.get("/auth/google/login")
async def google_login(request: Request):
    """Start the OAuth 2.0 Authorization Code flow.

    If Google isn't configured, show a friendly page instead of crashing or
    redirecting nowhere (clone-and-run friendliness). Otherwise Authlib
    builds the consent URL, stashes `state`+`nonce` in the session, and 302s
    to accounts.google.com.
    """
    if not config.is_google_configured():
        with open(os.path.join(TEMPLATE_DIR, "oauth_not_configured.html"), "r") as f:
            return HTMLResponse(content=f.read())
    # state (CSRF) + nonce (replay) are stored in request.session by Authlib.
    return await oauth.google.authorize_redirect(request, config.GOOGLE_REDIRECT_URI)


@router.get("/auth/google/callback")
async def google_callback(request: Request):
    """Handle Google's redirect back to the app.

    Verifies state/code/ID-token (Authlib), resolves or creates the user,
    logs them in via the SAME session cookie the password flow uses, and
    lands on the dashboard. Every failure degrades to /login WITHOUT leaking
    details. No JWT or extra cookie is issued -- the session is the single
    auth mechanism.
    """
    # Requirement: explicit user-denied / provider error.
    if request.query_params.get("error"):
        return RedirectResponse(url="/login", status_code=302)

    try:
        # Validates state (anti-CSRF), exchanges the code, verifies the ID
        # token (signature + iss/aud/exp/nonce). Raises on any mismatch or a
        # lost session (expired) -- caught below.
        token = await oauth.google.authorize_access_token(request)
    except Exception:
        return RedirectResponse(url="/login", status_code=302)

    userinfo = token.get("userinfo") or {}
    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name", "")
    picture = userinfo.get("picture", "")

    # Missing user information -> no account created.
    user = oauth_service.find_or_create_google_user(google_id, email, name, picture)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # Log in by writing the SAME session keys as auth_service.login(). This is
    # the only auth mechanism -- SessionMiddleware signs these into the cookie.
    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["email"] = user["email"]

    return RedirectResponse(url="/welcome", status_code=302)
```

### 5.4 Line-by-Line Justification
| Block | Decision | Spec ref |
|---|---|---|
| `is_google_configured()` guard → not-configured page | Graceful degradation, no crash | FR-03, AC-02, NFR-01 |
| `authorize_redirect(request, redirect_uri)` | Authlib stores state/nonce, 302 to Google | FR-03, AC-03 |
| `query_params.get("error")` → /login | User-denied / provider error | FR-09, EC-01 |
| `try/except` around `authorize_access_token` | State mismatch / expired session / invalid token | FR-04, FR-09, EC-02 |
| `userinfo` sub/email check → /login | Missing user info, no account | FR-04, FR-09, EC-03 |
| session keys identical to `login()`; no other cookie | Single auth mechanism (session) | FR-07, NFR-02, AC-07 |
| 302 `/welcome` | Land on dashboard | FR-08 |

### 5.5 What NOT to change
- **DO NOT** add any `app.add_middleware` or edit `main.py`.
- **DO NOT** add a `/auth/token/refresh` route, a `tokens` import, or any cookie beyond the session — there is no JWT in this feature.
- **DO NOT** modify the existing `/logout` handler — clearing the session is already a complete logout.
- **DO NOT** put SQL/business logic in the handlers — use `oauth_service`.
- **DO NOT** reflect exception text into any response.
- **DO NOT** alter `index`/`signup`/`login`/`search`/`welcome`/`profile` handlers.

### 5.6 Phase 5 Verification
```bash
grep -n '@router.get("/auth/google/login")\|@router.get("/auth/google/callback")' backend/app/api/routes/auth.py
grep -n 'access_token\|refresh_token\|tokens\.' backend/app/api/routes/auth.py || echo '(no JWT/token wiring — good)'
cd backend && uv run python -c "from app.main import app; print('boot ok')" && cd ..
```
Expected: both routes present; no token wiring; boot prints `boot ok`.

---

## Phase 6 — Templates + CSS

### 6.1 Goal
Add the "Continue with Google" button + divider to `login.html` and `signup.html`, create `oauth_not_configured.html`, and style both.

### 6.2 Button block (insert after the existing `</form>` in BOTH login.html and signup.html)
```html
                <div class="auth-divider"><span>or</span></div>
                <a href="/auth/google/login" class="btn btn-google">
                    <img src="/static/images/google-g.svg" alt="" class="btn-google-icon" aria-hidden="true">
                    Continue with Google
                </a>
```
> If adding an SVG asset is undesirable, inline the Google "G" as an `<svg>` element instead of an `<img>` so no new image file is needed. Either way it is decorative (`aria-hidden`).

### 6.3 `frontend/templates/oauth_not_configured.html` (new)
A minimal static page carrying the **same** pre-paint theme `<script>`, header, and theme-toggle script as the other templates (copy from `login.html`), with a body explaining that Google login is not configured and pointing to the README "Continue with Google — Setup" section, plus a link back to `/login`. No `{{...}}` placeholders, no reflected input (VULN-2/3 N/A).

### 6.4 CSS (append to `styles.css`)
```css
/* ===================== Continue with Google ===================== */
.auth-divider {
    display: flex;
    align-items: center;
    text-align: center;
    margin: 20px 0;
    color: var(--text-muted);
    font-size: 0.85rem;
}
.auth-divider::before,
.auth-divider::after {
    content: "";
    flex: 1;
    border-bottom: 1px solid var(--card-border);
}
.auth-divider span { padding: 0 12px; }

.btn-google {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    background: var(--card-bg);
    color: var(--text-primary);
    border: 1px solid var(--card-border);
    text-decoration: none;
}
.btn-google:hover { background: var(--input-bg, var(--card-bg)); }
.btn-google-icon { width: 18px; height: 18px; }
```
> Match the actual variable names in the file's `:root` / `[data-theme="dark"]` blocks (the dashboard/profile cards already define card bg/border/text/muted). Substitute the real names if they differ.

### 6.5 What NOT to change
- **DO NOT** wrap the button in a `<form>` or add a `csrf_token` — it is a GET link.
- **DO NOT** alter the existing login/signup form, its fetch script, or the `csrf_token` hidden field.
- **DO NOT** render Google `name`/`picture` anywhere (out of scope this release).

### 6.6 Phase 6 Verification
```bash
grep -c 'href="/auth/google/login"' frontend/templates/login.html frontend/templates/signup.html
grep -c 'id="theme-toggle"' frontend/templates/oauth_not_configured.html
grep -n '.btn-google\|.auth-divider' frontend/static/css/styles.css
```
Expected: `1` per auth template; `1` toggle in the new page; CSS selectors present.

---

## Phase 7 — Docs + End-to-End Verification

### 7.1 README — Feature Enhancements row
Change feature #5 status to **Done (v1.0.3)** and trim the description to the shipped slice (OAuth 2.0 Authorization Code via Authlib; auto-create/link; session login; graceful not-configured).

### 7.2 README — API Endpoints table (add rows)
```
| GET | `/auth/google/login` | Start Google OAuth (or show setup page if unconfigured) | No |
| GET | `/auth/google/callback` | OAuth redirect URI: verify, create/link user, log in via session | No |
```

### 7.3 README — new "Continue with Google — Setup" section
Document, step by step: create a Google Cloud project → **Google Auth Platform** consent screen (App info → Audience → Contact → Finish) → publish to Production (or add Test users) → **Clients → Create client → Web application** → add `http://localhost:3001/auth/google/callback` as an Authorized redirect URI → copy `.env.example` to `.env` and fill `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` → `uv run backend/app/main.py`. Note that **without** setup the app still runs and the button shows the not-configured page, and that `.env` is git-ignored (never commit secrets). *(The reader-friendly long-form version lives in `docs/continue-with-google-explained.md`.)*

### 7.4 CLAUDE.md edits
- **Frontend-Backend Integration** subsection: "Continue with Google (OAuth 2.0)" — flow summary, **session is the single auth mechanism (no JWT)**, Authlib/state, config layer, no `main.py`/`logout` change.
- **Important Rules** entry: keep `oauth_service.py` parameterized (VULN-1) and OAuth rows' `password` NULL (VULN-5); never commit `.env`/secrets (VULN-4); OAuth routes are GETs guarded by `state`, do not route them through / weaken `CSRFMiddleware`; Google login uses the existing session only — do not add JWT/bearer tokens; don't render Google `name`/`picture` unescaped if later surfaced (VULN-2).
- **Architecture / Vulnerability Map**: note the schema change (first one) and that all 8 vulns stay closed.
- **Specification Hierarchy**: append `14. .claude/specs/continue-with-google.md + -plan.md — Continue with Google (v1.0.3 feature)`.

### 7.5 Walk spec §10
Cover: install/boot with no creds (§10.1), not-configured page (§10.2), buttons (§10.3), schema migration (§10.4), **[needs creds]** configured redirect (§10.5) and full sign-in/logout (§10.6), preservation + file audit (§10.7), affected-files audit (§10.8). For the credential-gated paths without real Google creds, exercise the service layer directly (Phase 4.4) and the not-configured HTTP path; record that the live Google round-trip requires `.env` credentials.

### 7.6 Phase 7 Verification
```bash
grep -n 'Continue with Google' README.md CLAUDE.md
grep -n '/auth/google/callback' README.md
grep -n 'continue-with-google.md' CLAUDE.md
```
Expected: each grep matches.

### AC Roll-Up (spec §8)
- [ ] AC-01 buttons (6.6) · AC-02 not-configured (§10.2) · AC-03 redirect (§10.5) · AC-04 new user (§10.6/4.4) · AC-05 returning (4.4) · AC-06 link (4.4) · AC-07 session-only cookie (5.6/§10.6) · AC-08 logout unchanged (§10.7) · AC-09 errors (5.4) · AC-10 parameterized (4.4) · AC-11 schema (§10.4) · AC-12 unchanged files (§10.7) · AC-13 no committed secret (§10.7) · AC-14 deps/boot (1.7/5.6) · AC-15 docs (7.6) · AC-16 vulns preserved (§10.7)

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Importing OAuth/config crashes a fresh clone with no creds | Med | High | Guarded register + `is_google_configured()` gate + non-fatal `.env` loader; Phase 1.7/3.4 boot checks |
| Editing `main.py` to "wire" OAuth → risks VULN-4/7/8 | Low | High | Authlib uses existing SessionMiddleware; Phase 5.5 MUST-NOT; §10.7 asserts `main.py` diff empty |
| String-concatenated SQL slips into `oauth_service` → re-opens VULN-1 | Low | High | Phase 4 uses `?`; Phase 4.4 + §10.7 greps |
| Committing a real `.env`/secret | Med | High | `.env` git-ignored (Phase 1.5); `.env.example` placeholders only; §10.7 secret grep |
| `ALTER TABLE` can't add a UNIQUE column on migrated DBs | Med | Low | Documented; partial unique index option; service always SELECTs by `google_id` before INSERT |
| Rendering Google name/picture later without escaping → VULN-2 | Low | Med | Not rendered this release; CLAUDE rule added (7.4) for future specs |
| `redirect_uri` mismatch with the Google console → callback fails | Med | Med | `.env.example` + README setup spell out the exact URI; error path degrades to /login |

---

## Rollback Procedure
```bash
git restore backend/app/db/session.py backend/app/api/routes/auth.py \
  frontend/templates/login.html frontend/templates/signup.html \
  frontend/static/css/styles.css .gitignore pyproject.toml backend/pyproject.toml \
  README.md CLAUDE.md
rm -f backend/app/core/config.py backend/app/core/oauth.py \
  backend/app/services/oauth_service.py frontend/templates/oauth_not_configured.html .env.example
uv sync   # drops authlib/httpx again
```
The schema migration is additive (extra nullable columns); existing rows are untouched, so reverting the code leaves a harmless superset DB. To fully reset the data layer: `rm vulnerable_app.db` and restart.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do
- **No JWT / access tokens / refresh tokens / bearer auth** — Google login uses the existing signed-session cookie only (one cookie for everyone).
- No "Continue with GitHub" (separate future spec, feature #6).
- No avatar/name rendering (stored only, this release).
- No account-unlink / multi-provider table.
- No `main.py` edit, no `/logout` edit, no new middleware, no middleware re-ordering.
- No change to `signup()`/`login()`/`change_password()`/`/search`/`/welcome`/`/profile`.
- No change to `security.py`/`csrf.py`/`rate_limit.py`.
- No committed secrets; no `python-dotenv` dependency.
- No reversal of any prior fix — VULN-1 through VULN-8 stay closed.
