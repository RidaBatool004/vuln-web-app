# Software Specification Document — Continue with Google (OAuth 2.0)

**Version:** 1.1.0
**Last Updated:** 2026-06-19
**Target Release Tag:** v1.0.3
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [Continue with Google (OAuth 2.0) — README "Feature Enhancements" #5](https://github.com/arifpucit/vuln-web-app/issues)

> **Changelog:** v1.1.0 removes JWT access/refresh tokens entirely. Google login now establishes the **same signed-session cookie** the password flow already uses — one auth mechanism, one cookie, no second token system. (The earlier v1.0.0 draft minted additive JWTs; that was dropped as redundant.)

---

## 1. Overview / Purpose

This document specifies the **Continue with Google** enhancement — item #5 in the README's "Feature Enhancements" table. It adds a **social-login** path alongside the existing username/password flow: a visitor clicks **"Continue with Google"** on the login or signup page, authenticates with Google via the **OAuth 2.0 Authorization Code flow (OpenID Connect)**, and is returned to the app already logged in. New Google users get an account created automatically; returning users (or local users with a matching email) are logged into their existing account.

This is the project's **first OAuth feature** and its **first database-schema change**. It is implemented as a **secure** feature — it adds no new vulnerability and keeps all eight closed vulnerabilities closed. Concretely:

- **OAuth 2.0 Authorization Code flow** via [Authlib](https://docs.authlib.org/) (`authlib.integrations.starlette_client`), using Google's OpenID Connect discovery document. Authlib performs the `state` (anti-CSRF) check, the code↔token exchange, and **ID-token signature/`iss`/`aud`/`exp`/`nonce` verification** for us.
- **One auth mechanism: the existing signed session.** On success the Google callback writes the **same** `request.session` keys (`user_id`, `username`, `email`) that `auth_service.login()` already writes. So `/welcome` and `/profile` gate Google users and password users **identically**, with the **same single session cookie**. No JWT, no access/refresh tokens, no second cookie, no new signing key.
- **Credentials are never committed.** `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` are read from environment variables, optionally via a **git-ignored `.env`** file loaded by a tiny stdlib loader. A committed `.env.example` documents the shape. A fresh clone with **no** Google credentials still runs perfectly: the password flow is untouched, and clicking "Continue with Google" lands on a friendly **"Google login is not configured"** page that points at the README setup section.

The feature is built on the project's existing primitives wherever possible, but — unlike every prior feature — it **does** add dependencies (Authlib + its HTTP client `httpx`) and **does** change the database schema (four new columns on `users`, `password` made nullable). Both departures are inherent to OAuth and are called out explicitly below.

The implementation touches:

- New: `backend/app/core/config.py` (env/`.env` loader + OAuth settings), `backend/app/core/oauth.py` (Authlib client), `backend/app/services/oauth_service.py` (find-or-create user), `frontend/templates/oauth_not_configured.html`, `.env.example`.
- Modified: `backend/app/db/session.py` (schema + lightweight migration), `backend/app/api/routes/auth.py` (two new GET handlers), `frontend/templates/login.html` + `frontend/templates/signup.html` (the button), `frontend/static/css/styles.css` (button + divider), `.gitignore` (`.env`), `pyproject.toml` + `backend/pyproject.toml` (deps), `README.md` + `CLAUDE.md` (docs).

**`backend/app/main.py` is NOT modified** — Authlib rides on the existing `SessionMiddleware`, and the new routes are auto-discovered by the existing `include_router(router)`. The middleware stack (VULN-4 / VULN-7 / VULN-8) stays byte-for-byte. **`GET /logout` is NOT modified either** — it already `request.session.clear()`s, which is all that's needed now that there is no extra token cookie.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Config layer** (`core/config.py`): load `.env` (if present) into `os.environ` with a stdlib parser (no new dependency), then expose `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` (default `http://localhost:3001/auth/google/callback`), and `is_google_configured()` → `bool(client_id and client_secret)`.
- **OAuth client** (`core/oauth.py`): a module-level Authlib `OAuth()` with a `google` provider registered from Google's OIDC discovery URL (`https://accounts.google.com/.well-known/openid-configuration`) and scope `openid email profile`. Registration is guarded so importing the module without credentials does not crash the app.
- **OAuth service** (`services/oauth_service.py`): `find_or_create_google_user(google_id, email, name, picture)` → returns a user row dict. Resolution order, all with **parameterized** SQL: (1) match by `google_id`; (2) else match by `email` and **link** (set `google_id`/`name`/`picture`/`auth_provider`); (3) else **create** a new row (`auth_provider='google'`, `password=NULL`, a unique generated `username`). Plus `_unique_username(conn, base)` to de-collide generated usernames against the `UNIQUE` constraint.
- **Routes** (added to `api/routes/auth.py`):
  - `GET /auth/google/login` — if `not is_google_configured()`, render `oauth_not_configured.html` (HTTP 200). Else `await oauth.google.authorize_redirect(request, redirect_uri)` (Authlib stores `state`+`nonce` in the session and 302s to Google).
  - `GET /auth/google/callback` — exchange + verify via `await oauth.google.authorize_access_token(request)`, extract `userinfo`, call the service, populate the **session** (`user_id`/`username`/`email`), and 302 to `/welcome`. Full error handling per §FR-09.
- **Templates**: a **"Continue with Google"** button (a styled `<a href="/auth/google/login">`, **not** a form POST — so no CSRF token needed) plus an `or` divider, added to both `login.html` and `signup.html`. A new `oauth_not_configured.html` page.
- **CSS**: `.btn-google` (with the Google "G" mark) and `.auth-divider` rules, theme-aware via existing `var(--...)` custom properties.
- **Schema** (`db/session.py`): the `users` table gains `google_id TEXT UNIQUE`, `name TEXT`, `picture TEXT`, `auth_provider TEXT DEFAULT 'local'`; `password` becomes nullable (`TEXT NULL`). `init_db()` keeps creating the full table for fresh DBs **and** runs a tiny idempotent migration (`PRAGMA table_info` → `ALTER TABLE ADD COLUMN`) so an existing `vulnerable_app.db` is upgraded in place without data loss.
- **Dependencies**: add `authlib` and `httpx` to `pyproject.toml` and `backend/pyproject.toml`; `uv sync`.
- **Config files**: commit `.env.example`; add `.env` to `.gitignore`.
- **Docs**: README — move feature #5 to "Done (v1.0.3)", add the new endpoints to the API table, add a **"Continue with Google — Setup"** section (Google Cloud Console steps + env config). CLAUDE.md — integration subsection, Important-Rules entry, schema-change note, spec-hierarchy entry.

### 2.2 Out of Scope (Intentionally)

- **No JWT, no access/refresh tokens, no bearer tokens.** Google login uses the existing signed-session cookie only — the same mechanism, the same single cookie, as password login. (This was explicitly removed; see the changelog.)
- **No avatar/name rendering this release.** The `picture` and `name` are **retrieved and stored** (requirements #4/#5) but are **not** displayed on the dashboard or profile page in v1.0.3 — surfacing them would touch `dashboard.html`/`profile.html` rendering and conditional-image logic. A future spec can surface the avatar; this release keeps the UI change surgical (one button per auth page).
- **No "Continue with GitHub".** That is README feature #6, a separate future spec that will reuse this scaffolding.
- **No account-unlink, no "disconnect Google", no multi-provider-per-user table.** Linking is one-directional (Google → existing local email). The schema stores a single `google_id` per user.
- **No email-verification gate.** Google already verifies the email; `email_verified` from the ID token is trusted but no extra verification email is sent (that is README feature #3).
- **No change to the local password flow.** `signup()` / `login()` / `change_password()` in `auth_service.py` are byte-for-byte unchanged. A Google-only account (NULL password) simply cannot log in via the password form — `verify_password(pw, None)` returns `False` (it already fails closed), so no code change is needed there.
- **No new middleware, no middleware re-ordering, no `main.py` edit, no `/logout` edit.** Authlib uses the existing `SessionMiddleware`; logout already clears the session.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** every statement in `oauth_service.py` (SELECT by `google_id`, SELECT by `email`, the link `UPDATE`, the create `INSERT`, the unique-username `SELECT`) uses `?` placeholders. `signup()` / `login()` / `change_password()` / `/search` keep their parameterized queries byte-for-byte.
- **VULN-2 (Stored XSS):** `welcome_page` / `profile_page` keep escaping rendered user values with `html.escape(..., quote=True)`. The Google `name`/`picture` are not rendered this release; if a later spec renders them, they MUST be escaped on output.
- **VULN-3 (Reflected XSS):** `/search` is untouched. The `oauth_not_configured.html` page is static (no reflected input). Any error message rendered by the callback is a fixed string, never reflected attacker input.
- **VULN-4 (Session Hijacking):** `main.py` keeps sourcing `SECRET_KEY` from the environment with a random fallback, and is **not modified**. The session cookie that authenticates Google users is signed by that same `SECRET_KEY` — no new signing key, no hardcoded secret is introduced.
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged. OAuth accounts store `password=NULL` (no weak hash); local accounts keep bcrypt. No MD5, no fallback.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added. The new schema columns do not expose the DB file.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered. The OAuth routes are GETs (the limiter is POST-scoped), so they are not throttled — which is correct (the Google round-trip and the `state` check already gate abuse). `main.py` / `core/rate_limit.py` unchanged.
- **VULN-8 (CSRF):** `CSRFMiddleware` stays registered and unchanged. The OAuth flow's CSRF defense is the OAuth **`state`** parameter (validated by Authlib in `authorize_access_token`). The "Continue with Google" button is a GET link, so the POST-scoped CSRF middleware correctly ignores it; no token is needed on the button.

### 2.4 Explicit Non-Goals

- No template engine / build step / JS framework. The button is a plain anchor; `oauth_not_configured.html` uses the same static-HTML + theme-script pattern as the other pages.
- No downloading/caching the Google profile image — only the hosted URL string is stored.
- No proxy-header trust changes.

---

## 3. Affected Files

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/config.py` | **New** | stdlib `.env` loader + OAuth settings + `is_google_configured()` |
| `backend/app/core/oauth.py` | **New** | Authlib `OAuth()` with the guarded `google` OIDC client |
| `backend/app/services/oauth_service.py` | **New** | `find_or_create_google_user()` (parameterized find-link-create) + unique-username helper |
| `frontend/templates/oauth_not_configured.html` | **New** | Friendly "Google login not configured — see README" page |
| `.env.example` | **New** | Committed template for `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URI` |
| `backend/app/db/session.py` | Modified | New columns on `users`; nullable `password`; idempotent `ALTER TABLE` migration |
| `backend/app/api/routes/auth.py` | Modified | Add `GET /auth/google/login` and `GET /auth/google/callback` |
| `frontend/templates/login.html` | Modified | Add the "Continue with Google" button + divider |
| `frontend/templates/signup.html` | Modified | Add the "Continue with Google" button + divider |
| `frontend/static/css/styles.css` | Modified | `.btn-google` + `.auth-divider` rules (theme-aware) |
| `.gitignore` | Modified | Ignore `.env` (never commit real secrets) |
| `pyproject.toml` | Modified | Add `authlib`, `httpx` |
| `backend/pyproject.toml` | Modified | Add `authlib`, `httpx` |
| `README.md` | Modified | Feature row → Done (v1.0.3); API rows; "Continue with Google — Setup" section |
| `CLAUDE.md` | Modified | Integration subsection, Important-Rules entry, schema-change note, spec hierarchy |

Files that MUST NOT be modified:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / port (VULN-4 / VULN-7 / VULN-8). Routes auto-included; Authlib uses the existing `SessionMiddleware`.
- `backend/app/core/security.py` — bcrypt (VULN-5).
- `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py` — VULN-8 / VULN-7 middleware.
- `backend/app/services/auth_service.py` — `signup()` / `login()` / `change_password()` / `password_meets_policy()` stay byte-for-byte.
- `frontend/templates/dashboard.html`, `frontend/templates/profile.html` — no avatar/name rendering this release.
- The existing `GET /logout` handler — unchanged (it already clears the session).
- `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, every prior spec/plan pair.

---

## 4. Functional Requirements

### FR-01: Configuration Detection & `.env` Loading
- `core/config.py` MUST, at import, load a `.env` file from the repo root **if it exists**, using a stdlib parser (`KEY=VALUE` lines, `#` comments, ignore blanks), setting only keys not already present in `os.environ` (real env vars win). It MUST NOT require `python-dotenv`.
- It MUST expose `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI` (default `http://localhost:3001/auth/google/callback`), and `is_google_configured()` returning `True` only when both client id and secret are non-empty.

### FR-02: OAuth Client Registration (Guarded)
- `core/oauth.py` MUST register a `google` provider on a module-level `OAuth()` using `server_metadata_url="https://accounts.google.com/.well-known/openid-configuration"`, `client_id`/`client_secret` from config, and `client_kwargs={"scope": "openid email profile"}`.
- Importing `core/oauth.py` MUST NOT raise when credentials are absent; the route's `is_google_configured()` gate prevents an actual unconfigured redirect.

### FR-03: `GET /auth/google/login`
- If `not is_google_configured()`, the handler MUST load and return `oauth_not_configured.html` (HTTP 200) — it MUST NOT redirect to Google or raise.
- Otherwise it MUST call `await oauth.google.authorize_redirect(request, GOOGLE_REDIRECT_URI)` and return the resulting 302. Authlib stores the `state` and `nonce` in `request.session`.

### FR-04: `GET /auth/google/callback` — Token Exchange & Verification
- The handler MUST call `token = await oauth.google.authorize_access_token(request)`, which validates the `state` (anti-CSRF), exchanges the authorization code, and verifies the ID token (signature via Google JWKS, plus `iss`/`aud`/`exp`/`nonce`).
- It MUST read the verified profile from `token["userinfo"]` (or `token.get("userinfo")`): `sub` (Google ID), `email`, `name`, `picture`, `email_verified`.

### FR-05: Find-or-Create (Account Resolution)
- `find_or_create_google_user(google_id, email, name, picture)` MUST resolve, with parameterized SQL, in this order:
  1. `SELECT * FROM users WHERE google_id = ?` → if found, return it (optionally refresh `name`/`picture`).
  2. Else `SELECT * FROM users WHERE email = ?` → if found, **link**: `UPDATE users SET google_id = ?, name = ?, picture = ?, auth_provider = ? WHERE id = ?` and return it.
  3. Else **create**: `INSERT INTO users (username, email, password, google_id, name, picture, auth_provider) VALUES (?, ?, NULL, ?, ?, ?, 'google')` with a unique generated username (FR-06), and return the new row.

### FR-06: Username Generation
- A new Google account's `username` MUST be derived from the email local-part (or `name`, sanitized to `[A-Za-z0-9_]`), and MUST be de-collided against the `UNIQUE(username)` constraint by appending an integer suffix (`alice`, `alice1`, `alice2`, …) using a parameterized existence check.

### FR-07: Session Login (Single Auth Mechanism)
- On success the callback MUST set `request.session["user_id"]`, `request.session["username"]`, and `request.session["email"]` from the resolved row — exactly the keys `login()` sets — so `/welcome` and `/profile` gate Google users identically to password users, using the **same single session cookie**. Existing session keys (e.g. `csrf_token`) MUST be preserved (merge, not replace).
- The callback MUST NOT set any additional auth cookie or token.

### FR-08: Redirect to Dashboard
- After populating the session, the callback MUST return `RedirectResponse(url="/welcome", status_code=302)`.

### FR-09: Error Handling
The callback MUST handle, each with a graceful, non-leaking response (a 302 back to `/login` with no reflected attacker input):
- **Authentication failure / user-denied:** Google returns `?error=...` (e.g. `access_denied`) → redirect to `/login`.
- **Invalid token / state mismatch / expired session:** `authorize_access_token` raises `OAuthError` (or `MismatchingStateError`) — e.g. the `state`/`nonce` is gone because the session expired between redirect and callback → catch and redirect to `/login`.
- **Missing user information:** `userinfo` lacks `email` or `sub` → do NOT create an account; redirect to `/login`.
The underlying exception text MUST NEVER be reflected to the client.

### FR-10: "Continue with Google" Button
- `login.html` and `signup.html` MUST each contain a styled `<a href="/auth/google/login" class="btn btn-google">` with a visible "Continue with Google" label and the Google "G" mark, plus an `or` divider separating it from the existing form. The button MUST be a GET link (no form, no `csrf_token`).
- The button is **always rendered**; when Google is not configured, clicking it lands on `oauth_not_configured.html`.

### FR-11: Logout (Unchanged)
- `GET /logout` MUST remain byte-for-byte unchanged: `request.session.clear()` + 302 to `/login`. Because Google login adds no extra cookie, clearing the session is a complete logout for Google and password users alike.

### FR-12: Schema Change & Migration
- `db/session.py` `CREATE TABLE` MUST define `users` with `id, username TEXT UNIQUE, email TEXT, password TEXT, google_id TEXT UNIQUE, name TEXT, picture TEXT, auth_provider TEXT DEFAULT 'local'`.
- `init_db()` MUST run an idempotent migration for pre-existing DBs: read `PRAGMA table_info(users)`, and for each of `google_id`/`name`/`picture`/`auth_provider` not present, `ALTER TABLE users ADD COLUMN ...`. This MUST NOT drop or rewrite existing rows.

### FR-13: Parameterized SQL (VULN-1 Preserved)
- Every SQL statement in `oauth_service.py` MUST use `?` placeholders. No string concatenation into SQL.

### FR-14: Secrets Never Committed (VULN-4 Posture)
- `.env` MUST be git-ignored. `.env.example` (committed) MUST contain only placeholders. No client secret or client id may be hardcoded in any committed source file.

---

## 5. Non-Functional Requirements

- **NFR-01 — Graceful degradation:** a fresh clone with no Google credentials boots and runs the full password flow; the Google button degrades to the not-configured page. No traceback, no crash on import.
- **NFR-02 — One auth mechanism:** Google users and password users are both authenticated by the single signed-session cookie. There is no second token system to reason about, expire, or refresh.
- **NFR-03 — No secret leakage:** OAuth errors return fixed strings; the client secret never appears in any response, client-visible log line, or committed file.
- **NFR-04 — Output encoding preserved:** no unescaped user-controlled value is spliced into HTML by this feature (the not-configured page is static; `name`/`picture` are not rendered).
- **NFR-05 — Idempotent migration:** running the app repeatedly against an upgraded DB performs zero further `ALTER`s and preserves all rows.
- **NFR-06 — Consistency with existing patterns:** thin route handlers → service layer; `get_db()` + `try/finally`; `str.replace` template splice; static pages carry the same pre-paint theme script + toggle; session populated exactly as `login()` does.
- **NFR-07 — Standard OAuth security:** `state` (anti-CSRF) and `nonce` (anti-replay) are enforced (by Authlib); the ID token signature and claims are verified.

---

## 6. Success Paths

- **SP-01 — New Google user:** click button → Google consent → callback verifies token, `userinfo` has new `sub`/`email` → no row by `google_id` or `email` → INSERT new account (NULL password, generated username) → session set → 302 `/welcome`.
- **SP-02 — Returning Google user:** same flow, row found by `google_id` → logged into the existing account → `/welcome`.
- **SP-03 — Link to existing local account:** a user who signed up locally with `alice@x.com` clicks Google with the same email → no `google_id` row, but an `email` row → that row is linked (`google_id`/`name`/`picture`/`auth_provider` set) → logged in. Their local password still works afterward.
- **SP-04 — Logout:** `/logout` clears the session → 302 `/login`; the user is fully logged out (no other cookie to clear).
- **SP-05 — Not configured:** on a fresh clone, clicking the button shows `oauth_not_configured.html` with setup guidance; the password flow is unaffected.

---

## 7. Edge Cases

- **EC-01 — User denies consent:** Google redirects to the callback with `?error=access_denied` → redirect to `/login`, no account created.
- **EC-02 — Session lost before callback (expired session / cleared cookies):** `state`/`nonce` missing → `authorize_access_token` raises → caught → redirect to `/login`.
- **EC-03 — `userinfo` missing email/sub:** no account created → redirect to `/login`.
- **EC-04 — Generated username collision:** `_unique_username` appends a numeric suffix until the parameterized existence check finds a free name.
- **EC-05 — Google email matches a local account that already has a different `google_id`:** treated as the same account (logged in by the `google_id` match in step 1 if it was that account, else by email); a second distinct Google identity is not merged — out of scope, documented.
- **EC-06 — Google-only account uses the password form:** `password` is NULL → `verify_password(pw, None)` returns `False` → generic 401 from the unchanged `login()`. No code change needed.
- **EC-07 — Existing `vulnerable_app.db` from v1.0.2:** the `ALTER TABLE` migration adds the four columns in place; existing local users keep working (their `auth_provider` defaults to `'local'`).

---

## 8. Acceptance Criteria

- **AC-01** Both `login.html` and `signup.html` render a "Continue with Google" button linking to `/auth/google/login`.
- **AC-02** With no credentials configured, `GET /auth/google/login` returns HTTP 200 and the not-configured page (no redirect, no crash); the password flow still works.
- **AC-03** With credentials configured, `GET /auth/google/login` 302-redirects to `accounts.google.com` and stores `state` in the session.
- **AC-04** A successful callback for a new Google user creates exactly one `users` row with `auth_provider='google'`, `password IS NULL`, a non-null `google_id`, sets the session, and 302s to `/welcome`.
- **AC-05** A successful callback for a returning Google user reuses the existing row (no duplicate).
- **AC-06** A Google login whose email matches an existing local account links to that row (sets `google_id`) instead of creating a duplicate.
- **AC-07** After a Google login, the only auth cookie set is the existing signed `session` cookie — no `access_token`/`refresh_token`/JWT cookie exists.
- **AC-08** `GET /logout` clears the session and 302s to `/login`, and is byte-for-byte unchanged from before this feature.
- **AC-09** All three error cases (denied, state/session loss, missing userinfo) are handled without leaking exception text.
- **AC-10** `oauth_service.py` uses parameterized SQL throughout (no concatenation).
- **AC-11** `users` has the four new columns; `password` is nullable; an existing DB is migrated in place with no row loss.
- **AC-12** `backend/app/main.py`, `backend/app/core/security.py`/`csrf.py`/`rate_limit.py`, the `/logout` handler, and `auth_service.py` `signup`/`login`/`change_password` are byte-for-byte unchanged.
- **AC-13** `.env` is git-ignored; `.env.example` is committed with placeholders only; no secret is hardcoded in committed source.
- **AC-14** `authlib` and `httpx` are added to both pyproject files; `uv sync` succeeds; the app boots.
- **AC-15** README shows feature #5 as "Done (v1.0.3)", lists the new endpoints, and has a "Continue with Google — Setup" section; CLAUDE.md has the integration subsection, rule, schema note, and hierarchy entry.
- **AC-16** All eight closed vulnerabilities remain closed (§2.3).

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected |
|----|----------|--------------|----------|
| TC-01 | Button present | Repo checkout | `grep -c 'href="/auth/google/login"' login.html signup.html` → 1 each |
| TC-02 | Not-configured page | No creds; app running | `GET /auth/google/login` → 200, page mentions configuring Google / README |
| TC-03 | Configured redirect | Creds set; app running | `GET /auth/google/login` → 302 to `accounts.google.com`, `state=` in `Location` |
| TC-04 | New-user create | Mocked callback (new sub) | one new row, `auth_provider='google'`, `password IS NULL`, session set, redirect `/welcome` |
| TC-05 | Returning user | Mocked callback (existing sub) | no new row; logged in |
| TC-06 | Email link | Local `alice@x.com` exists; Google sub new, same email | row linked (`google_id` set), no duplicate |
| TC-07 | Only session cookie | After success | `Set-Cookie` is the `session` cookie only; no `access_token`/`refresh_token` |
| TC-08 | Logout | Logged in via Google | `GET /logout` → 302 `/login`, session cleared; logout handler unchanged |
| TC-09 | Denied consent | callback `?error=access_denied` | 302 `/login`, no account created |
| TC-10 | State/session loss | callback with no session state | 302 `/login` (no traceback) |
| TC-11 | Missing userinfo | Mocked callback, no email | 302 `/login`, no account created |
| TC-12 | Parameterized SQL | Repo checkout | `oauth_service.py` shows `?`-bound SELECT/UPDATE/INSERT; no f-string SQL |
| TC-13 | Schema migrated | v1.0.2 DB present | startup adds 4 columns; `PRAGMA table_info(users)` shows them; rows intact |
| TC-14 | main.py unchanged | Repo checkout | `git diff --stat -- backend/app/main.py` empty |
| TC-15 | auth_service unchanged | Repo checkout | `signup`/`login`/`change_password` byte-for-byte; `/logout` unchanged |
| TC-16 | .env ignored | Repo checkout | `.env` in `.gitignore`; `git check-ignore .env` matches; `.env.example` committed |
| TC-17 | Deps added | Repo checkout | `authlib` + `httpx` in both pyproject files; `uv sync` ok |
| TC-18 | App boots | Fresh checkout, no creds | `uv run backend/app/main.py` starts, password login works |

---

## 10. Verification Steps

Run from the repo root. (The Google round-trip needs real credentials; steps that require Google are marked **[needs creds]** and otherwise are exercised with the not-configured path or a mocked `userinfo`.)

### 10.1 Install & Boot (no creds)
```bash
rm -f vulnerable_app.db
uv sync
uv run backend/app/main.py   # one terminal
```
Expected: starts with no traceback.

### 10.2 Not-Configured Path (AC-02, TC-02)
```bash
curl -s -o /dev/null -w 'glogin=%{http_code}\n' http://localhost:3001/auth/google/login
curl -s http://localhost:3001/auth/google/login | grep -io 'not configured\|README' | head -1
```
Expected: `glogin=200`; the page references configuration / README.

### 10.3 Buttons Present (AC-01, TC-01)
```bash
grep -c 'href="/auth/google/login"' frontend/templates/login.html frontend/templates/signup.html
```
Expected: `1` for each file.

### 10.4 Schema Migration (AC-11, TC-13)
```bash
sqlite3 vulnerable_app.db "PRAGMA table_info(users);"
```
Expected: rows for `google_id`, `name`, `picture`, `auth_provider`; `password` not `NOT NULL`.

### 10.5 Configured Redirect **[needs creds]** (AC-03, TC-03)
```bash
# with GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET set (env or .env)
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://localhost:3001/auth/google/login
```
Expected: `302` and a `redirect_url` on `accounts.google.com` containing `state=`.

### 10.6 End-to-End Sign-in **[needs creds]** (AC-04/05/06/07/08)
Walk the browser flow: click "Continue with Google" on `/login`, consent, land on `/welcome`. Then:
```bash
sqlite3 vulnerable_app.db "SELECT username,email,auth_provider,google_id IS NOT NULL, password IS NULL FROM users;"
```
Expected: a `google` row with non-null `google_id` and NULL `password`; the browser holds only the `session` cookie (no token cookies); `/logout` then clears the session.

### 10.7 Preservation + File Audit (AC-12, AC-13, TC-14–TC-17)
```bash
git diff --stat -- backend/app/main.py backend/app/core/security.py \
  backend/app/core/csrf.py backend/app/core/rate_limit.py
grep -n 'def signup\|def login\|def change_password\|async def logout' backend/app/services/auth_service.py backend/app/api/routes/auth.py
git check-ignore .env
grep -n 'authlib\|httpx' pyproject.toml backend/pyproject.toml
grep -RIni 'GOCSPX\|client_secret *= *["'\'']' backend/app || echo '(no hardcoded secret — good)'
```
Expected: the four diffs empty; the auth functions + unchanged `logout` present; `.env` ignored; both deps listed; no hardcoded secret.

### 10.8 Affected-Files Audit
```bash
git status --porcelain
```
Expected — exactly the declared files plus the two new spec docs (`continue-with-google.md`, `continue-with-google-plan.md`). No `main.py`, `security.py`, `csrf.py`, `rate_limit.py`, `dashboard.html`, or `profile.html` entry.
