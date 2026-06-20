# CLAUDE.md

## Project Context

This is an **intentionally vulnerable web application** for security education. It originally shipped with 8 OWASP Top 10 vulnerabilities. All 8 of them — VULN-5 (Weak Password Storage), VULN-1 (SQL Injection), VULN-6 (Exposed DB), VULN-4 (Session Hijacking), VULN-2 (Stored XSS), VULN-3 (Reflected XSS), VULN-7 (No Rate Limiting), and VULN-8 (CSRF) — have since been closed. No vulnerabilities remain intentionally exploitable; the project is now a complete "before / after" reference, with v0.1.0 as the fully vulnerable baseline.

**WARNING:** All eight closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db` route, the hardened session secret, the escaped dashboard username, the escaped search output, the per-IP POST rate-limit middleware, and the synchronizer-token CSRF middleware) are permanent — do not revert them. To study the original vulnerabilities, students should check out the `v0.1.0` tag rather than weakening the current codebase.

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
| 3 | Reflected XSS | `backend/app/api/routes/auth.py` | Was unescaped `q` (and result rows / error text) in `/search`; now `html.escape(..., quote=True)` on every sink before splicing (output encoding; raw values still in URL/DB) | **Closed** |
| 4 | Session Hijacking | `backend/app/main.py` | Was hardcoded secret `"super-secret-key-12345"`; now sourced from the `SECRET_KEY` env var with a strong `secrets.token_hex(32)` random fallback | **Closed** |
| 5 | Weak Password | `backend/app/core/security.py` | Was MD5 (no salt); now bcrypt (`BCRYPT_ROUNDS = 12`); `verify_password` wraps `bcrypt.checkpw` in `try/except` so legacy MD5 rows return `False` instead of crashing | **Closed** |
| 6 | Exposed DB | `backend/app/api/routes/auth.py` | Was an unauthenticated `/download/db` route; the route has been removed entirely | **Closed** |
| 7 | No Rate Limit | `backend/app/core/rate_limit.py` + `backend/app/main.py` | Stdlib `RateLimitMiddleware` enforces a per-IP sliding window on every POST (default 5 / 60 s); throttled requests get HTTP 429 + `Retry-After` before the handler runs | **Closed** |
| 8 | CSRF | `backend/app/core/csrf.py` + `backend/app/main.py` + form templates | Synchronizer-token `CSRFMiddleware` rejects every POST whose `csrf_token` form field does not match `request.session["csrf_token"]`; token issued by `get_or_create_csrf_token` on `GET /login` / `GET /signup` and spliced into the rendered HTML | **Closed** |

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

### Rate Limiting After the Fix

`main.py` registers a stdlib-only `RateLimitMiddleware` (defined in `backend/app/core/rate_limit.py`) after `SessionMiddleware`:

```python
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
```

- **Scope:** every `POST` request, identified by `request.client.host`. GET / HEAD / OPTIONS / static-file requests bypass the limiter with a single method-check.
- **State:** in-process `dict[str, collections.deque[float]]` of `time.monotonic()` timestamps, guarded by a single `asyncio.Lock`. Reset on every restart — no Redis, no disk persistence.
- **Throttled response:** HTTP `429` with body `{"error": "Too many requests", "retry_after": <int>}` and a `Retry-After: <int>` header. The downstream handler — including the bcrypt verify on `POST /login` — is never invoked on a throttled call.
- **No proxy-header trust:** `X-Forwarded-For` is intentionally ignored. If you front the app with a reverse proxy in a real deployment, configure the proxy to populate `request.client.host` (e.g., uvicorn's `--proxy-headers` with a trusted-IP allowlist) rather than trusting headers blindly.
- **Local lab use:** run with no env overrides — the defaults are conservative enough to make brute-force impractical without locking out a user who mistypes their password a few times. To experiment, set `RATE_LIMIT_MAX=2 RATE_LIMIT_WINDOW_SECONDS=5` before launch.

### CSRF Protection After the Fix

`main.py` registers a stdlib-only **pure-ASGI** `CSRFMiddleware` (defined in `backend/app/core/csrf.py`) as the first `add_middleware` call, with `SessionMiddleware` second and `RateLimitMiddleware` last:

```python
app.add_middleware(CSRFMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
```

Starlette's `add_middleware` prepends to its internal middleware list, so the *last* `add_middleware` call is the *outermost* layer on the request path. The resulting flow is `RateLimit (outer) → Session → CSRF (inner) → handler`. Rate-limit still gates floods first; CSRF reads the already-decoded session.

- **Token:** `secrets.token_urlsafe(32)` — 256 bits of entropy, URL-safe Base64 (43 characters, `[A-Za-z0-9_-]`).
- **Storage:** `request.session["csrf_token"]` — lives only inside the signed session cookie (VULN-4's `SECRET_KEY` signs the whole session dict). No database column, no in-process map.
- **Issuance:** `GET /login` and `GET /signup` call `get_or_create_csrf_token(request)`, which lazily writes a token on first read and returns the existing value on subsequent reads (one token per session, not per request).
- **Splice:** the handlers do `page.replace("{{csrf_token}}", html.escape(token, quote=True))` — same pattern as the `{{username}}` splice in `welcome_page`. The hidden input `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` is the first child of each form.
- **Validation:** on every POST, `CSRFMiddleware` drains the ASGI `receive` to buffer the body, parses the urlencoded body with `urllib.parse.parse_qs`, and compares the `csrf_token` value against `scope["session"]["csrf_token"]` with `secrets.compare_digest` (constant-time). Mismatch, missing field, empty field, wrong content-type, or any internal exception → HTTP `403` with body `{"error": "CSRF token missing or invalid"}` (fail-CLOSED). On success the same body bytes are replayed to the downstream handler via a wrapped `receive`. The middleware is pure ASGI rather than `BaseHTTPMiddleware` because the latter consumes the body on its own `Request` wrapper, leaving FastAPI's `Form(...)` dependency to see an empty stream.
- **Scope:** every `POST` request. GET / HEAD / OPTIONS / static-file requests bypass with a single method-check.
- **What it does not do:** no `Origin` / `Referer` header check, no double-submit cookie, no per-request rotation, no `SameSite` cookie-attribute change. The synchronizer token alone is sufficient on this single-origin lab.
- **Local lab use:** no configuration needed. Visit `/login` or `/signup` and the token is issued automatically; subsequent forms in the same session reuse it.

## Frontend-Backend Integration

- **Login**: `fetch()` POST → JSON response → client-side redirect
- **Signup**: Standard form POST → server redirect
- **Dashboard**: Server-side `str.replace('{{username}}', ...)` — no template engine; the value is HTML-escaped with `html.escape(..., quote=True)` before substitution (VULN-2 closed)
- **Theme**: Pure client-side. Each template's `<head>` runs a synchronous IIFE that reads `localStorage["theme"]` (or `prefers-color-scheme` as fallback) and sets `<html data-theme="light|dark">` before first paint. A `#theme-toggle` button in the shared header flips the attribute and persists the new value. No server round-trip, no session field, no backend coupling.
- **Password strength meter** (shipped in v1.0.1): Pure client-side. An inline `<script>` in `signup.html` listens to `input` on `#password`, scores the password against five criteria (length ≥ 8, lowercase, uppercase, digit, special) in JS, and updates a colored bar + live checklist beneath the password field. Advisory UX only — the backend's signup handler still accepts any non-empty password; nothing about the strength is sent to the server, stored in the session, or written to the database. The bar's colors are CSS custom properties shared between `:root` and `[data-theme="dark"]`, so toggling theme recolors the bar without re-running JS.
- **Profile / Change Password** (shipped in v1.0.2): `GET /profile` (session-gated, like `/welcome`) renders `profile.html` with the CSRF token and HTML-escaped `{{username}}`/`{{email}}` spliced in. `POST /profile/password` is a thin handler over `auth_service.change_password()`, which verifies the current password with bcrypt and runs a parameterized `UPDATE`. The form submits via `fetch()` with the body wrapped in `URLSearchParams` (so the CSRF middleware's urlencoded parser accepts it), returning JSON for inline feedback. The **new password is enforced against the same five-criteria strength policy the signup meter advertises** (length ≥ 8 plus lower/upper/digit/special) — checked in JS for inline feedback and re-checked server-side by `auth_service.password_meets_policy()` as the authoritative gate (weak passwords get a 400). Unlike signup, the strength-meter widget is **not** rendered on the profile form; only the rules apply. No schema change; the theme toggle stays frontend-only.
- **Continue with Google / OAuth 2.0** (shipped in v1.0.3): `GET /auth/google/login` and `GET /auth/google/callback` (both in `auth.py`) run the OAuth 2.0 Authorization Code flow via **Authlib** (`core/oauth.py`, registered from Google's OIDC discovery URL with scope `openid email profile`). The login route degrades to `oauth_not_configured.html` when `core/config.is_google_configured()` is false. The callback validates the `state`/ID-token (Authlib), then `oauth_service.find_or_create_google_user()` resolves the identity with **parameterized** SQL — find by `google_id`, else link by `email`, else create (`auth_provider='google'`, `password=NULL`, **`is_verified=1`**). It then **logs the user in by writing the same `request.session` keys (`user_id`/`username`/`email`) as `auth_service.login()`** and 302s to `/welcome`. **The signed session cookie is the single auth mechanism — there is no JWT, access/refresh token, or extra cookie.** Both routes are GETs (the OAuth `state` param is the CSRF defense; the POST-only `CSRFMiddleware` and `RateLimitMiddleware` correctly ignore them). Credentials are read from env/`.env` via `core/config.py` (stdlib loader, no `python-dotenv`); `.env` is git-ignored, `.env.example` is committed. This is the project's **first DB-schema change**: `users` gains nullable `google_id`/`name`/`picture`/`auth_provider`, applied to existing DBs by an idempotent `ALTER TABLE` migration in `init_db()`. `main.py` and `/logout` are **not** modified (Authlib rides the existing `SessionMiddleware`; clearing the session is a complete logout). The Google `name`/`picture` are stored but **not rendered** this release.
- **Email Verification on Signup** (shipped in v1.0.4): `POST /signup` now creates an **unverified** account (`is_verified=0`) and `auth_service.signup()` calls `verification_service.start_verification()` to issue a single-use, 1-hour `secrets.token_urlsafe(32)` token (stored raw on the user's row) and email a `{APP_BASE_URL}/verify?token=…` link via **`core/mailer.py`** (stdlib `smtplib`+`email`, **no new dependency**). Signup then 302s to `GET /check-email`. `GET /verify` (a **GET** — the unguessable token is the capability, like the OAuth callback; the POST-only middleware ignore it) calls `verification_service.verify_email_token()`, which on a valid, unexpired match sets `is_verified=1` and **clears the token columns (single-use)** and returns the user. The route then **logs the user straight in** — writing the same `request.session` keys (`user_id`/`username`/`email`) as `login()` — and **302s to `/welcome`** (clicking the emailed link proves control of the address). Only the **expired/invalid** outcomes render `verify_result.html` with a fixed, HTML-escaped message — **the raw token is never reflected** (VULN-3). The posture is **block-login-until-verified**: `auth_service.login()` verifies the password with bcrypt and then **refuses to create a session for an unverified account**, returning `401 {"error": "...", "unverified": true}`. Because an unverified user therefore has no session, **resend is credential-based, not session-based**: the login page reveals a "Resend verification email" button (shown only on the `unverified` response) that re-POSTs the same username+password to `POST /verify/resend`; `verification_service.resend_for_credentials()` re-checks them with bcrypt (the correct password is the authorization — it can't be used to spam a stranger, and a bad username/password returns the same generic `401` as login) before re-issuing. That POST is automatically covered by the existing **CSRF** (hidden `csrf_token`, urlencoded via `URLSearchParams`) and **rate-limit** middleware (it is a POST). `GET /welcome` is **unchanged** (only verified users ever reach it, so there is no banner). When SMTP is unconfigured, `core/config.is_email_configured()` is false and both `GET`/`POST /signup` render `email_not_configured.html` (HTTP 200) and create **no** account — the OAuth-style degrade; nothing is logged or leaked. This is the project's **second DB-schema change**: `users` gains `is_verified`/`verification_token`/`verification_token_expires` via the same idempotent `ALTER TABLE` migration, and **existing rows are grandfathered to `is_verified=1`** the first time the column is added. Google accounts are auto-verified (above). SMTP creds come from env/`.env` via `core/config.py`; `main.py` and `core/security.py` are **not** modified.
- **Account Lockout** (shipped in v1.0.5): a per-**account** brute-force defense that **complements — does not replace — the per-IP `RateLimitMiddleware` (VULN-7)**. After `config.ACCOUNT_LOCKOUT_MAX_ATTEMPTS` (default **6**) consecutive failed credential checks against one account, it is locked for `config.ACCOUNT_LOCKOUT_DURATION_SECONDS` (default **3600 s**), then **auto-unlocks** (time-based; no admin action). State lives **server-side on the `users` row** (this project's **third DB-schema change**: nullable/defaulted `failed_login_attempts INTEGER DEFAULT 0` and `locked_until REAL`, added by the same idempotent `ALTER TABLE` migration in `init_db()` — **no grandfather `UPDATE`**, because the defaults already mean "no failures, not locked"). The new **`services/lockout_service.py`** holds four stdlib helpers: `seconds_remaining(row)` reads the already-fetched row (no DB); `register_failure()`/`reset()` run **parameterized** `UPDATE`s and **fail open** on a DB error (a broken lockout must never deny every login — same posture as the rate limiter, opposite of fail-closed CSRF); `lock_message()` builds a fixed countdown string with **no attacker input**. `auth_service.login()` checks the lock **before** `verify_password` — so a locked account never burns a bcrypt hash and is refused **even with the correct password**, returning `401 {"error": "…countdown…", "locked": true, "retry_after": <int>}` and **no session**; a correct password calls `reset()` *before* the verify/unverified gate, so a correct-but-unverified login also clears the chain. `verification_service.resend_for_credentials()` applies the **same** gate/register/reset against the **same** row, so `POST /login` and `POST /verify/resend` **share one counter** (an attacker can't earn a fresh allowance by switching endpoints). The lock message **reveals that the named account exists** — a **deliberate, bounded** relaxation of login enumeration resistance (only the *locked* state differs; every other failure keeps the identical generic `401 {"error": "Invalid username or password"}`). The login page needs **no change** — it already renders `data.error`, and the resend affordance (gated on `data.unverified`) stays hidden for a `locked` response. Thresholds are **env-tunable, non-secret** (no `is_*_configured()` gate); lower them to demo (`ACCOUNT_LOCKOUT_MAX_ATTEMPTS=3 ACCOUNT_LOCKOUT_DURATION_SECONDS=30`). **`main.py`, `core/rate_limit.py`, `core/security.py`, `core/csrf.py`, every route handler in `auth.py`, and every template/CSS file are not modified**; stdlib only, no new dependency.

- **Email OTP Two-Factor Authentication (2FA)** (shipped in v1.0.6): an **opt-in, per-account second factor** layered on the password login. A user enables it from `/profile` (`POST /profile/2fa`, **session-gated only** — no current-password re-prompt; CSRF + rate-limit middleware still apply). When enabled, `auth_service.login()` keeps the **unchanged** lockout gate → bcrypt verify → `lockout_service.reset()` → `is_verified` gate, and only **then**, instead of writing the session, writes a short-lived **`pending_2fa_user_id`** (NOT `user_id`, so `/welcome` and `/profile` stay gated), issues a **6-digit OTP** via the new **`services/otp_service.py`**, emails it with **`core/mailer.send_otp_email()`** (stdlib `smtplib`, fail-safe, **no new dependency**), and returns `200 {"otp_required": true, "redirect": "/login/otp"}`. `GET /login/otp` (gated on the pending marker) renders `otp_verify.html`; `POST /login/otp` calls `otp_service.verify()` and, on a match, **clears the pending keys and writes the same `user_id`/`username`/`email` session keys as `login()`** (the **signed session is the only auth mechanism — no JWT/token/extra cookie**, same as OAuth), 302-redirecting to `/welcome`. `POST /login/otp/resend` re-issues the code, honouring a per-account cooldown. The OTP is stored **raw** on the `users` row (`otp_code`) and bounded by an **attempt cap** (`OTP_MAX_ATTEMPTS`, default 5 → code invalidated), a **short expiry** (`OTP_TTL_SECONDS`, default 300 s), and a **resend cooldown** (`OTP_RESEND_COOLDOWN_SECONDS`, default 60 s), on top of the unchanged per-IP rate limiter; it is compared with `secrets.compare_digest` and **never reflected** into any page or log (VULN-3). This is the project's **fourth DB-schema change**: `users` gains `two_factor_enabled`/`otp_code`/`otp_expires`/`otp_attempts`/`otp_last_sent` via the same idempotent `ALTER TABLE` migration in `init_db()` — **no grandfather `UPDATE`** (defaults `0`/`NULL` already mean "2FA off, no challenge"). OTP delivery reuses the existing **`is_email_configured()`** gate: enabling 2FA is refused (`400`) when SMTP is unconfigured, and `login()` **fails closed** (`401`, no session) if 2FA is on but email is unavailable — it never silently bypasses the second factor. The 2FA challenge applies to the **password login path only**; the Google OAuth callback is **not** modified. `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, and `verification_service.py` are **not** modified; settings come from env/`.env` via `core/config.py` (non-secret tunables, no separate gate).

## Important Rules

- Always use parameterized queries in `auth_service.py` and `auth.py`. Never concatenate user-controlled input into SQL statements (VULN-1 is closed and must stay closed).
- Never remove the CSRF middleware in `backend/app/main.py` / `backend/app/core/csrf.py`, the hidden `csrf_token` field in the login/signup templates, or the `get_or_create_csrf_token` calls in the two GET handlers. VULN-8 is closed by a session-bound synchronizer-token pattern: a 256-bit token (`secrets.token_urlsafe(32)`) is stored in `request.session["csrf_token"]`, spliced into every form, and validated on every POST with `secrets.compare_digest`. The middleware, the hidden field, and the splice are permanent and must stay (stdlib-only, no third-party CSRF dependency).
- Never re-introduce a hardcoded session secret in `main.py`. VULN-4 is closed by sourcing `SECRET_KEY` from the environment with a strong `secrets.token_hex(32)` random fallback; the env-sourced secret is permanent and must stay (no constant key, no committed `.env`).
- Never remove the rate-limit middleware in `backend/app/main.py` / `backend/app/core/rate_limit.py`. VULN-7 is closed by an in-process per-IP sliding-window `RateLimitMiddleware` scoped to every POST (default 5 requests per 60 s, tunable via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_SECONDS` env vars). The middleware is permanent and must stay (stdlib-only, no third-party rate-limit dependency).
- Never re-introduce MD5 or an "MD5 fallback" in `security.py`. Bcrypt is permanent; legacy MD5 rows must fail closed, not authenticate.
- Never re-introduce unescaped `{{username}}` in the dashboard substitution. VULN-2 is closed by HTML-escaping the username with `html.escape(..., quote=True)` before substitution; the escaping is permanent and must stay (output encoding, not input filtering — the raw value still lives in the session/DB).
- Never re-introduce unescaped reflection in `/search`. VULN-3 is closed by HTML-escaping every attacker-controllable sink (`q`, the result-row `username`/`email`, and the exception text) with `html.escape(..., quote=True)` before splicing; the escaping is permanent and must stay (output encoding, not input filtering — the raw values still live in the URL/DB).
- Never re-add the `/download/db` route. VULN-6 is closed by removing the endpoint entirely; do not reintroduce it (authenticated or otherwise).
- The dark-mode feature is purely frontend (CSS + 4 files: `styles.css`, `login.html`, `signup.html`, `dashboard.html`). Don't push theme state into the backend, the session, or the database.
- The password strength meter on the signup form is purely frontend and advisory (CSS + `signup.html` only). Don't push strength state into the backend, the session, or the database, and don't block form submission on a weak password — the bcrypt-hashing server-side gate (VULN-5 closure) is what authenticates; the meter only informs the user.
- The User Profile Page (`/profile`, `/profile/password`) is session-gated and must stay so. `change_password` in `auth_service.py` must keep its parameterized `SELECT`/`UPDATE` (VULN-1) and bcrypt verify/hash (VULN-5); the change-password form must keep its hidden `csrf_token` field (VULN-8) and submit urlencoded via `URLSearchParams`. The new password must satisfy the five-criteria strength policy (length ≥ 8 plus lower/upper/digit/special), enforced server-side by `password_meets_policy()` and mirrored in the profile form's JS — keep both in sync; the profile form deliberately omits the strength-meter widget. Do not add a `created_at`/theme/profile column — the feature is intentionally schema-free, and dark mode stays frontend-only.
- The Continue-with-Google feature (`/auth/google/login`, `/auth/google/callback`) must keep the session as its **only** auth mechanism — do **not** add JWT/access/refresh/bearer tokens or any extra auth cookie; the callback logs in by writing the same `request.session` keys as `login()`. Keep `oauth_service.py` SQL **parameterized** (VULN-1) and OAuth rows' `password` **NULL** (VULN-5, no weak hash). The OAuth routes must stay **GET** (the `state` param is the CSRF defense — do not route them through or weaken `CSRFMiddleware`). Never hardcode the client id/secret; they come from env/`.env` (git-ignored) via `core/config.py` — keep `.env` out of git and `.env.example` placeholder-only (VULN-4 posture). Do **not** modify `main.py` or `/logout` for this feature (Authlib uses the existing `SessionMiddleware`). The schema migration in `init_db()` is additive/idempotent — never drop or rewrite rows, and keep `password` nullable. If a future spec renders the Google `name`/`picture`, it MUST `html.escape(..., quote=True)` them on output (VULN-2).
- The Email-Verification feature (`/check-email`, `/verify`, `/verify/resend`, `core/mailer.py`, `services/verification_service.py`) must keep all SQL **parameterized** (VULN-1) and must **never reflect or log the verification token** — `GET /verify` renders a fixed, `html.escape(..., quote=True)`-encoded outcome message, not the token (VULN-3). The token stays a single-use, expiring `secrets.token_urlsafe(32)`; a successful verify MUST clear `verification_token`/`verification_token_expires`. SMTP credentials come **only** from env/`.env` via `core/config.py` — never hardcode them, keep `.env` git-ignored and `.env.example` placeholder-only (VULN-4). `GET /verify` must stay a **GET** (the token is the capability) and `POST /verify/resend` must stay a **POST** behind the existing CSRF + rate-limit middleware (VULN-7/VULN-8) — do **not** add new middleware or modify `main.py`. The mailer stays **stdlib-only** (`smtplib`+`email`, no new dependency) and **fail-safe** (returns `False`, never raises; a failed send must not crash signup or change verification state). The `init_db()` migration stays additive/idempotent and MUST keep grandfathering pre-existing rows to `is_verified=1`. **`login()` MUST refuse to create a session for an unverified local account** (the chosen posture is block-login-until-verified) — return `401` with an `unverified` flag and no session; never log an unverified user in. Resend is **credential-based** (`resend_for_credentials` re-checks the password with bcrypt) so it works without a session and can't spam a stranger — keep the resend form's hidden `csrf_token` and urlencoded `URLSearchParams` submit. Google and grandfathered accounts (`is_verified=1`) must continue to pass the login gate unaffected.
- The Account-Lockout feature (`services/lockout_service.py`, the `login()` and `resend_for_credentials()` gates, the `failed_login_attempts`/`locked_until` columns) must keep all SQL **parameterized** (VULN-1) and the lock check must stay **before** `verify_password` so bcrypt remains the sole authenticator on the unlocked path and a locked account never burns a hash (VULN-5). It is **additive** defense in depth: **never remove or weaken `RateLimitMiddleware` or modify `main.py`/`core/rate_limit.py`** — VULN-7 stays closed and the per-account lockout layers on top (do **not** "drop rate limiting because lockout exists"). Thresholds come **only** from env via `core/config.py` (`ACCOUNT_LOCKOUT_MAX_ATTEMPTS`/`ACCOUNT_LOCKOUT_DURATION_SECONDS`) — never hardcode them; they are non-secret with safe defaults (no `is_*_configured()` gate). `lockout_service` stays **stdlib-only** and its bookkeeping writes **fail open** (a DB error must not deny all logins). The `init_db()` migration stays additive/idempotent (two columns, **no grandfather `UPDATE`** — the defaults are already correct). Login and resend MUST **share the same counter** on the `users` row (don't give an attacker a fresh allowance per endpoint), a correct password MUST `reset()` it, and the threshold hit MUST also zero the counter so the post-expiry allowance is full. The lock message is the **only** deliberate enumeration relaxation and MUST contain **no attacker input** (a fixed countdown string — VULN-3); every non-locked failure keeps the generic `401`. Do **not** modify any route handler, template, or CSS — the countdown rides the login page's existing `data.error` path.
- The Email-OTP-2FA feature (`services/otp_service.py`, `core/mailer.send_otp_email`, the `login()` 2FA branch, the `/profile/2fa` + `/login/otp` + `/login/otp/resend` routes, `otp_verify.html`, the `two_factor_enabled`/`otp_code`/`otp_expires`/`otp_attempts`/`otp_last_sent` columns) must keep all SQL **parameterized** (VULN-1) and the OTP branch MUST stay **after** bcrypt and the email-verified gate in `login()`, so bcrypt remains the sole password authenticator and a wrong/locked/unverified login never issues an OTP (VULN-5). The raw OTP MUST **never** be reflected into any response, URL, template, or log (VULN-3) — it is emailed and compared server-side with `secrets.compare_digest`. Keep auth **session-only**: the second step completes by writing the same `request.session` keys as `login()` — do **not** add a JWT/access/refresh/bearer token or any extra cookie; between the two steps only the short-lived `pending_2fa_user_id` (never `user_id`) is in the signed session. `login()` MUST **fail closed** (`401`, no session) when 2FA is on but `is_email_configured()` is false — never silently bypass the second factor — and enabling 2FA MUST be refused when email is unconfigured. The `/profile/2fa` toggle is **session-gated by design** (no password re-prompt) — keep its hidden `csrf_token` and urlencoded `URLSearchParams` submit; the OTP forms likewise. The mailer stays **stdlib-only** and **fail-safe** (returns `False`, never raises; a failed send must not crash login or complete it). The `init_db()` migration stays additive/idempotent (five columns, **no grandfather `UPDATE`**). OTP thresholds come **only** from env via `core/config.py` (`OTP_TTL_SECONDS`/`OTP_MAX_ATTEMPTS`/`OTP_RESEND_COOLDOWN_SECONDS`, non-secret, no `is_*_configured()` gate of their own — delivery reuses `is_email_configured()`); never hardcode them. Do **not** modify `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, or the Google OAuth path for this feature — the 2FA challenge applies to the password login only.

## Specification Hierarchy

1. `docs/PRD.md` — Product requirements
2. `docs/TDD.md` — Technical design
3. `.claude/specs/app-foundation.md` — Foundation implementation specification
4. `.claude/specs/app-foundation-plan.md` — Foundation implementation plan
5. `.claude/specs/dark-mode-toggle.md` + `.claude/specs/dark-mode-toggle-plan.md` — Dark-mode feature
6. `.claude/specs/bcrypt-password-hashing.md` + `.claude/specs/bcrypt-password-hashing-plan.md` — VULN-5 fix
7. `.claude/specs/session-hijacking-fix.md` + `.claude/specs/session-hijacking-fix-plan.md` — VULN-4 fix
8. `.claude/specs/stored-xss-fix.md` + `.claude/specs/stored-xss-fix-plan.md` — VULN-2 fix
9. `.claude/specs/reflected-xss-fix.md` + `.claude/specs/reflected-xss-fix-plan.md` — VULN-3 fix
10. `.claude/specs/no-rate-limiting-fix.md` + `.claude/specs/no-rate-limiting-fix-plan.md` — VULN-7 fix
11. `.claude/specs/csrf-fix.md` + `.claude/specs/csrf-fix-plan.md` — VULN-8 fix
12. `.claude/specs/pwd-str-meter.md` + `.claude/specs/pwd-str-meter-plan.md` — Password strength meter (signup, frontend-only, advisory; shipped in v1.0.1)
13. `.claude/specs/user-profile-page.md` + `.claude/specs/user-profile-page-plan.md` — User Profile Page (v1.0.2 feature)
14. `.claude/specs/continue-with-google.md` + `.claude/specs/continue-with-google-plan.md` — Continue with Google / OAuth 2.0 (v1.0.3 feature)
15. `.claude/specs/email-verification-on-signup.md` + `.claude/specs/email-verification-on-signup-plan.md` — Email Verification on Signup (v1.0.4 feature)
16. `.claude/specs/account-lockout.md` + `.claude/specs/account-lockout-plan.md` — Account Lockout (v1.0.5 feature)
17. `.claude/specs/email-otp-2fa.md` + `.claude/specs/email-otp-2fa-plan.md` — Email OTP Two-Factor Authentication (v1.0.6 feature)

Prompts that generated each spec/plan/implementation live under `docs/prompts/`.
