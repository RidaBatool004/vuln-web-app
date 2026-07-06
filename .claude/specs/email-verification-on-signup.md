# Software Specification Document — Email Verification on Signup

**Version:** 1.0.0
**Last Updated:** 2026-06-20
**Target Release Tag:** v1.0.4
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [Email Verification on Signup — README "Feature Enhancements" #3](https://github.com/arifpucit/vuln-web-app/issues)

---

## 0. Amendment (v1.0.4 final — supersedes the "allow login" posture below)

The shipped feature uses a **block-login-until-verified** posture, not the
"allow login, restrict app" posture described in some sections below. Where the
two conflict, **this amendment governs**:

- `auth_service.login()` verifies the password and then **refuses to create a
  session for an unverified local account**, returning `401 {"error": "...",
  "unverified": true}`. Only verified (or Google / grandfathered) accounts get
  a session, so `GET /welcome` is reached **only** by verified users.
- **`GET /verify` auto-logs-in on success.** A valid, unexpired token verifies
  the account, and the route then writes the same session keys as `login()` and
  **302s to `/welcome`** (the emailed link proves control of the address), so
  the user lands on their dashboard — they do **not** bounce back to `/login`.
  Only expired/invalid tokens render `verify_result.html`.
- There is therefore **no dashboard verification banner** and **no
  session-based resend**. `GET /welcome` and `dashboard.html` are unchanged.
- **Resend is credential-based.** The login page reveals a "Resend verification
  email" button on the `unverified` response; it re-POSTs the username +
  password to `POST /verify/resend`, and
  `verification_service.resend_for_credentials()` re-checks them with bcrypt
  before re-issuing (the correct password is the authorization; a bad
  username/password returns the same generic `401` as login). The POST is still
  covered by the existing CSRF + rate-limit middleware.

Everything else in the spec (schema, token model, `/verify`, `/check-email`,
the SMTP not-configured degrade, Google auto-verify, grandfathering, stdlib
mailer, parameterized SQL, no `main.py` change, no new dependency) is unchanged.

---

## 1. Overview / Purpose

This document specifies the **Email Verification on Signup** enhancement. It is item #3 in the README's "Feature Enhancements" table. During registration the app sends a confirmation email containing a single-use, time-limited verification link; the user's account is marked **verified** only after they click the link.

The chosen posture for this slice is **"allow login, restrict app"**: an unverified user can still register and log in, but the dashboard shows a persistent "please verify your email" banner with a **Resend** button, and the account is flagged `is_verified = 0` until the link is clicked. (Blocking login outright is intentionally **not** chosen — see §2.4.)

The feature is built on the project's existing primitives and the schema-migration precedent set by Continue-with-Google (v1.0.3), with **no new third-party dependency**:

- Email is sent with the Python **standard library only** (`smtplib` + `email.message`), mirroring the stdlib-only posture of `core/csrf.py` and `core/rate_limit.py`. No `python-dotenv`, no transactional-email SDK.
- SMTP credentials are read from the environment / git-ignored `.env` through the existing **`core/config.py`** loader — the same mechanism that already holds the Google OAuth secrets (VULN-4 posture: no hardcoded secrets, `.env` never committed).
- The verification token is a 256-bit `secrets.token_urlsafe(32)` value — the same primitive used for the CSRF token — stored **server-side** on the user's row with a 1-hour expiry, and validated on `GET /verify`.
- All new SQL is **parameterized** (VULN-1), the displayed token / messages are **HTML-escaped on output** (VULN-2/VULN-3 posture), the resend POST is automatically covered by the existing **CSRF** and **rate-limit** middleware (VULN-7/VULN-8), and `main.py` is **not** modified (VULN-4 posture preserved).

When SMTP is **not configured**, the signup flow degrades to a friendly **`email_not_configured.html`** page (HTTP 200) that points the operator at the README — exactly mirroring the `oauth_not_configured.html` degrade for Continue-with-Google. No account is created and **no verification link is logged or leaked**; the app still boots.

This feature does **not** change any of the eight closed vulnerabilities. After this change, all eight remain closed and the app gains its second post-fix authenticated feature surface and its **second** database-schema change.

The implementation touches:

- Two new backend modules: `backend/app/core/mailer.py` (stdlib SMTP sender) and `backend/app/services/verification_service.py` (token issue / verify / resend logic).
- Three new templates: `frontend/templates/check_email.html`, `frontend/templates/verify_result.html`, `frontend/templates/email_not_configured.html`.
- The existing `backend/app/core/config.py` (SMTP settings + `is_email_configured()`), `backend/app/db/session.py` (additive migration), `backend/app/services/auth_service.py` (`signup()` flags `is_verified = 0` and triggers the email), `backend/app/services/oauth_service.py` (Google users are auto-verified), `backend/app/api/routes/auth.py` (signup gate + three new handlers + dashboard banner), `frontend/templates/dashboard.html` (banner), `frontend/static/css/styles.css` (banner + new-page styling).
- `.env.example` (SMTP placeholders), `README.md`, and `CLAUDE.md` (documentation).

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/oauth.py`, `frontend/templates/login.html`, and `frontend/templates/signup.html` remain byte-for-byte unchanged. No dependency is added.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Schema (additive, idempotent — second-ever schema change).** Add three columns to `users` in `init_db()`:
  - `is_verified INTEGER DEFAULT 0` — `0` = unverified, `1` = verified.
  - `verification_token TEXT` — the active raw token, or `NULL` when none is outstanding.
  - `verification_token_expires REAL` — Unix epoch seconds (`time.time()`-based) after which the token is dead, or `NULL`.
  - The migration adds any missing column with `ALTER TABLE ... ADD COLUMN`, never dropping a row, exactly like the Continue-with-Google migration. **Grandfathering:** the *first* time `is_verified` is added to a pre-existing DB, all existing rows are set to `is_verified = 1` so current accounts are not retroactively locked behind verification.
- **SMTP config (`core/config.py`).** Read `SMTP_HOST`, `SMTP_PORT` (default `587`), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (defaults to `SMTP_USER`), `APP_BASE_URL` (default `http://localhost:3001`), and `EMAIL_VERIFICATION_TTL_SECONDS` (default `3600`) from the environment / `.env`. Expose `is_email_configured()` → `bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)`.
- **Mailer (`core/mailer.py`, new, stdlib only).** `send_verification_email(to_email, username, verify_url) -> bool` builds a multipart text+HTML message, connects to SMTP (STARTTLS on 587, implicit TLS on 465), authenticates, and sends. It returns `False` (never raises) on any failure or when `is_email_configured()` is false, logging the cause server-side.
- **Verification service (`services/verification_service.py`, new).**
  - `start_verification(user_id, username, email) -> bool` — generate a token + 1-hour expiry, write them to the user's row with a **parameterized** `UPDATE`, then send the email via the mailer; return the mailer's success boolean.
  - `verify_email_token(token) -> str` — look up the row by token (parameterized), return `"invalid"` (no/blank token, no match, or DB error), `"expired"` (matched but past `verification_token_expires`), or `"ok"` (matched + unexpired → set `is_verified = 1`, clear both token columns, single-use).
  - `resend_for_user(user_id) -> JSONResponse` — load the row; `401` if missing, `200 {"success": true, "message": "already verified"}` if already verified, else re-issue + resend and return `200 {"success": true, ...}` or `400 {"error": ...}` if the send failed.
- **Signup flow (`services/auth_service.py`).** `signup()` inserts the user with `is_verified = 0` (explicit column in the parameterized INSERT), captures `cursor.lastrowid`, and after commit calls `verification_service.start_verification(...)`. On success it returns `RedirectResponse("/check-email", 302)` (replacing the old redirect to `/login`). A failed send does **not** fail signup — the account exists and the user can resend after logging in.
- **Routes (`api/routes/auth.py`).**
  - `GET /signup` and `POST /signup` are **gated** on `config.is_email_configured()`. When false, both render `email_not_configured.html` (HTTP 200) and **no account is created**.
  - `GET /check-email` — render the static `check_email.html` ("we sent you a link") page.
  - `GET /verify` — read `token` from the query string, call `verify_email_token`, and render `verify_result.html` with an outcome-specific (server-controlled, HTML-escaped) title + message.
  - `POST /verify/resend` — session-gated thin handler returning `verification_service.resend_for_user(user_id)` as JSON; `401` JSON when no `user_id`.
  - `GET /welcome` — additionally reads the row's `is_verified` (parameterized `SELECT`), issues/splices the per-session CSRF token for the resend form, and splices a `{{verify_banner_hidden}}` flag so the banner shows only for unverified users.
- **OAuth (`services/oauth_service.py`).** New Google accounts INSERT `is_verified = 1`; linking Google to an existing local account also sets `is_verified = 1` (Google has already verified the address). Returning Google users are unaffected (already verified, or grandfathered).
- **Templates.**
  - `check_email.html` (new) — static "check your inbox" confirmation, reusing the `notice-card` styling; no user input reflected.
  - `verify_result.html` (new) — `{{title}}` + `{{message}}` splice (escaped), with "Go to Dashboard" / "Login" links; no user input reflected.
  - `email_not_configured.html` (new) — static "email isn't set up — see the README" page, mirroring `oauth_not_configured.html`.
  - `dashboard.html` (modified) — a `verify-banner` block (hidden via `{{verify_banner_hidden}}` for verified users) containing the resend `<form>` (hidden `csrf_token` as first child), a message span, and an inline `fetch()` resend script.
- **CSS (`styles.css`).** Append `.verify-banner*` rules and any `check_email` / `verify_result` styling, all via the existing `var(--color-...)` custom properties so both themes are handled.
- **`.env.example`.** Append commented SMTP placeholders (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `APP_BASE_URL`) — placeholders only, never a real secret.
- **Docs.** Update `README.md` (move feature #3 to "Done (v1.0.4)"; add the new endpoints; add an "Email Verification — Setup" section; add a v1.0.4 release row; **remove** the two Continue-with-Google blockquote notes as requested) and `CLAUDE.md` (integration subsection, Important-Rules entry, Specification-Hierarchy entry, Vulnerability-Map note).

### 2.2 Out of Scope (Intentionally)

- **No blocking login on unverified accounts.** Per the chosen posture, `login()` is unchanged and unverified users authenticate normally; access is restricted only by the dashboard banner messaging in this slice. A future spec may harden specific routes behind verification.
- **No email change / re-verification on email change.** The email shown on `/profile` stays read-only; there is no flow to change it, so no re-verification path is needed.
- **No "verified" badge on the profile/dashboard beyond the banner.** The banner is the only surfaced state.
- **No admin/bulk re-send, no verification analytics, no email templating engine.** The email body is built inline in `mailer.py` with stdlib `email.message.EmailMessage`.
- **No token hashing at rest (Option A chosen).** The token is stored raw, mirroring how the CSRF token is stored raw in the session; single-use + 1-hour expiry bound the exposure. Hashing the token at rest is a documented future hardening, not part of this slice.
- **No new middleware and no middleware re-ordering.** The resend POST is covered by the existing CSRF + rate-limit stack automatically. `main.py` is not modified.
- **No new dependency.** `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. Email uses stdlib `smtplib`/`email`.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** every new statement in `verification_service.py`, the modified `signup()` INSERT, the `/welcome` `is_verified` read, and the OAuth INSERT/UPDATE use parameterized `?` placeholders. No string concatenation.
- **VULN-2 (Stored XSS):** `welcome_page` keeps escaping `{{username}}`; the new `verify_result.html` splices only server-controlled, `html.escape(..., quote=True)`-escaped strings; no Google `name`/`picture` or user value is rendered raw.
- **VULN-3 (Reflected XSS):** `/search` is untouched; `/verify` does **not** reflect the raw `token` into the page — it renders a fixed outcome message, not the token.
- **VULN-4 (Session Hijacking):** `main.py` is not modified; SMTP secrets come from env/`.env` (git-ignored), never hardcoded.
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged; verification adds no password handling and stores no password for the email flow.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered; `POST /verify/resend` is a POST and is throttled automatically (prevents an email-bomb). `GET /verify` is a GET (its secret is the high-entropy token) and is correctly out of scope of the POST-only limiter.
- **VULN-8 (CSRF):** the resend form carries the hidden `csrf_token` as the first child; `GET /welcome` issues the token; the existing `CSRFMiddleware` validates `POST /verify/resend`. `GET /verify` is intentionally a GET (token-in-link is the capability) and is out of scope of the POST-only middleware — the same rationale as the OAuth GET callback.

### 2.4 Explicit Non-Goals

- This feature does **not** introduce a template engine, build step, or JS framework. New pages use the same `str.replace("{{...}}", ...)` splice and inline `<script>` idiom as the rest of the app.
- This feature does **not** modify `login()`; an unverified user is not blocked from authenticating.
- This feature does **not** log or print the verification link when SMTP is unconfigured — it shows the not-configured page and declines to create the account.
- This feature does **not** add a flash-message framework; resend feedback is inline via the existing `fetch()` + JSON pattern.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec/plan pair and the prompt docs).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/mailer.py` | **New** | Stdlib SMTP sender: `send_verification_email()`, fail-safe (`return False`, never raises) |
| `backend/app/services/verification_service.py` | **New** | `start_verification()`, `verify_email_token()`, `resend_for_user()` — all parameterized SQL |
| `frontend/templates/check_email.html` | **New** | Static "check your inbox" page (no reflected input) |
| `frontend/templates/verify_result.html` | **New** | Outcome page; `{{title}}` + `{{message}}` escaped splice |
| `frontend/templates/email_not_configured.html` | **New** | Static "SMTP not set up — see README" page (mirrors `oauth_not_configured.html`) |
| `backend/app/core/config.py` | Modified | SMTP settings + `is_email_configured()` |
| `backend/app/db/session.py` | Modified | Additive idempotent migration (3 columns) + grandfather existing rows to verified |
| `backend/app/services/auth_service.py` | Modified | `signup()`: INSERT `is_verified=0`, capture `lastrowid`, trigger `start_verification()`, redirect to `/check-email` |
| `backend/app/services/oauth_service.py` | Modified | Google create/link sets `is_verified = 1` |
| `backend/app/api/routes/auth.py` | Modified | Signup gate; `GET /check-email`, `GET /verify`, `POST /verify/resend`; `/welcome` banner |
| `frontend/templates/dashboard.html` | Modified | Verify banner (resend form + message + inline fetch script) |
| `frontend/static/css/styles.css` | Modified | `.verify-banner*` + new-page rules via existing custom properties |
| `.env.example` | Modified | Commented SMTP placeholders |
| `README.md` | Modified | Feature/API/Release tables; "Email Verification — Setup" section; remove two CWG blockquote notes |
| `CLAUDE.md` | Modified | Integration subsection, Important-Rules entry, hierarchy + vuln-map entries |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / port (VULN-4 / VULN-7 / VULN-8 closures). The router auto-discovers the new handlers.
- `backend/app/core/security.py` — bcrypt (VULN-5 closure).
- `backend/app/core/csrf.py` — CSRF middleware (VULN-8 closure).
- `backend/app/core/rate_limit.py` — rate-limit middleware (VULN-7 closure).
- `backend/app/core/oauth.py` — Authlib client registration.
- `frontend/templates/login.html`, `frontend/templates/signup.html` — unchanged (the signup gate lives in the route, not the template).
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` — no dependency change.

---

## 4. Functional Requirements

### FR-01: Additive, Idempotent Schema Migration

- `init_db()` MUST add `is_verified INTEGER DEFAULT 0`, `verification_token TEXT`, and `verification_token_expires REAL` to a fresh `CREATE TABLE users`, and MUST add any of the three that are missing from a pre-existing DB via `ALTER TABLE users ADD COLUMN ...`. No row is dropped or rewritten.
- The *first* time `is_verified` is added to a pre-existing table (i.e., the column was absent), the migration MUST run `UPDATE users SET is_verified = 1` so existing accounts are grandfathered as verified. This runs once (it is keyed on the column having just been added).

### FR-02: SMTP Configuration Gate

- `config.is_email_configured()` MUST return `True` only when `SMTP_HOST`, `SMTP_USER`, and `SMTP_PASSWORD` are all non-empty.
- Settings MUST come exclusively from the environment / `.env` (no hardcoded secret). `SMTP_FROM` defaults to `SMTP_USER`; `SMTP_PORT` defaults to `587`; `APP_BASE_URL` defaults to `http://localhost:3001`; `EMAIL_VERIFICATION_TTL_SECONDS` defaults to `3600`.

### FR-03: Signup Is Gated on SMTP Configuration

- `GET /signup` MUST render `email_not_configured.html` (HTTP 200) when `is_email_configured()` is false, instead of the signup form.
- `POST /signup` MUST render `email_not_configured.html` (HTTP 200) when `is_email_configured()` is false, and MUST NOT create an account (defense in depth against a direct POST).

### FR-04: Signup Creates an Unverified Account and Sends the Email

- When configured, `auth_service.signup()` MUST insert the user with `is_verified = 0` using a **parameterized** INSERT that lists `is_verified` explicitly, and MUST capture `cursor.lastrowid`.
- After a successful commit, it MUST call `verification_service.start_verification(user_id, username, email)`.
- On success it MUST return `RedirectResponse("/check-email", status_code=302)`.
- A `False` return from `start_verification()` (email send failed) MUST NOT fail signup — the account stays created and the redirect to `/check-email` still occurs (the user can resend after login).
- The existing empty-field (`400`) and duplicate-username (`400`, `sqlite3.IntegrityError`) branches are preserved.

### FR-05: Token Issuance

- `start_verification()` MUST generate the token with `secrets.token_urlsafe(32)` (43-char, 256-bit) and set `verification_token_expires = time.time() + EMAIL_VERIFICATION_TTL_SECONDS`.
- It MUST persist both via a **parameterized** `UPDATE users SET verification_token = ?, verification_token_expires = ? WHERE id = ?`.
- The link emailed MUST be `f"{APP_BASE_URL}/verify?token={token}"`.

### FR-06: Verification Endpoint

- `GET /verify` MUST read `token = request.query_params.get("token")` and call `verify_email_token(token)`.
- `verify_email_token` MUST:
  1. Return `"invalid"` for a missing/blank token.
  2. `SELECT id, verification_token_expires FROM users WHERE verification_token = ?` (parameterized); return `"invalid"` if no row matches.
  3. Return `"expired"` if `verification_token_expires` is `NULL` or `time.time()` is past it.
  4. Otherwise set `is_verified = 1` and clear `verification_token`/`verification_token_expires` (single-use) via a **parameterized** `UPDATE`, then return `"ok"`.
  5. Return `"invalid"` on any unexpected DB error (logged server-side).
- `GET /verify` MUST render `verify_result.html`, splicing a fixed, outcome-specific `{{title}}`/`{{message}}` (HTML-escaped). It MUST NOT reflect the raw token into the response.

### FR-07: Resend Endpoint

- `POST /verify/resend` MUST be session-gated: no `user_id` → `JSONResponse({"error": "Not authenticated"}, 401)`.
- It MUST be a thin handler returning `verification_service.resend_for_user(user_id)`.
- `resend_for_user` MUST: return `401` if the row is gone; return `200 {"success": true, "message": "Your email is already verified."}` if `is_verified = 1`; otherwise re-issue a token (FR-05) + send, returning `200 {"success": true, "message": "Verification email sent. Check your inbox."}` on send success or `400 {"error": "Could not send the verification email. Please try again later."}` on failure.
- The hidden `csrf_token` is validated by `CSRFMiddleware`; the request is rate-limited by `RateLimitMiddleware` (both because it is a POST). No new wiring.

### FR-08: Dashboard Verification Banner

- `GET /welcome` MUST read the user's `is_verified` with a **parameterized** `SELECT ... WHERE id = ?`, issue/splice the per-session CSRF token (`get_or_create_csrf_token`), and splice `{{verify_banner_hidden}}` with `""` (banner visible) when unverified or `hidden` (HTML attribute, banner hidden) when verified.
- `dashboard.html` MUST contain a `verify-banner` block whose resend `<form id="resend-form">` has `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` as its **first** child, a submit button, and a `#resend-message` span.
- An inline `<script>` MUST `preventDefault()` and submit via `fetch("/verify/resend", { method: "POST", body: new URLSearchParams(new FormData(form)) })`, then render the JSON `message`/`error` into `#resend-message`. (`URLSearchParams` is required so `CSRFMiddleware` accepts the urlencoded body — same pattern as `login.html`.)

### FR-09: Google Users Are Auto-Verified

- In `oauth_service.find_or_create_google_user()`, the new-account INSERT MUST set `is_verified = 1`, and the link-to-existing-local-account UPDATE MUST set `is_verified = 1`. SQL stays parameterized; `password` stays `NULL` for new Google accounts (VULN-5 posture).

### FR-10: Fail-Safe Mailer (Stdlib Only)

- `mailer.send_verification_email()` MUST use only stdlib `smtplib` + `email`. It MUST return `False` (never raise) when `is_email_configured()` is false or on any SMTP/exception path, logging the cause. It MUST use STARTTLS for port 587 and implicit TLS (`SMTP_SSL`) for port 465, with the `OAUTH_HTTP_TIMEOUT`-independent SMTP timeout sourced from config.

### FR-11: Parameterized SQL Everywhere (VULN-1 Preserved)

- Every SQL statement added or modified by this feature MUST use `?` placeholders with a separate parameter list. String concatenation into SQL is forbidden.

### FR-12: No Schema Beyond the Three Columns, No New Dependency

- Only `is_verified`, `verification_token`, `verification_token_expires` are added to `users`. No other column. No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`.

### FR-13: Existing Auth Functions Otherwise Unchanged

- `login()` MUST remain byte-for-byte unchanged. `change_password()` and `password_meets_policy()` are unchanged. The only `auth_service.py` edit is inside `signup()` plus the new `verification_service` import.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
Exactly the files in §3 change (plus the spec/plan/prompt docs). No `main.py`, no `core/security.py`, no `core/csrf.py`, no `core/rate_limit.py`, no `core/oauth.py`, no `login.html`, no `signup.html`, no lockfile.

### NFR-02: No Hardcoded Secrets (VULN-4 Posture)
SMTP credentials live only in the environment / git-ignored `.env`. `.env.example` holds placeholders only. A fresh clone with no SMTP still boots and shows the not-configured page.

### NFR-03: CSRF + Rate Limit on the New POST (No New Wiring)
`POST /verify/resend` is covered by the existing `CSRFMiddleware` and `RateLimitMiddleware` because it is a POST. The form carries the hidden token; `/welcome` issues it.

### NFR-04: No Information Leakage
`GET /verify` renders a fixed outcome message and never echoes the token. The not-configured page leaks no internals. Mailer/DB exceptions are logged server-side, never reflected to the client.

### NFR-05: Output Encoding on Display (VULN-2/VULN-3 Posture)
Every value spliced into a template (the `verify_result` title/message, the dashboard username) is `html.escape(..., quote=True)`-encoded. No raw user value reaches the page.

### NFR-06: Fail-Safe Email Send
A failed or unconfigured send never raises into a request handler and never changes verification state. Signup still succeeds; resend reports a generic error.

### NFR-07: Single-Use, Time-Limited Token
A verified `GET /verify` clears the token columns, so the link is single-use. A token past `verification_token_expires` (default 1 hour) yields `"expired"` and grants nothing.

### NFR-08: Theme Stays Frontend-Only
New pages and the banner carry the same pre-paint theme script + toggle and use only `var(--color-...)` properties. No backend theme state is introduced.

### NFR-09: Consistency With Existing Patterns
Thin route → service (like `login`); `fetch()` + JSON inline feedback (like `login.html`/the profile form); `str.replace` template splice (like `welcome_page`); `get_db()` + `try/finally` connection handling; stdlib-only middleware-adjacent code; env/`.env` config via `core/config.py`; not-configured degrade page mirroring `oauth_not_configured.html`.

---

## 6. Success Paths

### SP-01: Configured Signup → Check Email
1. SMTP configured. User submits `GET`→`POST /signup` with valid fields + CSRF token.
2. `signup()` inserts the user (`is_verified = 0`), captures `lastrowid`, issues a token (1-hour expiry), sends the email, and 302s to `/check-email`.
3. The "check your inbox" page renders.

### SP-02: Click the Link → Verified
1. User opens `…/verify?token=<token>` within the hour.
2. `verify_email_token` matches the row, sets `is_verified = 1`, clears the token columns, returns `"ok"`.
3. `verify_result.html` shows the success title/message.

### SP-03: Unverified Login → Banner + Resend
1. An unverified user logs in normally (login is not blocked).
2. `/welcome` reads `is_verified = 0`, shows the banner with a Resend button and a populated CSRF token.
3. Clicking Resend `fetch()`-POSTs `/verify/resend`; the service re-issues + re-sends and returns `{"success": true, "message": "Verification email sent. Check your inbox."}`, shown inline.

### SP-04: Google Sign-In Is Pre-Verified
1. A user signs in with Google (configured).
2. `find_or_create_google_user` creates/links the row with `is_verified = 1`.
3. `/welcome` shows **no** banner.

### SP-05: SMTP Not Configured → Friendly Page
1. SMTP unset. User hits `GET /signup` (or POSTs directly).
2. The app renders `email_not_configured.html` (HTTP 200); **no** account is created; **no** link is logged.

### SP-06: Expired Link
1. User opens the link after the TTL.
2. `verify_email_token` returns `"expired"`; `verify_result.html` explains the link expired and to resend after logging in. No state change.

---

## 7. Edge Cases

- **EC-01 — Resend by a verified user:** `resend_for_user` returns `200 {"success": true, "message": "Your email is already verified."}`; no new token issued, no un-verify.
- **EC-02 — Resend with no session:** `CSRFMiddleware` rejects (`403`) a session-less POST first; even if it passed, the handler returns `401`. No state change.
- **EC-03 — `GET /verify` with no/blank token:** `"invalid"` outcome page; no DB write.
- **EC-04 — Reused (already-consumed) token:** the columns were cleared on first use, so the second click matches no row → `"invalid"`.
- **EC-05 — Email send fails at signup (bad app password, network):** account still created; `start_verification` returns `False`; user is redirected to `/check-email` and can Resend after login. Failure is logged, not reflected.
- **EC-06 — Grandfathered legacy rows:** existing accounts become `is_verified = 1` on migration; they see no banner and need no action.
- **EC-07 — Concurrent resends:** each issues a fresh token + expiry, overwriting the prior; only the latest link verifies. Rate-limit middleware throttles rapid repeats (`429`).
- **EC-08 — Username/email with HTML in the email/page:** the `verify_result` page renders only fixed escaped strings; the email body escapes the username before splicing into HTML. No markup executes.
- **EC-09 — `APP_BASE_URL` misconfig:** the link points wherever `APP_BASE_URL` says; documented as operator config. Default is `http://localhost:3001`.
- **EC-10 — JS disabled on the dashboard:** the Resend button (fetch-driven) won't submit; the rest of the dashboard renders. Acceptable for the lab (login already requires JS). Verification via the emailed link is unaffected (plain GET).

---

## 8. Acceptance Criteria

- **AC-01:** With SMTP configured, `POST /signup` (valid fields + CSRF) returns `302` to `/check-email`, and the new row has `is_verified = 0` with a non-NULL `verification_token`.
- **AC-02:** `GET /check-email` returns `200` and an HTML page indicating an email was sent.
- **AC-03:** `GET /verify?token=<valid>` returns `200`, the row becomes `is_verified = 1`, and `verification_token`/`verification_token_expires` are `NULL` afterward.
- **AC-04:** A second `GET /verify` with the same (now-cleared) token renders the invalid outcome (no crash, no state change).
- **AC-05:** `GET /verify?token=<expired>` renders the expired outcome and leaves `is_verified = 0`.
- **AC-06:** An unverified, logged-in user's `GET /welcome` contains the visible `verify-banner` with a 43-char CSRF token; a verified user's `/welcome` has the banner hidden (`hidden` attribute present).
- **AC-07:** `POST /verify/resend` (logged-in, valid CSRF) returns `200 {"success": true, ...}`; without a valid `csrf_token` it returns `403`; with no session it returns `401`/`403`.
- **AC-08:** With SMTP unconfigured, `GET /signup` and `POST /signup` return `200` rendering `email_not_configured.html`, and no row is inserted.
- **AC-09:** A Google sign-in (new or linked) yields a row with `is_verified = 1`.
- **AC-10:** Existing rows present before the migration are `is_verified = 1` after first boot on the new code.
- **AC-11:** `verification_service.py` and the modified `signup()`/`/welcome`/OAuth SQL are all parameterized (no concatenation). `core/security.py` is unchanged.
- **AC-12:** Only three columns were added to `users`; `git diff` of `backend/app/main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `login.html`, `signup.html`, and the lockfiles is empty.
- **AC-13:** `login()` is byte-for-byte unchanged.
- **AC-14:** No new dependency: `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` unchanged.
- **AC-15:** `GET /verify` never contains the raw token in its response body.
- **AC-16:** `README.md` shows feature #3 as "Done (v1.0.4)", lists `/verify` and `/verify/resend`, has an "Email Verification — Setup" section, and no longer contains the two removed Continue-with-Google blockquote notes. `CLAUDE.md` has the new subsection, rule, hierarchy, and vuln-map entries.
- **AC-17:** `uv run backend/app/main.py` boots with no traceback (configured **and** unconfigured).
- **AC-18:** VULN-1…VULN-8 all remain closed (parameterized SQL; escaped output; env-sourced secrets; bcrypt intact; no `/download/db`; rate-limit + CSRF cover the new POST).

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Configured signup | SMTP set, fresh DB | `POST /signup` → `302 /check-email`; row `is_verified=0`, token non-NULL |
| TC-02 | Check-email page | App running | `GET /check-email` → `200`, "check your inbox" HTML |
| TC-03 | Verify success | Valid unexpired token | `GET /verify?token=…` → `200`; row `is_verified=1`, token columns NULL |
| TC-04 | Verify reuse | Token already consumed | `GET /verify?token=…` → invalid outcome page, no change |
| TC-05 | Verify expired | Token past TTL | `GET /verify?token=…` → expired outcome; `is_verified` stays `0` |
| TC-06 | Verify no token | — | `GET /verify` → invalid outcome page |
| TC-07 | Banner shown | Unverified, logged in | `/welcome` HTML has visible `verify-banner` + 43-char csrf token |
| TC-08 | Banner hidden | Verified, logged in | `/welcome` banner carries `hidden` attribute |
| TC-09 | Resend OK | Logged in, unverified, valid csrf | `POST /verify/resend` → `200 {"success":true,...}` |
| TC-10 | Resend already verified | Logged in, verified | `200 {"success":true,"message":"...already verified."}` |
| TC-11 | Resend CSRF enforced | Logged in, no/invalid csrf | `403` |
| TC-12 | Resend no session | No cookie | `403` (CSRF) or `401` |
| TC-13 | Resend rate limited | App running | 6th `POST /verify/resend` from one IP in 60 s → `429` |
| TC-14 | SMTP unconfigured signup | No SMTP env | `GET`/`POST /signup` → `200` not-configured page; 0 rows inserted |
| TC-15 | Google auto-verify | OAuth configured | New/linked Google row `is_verified=1` |
| TC-16 | Grandfather | Pre-migration DB | Existing rows `is_verified=1` after boot |
| TC-17 | Parameterized SQL | Repo checkout | `verification_service.py` uses `?` placeholders; no concatenation |
| TC-18 | No token reflection | Valid/invalid token | `/verify` response body does not contain the raw token |
| TC-19 | Untouched files | Repo checkout | `git diff --stat` empty for main.py, security.py, csrf.py, rate_limit.py, oauth.py, login.html, signup.html, lockfiles |
| TC-20 | login() unchanged | Repo checkout | `login()` body byte-for-byte unchanged |
| TC-21 | No new dep | Repo checkout | `git diff --stat` empty for pyproject/uv.lock |
| TC-22 | App boots | Configured + unconfigured | `uv run backend/app/main.py` no traceback |
| TC-23 | README/CLAUDE updated | Repo checkout | feature #3 "Done (v1.0.4)"; endpoints listed; setup section; two CWG notes removed; CLAUDE entries present |

---

## 10. Verification Steps

Run from the repo root. (SMTP envs from `.env`.)

### 10.1 Unconfigured Degrade (AC-08, TC-14)
```bash
rm -f vulnerable_app.db
# with NO SMTP_* set:
uv run backend/app/main.py &
curl -s -o /dev/null -w 'signup_get=%{http_code}\n' http://localhost:3001/signup   # expect 200 (not-configured page)
```

### 10.2 Configured Signup → Verify (AC-01, AC-03, TC-01, TC-03)
```bash
# with SMTP_* set in .env, fresh DB:
TOKEN=$(curl -s -c jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'signup=%{http_code}\n' -b jar.txt -c jar.txt -X POST http://localhost:3001/signup \
  --data-urlencode 'username=alice' --data-urlencode 'email=alice@example.com' \
  --data-urlencode 'password=Str0ng!pass' --data-urlencode "csrf_token=$TOKEN"   # expect 302
# read the token from the email, then:
curl -s -o /dev/null -w 'verify=%{http_code}\n' "http://localhost:3001/verify?token=<TOKEN_FROM_EMAIL>"   # expect 200
sqlite3 vulnerable_app.db "SELECT is_verified, verification_token FROM users WHERE username='alice';"     # expect 1|
```

### 10.3 Banner + Resend (AC-06, AC-07, TC-07, TC-09, TC-11)
```bash
# log in as an unverified user, then:
curl -s -b jar.txt http://localhost:3001/welcome | grep -o 'verify-banner'                 # present
PT=$(curl -s -b jar.txt http://localhost:3001/welcome | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -w '\nresend=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/verify/resend --data-urlencode "csrf_token=$PT"   # expect 200 + success
curl -s -o /dev/null -w 'nocsrf=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/verify/resend                          # expect 403
```

### 10.4 File Audit (AC-12, AC-13, AC-14, TC-19, TC-20, TC-21)
```bash
git diff --stat -- backend/app/main.py backend/app/core/security.py backend/app/core/csrf.py \
  backend/app/core/rate_limit.py backend/app/core/oauth.py \
  frontend/templates/login.html frontend/templates/signup.html \
  pyproject.toml backend/pyproject.toml uv.lock     # all empty
```

Expected `git status --porcelain` (declared files + docs only):
```
?? backend/app/core/mailer.py
?? backend/app/services/verification_service.py
?? frontend/templates/check_email.html
?? frontend/templates/verify_result.html
?? frontend/templates/email_not_configured.html
 M backend/app/core/config.py
 M backend/app/db/session.py
 M backend/app/services/auth_service.py
 M backend/app/services/oauth_service.py
 M backend/app/api/routes/auth.py
 M frontend/templates/dashboard.html
 M frontend/static/css/styles.css
 M .env.example
 M README.md
 M CLAUDE.md
?? .claude/specs/email-verification-on-signup.md
?? .claude/specs/email-verification-on-signup-plan.md
?? docs/prompts/email-verification-spec-prompt.txt
?? docs/prompts/email-verification-spec-plan-prompt.txt
?? docs/prompts/email-verification-spec-execution-prompt.txt
```
