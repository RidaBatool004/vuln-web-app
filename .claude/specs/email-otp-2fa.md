# Software Specification Document — Email OTP Two-Factor Authentication (2FA)

**Version:** 1.0.0
**Last Updated:** 2026-06-20
**Target Release Tag:** v1.0.6
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [OTP via Email — README "Feature Enhancements" #6](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **Email OTP Two-Factor Authentication (2FA)** enhancement. It is item #6 ("OTP via Email") in the README's "Feature Enhancements" table. When a user **opts in** from their profile page, a successful username + password login no longer completes immediately: the app generates a **6-digit one-time passcode (OTP)**, emails it to the user's registered address, and holds the login in a **pending** state until the user enters the correct OTP on a dedicated verification screen. Only after the OTP is verified is the authenticated session created.

**This is a second authentication factor layered on the existing password flow — not a replacement for it.** It composes with every already-closed control:

| Stage (password login) | Control already in place | What this feature adds |
|------------------------|--------------------------|------------------------|
| Flood of POSTs | per-IP `RateLimitMiddleware` (VULN-7) | — (unchanged; covers the new POSTs too) |
| Forged cross-site POST | synchronizer-token `CSRFMiddleware` (VULN-8) | — (unchanged; the OTP forms carry `csrf_token`) |
| Per-account brute force | Account Lockout (v1.0.5) | — (unchanged; runs before bcrypt) |
| Password check | bcrypt verify (VULN-5) | **Second factor:** even a correct password does **not** create a session when 2FA is on |
| Email confirmation | Email Verification (v1.0.4) | OTP delivery reuses the same stdlib SMTP mailer |

The feature is built entirely on the project's existing primitives, with **no new third-party dependency** (stdlib `secrets` + `smtplib` + `email`, the existing `core/config.py` env loader, the existing `SessionMiddleware`):

- **2FA state and the live OTP challenge live server-side on the user's row** — five new columns — mirroring the schema-on-`users` precedent set by Continue-with-Google (v1.0.3), Email Verification (v1.0.4), and Account Lockout (v1.0.5).
- **The pending-login handshake rides the existing signed session cookie.** Between the password step and the OTP step the app writes a short-lived `pending_2fa_user_id` into `request.session` (NOT `user_id`), so the `/welcome` and `/profile` gates — which require `user_id` — still treat the user as logged-out until the OTP succeeds. The session is signed by the VULN-4 `SECRET_KEY`, so the pending marker cannot be forged.
- **Auth stays session-only.** As with Continue-with-Google, the signed session cookie is the single auth mechanism — there is **no JWT, access/refresh token, or extra cookie**. The PRD phrase "issue tokens" is satisfied by promoting the session, consistent with `CLAUDE.md`'s session-only rule.
- All new SQL is **parameterized** (VULN-1). The OTP is never reflected into any page (VULN-3); usernames/emails spliced into the OTP email are `html.escape(..., quote=True)`'d (VULN-2 posture).

**Toggle posture (product-owner choice): session-gated.** Enabling/disabling 2FA from `/profile` requires only the existing authenticated session (plus the CSRF token enforced on every POST). It does **not** ask for the current password again. (This was an explicit product decision favouring UX; see NFR-09 for the accepted trade-off.)

**OTP-storage posture (product-owner choice): raw code + attempt cap.** The 6-digit code is stored in plaintext on the user's row (easy to inspect for teaching) and protected by a **verification-attempt cap** (default 5 wrong tries → the code is invalidated and the user must request a new one), a **short expiry** (default 5 minutes), and a **per-account resend cooldown** (default 60 seconds) — on top of the unchanged per-IP rate limiter.

This feature does **not** change any of the eight closed vulnerabilities. After this change, all eight remain closed and the app gains its **fourth** database-schema change.

The implementation touches:

- One new backend module: `backend/app/services/otp_service.py` (OTP issue / verify / resend / toggle helpers, parameterized SQL).
- One new template: `frontend/templates/otp_verify.html` (the OTP entry screen).
- Existing files: `backend/app/core/config.py` (OTP settings), `backend/app/core/mailer.py` (new `send_otp_email`), `backend/app/db/session.py` (additive migration, five columns), `backend/app/services/auth_service.py` (`login()` branches to the OTP challenge when 2FA is on), `backend/app/api/routes/auth.py` (four new routes), `frontend/templates/login.html` (redirect to the OTP screen), `frontend/templates/profile.html` (the enable/disable card).
- `.env.example`, `README.md`, and `CLAUDE.md` (documentation).

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/oauth.py`, `backend/app/services/oauth_service.py`, `backend/app/services/lockout_service.py`, `backend/app/services/verification_service.py`, and the other templates / CSS remain unchanged. No dependency is added.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Schema (additive, idempotent — fourth-ever schema change).** Add five columns to `users` in `init_db()`:
  - `two_factor_enabled INTEGER DEFAULT 0` — `1` when the user has turned on Email OTP 2FA, else `0`.
  - `otp_code TEXT` — the current outstanding 6-digit OTP (raw), or `NULL` when none is pending.
  - `otp_expires REAL` — Unix epoch seconds after which the OTP is dead, or `NULL`.
  - `otp_attempts INTEGER DEFAULT 0` — wrong-OTP submissions against the current code; reset to `0` on each new code.
  - `otp_last_sent REAL` — Unix epoch seconds of the most recent OTP send, for the resend cooldown, or `NULL`.
  - The migration adds any missing column with `ALTER TABLE users ADD COLUMN ...`, never dropping a row, exactly like the v1.0.3 / v1.0.4 / v1.0.5 migrations. **No grandfather `UPDATE` is needed:** the defaults (`0` / `NULL`) already mean "2FA off, no challenge outstanding", so every existing row starts correct.
- **OTP configuration (`core/config.py`).** Read three settings from the environment / `.env`, all with safe defaults (no secret involved); plus one fixed module constant for the code length:
  - `OTP_TTL_SECONDS` (default `300`, i.e. **5 minutes**) — OTP lifetime.
  - `OTP_MAX_ATTEMPTS` (default `5`) — wrong-code submissions before the OTP is invalidated.
  - `OTP_RESEND_COOLDOWN_SECONDS` (default `60`) — minimum gap between OTP sends for one account.
  - `OTP_LENGTH = 6` — fixed module constant (the feature is specified as a 6-digit code; not env-overridable to avoid weak configurations).
  - No new `is_*_configured()` gate of its own: these are non-secret tunables and the feature is always available **when email is configured**. OTP delivery depends on SMTP, so enabling 2FA and issuing a challenge both reuse the existing **`is_email_configured()`** gate.
- **OTP service (`services/otp_service.py`, new).** Stdlib-only helpers (`secrets`, `time`, `threading`, `logging`), all parameterized SQL, importable by `auth_service` and the route layer without a circular import (it imports only `secrets`/`time`/`threading`/`logging`, `core.config`, `core.mailer`, `db.session`):
  - `set_two_factor(user_id, enabled) -> bool` — parameterized `UPDATE users SET two_factor_enabled = ?`; when **disabling**, also clear any outstanding OTP columns in the same statement. Returns `True` on success, `False` on a DB error (so the route can report).
  - `start_challenge(user_id, username, email, background=False) -> bool` — generate a fresh OTP with `f"{secrets.randbelow(10**OTP_LENGTH):0{OTP_LENGTH}d}"`, persist `otp_code` + `otp_expires = now + OTP_TTL_SECONDS` + `otp_attempts = 0` + `otp_last_sent = now` via a parameterized `UPDATE`, then send the email. `background=True` (login challenge) hands the SMTP send to a daemon thread and returns immediately; `background=False` (resend) sends synchronously and returns the mailer's success boolean. Mirrors `verification_service.start_verification`.
  - `seconds_until_resend(row) -> int` — given a fetched row, return how many seconds remain on the resend cooldown (`0` when a resend is allowed); reads `otp_last_sent` only, no DB access.
  - `verify(user_id, code) -> dict` — fetch the row, then return `{"status": <str>, "user": <dict|None>}`:
    - `"ok"` — there is an outstanding, unexpired code, the attempt cap is not exhausted, and `secrets.compare_digest(stored, code)` matches; the OTP columns are cleared (single-use) and `user` carries `{id, username, email}`.
    - `"no_challenge"` — no outstanding code (`otp_code` is `NULL`); the user must restart login.
    - `"expired"` — a code exists but `time.time() > otp_expires`; the code is cleared.
    - `"too_many"` — the attempt cap is already reached; the code is cleared and the user must resend.
    - `"invalid"` — wrong code with attempts remaining; `otp_attempts` is incremented (and the code cleared if this increment hits the cap).
  - The verify/issue writes use parameterized SQL; comparison is constant-time (`secrets.compare_digest`).
- **Login branches to the OTP challenge (`services/auth_service.py`, `login()` only).** After the **unchanged** lockout gate, bcrypt verify, `lockout_service.reset()`, and `is_verified` gate, and **before** writing the full session keys:
  1. If `user["two_factor_enabled"]` is falsy → write `user_id`/`username`/`email` exactly as today (no behaviour change for non-2FA users).
  2. If `two_factor_enabled` is truthy **and** `config.is_email_configured()` → write `request.session["pending_2fa_user_id"] = user["id"]` (and `pending_2fa_username`), issue `otp_service.start_challenge(..., background=True)`, and return `200 {"otp_required": true, "redirect": "/login/otp"}`. **No `user_id` is written**, so the user is not yet authenticated.
  3. If `two_factor_enabled` is truthy **but** email is not configured → fail **closed**: return `401 {"error": "Two-factor authentication is enabled but email delivery is unavailable."}` and write no session. (In practice unreachable: signup itself requires SMTP, and 2FA can only be enabled while email is configured — defensive only.)
- **New routes (`api/routes/auth.py`).** Four thin handlers; the three POSTs ride the existing CSRF + rate-limit middleware automatically:
  - `POST /profile/2fa` — session-gated; reads an `enable` form field (`"1"`/`"0"`) and calls `otp_service.set_two_factor`. Enabling is refused with `400` when `is_email_configured()` is false (can't deliver an OTP). Returns JSON for inline feedback.
  - `GET /login/otp` — render `otp_verify.html` (with a spliced CSRF token) **only** when `request.session["pending_2fa_user_id"]` is present; otherwise `302 → /login`. No user input is reflected (the screen is generic; it does not echo the email or the code).
  - `POST /login/otp` — read the `otp` form field + `pending_2fa_user_id`; call `otp_service.verify`. On `"ok"`, **clear the pending keys, write the full session** (`user_id`/`username`/`email`), and return `200 {"success": true, "redirect": "/welcome"}`. On any other status, return a `401`/`400` JSON message (no session). With no pending marker → `401 {"error": "Your login session expired. Please sign in again."}`.
  - `POST /login/otp/resend` — read `pending_2fa_user_id`; enforce the resend cooldown via `seconds_until_resend`; on success call `start_challenge(..., background=False)` and return a JSON sent/cooldown message.
- **Templates.**
  - **New `otp_verify.html`** — same shared header / theme-toggle / pre-render theme IIFE as the other pages; a form with a hidden `csrf_token`, a single 6-digit `otp` input, a Verify button, a Resend button (with a JS countdown), and a status element. Submits urlencoded via `URLSearchParams` (so the CSRF middleware's parser accepts it), reads JSON, and redirects on success — modeled on `login.html`.
  - **`login.html`** — one additive branch in the existing fetch handler: when the JSON response has `data.otp_required`, `window.location.href = data.redirect`. No other change; the resend-verification affordance and Google button are untouched.
  - **`profile.html`** — a new "Two-Factor Authentication" card showing the current status and an enable/disable button that POSTs to `/profile/2fa` (urlencoded, hidden `csrf_token`). When email is not configured, the card shows a short "requires email setup" note and the button is disabled. The current state is supplied by the handler (see below).
- **Profile handler reads 2FA state (`api/routes/auth.py`, `profile_page`).** `profile_page` additionally SELECTs `two_factor_enabled` for the session user (parameterized) and splices a `{{twofa_enabled}}` flag (and an email-configured flag) into `profile.html` so the card renders the correct initial state. (The session does not carry the 2FA flag, so a tiny DB read is added here only.)
- **Mailer (`core/mailer.py`).** Add `send_otp_email(to_email, username, code) -> bool` alongside `send_verification_email`: same fail-safe contract (returns `False`, never raises), same STARTTLS/implicit-TLS handling, username `html.escape`'d into the HTML part. The code is a server-generated digit string (no escaping concern) shown prominently in the body.
- **`.env.example`.** Append three commented placeholders (`OTP_TTL_SECONDS`, `OTP_MAX_ATTEMPTS`, `OTP_RESEND_COOLDOWN_SECONDS`) with their defaults — values, not secrets.
- **Docs.** Update `README.md` (move feature #6 to "Done (v1.0.6)"; add a v1.0.6 release row; add the four new routes to the API table) and `CLAUDE.md` (integration subsection, Important-Rules entry, Specification-Hierarchy entry).

### 2.2 Out of Scope (Intentionally)

- **No TOTP / authenticator-app 2FA.** That is the separate README item #5 (MFA via Authenticator App). This slice is **email** OTP only.
- **No 2FA on the Continue-with-Google path.** `oauth.py`, `oauth_service.py`, and the `/auth/google/callback` handler are **not** modified (CLAUDE.md forbids it). Google identities have `password = NULL` and a Google-verified email; the email-OTP second factor is defined for the **password** login path only. A Google user may still toggle the profile setting, but it only affects a (nonexistent) password login. Documented as a non-goal.
- **No backup/recovery codes, no "remember this device", no SMS fallback.** A user who enables 2FA and then loses email access has no self-service recovery in this slice (admin can clear the flag in the DB). These are documented future hardening, not this feature.
- **No 2FA on `/profile/password`.** Changing the password already requires an authenticated session and the current password; adding an OTP there is out of scope (keeps the change surgical).
- **No change to the rate limiter, CSRF, session secret, bcrypt, or lockout.** Those middlewares/services stay byte-for-byte unchanged; the new POSTs inherit their protection.
- **No new dependency.** `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. The OTP uses stdlib `secrets`; delivery reuses the stdlib `smtplib` mailer.
- **No template engine / JS framework.** The OTP screen is one hand-written HTML file with an inline `<script>`, like every other page.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** every statement in `otp_service.py` and the modified `login()` / `profile_page` SELECT uses parameterized `?` placeholders. No string concatenation.
- **VULN-2 (Stored XSS):** the OTP email `html.escape(..., quote=True)`'s the username before splicing into the HTML part (same as `send_verification_email`); `profile.html`'s spliced `{{twofa_enabled}}` is a server-controlled `"0"`/`"1"` flag, not user input.
- **VULN-3 (Reflected XSS):** the OTP code is **never** reflected into any page; `otp_verify.html` shows a fixed, generic prompt. The `/login/otp` JSON messages are fixed, server-controlled strings.
- **VULN-4 (Session Hijacking):** `main.py` is not modified; the pending-login marker lives in the existing **signed** session cookie (signed by `SECRET_KEY`), so it cannot be forged to impersonate another user. OTP settings come from env/`.env` with non-secret defaults.
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged; bcrypt remains the sole password authenticator and runs **before** the 2FA branch (a wrong password never reaches OTP issuance). 2FA adds a factor; it does not weaken the first.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered and unchanged; the new `POST /login/otp`, `POST /login/otp/resend`, and `POST /profile/2fa` are throttled by it like every other POST. The per-account OTP resend cooldown and attempt cap are **additional** layers.
- **VULN-8 (CSRF):** the three new POSTs carry the hidden `csrf_token`; `CSRFMiddleware` validates them. The two new GET-able capabilities (`GET /login/otp`) reflect nothing and are gated on the session.

### 2.4 Explicit Non-Goals

- This feature does **not** change `signup()`, `change_password()`, `password_meets_policy()`, `verify_email_token()`, `start_verification()`, `resend_for_credentials()`, the lockout helpers, or the OAuth path.
- This feature does **not** add per-account lock state for wrong OTPs to the lockout columns — OTP brute force is bounded by its own `otp_attempts` cap (the credential check already passed). The per-IP rate limiter still throttles rapid OTP submissions.
- This feature does **not** persist any token outside `users` / the signed session. No Redis, no in-memory map, no extra cookie.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec/plan pair and the prompt docs).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/services/otp_service.py` | **New** | `set_two_factor()`, `start_challenge()`, `seconds_until_resend()`, `verify()` — parameterized SQL, stdlib OTP generation, fail-safe send |
| `frontend/templates/otp_verify.html` | **New** | OTP entry screen (hidden `csrf_token`, single code input, resend w/ countdown, fetch → JSON → redirect) |
| `backend/app/core/config.py` | Modified | `OTP_TTL_SECONDS` (300) + `OTP_MAX_ATTEMPTS` (5) + `OTP_RESEND_COOLDOWN_SECONDS` (60) + `OTP_LENGTH` (6); docstring note |
| `backend/app/core/mailer.py` | Modified | Add `send_otp_email()` (fail-safe, escaped username) |
| `backend/app/db/session.py` | Modified | Additive idempotent migration (5 columns); no grandfather needed |
| `backend/app/services/auth_service.py` | Modified | `login()`: branch to the OTP challenge when `two_factor_enabled` (after the unchanged gates) |
| `backend/app/api/routes/auth.py` | Modified | 4 new routes (`POST /profile/2fa`, `GET`+`POST /login/otp`, `POST /login/otp/resend`); `profile_page` reads 2FA state |
| `frontend/templates/login.html` | Modified | Redirect to `/login/otp` when `data.otp_required` |
| `frontend/templates/profile.html` | Modified | "Two-Factor Authentication" enable/disable card |
| `.env.example` | Modified | Commented OTP placeholders (defaults shown) |
| `README.md` | Modified | Feature #6 → Done (v1.0.6); release row; API-endpoint rows |
| `CLAUDE.md` | Modified | Integration subsection, Important-Rules entry, hierarchy entry |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / `RATE_LIMIT_*` / port (VULN-4 / VULN-7 / VULN-8 closures). The 2FA logic is service/route-layer; no middleware is added.
- `backend/app/core/rate_limit.py`, `backend/app/core/csrf.py`, `backend/app/core/security.py` — VULN-7 / VULN-8 / VULN-5 closures stay exactly as-is.
- `backend/app/core/oauth.py`, `backend/app/services/oauth_service.py` — the Google path is not given email-OTP 2FA.
- `backend/app/services/lockout_service.py`, `backend/app/services/verification_service.py` — unchanged (login's lockout + verified gates are reused as-is, before the new branch).
- The other templates (`signup.html`, `dashboard.html`, `check_email.html`, `verify_result.html`, `email_not_configured.html`, `oauth_not_configured.html`) and `frontend/static/css/styles.css` — the OTP screen reuses existing classes; no CSS edit is required.
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` — no dependency change.

---

## 4. Functional Requirements

### FR-01: Additive, Idempotent Schema Migration
- `init_db()` MUST add `two_factor_enabled INTEGER DEFAULT 0`, `otp_code TEXT`, `otp_expires REAL`, `otp_attempts INTEGER DEFAULT 0`, and `otp_last_sent REAL` to a fresh `CREATE TABLE users`, and MUST add any that are missing from a pre-existing DB via `ALTER TABLE users ADD COLUMN ...`. No row is dropped or rewritten.
- No grandfather `UPDATE` is run: the defaults (`0` / `NULL`) already place every existing row in "2FA off, no challenge outstanding".

### FR-02: OTP Configuration
- `config.OTP_TTL_SECONDS` MUST be read from the environment as an `int`, defaulting to `300`.
- `config.OTP_MAX_ATTEMPTS` MUST be read from the environment as an `int`, defaulting to `5`.
- `config.OTP_RESEND_COOLDOWN_SECONDS` MUST be read from the environment as an `int`, defaulting to `60`.
- `config.OTP_LENGTH` MUST be the fixed integer `6` (not env-overridable).
- None of these is a secret; the three tunables are documented in `.env.example` with their defaults. No new `is_*_configured()` gate is added; OTP delivery reuses `is_email_configured()`.

### FR-03: OTP Service Helpers (`otp_service.py`)
- `set_two_factor(user_id, enabled) -> bool` MUST set `two_factor_enabled` via parameterized SQL; when `enabled` is false it MUST also clear `otp_code`, `otp_expires`, `otp_attempts (→ 0)`, and `otp_last_sent` in the same statement. It MUST return `False` (not raise) on a DB error.
- `start_challenge(user_id, username, email, background=False) -> bool` MUST generate a uniformly random `OTP_LENGTH`-digit code with `secrets.randbelow(10**OTP_LENGTH)` (zero-padded), persist `otp_code`, `otp_expires = time.time() + OTP_TTL_SECONDS`, `otp_attempts = 0`, and `otp_last_sent = time.time()` via parameterized SQL, then send via `mailer.send_otp_email`. With `background=True` it MUST dispatch the send on a daemon thread and return `True` immediately; with `background=False` it MUST send synchronously and return the mailer's boolean.
- `seconds_until_resend(row) -> int` MUST return `0` when `otp_last_sent` is `NULL` or the cooldown has elapsed, else the integer seconds remaining. No DB access.
- `verify(user_id, code) -> dict` MUST return the `{"status", "user"}` contract in §2.1 with statuses `ok` / `no_challenge` / `expired` / `too_many` / `invalid`. On `ok` it MUST clear all four OTP columns (single-use); on `expired` / `too_many` it MUST clear the code; on `invalid` it MUST increment `otp_attempts` (and clear the code if the increment reaches `OTP_MAX_ATTEMPTS`). Comparison MUST be constant-time (`secrets.compare_digest`).
- All SQL MUST be parameterized. A malformed/empty `code` MUST be treated as `invalid` (or `no_challenge` when no code is outstanding), never raising.

### FR-04: Login Branches to the OTP Challenge
- `login()` MUST keep the existing order — lockout gate → bcrypt verify → `lockout_service.reset()` → `is_verified` gate — **unchanged**, and only then consult `two_factor_enabled`.
- When `two_factor_enabled` is truthy and `config.is_email_configured()`, `login()` MUST write `request.session["pending_2fa_user_id"]` (and `pending_2fa_username`), MUST NOT write `user_id`, MUST issue `otp_service.start_challenge(..., background=True)`, and MUST return `200 {"otp_required": true, "redirect": "/login/otp"}`.
- When `two_factor_enabled` is truthy but email is not configured, `login()` MUST fail closed: `401` with a fixed error and no session.
- When `two_factor_enabled` is falsy, `login()` MUST write the full session exactly as today (no behaviour change).

### FR-05: OTP Verification Route Completes the Login
- `GET /login/otp` MUST render `otp_verify.html` only when `pending_2fa_user_id` is in the session; otherwise `302 → /login`. It MUST splice a CSRF token and MUST NOT reflect the email or any code.
- `POST /login/otp` MUST read the `otp` form field and `pending_2fa_user_id`. With no pending marker it MUST return `401`. On `verify(...) == "ok"` it MUST delete the pending keys, write `user_id`/`username`/`email` from the returned user, and return `200 {"success": true, "redirect": "/welcome"}`. On any other status it MUST return a `401`/`400` JSON error and write no `user_id`.
- `POST /login/otp/resend` MUST read `pending_2fa_user_id`, enforce `seconds_until_resend`, and on success call `start_challenge(..., background=False)`, returning a JSON message; during the cooldown it MUST return a JSON "please wait N seconds" message without re-sending.

### FR-06: Profile Toggle (Session-Gated)
- `POST /profile/2fa` MUST require a session `user_id` (return `401` otherwise) and read an `enable` flag. Enabling MUST be refused with `400` when `is_email_configured()` is false. On success it MUST call `set_two_factor` and return `200 {"success": true, "two_factor_enabled": <bool>, "message": "..."}`.
- `profile_page` MUST read `two_factor_enabled` for the session user (parameterized SELECT) and splice the initial state (and an email-configured flag) into `profile.html`. It MUST NOT require or accept the current password for the toggle (session-gate-only posture).

### FR-07: OTP Lifecycle Semantics
- An OTP is single-use: a successful `verify` clears all OTP columns. A second submission of the same code returns `no_challenge`.
- A new `start_challenge` overwrites any prior code and resets `otp_attempts` to `0` and `otp_last_sent` to now (the most recent code is the only valid one).
- A wrong code increments `otp_attempts`; reaching `OTP_MAX_ATTEMPTS` invalidates the code (cleared) and subsequent submissions return `too_many` until a resend issues a new code.
- An expired code (`time.time() > otp_expires`) is invalid and cleared on the verify attempt.

### FR-08: Parameterized SQL Everywhere (VULN-1 Preserved)
- Every SQL statement added by this feature (in `otp_service.py` and the `profile_page` SELECT) MUST use `?` placeholders with a separate parameter list. String concatenation into SQL is forbidden.

### FR-09: Session-Only Auth Preserved (no JWT/tokens)
- The pending handshake and the completed login MUST use only `request.session` keys (signed cookie). No JWT, access/refresh token, bearer header, or extra cookie is introduced (consistent with the Continue-with-Google rule).

### FR-10: OTP Never Reflected (VULN-3 Preserved)
- The raw OTP MUST NOT appear in any HTTP response body, log line at INFO+, URL, or template. It is delivered only via email and compared server-side.

### FR-11: No New Dependency
- No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`. OTP generation/comparison uses stdlib `secrets`; delivery reuses the stdlib `smtplib` mailer.

### FR-12: Untouched Functions / Files
- `signup()`, `change_password()`, `password_meets_policy()` (in `auth_service.py`), the lockout helpers, the verification helpers, every OAuth function, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `main.py`, the non-listed templates, and all CSS MUST remain unchanged.

### FR-13: Email Delivery is Fail-Safe
- `mailer.send_otp_email` MUST return `False` (never raise) on any unconfigured/connect/login/send error, logging the cause server-side. A failed send MUST NOT crash the login or change the user's session state; the login already holds in the pending state, and the user can resend or restart.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
Exactly the files in §3 change (plus the spec/plan/prompt docs). No `main.py`, no `core/rate_limit.py`/`csrf.py`/`security.py`/`oauth.py`, no `oauth_service.py`/`lockout_service.py`/`verification_service.py`, no unrelated template/CSS, no lockfile.

### NFR-02: Configuration, Not Hardcoded Magic Numbers
OTP TTL, attempt cap, and resend cooldown come from `core/config.py` (env/`.env`) with documented defaults, mirroring `EMAIL_VERIFICATION_TTL_SECONDS` and the lockout thresholds. Demos can set short values (`OTP_TTL_SECONDS=30 OTP_RESEND_COOLDOWN_SECONDS=5`).

### NFR-03: Second Factor, Not a Weaker First Factor
The 2FA branch runs strictly **after** the bcrypt verify and the lockout + verified gates. A wrong password, a locked account, or an unverified account never triggers OTP issuance, so 2FA cannot become an oracle and adds no new pre-auth email-send surface beyond what a correct password already unlocks.

### NFR-04: Brute-Force Resistance of a Low-Entropy Code
A 6-digit code has ~10⁶ possibilities. Resistance comes from the layered bounds: per-OTP attempt cap (default 5), short expiry (default 5 min), per-account resend cooldown (default 60 s), and the unchanged per-IP rate limiter. The expected number of guesses an attacker can make against one code before it is invalidated/expired is far below 10⁶, keeping the success probability negligible.

### NFR-05: Fail-Safe Delivery, Fail-Closed Auth
Email sending is fail-safe (bool, never raises). The auth decision is fail-closed: if 2FA is on and email cannot deliver, login is refused (no session) rather than silently bypassing the second factor.

### NFR-06: No Information Leakage
The OTP screen and all OTP JSON messages are fixed, server-controlled strings — no email address, no code, no attempt count, no internal field is reflected. DB exceptions are logged server-side, never surfaced.

### NFR-07: Consistency With Existing Patterns
Thin route → service; `get_db()` + `try/finally` per call; parameterized SQL; env config via `core/config.py`; additive idempotent migration like v1.0.3–v1.0.5; `time.time()`-based epoch columns like `verification_token_expires` / `locked_until`; background daemon-thread send like `start_verification`; fetch + `URLSearchParams` + hidden `csrf_token` like the login/profile forms; pre-render theme IIFE + shared header in the new template.

### NFR-08: Pending State is Tamper-Proof and Short-Lived
`pending_2fa_user_id` lives only in the signed session cookie. It is set only after a correct password + verified gate, cleared on successful OTP verification, and naturally discarded on `/logout` (`session.clear()`). It grants no access on its own — `/welcome` and `/profile` require `user_id`, which is written only post-OTP.

### NFR-09: Deliberate Toggle Trade-off (session-gate-only)
Enabling/disabling 2FA requires only the authenticated session (+ CSRF), not a password re-prompt — the product owner's chosen UX. Accepted risk: an already-hijacked session could disable 2FA. This is bounded by the fact that obtaining the session already required clearing the first factor (and, when 2FA was on, a prior OTP). The trade-off MUST be documented in the code comments, `CLAUDE.md`, and this spec. (A future hardening could require the current password to disable 2FA.)

---

## 6. Success Paths

### SP-01: Non-2FA Login Unaffected
1. A verified user with `two_factor_enabled = 0` submits the correct password.
2. Lockout gate passes, bcrypt verifies, `reset()` runs, verified gate passes, the 2FA branch is skipped, the full session is written → `200 {"success": true, "redirect": "/welcome"}`. Byte-for-byte the current behaviour.

### SP-02: Enable 2FA From Profile
1. A logged-in user opens `/profile`; the 2FA card shows "Disabled".
2. They click **Enable**; the page POSTs `enable=1` (urlencoded, CSRF token) to `/profile/2fa`.
3. `is_email_configured()` is true → `set_two_factor(user_id, True)` → `200`; the card flips to "Enabled".

### SP-03: 2FA Login Happy Path
1. A user with `two_factor_enabled = 1` submits the correct password.
2. `login()` writes `pending_2fa_user_id`, fires `start_challenge(background=True)` (a 6-digit code is emailed), and returns `{"otp_required": true, "redirect": "/login/otp"}`; the login page redirects to `/login/otp`.
3. The user enters the code; `POST /login/otp` → `verify` returns `ok`; the pending keys are removed, the full session is written → `200 {"success": true, "redirect": "/welcome"}`.

### SP-04: Resend Within Limits
1. On `/login/otp` the user clicks **Resend** after the 60-second cooldown.
2. `seconds_until_resend` returns `0` → `start_challenge(background=False)` sends a fresh code (new `otp_code`, `otp_attempts = 0`, `otp_last_sent = now`) → JSON "Verification code sent."

### SP-05: Disable 2FA
1. A logged-in user clicks **Disable**; `POST /profile/2fa` with `enable=0`.
2. `set_two_factor(user_id, False)` flips the flag and clears any outstanding OTP columns → `200`; subsequent logins skip the OTP step.

---

## 7. Edge Cases

- **EC-01 — Wrong password, 2FA on:** bcrypt fails before the 2FA branch; the generic `401` (and lockout counting) applies exactly as today. No OTP is issued.
- **EC-02 — Correct password, 2FA on, but unverified:** the `is_verified` gate returns its `401 {"unverified": true}` before the 2FA branch; no OTP is issued. (Unverified accounts can't have logged in to enable 2FA anyway — defensive ordering.)
- **EC-03 — Wrong OTP, attempts remain:** `verify` → `invalid`, `otp_attempts++`; `401 {"error": "Incorrect code. Please try again."}`. No session.
- **EC-04 — Wrong OTP hits the cap:** the increment reaches `OTP_MAX_ATTEMPTS`; the code is cleared; `401 {"error": "Too many incorrect attempts. Request a new code."}`. The user must resend.
- **EC-05 — Expired OTP:** `verify` → `expired` (code cleared); `401 {"error": "This code has expired. Request a new one."}`.
- **EC-06 — `GET /login/otp` with no pending marker** (deep link, or after logout): `302 → /login`.
- **EC-07 — `POST /login/otp` with no pending marker** (session expired/cleared): `401 {"error": "Your login session expired. Please sign in again."}`.
- **EC-08 — Resend during cooldown:** `seconds_until_resend > 0` → JSON "Please wait N seconds before requesting another code." No new send; the existing code stays valid.
- **EC-09 — Enable 2FA while email unconfigured:** `POST /profile/2fa` `enable=1` → `400 {"error": "Email delivery is not configured, so OTP 2FA can't be enabled."}`. The flag stays `0`.
- **EC-10 — 2FA on but email breaks at login time:** `login()` still issues the challenge (background send fails fast, logged), the user lands on `/login/otp` but no code arrives; they can resend (which reports the failure) or restart. The session is never silently completed. (If `is_email_configured()` itself is false, FR-04 fails closed at `401`.)
- **EC-11 — Google (OAuth) account toggles 2FA:** the flag is stored but the OAuth callback path is unchanged, so a Google sign-in is unaffected. A password login for that row would fail closed (`password = NULL`) before reaching the 2FA branch. Documented non-goal.
- **EC-12 — DB error in `set_two_factor`:** returns `False`; the route returns `400 {"error": "Could not update the 2FA setting."}`; no state change.
- **EC-13 — Concurrent OTP submissions:** single-process SQLite serializes the short `UPDATE`s; worst case is an off-by-one in `otp_attempts`, which only shifts when the cap trips by one — acceptable (documented).
- **EC-14 — Pre-migration DB:** existing rows gain the five columns at defaults (`0`/`NULL`); 2FA is off for everyone until they opt in.

---

## 8. Acceptance Criteria

- **AC-01:** A fresh DB's `users` table has `two_factor_enabled` (default 0), `otp_code`, `otp_expires`, `otp_attempts` (default 0), and `otp_last_sent` per `PRAGMA table_info(users)`.
- **AC-02:** A pre-existing DB gains all five columns on first boot; existing rows read `two_factor_enabled = 0` and `NULL` OTP fields; no grandfather `UPDATE` runs.
- **AC-03:** A non-2FA user's correct-password login still returns `200 {"success": true, "redirect": "/welcome"}` and writes `user_id` (no behaviour change).
- **AC-04:** With 2FA enabled, a correct-password `POST /login` returns `200 {"otp_required": true, "redirect": "/login/otp"}`, writes `pending_2fa_user_id` but **not** `user_id`, and triggers an OTP email.
- **AC-05:** `GET /welcome` and `GET /profile` still redirect to `/login` while only `pending_2fa_user_id` (no `user_id`) is set.
- **AC-06:** Submitting the correct OTP to `POST /login/otp` returns `200 {"success": true}`, clears the pending keys, writes `user_id`, and clears all OTP columns on the row.
- **AC-07:** A wrong OTP returns `401 {"error": ...}` and increments `otp_attempts`; the `OTP_MAX_ATTEMPTS`-th wrong code clears `otp_code` and yields the "too many attempts" message.
- **AC-08:** An expired OTP (set `OTP_TTL_SECONDS=1`, wait) returns the "expired" `401` and clears the code.
- **AC-09:** `POST /login/otp/resend` within the cooldown returns a "please wait" message and does not change `otp_code`; after the cooldown it issues a new code and resets `otp_attempts` to `0`.
- **AC-10:** `POST /profile/2fa` `enable=1` while email is configured returns `200` and sets `two_factor_enabled = 1`; `enable=0` returns `200`, sets it to `0`, and clears any OTP columns.
- **AC-11:** `POST /profile/2fa` `enable=1` while email is **not** configured returns `400` and leaves the flag `0`.
- **AC-12:** The OTP value never appears in any HTTP response body, URL, or rendered page (inspect `/login/otp` HTML and all JSON).
- **AC-13:** All SQL in `otp_service.py` and the `profile_page` SELECT uses `?` placeholders (no concatenation).
- **AC-14:** `git diff` is empty for `main.py`, `core/rate_limit.py`, `core/csrf.py`, `core/security.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, `verification_service.py`, `signup.html`, `dashboard.html`, `styles.css`, and the lockfiles.
- **AC-15:** No new dependency: `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` unchanged.
- **AC-16:** `uv run backend/app/main.py` boots with no traceback; a normal (non-2FA) correct-password login still succeeds.
- **AC-17:** VULN-1…VULN-8 all remain closed (parameterized SQL; bcrypt intact and still the password authenticator, running before the 2FA branch; rate-limit + CSRF + session middleware unchanged; no `/download/db`; env-sourced config; no raw OTP reflection).
- **AC-18:** `README.md` shows feature #6 as "Done (v1.0.6)", adds a v1.0.6 release row, and lists the four new routes. `CLAUDE.md` has the new subsection, rule, and hierarchy entry.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Columns on fresh DB | `rm` DB, boot | `PRAGMA table_info(users)` shows all five columns at defaults |
| TC-02 | Migration on old DB | Pre-migration DB copy | Five columns added; existing rows `0`/`NULL`; 2FA off |
| TC-03 | Non-2FA login unchanged | Verified user, 2FA off | Correct pw → `200 {"success":true,"redirect":"/welcome"}` |
| TC-04 | Enable 2FA | Logged-in, email configured | `POST /profile/2fa` `enable=1` → `200`; row `two_factor_enabled=1` |
| TC-05 | 2FA login → pending | 2FA on | Correct pw → `200 {"otp_required":true}`; session has `pending_2fa_user_id`, no `user_id`; OTP emailed |
| TC-06 | Pending can't reach dashboard | Only pending marker set | `GET /welcome` → `302 /login` |
| TC-07 | Correct OTP completes | Pending + emailed code | `POST /login/otp` correct → `200`; `user_id` set; OTP columns cleared |
| TC-08 | Wrong OTP increments | Pending + code | Wrong code → `401`; `otp_attempts` +1 |
| TC-09 | Attempt cap | `OTP_MAX_ATTEMPTS=3` | 3rd wrong code → "too many"; `otp_code` cleared |
| TC-10 | Expiry | `OTP_TTL_SECONDS=1`, wait 2 s | Correct code → "expired" `401`; code cleared |
| TC-11 | Resend cooldown | Just sent | `POST /login/otp/resend` → "please wait"; `otp_code` unchanged |
| TC-12 | Resend after cooldown | `OTP_RESEND_COOLDOWN_SECONDS=1`, wait | New code issued; `otp_attempts` reset to 0 |
| TC-13 | Disable 2FA | 2FA on | `enable=0` → `200`; flag 0; OTP columns cleared |
| TC-14 | Enable blocked w/o email | SMTP unset | `enable=1` → `400`; flag stays 0 |
| TC-15 | OTP not reflected | Pending | `/login/otp` HTML + JSON contain no code or email |
| TC-16 | Parameterized SQL | Repo checkout | `otp_service.py` + `profile_page` SELECT use `?` placeholders |
| TC-17 | Untouched files | Repo checkout | `git diff --stat` empty for the forbidden files + lockfiles |
| TC-18 | No new dep | Repo checkout | `git diff --stat` empty for pyproject/uv.lock |
| TC-19 | App boots + normal login | Repo checkout | `uv run …` no traceback; non-2FA login → `200` |
| TC-20 | Docs updated | Repo checkout | feature #6 "Done (v1.0.6)"; v1.0.6 row; new routes; CLAUDE entries |

---

## 10. Verification Steps

Run from the repo root. Use short OTP windows for the demo (`OTP_TTL_SECONDS=60 OTP_RESEND_COOLDOWN_SECONDS=5`), and raise the per-IP limit if exercising many POSTs from one IP (`RATE_LIMIT_MAX=100`).

### 10.1 Schema (AC-01, TC-01)
```bash
rm -f vulnerable_app.db
uv run backend/app/main.py &
sqlite3 vulnerable_app.db "PRAGMA table_info(users);" | grep -E 'two_factor_enabled|otp_code|otp_expires|otp_attempts|otp_last_sent'   # all five
```

### 10.2 Enable 2FA, Then Log In (AC-04, AC-05, TC-04, TC-05, TC-06)
```bash
# Sign up + verify a user, log in, open /profile, click Enable (or POST /profile/2fa enable=1).
# Then log out and log back in:
#   POST /login  → {"otp_required": true, "redirect": "/login/otp"}
#   GET  /welcome (with only the pending marker) → 302 /login
# Read the 6-digit code from the email (or, for a local test, from the DB):
sqlite3 vulnerable_app.db "SELECT otp_code, otp_expires, otp_attempts FROM users WHERE username='alice';"
```

### 10.3 Complete / Fail the OTP (AC-06, AC-07, AC-08)
```bash
# Correct code → 200 {"success": true}; row's otp_code becomes NULL and user_id is set.
# Wrong code OTP_MAX_ATTEMPTS times → "too many" 401 and otp_code cleared.
# With OTP_TTL_SECONDS=1, waiting >1s → "expired" 401.
```

### 10.4 File Audit (AC-14, AC-15, TC-17, TC-18)
```bash
git diff --stat -- backend/app/main.py backend/app/core/rate_limit.py backend/app/core/csrf.py \
  backend/app/core/security.py backend/app/core/oauth.py backend/app/services/oauth_service.py \
  backend/app/services/lockout_service.py backend/app/services/verification_service.py \
  frontend/templates/signup.html frontend/templates/dashboard.html frontend/static/css/styles.css \
  pyproject.toml backend/pyproject.toml uv.lock     # all empty
```

Expected `git status --porcelain` (declared files + docs only):
```
?? backend/app/services/otp_service.py
?? frontend/templates/otp_verify.html
 M backend/app/core/config.py
 M backend/app/core/mailer.py
 M backend/app/db/session.py
 M backend/app/services/auth_service.py
 M backend/app/api/routes/auth.py
 M frontend/templates/login.html
 M frontend/templates/profile.html
 M .env.example
 M README.md
 M CLAUDE.md
?? .claude/specs/email-otp-2fa.md
?? .claude/specs/email-otp-2fa-plan.md
?? docs/prompts/email-otp-2fa-spec-prompt.txt
?? docs/prompts/email-otp-2fa-spec-plan-prompt.txt
?? docs/prompts/email-otp-2fa-spec-execution-prompt.txt
```
