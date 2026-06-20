# Software Specification Document — MFA via Authenticator App (TOTP)

**Version:** 1.0.0
**Last Updated:** 2026-06-20
**Target Release Tag:** v1.0.7
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [MFA via Authenticator App (TOTP) — README "Feature Enhancements" #5](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **MFA via Authenticator App (TOTP)** enhancement. It is item #5 ("MFA via Authenticator App (TOTP)") in the README's "Feature Enhancements" table. A user **enrolls** an authenticator app (Google Authenticator, Authy, 1Password, …) by scanning a **QR code** on their profile page. After enrollment, a successful username + password login no longer completes immediately: the app holds the login in a **pending** state and asks the user for the current **6-digit time-based one-time password (TOTP, RFC 6238)** shown in their authenticator app. Only after that code is verified is the authenticated session created.

**This is a second authentication factor layered on the existing password flow — not a replacement for it.** It is the direct sibling of the already-shipped **Email OTP 2FA** (v1.0.6, README item #6): same pending-session handshake, same "second factor after bcrypt" ordering, but the code comes from the user's **authenticator app** (a shared secret + the clock) instead of an emailed message. It composes with every already-closed control:

| Stage (password login) | Control already in place | What this feature adds |
|------------------------|--------------------------|------------------------|
| Flood of POSTs | per-IP `RateLimitMiddleware` (VULN-7) | — (unchanged; covers the new POSTs too) |
| Forged cross-site POST | synchronizer-token `CSRFMiddleware` (VULN-8) | — (unchanged; the TOTP forms carry `csrf_token`) |
| Per-account brute force | Account Lockout (v1.0.5) | — (unchanged; runs before bcrypt) |
| Password check | bcrypt verify (VULN-5) | **Second factor:** even a correct password does **not** create a session when TOTP is enrolled |
| Email confirmation | Email Verification (v1.0.4) | — (unchanged; TOTP needs no email at all) |
| Email OTP 2FA | Email OTP (v1.0.6) | TOTP is an **independent** second-factor method; when both are on, **TOTP takes precedence** at login |

### 1.1 Design Decisions (product-owner choices)

These four decisions were made explicitly before writing this spec and shape everything below:

1. **QR generation: add `segno`.** TOTP math (HOTP/TOTP, RFC 4226/6238) is implemented in **pure stdlib** (`hmac` + `hashlib` + `struct` + `base64` + `time`) — no `pyotp`. But rendering a QR-code **image** cannot reasonably be done in the standard library, so this feature adds exactly **one** new dependency: **`segno`** (a pure-Python, zero-transitive-dependency QR library) to render the QR server-side as a PNG `data:` URI. This is the project's **first feature-driven dependency since Authlib** (Continue-with-Google, v1.0.3) and is justified on the same grounds: a capability the stdlib genuinely cannot provide. Everything else stays stdlib.
2. **Coexistence with Email OTP: independent, TOTP wins.** TOTP and Email OTP are **independent** opt-ins on `/profile`. A user may have either, both, or neither. At login, **if TOTP is enrolled, it takes precedence** (the user is sent to the TOTP screen and **no email is sent**); only if TOTP is **not** enrolled does the existing Email OTP branch run. The Email OTP feature (v1.0.6) is **not modified in behaviour** — its branch simply moves to run *after* the new TOTP branch.
3. **Enrollment requires a confirm code.** Enabling TOTP is a two-step flow: (a) the app generates a secret + QR for the user to scan, storing the secret as **pending** (`totp_secret` set, `totp_enabled = 0`); (b) the user must submit one **valid current TOTP code** to **confirm**, which flips `totp_enabled = 1`. This proves the authenticator was provisioned correctly and prevents self-lockout from a mis-scanned secret. An unconfirmed secret grants nothing.
4. **No recovery / backup codes this slice.** TOTP has no email fallback, so a lost authenticator means lockout. Recovery is **out of scope** for this slice (an administrator clears the flag in the DB), exactly as the Email OTP feature deferred recovery. Documented as future hardening.

### 1.2 Built on existing primitives

- **TOTP enrollment state lives server-side on the user's row** — three new columns — mirroring the schema-on-`users` precedent of Continue-with-Google (v1.0.3), Email Verification (v1.0.4), Account Lockout (v1.0.5), and Email OTP (v1.0.6).
- **The pending-login handshake rides the existing signed session cookie.** Between the password step and the TOTP step the app writes a short-lived `pending_2fa_user_id` into `request.session` (NOT `user_id`), so the `/welcome` and `/profile` gates — which require `user_id` — still treat the user as logged-out until the code succeeds. The session is signed by the VULN-4 `SECRET_KEY`, so the pending marker cannot be forged. This reuses the **same** session keys the Email OTP feature introduced; a `pending_2fa_method` marker disambiguates which screen to show.
- **Auth stays session-only.** As with Continue-with-Google and Email OTP, the signed session cookie is the single auth mechanism — there is **no JWT, access/refresh token, or extra cookie**. The session is promoted to a full login only after the TOTP code is verified.
- All new SQL is **parameterized** (VULN-1). The login-time TOTP code is never reflected into any page (VULN-3); the enrollment secret/QR are shown **only to the enrolling owner** over their own authenticated session (that is the point of enrollment) and are never logged.

**Toggle / disable posture (product-owner choice): session-gated.** Enrolling, confirming, and disabling TOTP from `/profile` require only the existing authenticated session (plus the CSRF token enforced on every POST). They do **not** re-prompt for the current password — consistent with the Email OTP toggle (v1.0.6, NFR-09). See NFR-09 for the accepted trade-off.

**Secret-storage posture (product-owner choice): raw base32 secret.** The TOTP shared secret is stored in plaintext (base32) on the user's row — easy to inspect for teaching, consistent with the raw-OTP-code storage in the Email OTP feature. Its protection in the lab is the unguessable 160-bit value plus the standard TOTP bounds (small validity window, ±skew, replay guard) on top of the unchanged per-IP rate limiter.

This feature does **not** change any of the eight closed vulnerabilities. After this change, all eight remain closed and the app gains its **fifth** database-schema change.

The implementation touches:

- One new backend module: `backend/app/services/totp_service.py` (secret generation, stdlib HOTP/TOTP, provisioning URI, QR via `segno`, enroll / confirm / verify / disable; parameterized SQL).
- One new template: `frontend/templates/totp_verify.html` (the login-time code entry screen).
- Existing files: `backend/app/core/config.py` (TOTP settings), `backend/app/db/session.py` (additive migration, three columns), `backend/app/services/auth_service.py` (`login()` branches to the TOTP challenge — before the Email OTP branch — when TOTP is enrolled), `backend/app/api/routes/auth.py` (five new routes; `profile_page` reads TOTP state), `frontend/templates/profile.html` (the enroll/confirm/disable card).
- Dependency manifests: `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` (add `segno`).
- `.env.example`, `README.md`, and `CLAUDE.md` (documentation).

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/oauth.py`, `backend/app/core/mailer.py`, `backend/app/services/oauth_service.py`, `backend/app/services/lockout_service.py`, `backend/app/services/verification_service.py`, `backend/app/services/otp_service.py` (the Email OTP service is reused untouched), `frontend/templates/login.html` (it already routes on `data.otp_required` → `data.redirect`), and the other templates / CSS remain unchanged.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Schema (additive, idempotent — fifth-ever schema change).** Add three columns to `users` in `init_db()`:
  - `totp_secret TEXT` — the base32 TOTP shared secret. Set (as *pending*) when enrollment starts; persists while enrolled; `NULL` when the user has no TOTP secret.
  - `totp_enabled INTEGER DEFAULT 0` — `1` only **after** a confirm code has validated the secret; `0` while disabled or while a secret is *pending* (generated but not yet confirmed).
  - `totp_last_step INTEGER` — the last accepted TOTP time-step counter, for **replay protection** (a code already used cannot be reused inside its window); `NULL` until the first successful verify.
  - The migration adds any missing column with `ALTER TABLE users ADD COLUMN ...`, never dropping a row, exactly like the v1.0.3–v1.0.6 migrations. **No grandfather `UPDATE` is needed:** the defaults (`NULL` / `0` / `NULL`) already mean "no secret, TOTP off, never used", so every existing row starts correct.
- **TOTP configuration (`core/config.py`).** Read three settings from the environment / `.env`, all non-secret with safe defaults; plus two fixed module constants:
  - `TOTP_ISSUER` (default `"Security Vulnerability Lab"`) — the issuer label embedded in the QR / `otpauth://` URI (shown in the authenticator app).
  - `TOTP_PERIOD_SECONDS` (default `30`) — the TOTP time step.
  - `TOTP_SKEW_STEPS` (default `1`) — how many steps **before and after** the current step are accepted at verify time (clock-drift tolerance: `1` ⇒ a ±30 s window).
  - `TOTP_DIGITS = 6` — fixed module constant (authenticator apps default to 6; not env-overridable to avoid weak configurations).
  - `TOTP_SECRET_BYTES = 20` — fixed module constant (160-bit secret, the RFC 6238 / Google Authenticator norm), base32-encoded for the QR.
  - **No `is_*_configured()` gate.** TOTP requires **no SMTP and no Google** — it works on a fresh clone with zero configuration. The settings are non-secret tunables, always on with safe defaults.
- **TOTP service (`services/totp_service.py`, new).** Stdlib-only helpers (`base64`, `hashlib`, `hmac`, `secrets`, `struct`, `time`, `urllib.parse`, `logging`) plus `segno` for the QR image only, all parameterized SQL, importable by `auth_service` and the route layer without a circular import (it imports only those modules, `core.config`, and `db.session`):
  - `generate_secret() -> str` — `base64.b32encode(secrets.token_bytes(TOTP_SECRET_BYTES))` decoded to an uppercase, unpadded base32 string.
  - `provisioning_uri(secret, username) -> str` — build `otpauth://totp/{issuer}:{username}?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30`, URL-encoding the label and issuer with `urllib.parse.quote`.
  - `qr_data_uri(uri) -> str | None` — `segno.make(uri).png_data_uri(scale=…)`; the **only** use of `segno`. Returns `None` on any rendering error so the route can report a friendly failure.
  - `start_enrollment(user_id, username) -> dict | None` — generate a fresh secret, persist it as **pending** (`totp_secret = secret`, `totp_enabled = 0`, `totp_last_step = NULL`) via a parameterized `UPDATE`, build the URI + QR, and return `{"secret": …, "otpauth_uri": …, "qr_data_uri": …}`. Returns `None` on a DB error.
  - `confirm(user_id, code) -> dict` — fetch the row; if there is no `totp_secret`, return `{"status": "no_pending"}`; otherwise verify `code` against the pending secret (with `TOTP_SKEW_STEPS`); on a match set `totp_enabled = 1` and record `totp_last_step`, returning `{"status": "ok"}`; else `{"status": "invalid"}`.
  - `verify(user_id, code) -> dict` — login-time check. Fetch the row; require `totp_enabled = 1` and a non-NULL `totp_secret` (else `{"status": "no_challenge", "user": None}`). Compute the valid codes for the current step ± `TOTP_SKEW_STEPS`, compare with `secrets.compare_digest` (constant-time), and **reject any step ≤ `totp_last_step`** (replay guard). On success, update `totp_last_step` to the matched step and return `{"status": "ok", "user": {id, username, email}}`; else `{"status": "invalid", "user": None}`.
  - `disable(user_id) -> bool` — parameterized `UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL`. Returns `False` (not raise) on a DB error.
  - All SQL is parameterized; comparisons are constant-time; a malformed/empty `code` is treated as `invalid` (or `no_challenge`/`no_pending` when no secret is outstanding), never raising.
- **Login branches to the TOTP challenge (`services/auth_service.py`, `login()` only).** After the **unchanged** lockout gate, bcrypt verify, `lockout_service.reset()`, and `is_verified` gate, and **before** the existing Email OTP branch:
  1. If `user["totp_enabled"]` is truthy → write `request.session["pending_2fa_user_id"] = user["id"]`, `pending_2fa_username`, and `pending_2fa_method = "totp"`; **do not** send any email; **do not** write `user_id`; return `200 {"otp_required": true, "redirect": "/login/totp"}`.
  2. Else if `user["two_factor_enabled"]` (Email OTP) → the **existing v1.0.6 branch runs unchanged** (sets `pending_2fa_method = "email"`, issues the emailed code, returns `redirect: "/login/otp"`).
  3. Else → write `user_id`/`username`/`email` exactly as today (no behaviour change for non-2FA users).
- **New routes (`api/routes/auth.py`).** Five thin handlers; the four POSTs ride the existing CSRF + rate-limit middleware automatically:
  - `POST /profile/totp/setup` — session-gated. Refused with `400` when `totp_enabled` is already `1` (the user must disable first to re-enroll). Otherwise calls `start_enrollment` and returns `200 {"success": true, "qr_data_uri": …, "secret": …, "otpauth_uri": …}` for the page to render the QR + manual-entry key.
  - `POST /profile/totp/confirm` — session-gated. Reads a `code` field, calls `confirm`. On `"ok"` returns `200 {"success": true, "message": "…"}`; on any other status returns `400 {"error": "…"}`.
  - `POST /profile/totp/disable` — session-gated. Calls `disable`; returns `200 {"success": true, …}`.
  - `GET /login/totp` — render `totp_verify.html` (with a spliced CSRF token) **only** when `request.session["pending_2fa_user_id"]` is present **and** `pending_2fa_method == "totp"`; otherwise `302 → /login`. No user input is reflected (the screen is generic; it does not echo the secret or any code).
  - `POST /login/totp` — read the `code` field + `pending_2fa_user_id`; call `verify`. On `"ok"`, **clear the pending keys, write the full session** (`user_id`/`username`/`email`), and return `200 {"success": true, "redirect": "/welcome"}`. On any other status, return a `401` JSON message (no session). With no pending marker → `401 {"error": "Your login session expired. Please sign in again."}`.
- **Templates.**
  - **New `totp_verify.html`** — same shared header / theme-toggle / pre-render theme IIFE as the other pages; a form with a hidden `csrf_token`, a single 6-digit `code` input, and a Verify button; a "Back to login" link. **No resend button** (the code comes from the authenticator app, not from us). Submits urlencoded via `URLSearchParams` (so the CSRF middleware's parser accepts it), reads JSON, and redirects on success — modeled on `otp_verify.html` minus the resend logic.
  - **`profile.html`** — a new "Authenticator App (TOTP)" card, **separate from** the existing "Two-Factor Authentication" (Email OTP) card. When TOTP is disabled it shows an **Enable / Set up** button that POSTs to `/profile/totp/setup`, then reveals the returned QR (`<img src="{data-uri}">`), the manual-entry base32 secret, a confirm-code input, and a Confirm button that POSTs to `/profile/totp/confirm`. When TOTP is enabled it shows "enabled" and a **Disable** button that POSTs to `/profile/totp/disable`. The initial state is supplied by the handler (see below).
- **Profile handler reads TOTP state (`api/routes/auth.py`, `profile_page`).** `profile_page` additionally SELECTs `totp_enabled` for the session user (parameterized, alongside the existing `two_factor_enabled` read) and splices a `{{totp_enabled}}` flag into `profile.html` so the card renders the correct initial state.
- **`segno` dependency.** Add `segno>=1.6.0` to `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock`. Pure-Python, no transitive dependencies.
- **`.env.example`.** Append three commented placeholders (`TOTP_ISSUER`, `TOTP_PERIOD_SECONDS`, `TOTP_SKEW_STEPS`) with their defaults — values, not secrets.
- **Docs.** Update `README.md` (move feature #5 to "Done (v1.0.7)"; add a v1.0.7 release row; add the five new routes to the API table; note the `segno` dependency) and `CLAUDE.md` (integration subsection, Important-Rules entry, Specification-Hierarchy entry).

### 2.2 Out of Scope (Intentionally)

- **No backup/recovery codes, no "remember this device", no SMS fallback.** A user who enrolls TOTP and then loses their authenticator has no self-service recovery in this slice (an admin clears `totp_secret`/`totp_enabled` in the DB). Documented future hardening, not this feature.
- **No TOTP on the Continue-with-Google path.** `oauth.py`, `oauth_service.py`, and `/auth/google/callback` are **not** modified (CLAUDE.md forbids it). Google identities have `password = NULL` and never reach the password `login()` branch where the TOTP challenge lives. A Google user could toggle the profile setting, but it only affects a (nonexistent) password login. Documented non-goal.
- **No change to the Email OTP feature's behaviour.** `otp_service.py`, `core/mailer.py`, `otp_verify.html`, and the `/login/otp*` + `/profile/2fa` routes are **not** modified. The only interaction is ordering: `login()` consults TOTP **before** Email OTP. (One line is added to the existing Email OTP branch to also set `pending_2fa_method = "email"` for screen disambiguation — a marker only, no behaviour change. See §2.4.)
- **No TOTP on `/profile/password`.** Changing the password already requires an authenticated session and the current password; adding TOTP there is out of scope.
- **No change to the rate limiter, CSRF, session secret, bcrypt, lockout, or mailer.** Those middlewares/services stay byte-for-byte unchanged; the new POSTs inherit their protection.
- **No `pyotp` dependency.** TOTP/HOTP is implemented in stdlib (RFC 4226/6238 is ~20 lines). The **only** added dependency is `segno`, and **only** for QR-image rendering.
- **No template engine / JS framework.** The TOTP screen and profile card are hand-written HTML with inline `<script>`, like every other page.
- **No SHA-256/512 TOTP, no 8-digit codes, no configurable period below/above the default beyond the env knob.** Algorithm is fixed to SHA-1 / 6 digits (the authenticator-app default) so any standard app works without manual configuration.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** every statement in `totp_service.py` and the modified `login()` / `profile_page` SELECT uses parameterized `?` placeholders. No string concatenation.
- **VULN-2 (Stored XSS):** `profile.html`'s spliced `{{totp_enabled}}` is a server-controlled `"0"`/`"1"` flag, not user input. The QR is a server-generated PNG `data:` URI placed in an `<img src>`; the manual-entry secret is a server-generated base32 string. The `otpauth://` URI URL-encodes the username (`urllib.parse.quote`).
- **VULN-3 (Reflected XSS):** the login-time TOTP code is **never** reflected into any page; `totp_verify.html` shows a fixed, generic prompt, and all `/login/totp` JSON messages are fixed, server-controlled strings. The enrollment secret/QR are returned **only** to the authenticated owner during their own setup (not a reflection of attacker input) and are never logged.
- **VULN-4 (Session Hijacking):** `main.py` is not modified; the pending-login marker lives in the existing **signed** session cookie (signed by `SECRET_KEY`), so it cannot be forged. TOTP settings come from env/`.env` with non-secret defaults; the per-user secret is generated with `secrets.token_bytes` (CSPRNG).
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged; bcrypt remains the sole password authenticator and runs **before** the TOTP branch (a wrong password never reaches the TOTP challenge). TOTP adds a factor; it does not weaken the first.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered and unchanged; the new `POST /login/totp`, `POST /profile/totp/setup`, `POST /profile/totp/confirm`, and `POST /profile/totp/disable` are throttled by it like every other POST. The TOTP replay guard and tiny validity window are **additional** layers.
- **VULN-8 (CSRF):** the four new POSTs carry the hidden `csrf_token`; `CSRFMiddleware` validates them. The one new GET-able capability (`GET /login/totp`) reflects nothing and is gated on the session.

### 2.4 Explicit Non-Goals / Minimal Touch

- This feature does **not** change `signup()`, `change_password()`, `password_meets_policy()`, the verification helpers, the lockout helpers, the OAuth path, or any Email OTP function.
- The **only** edit to the existing Email OTP code path is one added line in `auth_service.login()`'s Email OTP branch to also set `request.session["pending_2fa_method"] = "email"` (a screen-disambiguation marker; the Email OTP behaviour is otherwise byte-identical). `otp_service.py`, `otp_verify.html`, and the `/login/otp*` / `/profile/2fa` routes are untouched.
- This feature does **not** persist any state outside `users` / the signed session. No Redis, no in-memory map, no extra cookie.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec/plan pair and the prompt docs).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/services/totp_service.py` | **New** | `generate_secret()`, `provisioning_uri()`, `qr_data_uri()`, `start_enrollment()`, `confirm()`, `verify()`, `disable()` — stdlib HOTP/TOTP, parameterized SQL, `segno` QR, replay guard |
| `frontend/templates/totp_verify.html` | **New** | Login-time code entry screen (hidden `csrf_token`, single code input, fetch → JSON → redirect; no resend) |
| `backend/app/core/config.py` | Modified | `TOTP_ISSUER` + `TOTP_PERIOD_SECONDS` + `TOTP_SKEW_STEPS` + fixed `TOTP_DIGITS` (6) + `TOTP_SECRET_BYTES` (20); docstring note |
| `backend/app/db/session.py` | Modified | Additive idempotent migration (3 columns: `totp_secret`, `totp_enabled`, `totp_last_step`); no grandfather needed |
| `backend/app/services/auth_service.py` | Modified | `login()`: branch to the TOTP challenge when `totp_enabled` (after the unchanged gates, **before** the Email OTP branch); add `pending_2fa_method` marker |
| `backend/app/api/routes/auth.py` | Modified | 5 new routes (`POST /profile/totp/setup|confirm|disable`, `GET`+`POST /login/totp`); `profile_page` reads TOTP state |
| `frontend/templates/profile.html` | Modified | "Authenticator App (TOTP)" enroll/confirm/disable card |
| `pyproject.toml` | Modified | Add `segno>=1.6.0` |
| `backend/pyproject.toml` | Modified | Add `segno>=1.6.0` |
| `uv.lock` | Modified | Lock `segno` (regenerated by `uv sync`/`uv lock`) |
| `.env.example` | Modified | Commented TOTP placeholders (defaults shown) |
| `README.md` | Modified | Feature #5 → Done (v1.0.7); release row; API-endpoint rows; `segno` note |
| `CLAUDE.md` | Modified | Integration subsection, Important-Rules entry, hierarchy entry |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / `RATE_LIMIT_*` / port (VULN-4 / VULN-7 / VULN-8 closures). The TOTP logic is service/route-layer; no middleware is added.
- `backend/app/core/rate_limit.py`, `backend/app/core/csrf.py`, `backend/app/core/security.py`, `backend/app/core/mailer.py` — VULN-7 / VULN-8 / VULN-5 closures and the mailer stay exactly as-is.
- `backend/app/core/oauth.py`, `backend/app/services/oauth_service.py` — the Google path is not given TOTP.
- `backend/app/services/lockout_service.py`, `backend/app/services/verification_service.py`, `backend/app/services/otp_service.py` — unchanged (login's lockout + verified gates and the Email OTP branch are reused as-is).
- `frontend/templates/login.html` — unchanged; it already redirects to `data.redirect` on `data.otp_required`.
- The other templates (`signup.html`, `dashboard.html`, `otp_verify.html`, `check_email.html`, `verify_result.html`, `email_not_configured.html`, `oauth_not_configured.html`) and `frontend/static/css/styles.css` — the TOTP screen/card reuse existing classes; no CSS edit is required.

---

## 4. Functional Requirements

### FR-01: Additive, Idempotent Schema Migration
- `init_db()` MUST add `totp_secret TEXT`, `totp_enabled INTEGER DEFAULT 0`, and `totp_last_step INTEGER` to a fresh `CREATE TABLE users`, and MUST add any that are missing from a pre-existing DB via `ALTER TABLE users ADD COLUMN ...`. No row is dropped or rewritten.
- No grandfather `UPDATE` is run: the defaults (`NULL` / `0` / `NULL`) already place every existing row in "no secret, TOTP off".

### FR-02: TOTP Configuration
- `config.TOTP_ISSUER` MUST be read from the environment as a string, defaulting to `"Security Vulnerability Lab"`.
- `config.TOTP_PERIOD_SECONDS` MUST be read from the environment as an `int`, defaulting to `30`.
- `config.TOTP_SKEW_STEPS` MUST be read from the environment as an `int`, defaulting to `1`.
- `config.TOTP_DIGITS` MUST be the fixed integer `6`; `config.TOTP_SECRET_BYTES` MUST be the fixed integer `20`.
- None of these is a secret; the three tunables are documented in `.env.example`. **No new `is_*_configured()` gate is added** — TOTP needs neither SMTP nor Google and is always available.

### FR-03: TOTP Service Helpers (`totp_service.py`)
- `generate_secret()` MUST return an uppercase base32 string from `secrets.token_bytes(TOTP_SECRET_BYTES)`.
- HOTP/TOTP MUST be computed in stdlib per RFC 4226/6238 (HMAC-SHA1, dynamic truncation, zero-padded to `TOTP_DIGITS`). No `pyotp`.
- `provisioning_uri(secret, username)` MUST produce a valid `otpauth://totp/...` URI with `issuer`, `algorithm=SHA1`, `digits`, and `period`, URL-encoding the label and issuer.
- `qr_data_uri(uri)` MUST render the URI to a PNG `data:` URI via `segno`, returning `None` (not raising) on any error.
- `start_enrollment(user_id, username)` MUST persist a fresh secret as pending (`totp_enabled = 0`, `totp_last_step = NULL`) via parameterized SQL and return `{secret, otpauth_uri, qr_data_uri}`, or `None` on a DB error.
- `confirm(user_id, code)` MUST verify `code` against the pending secret (± `TOTP_SKEW_STEPS`); on success set `totp_enabled = 1` and `totp_last_step`; return the `{"status"}` contract (`ok` / `invalid` / `no_pending`).
- `verify(user_id, code)` MUST require `totp_enabled = 1` and a secret, accept only a code matching the current step ± `TOTP_SKEW_STEPS` whose step is **strictly greater than** `totp_last_step` (replay guard), update `totp_last_step` on success, and return `{"status", "user"}` with statuses `ok` / `invalid` / `no_challenge`. Comparison MUST be constant-time (`secrets.compare_digest`).
- `disable(user_id)` MUST clear `totp_secret`/`totp_enabled`/`totp_last_step` via parameterized SQL, returning `False` (not raising) on a DB error.
- All SQL MUST be parameterized. A malformed/empty `code` MUST be treated as `invalid` (or `no_challenge`/`no_pending`), never raising.

### FR-04: Login Branches to the TOTP Challenge (TOTP Wins)
- `login()` MUST keep the existing order — lockout gate → bcrypt verify → `lockout_service.reset()` → `is_verified` gate — **unchanged**, then consult `totp_enabled` **before** `two_factor_enabled`.
- When `totp_enabled` is truthy, `login()` MUST write `pending_2fa_user_id` (+ `pending_2fa_username`, `pending_2fa_method = "totp"`), MUST NOT write `user_id`, MUST NOT send any email, and MUST return `200 {"otp_required": true, "redirect": "/login/totp"}`.
- When `totp_enabled` is falsy and `two_factor_enabled` is truthy, the **existing Email OTP branch** MUST run unchanged (plus the `pending_2fa_method = "email"` marker).
- When neither is set, `login()` MUST write the full session exactly as today (no behaviour change).

### FR-05: TOTP Verification Route Completes the Login
- `GET /login/totp` MUST render `totp_verify.html` only when `pending_2fa_user_id` is set **and** `pending_2fa_method == "totp"`; otherwise `302 → /login`. It MUST splice a CSRF token and MUST NOT reflect any secret or code.
- `POST /login/totp` MUST read the `code` form field and `pending_2fa_user_id`. With no pending marker it MUST return `401`. On `verify(...) == "ok"` it MUST delete the pending keys, write `user_id`/`username`/`email` from the returned user, and return `200 {"success": true, "redirect": "/welcome"}`. On any other status it MUST return a `401` JSON error and write no `user_id`.

### FR-06: Profile Enrollment / Disable (Session-Gated)
- `POST /profile/totp/setup` MUST require a session `user_id` (return `401` otherwise), MUST be refused with `400` when `totp_enabled` is already `1`, and otherwise MUST call `start_enrollment` and return the QR + secret + URI.
- `POST /profile/totp/confirm` MUST require a session `user_id`, read a `code`, call `confirm`, and return `200` only on `"ok"` (flag now `1`), else `400`.
- `POST /profile/totp/disable` MUST require a session `user_id` and call `disable`, returning `200`.
- `profile_page` MUST read `totp_enabled` for the session user (parameterized SELECT) and splice the initial state into `profile.html`. None of the toggle routes MUST require or accept the current password (session-gate-only posture).

### FR-07: TOTP Lifecycle Semantics
- Enrollment is two-step: a secret is **pending** (`totp_enabled = 0`) after `setup` and becomes **active** (`totp_enabled = 1`) only after a `confirm` code validates. A pending secret grants no login challenge (`verify` requires `totp_enabled = 1`).
- A new `setup` (allowed only while disabled) overwrites any prior pending secret and resets `totp_last_step` to `NULL`.
- At login, a code is accepted only if it matches the current step ± `TOTP_SKEW_STEPS` **and** its step is strictly greater than `totp_last_step`; the matched step is then stored, so the same code cannot be replayed within its window.
- `disable` clears the secret, the flag, and the last-step, returning the account to password-only (or Email OTP, if that is separately enabled).

### FR-08: Parameterized SQL Everywhere (VULN-1 Preserved)
- Every SQL statement added by this feature (in `totp_service.py` and the `profile_page` SELECT) MUST use `?` placeholders with a separate parameter list. String concatenation into SQL is forbidden.

### FR-09: Session-Only Auth Preserved (no JWT/tokens)
- The pending handshake and the completed login MUST use only `request.session` keys (signed cookie). No JWT, access/refresh token, bearer header, or extra cookie is introduced (consistent with Continue-with-Google and Email OTP).

### FR-10: Code Never Reflected; Secret Owner-Only (VULN-3 Preserved)
- The raw login-time TOTP code MUST NOT appear in any HTTP response body, log line, URL, or template.
- The enrollment secret and QR MUST be returned **only** to the authenticated owner during their own `setup`/`confirm` flow and MUST NOT be logged.

### FR-11: One New Dependency Only (`segno`)
- `segno` MAY be added to `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock`. **No other** dependency is added (no `pyotp`, no `qrcode`, no Pillow). TOTP/HOTP uses stdlib only.

### FR-12: Untouched Functions / Files
- `signup()`, `change_password()`, `password_meets_policy()`, the lockout helpers, the verification helpers, every OAuth function, **every Email OTP function (`otp_service.py`)**, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/mailer.py`, `main.py`, `login.html`, `otp_verify.html`, the non-listed templates, and all CSS MUST remain unchanged.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
Exactly the files in §3 change (plus the spec/plan/prompt docs and the three dependency manifests). No `main.py`, no `core/rate_limit.py`/`csrf.py`/`security.py`/`mailer.py`/`oauth.py`, no `oauth_service.py`/`lockout_service.py`/`verification_service.py`/`otp_service.py`, no unrelated template/CSS.

### NFR-02: Configuration, Not Hardcoded Magic Numbers
TOTP issuer, period, and skew come from `core/config.py` (env/`.env`) with documented defaults, mirroring the lockout and OTP thresholds. Digits and secret length are fixed constants to avoid weak configurations.

### NFR-03: Second Factor, Not a Weaker First Factor
The TOTP branch runs strictly **after** the bcrypt verify and the lockout + verified gates. A wrong password, a locked account, or an unverified account never reaches the TOTP challenge, so TOTP cannot become an oracle.

### NFR-04: Brute-Force & Replay Resistance of a Low-Entropy Code
A 6-digit code has ~10⁶ possibilities and, with ±1 skew, at most 3 are valid in any ~30 s window. Resistance comes from: the small validity window, the unchanged per-IP rate limiter (default 5 POST/60 s), the constant-time compare, and the **replay guard** (`totp_last_step`) that prevents reuse of an already-accepted code. The 160-bit secret itself is infeasible to guess.

### NFR-05: Zero-Config Availability, Owner-Only Secret Exposure
TOTP needs no SMTP and no Google — it works on a fresh clone. The shared secret is shown only to its authenticated owner during enrollment (required to provision the app) and is never logged or shown to anyone else.

### NFR-06: No Information Leakage
The login TOTP screen and all `/login/totp` JSON messages are fixed, server-controlled strings — no username, no secret, no code, no internal field is reflected. DB exceptions are logged server-side, never surfaced.

### NFR-07: Consistency With Existing Patterns
Thin route → service; `get_db()` + `try/finally` per call; parameterized SQL; env config via `core/config.py`; additive idempotent migration like v1.0.3–v1.0.6; `time.time()`-based math; fetch + `URLSearchParams` + hidden `csrf_token` like the login/profile/OTP forms; pre-render theme IIFE + shared header in the new template; the pending-session handshake reuses the Email OTP keys.

### NFR-08: Pending State is Tamper-Proof and Short-Lived
`pending_2fa_user_id` lives only in the signed session cookie. It is set only after a correct password + verified gate, cleared on successful TOTP verification, and naturally discarded on `/logout` (`session.clear()`). It grants no access on its own — `/welcome` and `/profile` require `user_id`, written only post-TOTP.

### NFR-09: Deliberate Toggle Trade-off (session-gate-only)
Enrolling / confirming / disabling TOTP requires only the authenticated session (+ CSRF), not a password re-prompt — consistent with the Email OTP toggle. Accepted risk: an already-hijacked session could disable TOTP. This is bounded by the fact that obtaining the session already required clearing the first factor (and, if TOTP was on, a prior TOTP code). The trade-off MUST be documented in code comments, `CLAUDE.md`, and this spec. (A future hardening could require a current TOTP code to disable.)

### NFR-10: Single Justified Dependency
`segno` is the only added dependency, justified exactly like Authlib (a capability — QR-image rendering — the stdlib cannot provide). It is pure-Python with no transitive dependencies, keeping `uv sync` light and the lab clonable.

---

## 6. Success Paths

### SP-01: Non-2FA Login Unaffected
1. A verified user with `totp_enabled = 0` and `two_factor_enabled = 0` submits the correct password.
2. Lockout gate passes, bcrypt verifies, `reset()` runs, verified gate passes, both 2FA branches are skipped, the full session is written → `200 {"success": true, "redirect": "/welcome"}`. Byte-for-byte the current behaviour.

### SP-02: Enroll TOTP From Profile
1. A logged-in user opens `/profile`; the Authenticator-App card shows "Disabled".
2. They click **Set up**; the page POSTs to `/profile/totp/setup`; the response carries a QR and a manual-entry key; the page renders them.
3. The user scans the QR in their authenticator app and types the current 6-digit code into the confirm field; the page POSTs to `/profile/totp/confirm`.
4. `confirm` validates the code → `totp_enabled = 1`; the card flips to "Enabled".

### SP-03: TOTP Login Happy Path
1. A user with `totp_enabled = 1` submits the correct password.
2. `login()` writes `pending_2fa_user_id` + `pending_2fa_method = "totp"` and returns `{"otp_required": true, "redirect": "/login/totp"}`; the login page redirects to `/login/totp`. **No email is sent.**
3. The user enters the code from their authenticator app; `POST /login/totp` → `verify` returns `ok`; the pending keys are removed, the full session is written → `200 {"success": true, "redirect": "/welcome"}`.

### SP-04: TOTP Takes Precedence Over Email OTP
1. A user has **both** `totp_enabled = 1` and `two_factor_enabled = 1`.
2. A correct password → the TOTP branch fires (no email sent), redirect `/login/totp`. The Email OTP branch is not reached.

### SP-05: Disable TOTP
1. A logged-in user clicks **Disable**; `POST /profile/totp/disable`.
2. `disable` clears the secret/flag/last-step → `200`; subsequent logins skip the TOTP step (falling back to Email OTP if that is separately enabled, else password-only).

---

## 7. Edge Cases

- **EC-01 — Wrong password, TOTP on:** bcrypt fails before the TOTP branch; the generic `401` (and lockout counting) applies exactly as today. No challenge is issued.
- **EC-02 — Correct password, TOTP on, but unverified:** the `is_verified` gate returns its `401 {"unverified": true}` before the TOTP branch. (Unverified accounts can't have logged in to enroll anyway — defensive ordering.)
- **EC-03 — Wrong TOTP code at login:** `verify` → `invalid`; `401 {"error": "Incorrect code. Open your authenticator app and try again."}`. No session. (No server-side attempt counter; the per-IP rate limiter bounds rapid tries.)
- **EC-04 — Replayed code:** a code whose step is ≤ `totp_last_step` is rejected as `invalid` even if it currently displays in the app, until the next step. Prevents reuse of a sniffed code within its window.
- **EC-05 — Clock drift:** a code from the immediately previous or next step (within `TOTP_SKEW_STEPS`) is accepted, tolerating modest device/server clock skew.
- **EC-06 — `GET /login/totp` with no pending marker** (deep link, or after logout): `302 → /login`.
- **EC-07 — `POST /login/totp` with no pending marker** (session expired/cleared): `401 {"error": "Your login session expired. Please sign in again."}`.
- **EC-08 — Confirm with a wrong/expired code during enrollment:** `confirm` → `invalid`; `400 {"error": "That code didn't match. Make sure your authenticator is set up and try the current code."}`; `totp_enabled` stays `0`; the pending secret remains so the user can retry.
- **EC-09 — `setup` while already enabled:** `400 {"error": "Authenticator 2FA is already enabled. Disable it first to re-enroll."}`; no new secret generated.
- **EC-10 — QR rendering fails (`segno` error):** `qr_data_uri` returns `None`; the route still returns the manual-entry secret + `otpauth_uri` with `qr_data_uri: null`, and the page shows the manual key so enrollment is still possible. (Defensive; not expected in practice.)
- **EC-11 — Both TOTP and Email OTP enabled:** TOTP wins at login (SP-04); disabling TOTP later transparently falls back to Email OTP. Both cards on `/profile` reflect their own independent state.
- **EC-12 — Google (OAuth) account toggles TOTP:** the flag is stored but the OAuth callback path is unchanged, so a Google sign-in is unaffected; a password login for that row fails closed (`password = NULL`) before the TOTP branch. Documented non-goal.
- **EC-13 — DB error in a service helper:** `start_enrollment`/`disable` return `None`/`False`; the route returns `400 {"error": "…"}`; no state change. `verify`/`confirm` return `invalid` on an internal error (logged server-side).
- **EC-14 — Pre-migration DB:** existing rows gain the three columns at defaults (`NULL`/`0`/`NULL`); TOTP is off for everyone until they enroll.
- **EC-15 — Pending secret never confirmed:** `totp_secret` is set but `totp_enabled = 0`; `login()` ignores it (challenge requires the flag), so login stays password-only until the user confirms. A later `disable` clears the stray pending secret.

---

## 8. Acceptance Criteria

- **AC-01:** A fresh DB's `users` table has `totp_secret`, `totp_enabled` (default 0), and `totp_last_step` per `PRAGMA table_info(users)`.
- **AC-02:** A pre-existing DB gains all three columns on first boot; existing rows read `totp_enabled = 0` and `NULL` secret/last-step; no grandfather `UPDATE` runs.
- **AC-03:** A non-2FA user's correct-password login still returns `200 {"success": true, "redirect": "/welcome"}` and writes `user_id` (no behaviour change).
- **AC-04:** `POST /profile/totp/setup` (logged in, TOTP off) returns a `qr_data_uri`, `secret`, and `otpauth_uri`; the row's `totp_secret` is set and `totp_enabled` stays `0`.
- **AC-05:** `POST /profile/totp/confirm` with a valid current code returns `200` and sets `totp_enabled = 1`; with a wrong code returns `400` and leaves it `0`.
- **AC-06:** With TOTP enabled, a correct-password `POST /login` returns `200 {"otp_required": true, "redirect": "/login/totp"}`, writes `pending_2fa_user_id` + `pending_2fa_method = "totp"` but **not** `user_id`, and sends **no** email.
- **AC-07:** `GET /welcome` and `GET /profile` still redirect to `/login` while only `pending_2fa_user_id` (no `user_id`) is set.
- **AC-08:** Submitting a valid TOTP code to `POST /login/totp` returns `200 {"success": true}`, clears the pending keys, writes `user_id`, and updates `totp_last_step`.
- **AC-09:** A wrong code returns `401 {"error": …}` and writes no session; a replayed (already-accepted-step) code is rejected.
- **AC-10:** With both TOTP and Email OTP enabled, login goes to `/login/totp` (TOTP precedence); no email is sent.
- **AC-11:** `POST /profile/totp/disable` returns `200` and clears `totp_secret`/`totp_enabled`/`totp_last_step`.
- **AC-12:** The TOTP secret never appears in any log; the login-time code never appears in any HTTP response body, URL, or rendered page (inspect `/login/totp` HTML and all JSON). The secret/QR appear **only** in the owner's own `setup`/`confirm` responses.
- **AC-13:** All SQL in `totp_service.py` and the `profile_page` SELECT uses `?` placeholders (no concatenation).
- **AC-14:** `git diff` is empty for `main.py`, `core/rate_limit.py`, `core/csrf.py`, `core/security.py`, `core/mailer.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, `verification_service.py`, `otp_service.py`, `login.html`, `otp_verify.html`, `signup.html`, `dashboard.html`, and `styles.css`.
- **AC-15:** Exactly one new dependency (`segno`) is added across `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock`; no `pyotp`/`qrcode`/Pillow appears.
- **AC-16:** `uv run backend/app/main.py` boots with no traceback; a normal (non-2FA) correct-password login still succeeds.
- **AC-17:** VULN-1…VULN-8 all remain closed (parameterized SQL; bcrypt intact and still the password authenticator, running before the TOTP branch; rate-limit + CSRF + session middleware unchanged; no `/download/db`; env-sourced config; no code reflection).
- **AC-18:** `README.md` shows feature #5 as "Done (v1.0.7)", adds a v1.0.7 release row, lists the five new routes, and notes the `segno` dependency. `CLAUDE.md` has the new subsection, rule, and hierarchy entry.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Columns on fresh DB | `rm` DB, boot | `PRAGMA table_info(users)` shows the three columns at defaults |
| TC-02 | Migration on old DB | Pre-migration DB copy | Three columns added; existing rows `NULL`/`0`/`NULL`; TOTP off |
| TC-03 | Non-2FA login unchanged | Verified user, TOTP off, Email OTP off | Correct pw → `200 {"success":true,"redirect":"/welcome"}` |
| TC-04 | Setup | Logged-in, TOTP off | `POST /profile/totp/setup` → `200` with `qr_data_uri`+`secret`; row `totp_secret` set, `totp_enabled=0` |
| TC-05 | Confirm valid | Pending secret | Valid current code → `200`; `totp_enabled=1` |
| TC-06 | Confirm invalid | Pending secret | Wrong code → `400`; `totp_enabled=0` |
| TC-07 | TOTP login → pending | TOTP on | Correct pw → `200 {"otp_required":true,"redirect":"/login/totp"}`; session has `pending_2fa_user_id`+method, no `user_id`; no email |
| TC-08 | Pending can't reach dashboard | Only pending marker set | `GET /welcome` → `302 /login` |
| TC-09 | Correct code completes | Pending + app code | `POST /login/totp` valid → `200`; `user_id` set; `totp_last_step` updated |
| TC-10 | Wrong code | Pending | Wrong code → `401`; no session |
| TC-11 | Replay rejected | Just used a code | Same code again (same step) → `401 invalid` |
| TC-12 | Skew tolerance | `TOTP_SKEW_STEPS=1` | Previous-step code accepted within window |
| TC-13 | Precedence | TOTP on + Email OTP on | Login → `/login/totp`; no email sent |
| TC-14 | Disable | TOTP on | `POST /profile/totp/disable` → `200`; secret/flag/last-step cleared |
| TC-15 | Setup blocked when enabled | TOTP on | `POST /profile/totp/setup` → `400`; no new secret |
| TC-16 | Code/secret not leaked | Pending / logs | `/login/totp` HTML + JSON contain no code; no secret in logs |
| TC-17 | Parameterized SQL | Repo checkout | `totp_service.py` + `profile_page` SELECT use `?` placeholders |
| TC-18 | Untouched files | Repo checkout | `git diff --stat` empty for the forbidden files |
| TC-19 | One new dep | Repo checkout | only `segno` added; no `pyotp`/`qrcode`/Pillow |
| TC-20 | App boots + normal login | Repo checkout | `uv run …` no traceback; non-2FA login → `200` |
| TC-21 | Docs updated | Repo checkout | feature #5 "Done (v1.0.7)"; v1.0.7 row; new routes; `segno` note; CLAUDE entries |

---

## 10. Verification Steps

Run from the repo root. Raise the per-IP limit if exercising many POSTs from one IP (`RATE_LIMIT_MAX=100`).

### 10.1 Schema (AC-01, TC-01)
```bash
rm -f vulnerable_app.db
uv run backend/app/main.py &
sqlite3 vulnerable_app.db "PRAGMA table_info(users);" | grep -E 'totp_secret|totp_enabled|totp_last_step'   # all three
```

### 10.2 Enroll, Then Log In (AC-04…AC-08, TC-04…TC-09)
```bash
# Sign up + verify a user, log in, open /profile, click Set up, scan the QR in an
# authenticator app, and submit the current code to confirm (totp_enabled -> 1).
# Then log out and log back in:
#   POST /login  → {"otp_required": true, "redirect": "/login/totp"}   (no email sent)
#   GET  /welcome (with only the pending marker) → 302 /login
# Enter the current 6-digit code from the app at /login/totp → 200 {"success": true}.
# Confirm the secret in the DB (teaching only):
sqlite3 vulnerable_app.db "SELECT totp_secret, totp_enabled, totp_last_step FROM users WHERE username='alice';"
```

### 10.3 Precedence, Replay, Disable (AC-09…AC-11)
```bash
# With both TOTP and Email OTP on, login lands on /login/totp and sends no email.
# Submitting the same just-used code again → 401 (replay guard).
# POST /profile/totp/disable → totp_secret/totp_enabled/totp_last_step cleared.
```

### 10.4 File Audit (AC-14, AC-15, TC-18, TC-19)
```bash
git diff --stat -- backend/app/main.py backend/app/core/rate_limit.py backend/app/core/csrf.py \
  backend/app/core/security.py backend/app/core/mailer.py backend/app/core/oauth.py \
  backend/app/services/oauth_service.py backend/app/services/lockout_service.py \
  backend/app/services/verification_service.py backend/app/services/otp_service.py \
  frontend/templates/login.html frontend/templates/otp_verify.html \
  frontend/templates/signup.html frontend/templates/dashboard.html \
  frontend/static/css/styles.css     # all empty
```

Expected `git status --porcelain` (declared files + docs only):
```
?? backend/app/services/totp_service.py
?? frontend/templates/totp_verify.html
 M backend/app/core/config.py
 M backend/app/db/session.py
 M backend/app/services/auth_service.py
 M backend/app/api/routes/auth.py
 M frontend/templates/profile.html
 M pyproject.toml
 M backend/pyproject.toml
 M uv.lock
 M .env.example
 M README.md
 M CLAUDE.md
?? .claude/specs/mfa-via-authenticator-app.md
?? .claude/specs/mfa-via-authenticator-app-plan.md
?? docs/prompts/mfa-via-authenticator-app-spec-prompt.txt
?? docs/prompts/mfa-via-authenticator-app-plan-prompt.txt
?? docs/prompts/mfa-via-authenticator-app-execution-prompt.txt
```
