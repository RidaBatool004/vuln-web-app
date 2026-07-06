# Software Specification Document — QR Code Login

**Version:** 1.0.0
**Last Updated:** 2026-06-21
**Target Release Tag:** v1.0.8
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [QR Code Login — README "Feature Enhancements" #7](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **QR Code Login** enhancement. It is item #7 ("QR Code Login") in the README's "Feature Enhancements" table. An **unauthenticated** browser (the *desktop*) opens `/login` and is shown a **QR code**. A **separate, already-authenticated device** (the *phone*) scans that QR, lands on a confirmation page, and taps **Approve**. The desktop — which has been quietly **polling** the server — then sees the approval, is logged in via the **same signed session cookie** the password flow uses, and is redirected to `/welcome`. This is the WhatsApp-Web / "scan to log in" pattern.

**The trust comes from the already-authenticated device.** The phone has already cleared the first factor (password) and any enrolled second factor (Email OTP / TOTP) to obtain its session. QR login lets that proven device *vouch for* a new device, exactly like WhatsApp Web. It is **not** a new password mechanism and adds **no** credential.

It composes with every already-closed control:

| Stage | Control already in place | What this feature adds |
|-------|--------------------------|------------------------|
| Flood of POSTs | per-IP `RateLimitMiddleware` (VULN-7) | — (unchanged; covers the new approve/reject POSTs too) |
| Forged cross-site POST | synchronizer-token `CSRFMiddleware` (VULN-8) | — (unchanged; the approve/reject forms carry `csrf_token`) |
| Session forgery | signed session cookie / `SECRET_KEY` (VULN-4) | The approving identity is read from the phone's **signed** session; the desktop is promoted only via that signed session |
| Login CSRF / session fixation | (n/a previously) | **Owner-binding:** only the browser that *created* a QR can be logged in by it (see §1.1.3) |

### 1.1 Design Decisions (product-owner choices)

These four decisions were made explicitly before writing this spec and shape everything below:

1. **Real-time mechanism: short polling.** After the QR is shown, the desktop page polls a lightweight `GET /qr/status` endpoint every `QR_LOGIN_POLL_INTERVAL_SECONDS` (default 2 s) until it sees `approved` / `rejected` / `expired`. **No Server-Sent Events and no WebSocket** — polling is pure FastAPI + `fetch`, matches the project's "simple enough to read in one sitting" ethos, and needs no new server machinery.
2. **Token storage: in-memory, no schema change.** Pending QR-login sessions live in a process-local `dict` guarded by a lock in a new `core/qr_login.py` module — the **same pattern as `core/rate_limit.py`**. There is **no DB schema change** (the first feature with none since the User Profile Page, v1.0.2) and **no new dependency** (QR images reuse `segno`, added in v1.0.7). Tokens reset on restart, which is fine for a lab.
3. **Approval requires an explicit confirmation step, session-gated.** Scanning opens a confirmation page (`GET /qr/scan/{token}`) that requires an authenticated session and shows *"Approve login for a new device as `<you>`?"* with **Approve** / **Reject** buttons. Approve and Reject are **POSTs** carrying the hidden `csrf_token` (so the existing `CSRFMiddleware` validates them). **No auto-approve-on-GET** — a GET must never mutate auth state, and the explicit step is the teachable defense against QR-login phishing ("quishing").
4. **QR content via `APP_BASE_URL`; one code path for both demo modes.** The QR encodes `{APP_BASE_URL}/qr/scan/{token}`. On `localhost` you "scan" by opening that URL in a **second, already-logged-in browser**; on a real deployment (or LAN IP) a **phone camera** can scan it. `APP_BASE_URL` already exists (Email Verification, v1.0.4) and is reused unchanged.

### 1.1.3 Owner-binding (the key security safeguard)

A naive "scan to log in" design is vulnerable to **login CSRF / session fixation**: an attacker gets *their own* phone to approve a token bound to *their* identity, then tricks a victim's browser into hitting `GET /qr/status?token=…` (e.g. via an `<img>`), silently logging the victim's browser into the **attacker's** account. To prevent this:

- `GET /qr/create` records the freshly minted token in the **creating browser's signed session** (`request.session["qr_login_token"] = token`).
- `GET /qr/status` promotes a session to a full login **only if** the polling browser's session already owns that exact token (`request.session.get("qr_login_token") == token`).

So a QR can only ever log in the **same browser that generated it**. An attacker-embedded cross-site `GET /qr/status` carries no matching `qr_login_token` in the victim's session and is ignored. The phone (a different device/session) **only approves** — it never needs to own the token.

### 1.2 Built on existing primitives

- **Auth stays session-only.** As with Continue-with-Google, Email OTP, and TOTP, the signed session cookie is the single auth mechanism — there is **no JWT, access/refresh token, or extra cookie**. The desktop is promoted by writing the **same** `user_id`/`username`/`email` session keys `auth_service.login()` writes.
- **No new login path through `auth_service`.** The approving phone is *already* logged in (so it has already passed the lockout, bcrypt, email-verified, and any 2FA gates). The desktop simply **inherits that proven identity**, captured from the phone's signed session at approval time. `auth_service.login()` is therefore **not modified**.
- **QR rendering reuses `segno`** (added in v1.0.7 for TOTP). No new dependency.
- The in-memory store mirrors `core/rate_limit.py`: a module-level `dict` of `token -> {status, identity, expiry}` guarded by a lock, lazily purged of expired entries, reset on restart. No Redis, no disk persistence, no DB row.
- All token values are high-entropy `secrets.token_urlsafe(32)`, **single-use**, and short-lived (`QR_LOGIN_TTL_SECONDS`, default 120 s). The login-time flow reflects **no** attacker-controlled input (VULN-3); the only user value rendered (the approving username on the confirm page) is `html.escape(..., quote=True)`'d (VULN-2 discipline).

**Approval posture (product-owner choice): session-gated, explicit confirm.** Approving/Rejecting a device requires the existing authenticated session (plus the CSRF token on every POST) and a conscious button press. It does **not** re-prompt for the password — consistent with the Email OTP / TOTP toggles (NFR-09).

**Second-factor posture (deliberate):** QR login **does not** re-challenge the desktop for 2FA. The second factor was already satisfied on the approving device; the QR is the proof-of-possession that vouches for the new device (exactly like WhatsApp Web). Documented as a design property in NFR-04 / §2.2.

This feature does **not** change any of the eight closed vulnerabilities. After this change all eight remain closed, and — notably — the app gains **no** schema change and **no** new dependency.

The implementation touches:

- One new backend module: `backend/app/core/qr_login.py` (in-memory token store: create / approve / reject / claim / status, lazy expiry, lock; `segno` QR render helper).
- One new template: `frontend/templates/qr_approve.html` (the phone-side confirmation page).
- Existing files: `backend/app/core/config.py` (two QR settings; `APP_BASE_URL` reused), `backend/app/api/routes/auth.py` (five new routes), `frontend/templates/login.html` (QR panel + polling script), `frontend/static/css/styles.css` (small additive QR-panel styling).
- `.env.example`, `README.md`, and `CLAUDE.md` (documentation).

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/db/session.py` (**no schema change**), `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/mailer.py`, `backend/app/core/oauth.py`, `backend/app/services/auth_service.py` (**no new login branch**), `backend/app/services/oauth_service.py`, `backend/app/services/lockout_service.py`, `backend/app/services/verification_service.py`, `backend/app/services/otp_service.py`, `backend/app/services/totp_service.py`, and the other templates remain unchanged.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **No schema change.** QR-login state is process-local and ephemeral; `backend/app/db/session.py` is **not** modified and `users` gains no column. (Explicitly called out because every feature since v1.0.3 added columns; this one does not.)
- **QR-login configuration (`core/config.py`).** Two non-secret env-tunables with safe defaults, plus reuse of the existing `APP_BASE_URL`:
  - `QR_LOGIN_TTL_SECONDS` (default `120`) — how long a pending QR token is valid before it expires.
  - `QR_LOGIN_POLL_INTERVAL_SECONDS` (default `2`) — the suggested desktop poll cadence, sent to the page so the interval is configurable without editing JS.
  - **Reuse `APP_BASE_URL`** (already defined for Email Verification) to build the scannable URL. **No `is_*_configured()` gate** — QR login needs no SMTP and no Google; it works on a fresh clone.
- **QR-login store (`core/qr_login.py`, new).** Stdlib-only (`secrets`, `time`, `threading`, `logging`) plus `segno` for the QR image only. A module-level `dict` guarded by a `threading.Lock`, lazily purged of expired entries on each access (mirrors `rate_limit.py`):
  - `create_token() -> str` — mint `secrets.token_urlsafe(32)`, store `{status: "pending", user_id: None, username: None, email: None, expires: now + TTL}`, return the token.
  - `approve(token, user_id, username, email) -> bool` — only if the token exists, is `"pending"`, and is unexpired: set `status = "approved"`, record the identity; return `True`, else `False`.
  - `reject(token) -> bool` — if the token exists and is `"pending"`: set `status = "rejected"`; return `True`/`False`.
  - `status(token) -> str` — return `"pending"` / `"approved"` / `"rejected"`, or `"expired"`/`"invalid"` for unknown/expired tokens (read-only; does not mutate identity).
  - `get(token) -> dict | None` — a snapshot copy of the entry (for the scan route to validate the token), or `None`.
  - `claim(token) -> dict | None` — **single-use consume**: if the token is `"approved"`, atomically mark it consumed (delete it) and return `{user_id, username, email}`; else `None`.
  - `render_qr(text) -> str | None` — `segno.make(text).png_data_uri(scale=…)`; the **only** use of `segno` here. Returns `None` on any render error so the page can fall back to the manual URL.
  - All lookups are under the lock; expired entries are dropped lazily.
- **New routes (`api/routes/auth.py`).** Five thin handlers:
  - `GET /qr/create` — vend a new QR. Mint a token, **bind it to the caller's session** (`request.session["qr_login_token"] = token`), build `qr_url = f"{APP_BASE_URL}/qr/scan/{token}"`, and return `200 {"token": …, "qr_url": …, "qr_data_uri": …, "poll_interval": QR_LOGIN_POLL_INTERVAL_SECONDS, "expires_in": QR_LOGIN_TTL_SECONDS}`. Intentionally a **GET** (an unauthenticated capability vendor; the token is useless until an authenticated POST approves it — there is nothing CSRF-sensitive to protect, mirroring the OAuth `GET` login).
  - `GET /qr/status?token=…` — desktop poll. If `request.session.get("qr_login_token") != token` → `200 {"status": "invalid"}` (owner-binding, §1.1.3). Otherwise read the store: `pending`/`rejected`/`expired` → `200 {"status": …}`; `approved` → **claim** the token, **clear** `qr_login_token`, **write** `user_id`/`username`/`email` into the desktop session, and return `200 {"status": "approved", "redirect": "/welcome"}`. A GET that promotes the session — justified exactly like the OAuth/verify GET callbacks, and additionally guarded by the owner-binding so a cross-site GET cannot trigger it.
  - `GET /qr/scan/{token}` — the phone landing page (what the QR encodes). **Session-gated:** no `user_id` → `302 → /login` (the phone must log in first, then re-scan). Logged in → render `qr_approve.html` with a spliced `csrf_token`, the `{{token}}`, and the HTML-escaped approving `{{username}}`; if the token is unknown/expired/already-acted-on, render the same page in a fixed "this code is no longer valid" state with the buttons hidden.
  - `POST /qr/approve` — session-gated + CSRF. Read `token`; call `qr_login.approve(token, session.user_id, session.username, session.email)`. `200 {"success": true, "message": "…return to the other device."}` on success, else `400 {"error": "This QR code has expired or was already used."}`.
  - `POST /qr/reject` — session-gated + CSRF. Read `token`; call `qr_login.reject(token)`. `200 {"success": true, …}`.
- **Templates.**
  - **`login.html` (modified)** — add a "Log in with a QR code" panel below the existing password form + Google button. An inline `<script>` calls `GET /qr/create` on load, shows the returned `qr_data_uri` in an `<img>` (with the `qr_url` as fallback text), then polls `GET /qr/status?token=…` every `poll_interval` seconds: on `approved` → `location = data.redirect`; on `rejected`/`expired` → show a message + a **"Show new QR"** button that re-calls `/qr/create`. Uses `fetch`; reads JSON; no new framework. The existing password-login and Google blocks are **unchanged**.
  - **`qr_approve.html` (new)** — same shared header / theme-toggle / pre-render theme IIFE as the other pages. Shows *"A device wants to sign in as `<username>`."* and a form with a hidden `csrf_token`, a hidden `token`, and **Approve** (POST `/qr/approve`) + **Reject** (POST `/qr/reject`) buttons; submits urlencoded via `URLSearchParams`, reads JSON, and shows a final "approved / rejected" confirmation. A spliced state flag hides the buttons when the token is already invalid.
- **CSS (`styles.css`, additive only).** A small `.qr-panel` block (centering the QR image + divider) reusing existing custom properties so it themes in light/dark automatically. No existing rule is modified.
- **`.env.example`.** Append two commented placeholders (`QR_LOGIN_TTL_SECONDS`, `QR_LOGIN_POLL_INTERVAL_SECONDS`) with their defaults — values, not secrets.
- **Docs.** Update `README.md` (move feature #7 to "Done (v1.0.8)"; add a v1.0.8 release row; add the five routes to the API table; note "no schema change, no new dependency") and `CLAUDE.md` (integration subsection, Important-Rules entry, Specification-Hierarchy entry).

### 2.2 Out of Scope (Intentionally)

- **No 2FA re-challenge on the desktop.** The approving device already satisfied every factor; QR login deliberately does not ask the desktop for a second factor (the WhatsApp-Web model). Documented design property, not an omission.
- **No persistence / multi-process support.** The store is in-memory and process-local. A restart or a second worker process invalidates pending QRs (the page simply shows a new one). No Redis/DB-backed store this slice.
- **No "trusted devices" / "remember this browser", no device naming, no session list / remote logout.** A future feature could list and revoke active QR-paired sessions; out of scope here.
- **No reverse flow (desktop approves phone), no email/SMS of the link, no deep-link return after the phone logs in.** If an unauthenticated phone scans, it is sent to `/login` and must re-scan (documented edge case).
- **No change to `auth_service.login()` or any 2FA path.** QR login is a parallel route-layer flow; `auth_service.py`, `otp_service.py`, `totp_service.py`, and the `/login/otp*` / `/login/totp*` routes are untouched.
- **No new dependency.** QR images reuse `segno`. No `qrcode`, no Pillow.
- **No template engine / JS framework.** Hand-written HTML + inline `<script>`, like every other page.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** this feature adds **no SQL** (the store is in-memory; the approving identity comes from the signed session, not a query). Nothing to parameterize, nothing concatenated.
- **VULN-2 (Stored XSS):** the only user value rendered is the approving `{{username}}` on `qr_approve.html`, HTML-escaped with `html.escape(..., quote=True)`. The QR is a server-generated PNG `data:` URI in an `<img src>`; the `{{token}}` is a server-minted `secrets.token_urlsafe` value (URL-safe alphabet) escaped on splice.
- **VULN-3 (Reflected XSS):** `GET /qr/status` returns fixed JSON statuses + a fixed redirect; `login.html`'s panel and all `/qr/*` messages are fixed, server-controlled strings. No token or status is reflected into HTML as raw markup; the scan page reflects only the escaped username.
- **VULN-4 (Session Hijacking):** `main.py` is unchanged; the owner-binding marker and the promoted login both live in the existing **signed** session cookie (signed by `SECRET_KEY`), so neither the token-ownership claim nor the resulting login can be forged. Tokens use `secrets.token_urlsafe` (CSPRNG).
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged; bcrypt remains the sole password authenticator. QR login issues **no** credential and runs only **after** a full password (+2FA) login occurred on the approving device.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered and unchanged; the new `POST /qr/approve` and `POST /qr/reject` are throttled like every other POST. The GET poll is bounded by the page's own interval and the short token TTL.
- **VULN-8 (CSRF):** the two new POSTs carry the hidden `csrf_token`; `CSRFMiddleware` validates them. The GET capabilities (`/qr/create`, `/qr/status`, `/qr/scan/{token}`) reflect nothing executable; `/qr/status`'s session promotion is gated by the unguessable token **and** the owner-binding, closing the login-CSRF vector.

### 2.4 Explicit Non-Goals / Minimal Touch

- This feature does **not** change `signup()`, `login()`, `change_password()`, `password_meets_policy()`, the verification/lockout/OAuth/OTP/TOTP helpers, or any middleware.
- This feature does **not** persist any state outside the process memory and the signed session. No DB row, no Redis, no extra cookie.
- The only edit to `login.html` is the **additive** QR panel + its script; the existing password and Google blocks are byte-unchanged.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec/plan pair and the prompt docs).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/qr_login.py` | **New** | In-memory token store (`create_token`/`approve`/`reject`/`status`/`get`/`claim`), lazy expiry under a lock, `segno` QR render helper |
| `frontend/templates/qr_approve.html` | **New** | Phone-side confirmation page (hidden `csrf_token` + `token`, Approve/Reject → JSON) |
| `backend/app/core/config.py` | Modified | `QR_LOGIN_TTL_SECONDS` + `QR_LOGIN_POLL_INTERVAL_SECONDS` (non-secret, defaults); reuse `APP_BASE_URL`; docstring note |
| `backend/app/api/routes/auth.py` | Modified | 5 new routes (`GET /qr/create`, `GET /qr/status`, `GET /qr/scan/{token}`, `POST /qr/approve`, `POST /qr/reject`) |
| `frontend/templates/login.html` | Modified | Additive "Log in with a QR code" panel + polling script (password/Google blocks unchanged) |
| `frontend/static/css/styles.css` | Modified | Small additive `.qr-panel` styling (no existing rule changed) |
| `.env.example` | Modified | Commented QR placeholders (defaults shown) |
| `README.md` | Modified | Feature #7 → Done (v1.0.8); release row; API-endpoint rows; "no schema change / no new dependency" note |
| `CLAUDE.md` | Modified | Integration subsection, Important-Rules entry, hierarchy entry |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / `RATE_LIMIT_*` / port. No middleware is added.
- `backend/app/db/session.py` — **no schema change** (no column, no migration).
- `backend/app/services/auth_service.py` — no new login branch (QR login completes in the route layer from the phone's existing session).
- `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/mailer.py`, `backend/app/core/oauth.py` — closures and helpers stay exactly as-is.
- `backend/app/services/oauth_service.py`, `lockout_service.py`, `verification_service.py`, `otp_service.py`, `totp_service.py` — unchanged.
- The other templates (`signup.html`, `dashboard.html`, `profile.html`, `otp_verify.html`, `totp_verify.html`, `check_email.html`, `verify_result.html`, `email_not_configured.html`, `oauth_not_configured.html`) — unchanged.

---

## 4. Functional Requirements

### FR-01: No Schema Change
- `init_db()` and the `users` table MUST be left unchanged. QR-login state MUST live only in process memory (`core/qr_login.py`) and the signed session.

### FR-02: QR-Login Configuration
- `config.QR_LOGIN_TTL_SECONDS` MUST be read from the environment as an `int`, defaulting to `120`.
- `config.QR_LOGIN_POLL_INTERVAL_SECONDS` MUST be read from the environment as an `int`, defaulting to `2`.
- `config.APP_BASE_URL` MUST be reused (not redefined) to build the scannable URL.
- Neither new value is a secret; both are documented in `.env.example`. **No new `is_*_configured()` gate is added.**

### FR-03: QR-Login Store (`qr_login.py`)
- `create_token()` MUST return a `secrets.token_urlsafe(32)` token and store it as `pending` with an expiry of `now + QR_LOGIN_TTL_SECONDS`.
- `approve(token, user_id, username, email)` MUST transition a `pending`, unexpired token to `approved` with the recorded identity, returning `True`; any other case returns `False`.
- `reject(token)` MUST transition a `pending` token to `rejected`, returning `True`/`False`.
- `status(token)` MUST return `"pending"`/`"approved"`/`"rejected"` for live tokens and `"expired"`/`"invalid"` for expired/unknown tokens, without consuming the token.
- `claim(token)` MUST, for an `approved` token, atomically delete it (single-use) and return `{user_id, username, email}`; otherwise return `None`.
- `render_qr(text)` MUST return a PNG `data:` URI via `segno`, or `None` (not raise) on error.
- All store access MUST be guarded by a lock; expired entries MUST be purged lazily. No SQL, no disk, no network.

### FR-04: Create + Owner-Binding
- `GET /qr/create` MUST mint a token, set `request.session["qr_login_token"] = token`, and return the token, the `{APP_BASE_URL}/qr/scan/{token}` URL, a `qr_data_uri`, `poll_interval`, and `expires_in`.
- The created token MUST be bound to the creating session so that only that browser can later be promoted by it (FR-06).

### FR-05: Scan + Approve / Reject (Session-Gated)
- `GET /qr/scan/{token}` MUST require a session `user_id`; without one it MUST `302 → /login`. With one it MUST render `qr_approve.html` splicing a CSRF token, the `{{token}}`, and the **HTML-escaped** session `{{username}}`. An unknown/expired/already-acted-on token MUST render a fixed "no longer valid" state (buttons hidden), reflecting no raw token.
- `POST /qr/approve` MUST require a session `user_id` (else `401`), read `token`, and call `qr_login.approve(token, user_id, username, email)`; `200` on success, `400` otherwise.
- `POST /qr/reject` MUST require a session `user_id` (else `401`), read `token`, and call `qr_login.reject(token)`; `200`.
- Both POSTs MUST carry the hidden `csrf_token` (validated by `CSRFMiddleware`) and MUST NOT require or accept the current password.

### FR-06: Status Poll Completes the Login (Owner-Bound)
- `GET /qr/status?token=…` MUST return `{"status": "invalid"}` when `request.session.get("qr_login_token") != token` (owner-binding).
- For an owned token it MUST return the live status; on `approved` it MUST `claim()` the token, clear `qr_login_token`, write `user_id`/`username`/`email` into the **desktop** session from the claimed identity, and return `{"status": "approved", "redirect": "/welcome"}`.
- A `pending`/`rejected`/`expired` owned token MUST return `{"status": …}` and write no session.

### FR-07: Login Page QR Panel
- `login.html` MUST add an additive QR panel that, via `fetch`, calls `GET /qr/create`, renders the `qr_data_uri`, and polls `GET /qr/status` at `poll_interval`. On `approved` it MUST navigate to `data.redirect`; on `rejected`/`expired` it MUST offer a "Show new QR" action that re-calls `/qr/create`. The existing password and Google blocks MUST be unchanged.

### FR-08: Session-Only Auth Preserved (no JWT/tokens)
- The owner-binding marker and the completed login MUST use only `request.session` keys (signed cookie). No JWT, access/refresh token, bearer header, or extra cookie is introduced.

### FR-09: No Reflection of Tokens; Username Escaped (VULN-2/3 Preserved)
- No QR token MUST be reflected into any page as executable markup; the scan page reflects only the **escaped** approving username. All `/qr/*` JSON messages MUST be fixed, server-controlled strings.

### FR-10: No New Dependency, No New Middleware, No Schema
- QR rendering MUST reuse `segno`; **no** new dependency is added. **No** middleware is registered (`main.py` untouched). **No** DB column/migration is added (`session.py` untouched).

### FR-11: Untouched Functions / Files
- `auth_service.py` (incl. `login()`/`signup()`/`change_password()`), every OAuth/OTP/TOTP/lockout/verification helper, `core/security.py`/`csrf.py`/`rate_limit.py`/`mailer.py`/`oauth.py`, `main.py`, `db/session.py`, and every template except `login.html`/`qr_approve.html` MUST remain unchanged.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
Exactly the files in §3 change (plus the spec/plan/prompt docs). No `main.py`, `db/session.py`, `auth_service.py`, no middleware, no other service/template/CSS beyond the listed two.

### NFR-02: Configuration, Not Hardcoded Magic Numbers
TTL and poll interval come from `core/config.py` (env/`.env`) with documented defaults, mirroring the lockout/OTP/TOTP thresholds. `APP_BASE_URL` is reused, not duplicated.

### NFR-03: Login CSRF / Session Fixation Resistance (Owner-Binding)
A QR can only log in the browser that created it (`qr_login_token` in that browser's signed session). A cross-site `GET /qr/status` in a victim's browser carries no matching marker and is ignored — closing the login-CSRF / session-fixation vector that a naive scan-to-login design would open.

### NFR-04: Trust Derives From the Already-Authenticated Device
The approving phone already cleared the first factor and any enrolled 2FA. QR login is a proof-of-possession that vouches for a new device; not re-challenging the desktop is the deliberate WhatsApp-Web model, documented here and in `CLAUDE.md`.

### NFR-05: Single-Use, Short-Lived, Unguessable Tokens
Tokens are `secrets.token_urlsafe(32)` (256-bit), valid for `QR_LOGIN_TTL_SECONDS` (default 120 s), and consumed on first successful claim (`claim()` deletes them). A rejected/expired token grants nothing.

### NFR-06: No Information Leakage
`/qr/status` returns only a coarse status + a fixed redirect; no username, identity, or internal field leaks to a poller who does not own the token. DB-free flow means no DB exceptions to surface. Server-side logs never record a token's identity binding beyond a non-sensitive id, and never a credential.

### NFR-07: Consistency With Existing Patterns
In-memory store + lock + lazy purge like `core/rate_limit.py`; env config via `core/config.py`; thin route → module; `fetch` + `URLSearchParams` + hidden `csrf_token` like the login/profile/OTP/TOTP forms; pre-render theme IIFE + shared header in the new template; `segno` QR like TOTP; session-only promotion like OAuth/OTP/TOTP.

### NFR-08: Owner-Binding Marker is Tamper-Proof and Short-Lived
`qr_login_token` lives only in the signed session cookie, is overwritten on each `GET /qr/create`, is cleared on a successful promotion, and is discarded on `/logout` (`session.clear()`). It grants no access on its own; `/welcome` requires `user_id`, written only after an approved claim.

### NFR-09: Deliberate Approval Trade-off (session-gate-only)
Approving/Rejecting requires only the authenticated session (+ CSRF) and an explicit button press, not a password re-prompt — consistent with the Email OTP / TOTP toggles. Accepted, bounded risk: a user who consciously approves a malicious QR could pair an attacker's device. The explicit confirm page (naming the account) is the mitigation; a future hardening could show device/IP context or require a 2FA code to approve.

### NFR-10: Zero-Config Availability
QR login needs no SMTP and no Google and adds no dependency; it works on a fresh clone. The only relevant setting for cross-device use is `APP_BASE_URL` (already present), which must point at an address the scanning device can reach.

---

## 6. Success Paths

### SP-01: Password & Google Login Unaffected
1. The existing password form and "Continue with Google" button behave byte-for-byte as before; the QR panel is purely additive.

### SP-02: QR Login Happy Path (cross-device)
1. An unauthenticated desktop opens `/login`; the panel calls `GET /qr/create`, shows a QR, and begins polling `GET /qr/status`. The token is bound to the desktop's session.
2. An already-logged-in phone scans the QR → `GET /qr/scan/{token}` → confirmation page naming the account.
3. The user taps **Approve** → `POST /qr/approve` → the token becomes `approved` with the phone's identity.
4. The desktop's next poll sees `approved`; the server claims the token, writes the desktop session, and returns `{"status": "approved", "redirect": "/welcome"}`; the desktop navigates to `/welcome`. **No password or 2FA was entered on the desktop.**

### SP-03: Reject
1. At step 3 the user taps **Reject** → `POST /qr/reject` → token `rejected`.
2. The desktop poll returns `{"status": "rejected"}`; the panel shows "Request denied" and offers a fresh QR. No session is written.

### SP-04: Expiry / New QR
1. No one scans within `QR_LOGIN_TTL_SECONDS`; the desktop poll returns `{"status": "expired"}`.
2. The panel shows "QR expired" with a **Show new QR** button; clicking it re-calls `/qr/create` and resumes polling.

### SP-05: Owner-Binding Blocks a Stolen Token
1. An attacker knows a token (e.g. from a shoulder-surfed QR) and gets it approved by their own phone.
2. A victim browser is induced to `GET /qr/status?token=…`; because the victim's session has no matching `qr_login_token`, the server returns `{"status": "invalid"}` and writes **no** session. The attack fails.

---

## 7. Edge Cases

- **EC-01 — Unauthenticated phone scans:** `GET /qr/scan/{token}` with no session → `302 → /login`. After logging in the user re-scans. (No auto-return this slice.)
- **EC-02 — Scan of an expired/used/rejected token:** the scan page renders a fixed "This QR code is no longer valid — generate a new one on the other device" state with the buttons hidden; no raw token reflected.
- **EC-03 — Approve after expiry:** `qr_login.approve` returns `False` → `400 {"error": "This QR code has expired or was already used."}`; no state change.
- **EC-04 — Double approve / approve-then-reject:** the first transition wins (`approve`/`reject` require `pending`); the second returns `False`/`400`. `claim()` deletes on first success, so a second poll cannot re-login.
- **EC-05 — Poll for a token this browser does not own:** `{"status": "invalid"}` (owner-binding), even if the token is genuinely `approved` for someone else.
- **EC-06 — Poll after a successful login:** `qr_login_token` was cleared and the token claimed/deleted → subsequent polls return `{"status": "invalid"}`; the page has already navigated away.
- **EC-07 — `APP_BASE_URL` unreachable from the scanner** (e.g. it is `localhost` but a real phone scans): the phone cannot open the URL; this is an environment/config issue, not a code fault. Documented: set `APP_BASE_URL` to an address the scanner can reach (LAN IP or public origin); on `localhost` use a second browser.
- **EC-08 — Server restart / second worker:** the in-memory store is empty/disjoint, so pending tokens read `expired`/`invalid`; the page shows a new QR. (Documented single-process assumption.)
- **EC-09 — QR render fails (`segno` error):** `render_qr` returns `None`; `GET /qr/create` still returns the `qr_url`, and the panel shows the URL/text so a manual open is still possible.
- **EC-10 — Logout mid-flow:** `/logout` clears the session (including `qr_login_token`); an in-flight poll returns `{"status": "invalid"}`.
- **EC-11 — Concurrent QR panels in one browser:** each `GET /qr/create` overwrites `qr_login_token`, so only the **most recently shown** QR can complete; older tokens become un-owned (`invalid`). Acceptable.
- **EC-12 — Rate-limit on rapid approve/reject:** the two POSTs are throttled by `RateLimitMiddleware` like any POST; a flood yields `429`.

---

## 8. Acceptance Criteria

- **AC-01:** `git diff` is empty for `backend/app/db/session.py`; `PRAGMA table_info(users)` is unchanged (no new column).
- **AC-02:** The existing password login and Google button work unchanged; the QR panel is additive on `/login`.
- **AC-03:** `GET /qr/create` returns a `token`, a `{APP_BASE_URL}/qr/scan/{token}` `qr_url`, a `qr_data_uri`, `poll_interval`, and `expires_in`, and sets `qr_login_token` in the caller's session.
- **AC-04:** `GET /qr/scan/{token}` while logged out → `302 /login`; while logged in → the confirm page with the **escaped** username, the token, and a CSRF token.
- **AC-05:** `POST /qr/approve` (logged in, valid pending token) → `200` and the token becomes `approved`; an expired/used token → `400`.
- **AC-06:** `POST /qr/reject` (logged in) → `200` and the token becomes `rejected`.
- **AC-07:** The desktop `GET /qr/status` returns `pending` before approval, then `{"status": "approved", "redirect": "/welcome"}` once approved, writing `user_id` into the desktop session and consuming the token (a second poll → `invalid`).
- **AC-08:** Owner-binding: `GET /qr/status?token=X` from a browser whose session's `qr_login_token != X` returns `{"status": "invalid"}` and writes no session, even when `X` is genuinely `approved`.
- **AC-09:** A rejected token poll returns `{"status": "rejected"}`; an expired token poll returns `{"status": "expired"}`; neither writes a session.
- **AC-10:** No QR token appears as raw markup in any rendered page; `qr_approve.html` escapes the username; all `/qr/*` JSON messages are fixed strings.
- **AC-11:** Tokens are `secrets.token_urlsafe(32)`; expire after `QR_LOGIN_TTL_SECONDS`; are single-use (claimed/deleted on success).
- **AC-12:** No new dependency is added (no `qrcode`/Pillow; `segno` already present); `git diff` is empty for `main.py`, `auth_service.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/mailer.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, `verification_service.py`, `otp_service.py`, `totp_service.py`, and every template except `login.html`/`qr_approve.html`.
- **AC-13:** `uv run backend/app/main.py` boots with no traceback; a normal password login still succeeds.
- **AC-14:** VULN-1…VULN-8 all remain closed (no SQL added; bcrypt/session/CSRF/rate-limit middlewares unchanged; no `/download/db`; env-sourced config; no token reflection; owner-binding closes login-CSRF).
- **AC-15:** `README.md` shows feature #7 as "Done (v1.0.8)", adds a v1.0.8 release row, lists the five new routes, and notes "no schema change, no new dependency". `CLAUDE.md` has the new subsection, rule, and hierarchy entry.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | No schema change | Repo checkout | `git diff` empty for `db/session.py`; `users` columns unchanged |
| TC-02 | Password/Google unchanged | Repo checkout | Existing login flows behave as before; QR panel additive |
| TC-03 | Create | `GET /qr/create` | JSON has `token`, `qr_url`, `qr_data_uri`, `poll_interval`, `expires_in`; session gains `qr_login_token` |
| TC-04 | Scan logged out | No session | `GET /qr/scan/{token}` → `302 /login` |
| TC-05 | Scan logged in | Session + pending token | Confirm page with escaped username, token, CSRF |
| TC-06 | Approve | Logged in, pending token | `POST /qr/approve` → `200`; token `approved` |
| TC-07 | Reject | Logged in, pending token | `POST /qr/reject` → `200`; token `rejected` |
| TC-08 | Status pending→approved | Desktop owns token | Poll `pending`, then after approve `{"status":"approved","redirect":"/welcome"}`; `user_id` written |
| TC-09 | Single-use | Just approved+claimed | Second `GET /qr/status` → `invalid`; no second login |
| TC-10 | Owner-binding | Token approved for another browser | Poll from non-owner → `invalid`; no session |
| TC-11 | Reject status | Token rejected | Desktop poll → `{"status":"rejected"}`; no session |
| TC-12 | Expiry | Wait > TTL | Desktop poll → `{"status":"expired"}`; "Show new QR" re-creates |
| TC-13 | Approve expired | Token past TTL | `POST /qr/approve` → `400`; no state change |
| TC-14 | Scan invalid token | Unknown/used token | Confirm page shows fixed "no longer valid" state; buttons hidden |
| TC-15 | No reflection | Pages + JSON | No raw token in HTML; username escaped; fixed JSON messages |
| TC-16 | CSRF on POSTs | Approve/Reject without token | `CSRFMiddleware` → `403` |
| TC-17 | Rate limit | Flood approve | `429` after the per-IP limit |
| TC-18 | Untouched files | Repo checkout | `git diff --stat` empty for the forbidden files |
| TC-19 | No new dep | Repo checkout | only `segno` (already present) used; no `qrcode`/Pillow |
| TC-20 | Boot + normal login | Repo checkout | `uv run …` no traceback; password login → `200` |
| TC-21 | Docs updated | Repo checkout | feature #7 "Done (v1.0.8)"; v1.0.8 row; routes; CLAUDE entries |

---

## 10. Verification Steps

Run from the repo root. Raise the per-IP limit if exercising many POSTs from one IP (`RATE_LIMIT_MAX=100`). For a real cross-device test, set `APP_BASE_URL` to an address the scanner can reach (e.g. `http://<LAN-IP>:3001`); on `localhost`, "scan" by opening the `qr_url` in a second, already-logged-in browser.

### 10.1 Untouched Schema & Files (AC-01, AC-12, TC-01, TC-18)
```bash
git diff --stat -- backend/app/db/session.py backend/app/main.py \
  backend/app/services/auth_service.py backend/app/core/security.py \
  backend/app/core/csrf.py backend/app/core/rate_limit.py backend/app/core/mailer.py \
  backend/app/core/oauth.py backend/app/services/oauth_service.py \
  backend/app/services/lockout_service.py backend/app/services/verification_service.py \
  backend/app/services/otp_service.py backend/app/services/totp_service.py \
  frontend/templates/signup.html frontend/templates/dashboard.html \
  frontend/templates/profile.html      # all empty
```

### 10.2 QR Login End-to-End (AC-03…AC-09, TC-03…TC-12)
```bash
# Browser A (logged out): open /login, observe the QR panel (GET /qr/create) and polling.
# Browser B (logged in):  open the qr_url shown under the QR -> confirm page -> Approve.
# Browser A: the poll flips to approved and navigates to /welcome (no password entered there).
# Re-run and click Reject in B -> A shows "denied". Let one expire -> A shows "expired" + new QR.
```

### 10.3 Owner-Binding (AC-08, SP-05, TC-10)
```bash
# Approve a token bound to Browser A's session, then from Browser C (different session)
# call GET /qr/status?token=<that token> -> {"status":"invalid"}, no login. Confirms login-CSRF is closed.
```

Expected `git status --porcelain` (declared files + docs only):
```
?? backend/app/core/qr_login.py
?? frontend/templates/qr_approve.html
 M backend/app/core/config.py
 M backend/app/api/routes/auth.py
 M frontend/templates/login.html
 M frontend/static/css/styles.css
 M .env.example
 M README.md
 M CLAUDE.md
?? .claude/specs/qr-code-login.md
?? .claude/specs/qr-code-login-plan.md
?? docs/prompts/qr-code-login-spec-prompt.txt
?? docs/prompts/qr-code-login-plan-prompt.txt
?? docs/prompts/qr-code-login-execution-prompt.txt
```
