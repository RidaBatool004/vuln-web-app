# Software Specification Document — CAPTCHA on Login (Cloudflare Turnstile)

**Version:** 1.0.0
**Last Updated:** 2026-06-21
**Target Release Tag:** v2.0.0
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [CAPTCHA on Login — README "Feature Enhancements" #8](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **CAPTCHA on Login** enhancement. It is item #8 ("CAPTCHA on Login") in the README's "Feature Enhancements" table. A **Cloudflare Turnstile** widget is placed on the login form; on every `POST /login`, the server verifies the Turnstile token against Cloudflare's `siteverify` endpoint **before** any credential processing. A request that fails the CAPTCHA is rejected with an inline error and never reaches the authentication logic — blocking automated and bot-driven login attempts (credential stuffing, brute force from a headless client).

**This is a bot-traffic filter layered on the existing password flow — not a replacement for any existing control.** It composes with every already-closed control and with the per-account / per-IP defenses already shipped:

| Stage (password login) | Control already in place | What this feature adds |
|------------------------|--------------------------|------------------------|
| Flood of POSTs | per-IP `RateLimitMiddleware` (VULN-7) | — (unchanged; the CAPTCHA POST is throttled too) |
| Forged cross-site POST | synchronizer-token `CSRFMiddleware` (VULN-8) | — (unchanged; the login form keeps its `csrf_token`) |
| Per-account brute force | Account Lockout (v1.0.5) | — (unchanged; runs inside `login()`) |
| **Automated / scripted client** | per-IP rate limit only | **Bot challenge:** a request with no/invalid Turnstile token is rejected **before** lockout/bcrypt/DB |
| Password check | bcrypt verify (VULN-5) | — (unchanged; only reached after the CAPTCHA passes) |

### 1.1 Design Decisions (product-owner choices)

These decisions were made explicitly before writing this spec and shape everything below:

1. **Provider: Cloudflare Turnstile.** Free, privacy-friendly, drop-in. The server-side verification is a single HTTPS POST to `https://challenges.cloudflare.com/turnstile/v0/siteverify`, implemented with **stdlib `urllib`** — so this feature adds **no new Python dependency** (it mirrors `core/mailer.py`'s stdlib `smtplib` posture; `core/oauth.py`'s Authlib is the OAuth-specific exception, not a general HTTP client). The site/secret keys come from env/`.env` exactly like the Google OAuth credentials.
2. **Trigger: always on `POST /login`** (when configured). Every password-login attempt must carry a valid Turnstile token. This is the literal README ask ("add a CAPTCHA to the login form") and the simplest to reason about and verify. (A risk-based "only after N failures" variant was considered and rejected for this slice — documented as future hardening.)
3. **Scope: login form only.** Only `POST /login` is gated. Signup, profile, the OAuth GET path, and the QR-login routes are **not** gated (documented non-goals).
4. **Unconfigured degrade: login behaves exactly as today.** With no `TURNSTILE_SITE_KEY`/`TURNSTILE_SECRET_KEY` set, the login page renders **no** widget and `POST /login` performs **no** CAPTCHA check — the password flow is byte-for-byte the current behaviour. This is mandatory: a fresh clone with no keys must still be able to log in. Same posture as the Google/SMTP "not configured" degrade.
5. **Provider unreachable: fail-OPEN.** When Turnstile **is** configured but the `siteverify` call errors (network failure, timeout, Cloudflare outage, non-JSON), `login()` is allowed to **proceed** (a warning is logged). Rationale: a CAPTCHA is a bot filter, not the authenticator; a transient outage must not lock every legitimate user out. This mirrors the rate-limiter/lockout "a broken control must not deny everyone" posture and is the **opposite** of `CSRFMiddleware`'s fail-closed choice (CSRF is an integrity gate; CAPTCHA is a traffic filter). The accepted risk — a bot could exploit a Cloudflare outage — is bounded by the unchanged password + lockout + per-IP rate-limit layers underneath.

### 1.2 Built on existing primitives

- **Verification lives in `core/`, not the service layer.** A new `core/captcha.py` (sibling to `core/oauth.py` / `core/mailer.py`) performs the outbound `siteverify` HTTP call. The route handler calls it; `auth_service.login()` is **not** modified (it stays free of network I/O, consistent with the project's layering).
- **Configuration rides the existing `core/config.py` env/`.env` loader,** with an `is_captcha_configured()` gate mirroring `is_google_configured()`. The **secret key is a real secret** (like `GOOGLE_CLIENT_SECRET`) and is read only from env/`.env`; the site key is public.
- **No new state.** The token is verified live per request — **no database column, no in-memory store, no session field.** This is the **second consecutive schema-free feature** (after QR Code Login, v1.0.8).
- **Auth stays session-only.** This feature adds no JWT/token/cookie; it only gates whether `auth_service.login()` runs.
- The site key is **HTML-escaped** before being spliced into the page (VULN-2 posture); the login-time token is **never reflected** into any response or log (VULN-3 posture).

This feature does **not** change any of the eight closed vulnerabilities. After this change, all eight remain closed and the app gains **no** database-schema change and **no** new dependency.

The implementation touches:

- One new backend module: `backend/app/core/captcha.py` (stdlib `urllib` `siteverify`, fail-open, never logs the secret).
- Existing files: `backend/app/core/config.py` (Turnstile settings + `is_captcha_configured()`), `backend/app/api/routes/auth.py` (`login_page` splices the widget when configured; `login_post` verifies the token before `auth_service.login()`), `frontend/templates/login.html` (widget + script placeholders), `frontend/static/css/styles.css` (small additive `.cf-turnstile` block).
- `.env.example`, `README.md`, and `CLAUDE.md` (documentation).

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/db/session.py`, `backend/app/services/auth_service.py` (and every other service), `backend/app/core/security.py`, `backend/app/core/csrf.py`, `backend/app/core/rate_limit.py`, `backend/app/core/oauth.py`, `backend/app/core/mailer.py`, `backend/app/core/qr_login.py`, every other template, and the dependency manifests (`pyproject.toml`, `backend/pyproject.toml`, `uv.lock`) remain unchanged.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **No schema change.** `backend/app/db/session.py` is **not** modified. The Turnstile token is verified live and discarded; nothing is persisted.
- **CAPTCHA configuration (`core/config.py`).** Read three settings from the environment / `.env`, plus one gate:
  - `TURNSTILE_SITE_KEY` (default `""`) — the public site key embedded in the login page's widget. **Public** (safe to expose / commit as a placeholder).
  - `TURNSTILE_SECRET_KEY` (default `""`) — the private key sent to `siteverify`. **A real secret** — read only from env/`.env`, never committed, never logged.
  - `TURNSTILE_HTTP_TIMEOUT` (default `10.0`) — network timeout (seconds) for the `siteverify` call, so a slow/hung endpoint cannot pin a worker (mirrors `OAUTH_HTTP_TIMEOUT` / `SMTP_TIMEOUT`).
  - `is_captcha_configured() -> bool` — returns `True` only when **both** the site key and secret key are present (mirrors `is_google_configured()`). This gate drives both the widget render (GET) and the enforcement (POST).
  - Update the module docstring's feature list to mention CAPTCHA.
- **CAPTCHA service (`core/captcha.py`, new).** Stdlib-only helpers (`urllib.request`, `urllib.parse`, `json`, `logging`) plus `from app.core import config`. No SQL (it touches no DB).
  - Module constant `TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"`.
  - `verify(token: str) -> bool` — returns **`True` = allow the login to proceed**, **`False` = block**. Logic:
    - empty/missing `token` → `False` (the widget was not solved; block — this is a *user* failure, not a provider failure, so it is **not** fail-open).
    - otherwise POST `{"secret": TURNSTILE_SECRET_KEY, "response": token}` urlencoded to `TURNSTILE_VERIFY_URL` with `timeout=config.TURNSTILE_HTTP_TIMEOUT`; parse the JSON reply:
      - `{"success": true}` → `True` (allow).
      - `{"success": false, ...}` → `False` (definitive bot/invalid verdict; block).
    - **any exception** (network error, timeout, DNS, non-JSON, Cloudflare down) → `True` (**fail-OPEN**) + `logger.warning(...)`.
  - **`remoteip` is intentionally omitted** from the verify payload (the app may sit behind a reverse proxy in production; sending a proxy IP is worse than sending none — consistent with the rate-limiter's documented "do not trust proxy headers blindly" stance).
  - The function **never raises** and **never logs `TURNSTILE_SECRET_KEY`** or the raw token.
- **Login route splices the widget when configured (`api/routes/auth.py`, `login_page`).** After the existing `csrf_token` splice, replace two placeholders:
  - `{{turnstile_head}}` → `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` when `config.is_captcha_configured()`, else `""`.
  - `{{turnstile_widget}}` → `<div class="cf-turnstile" data-sitekey="<html.escape(config.TURNSTILE_SITE_KEY, quote=True)>"></div>` when configured, else `""`.
- **Login route enforces the CAPTCHA before credentials (`api/routes/auth.py`, `login_post`).** Add a Form param with an alias (the Turnstile field name contains hyphens):
  - `cf_turnstile_response: str = Form("", alias="cf-turnstile-response")`.
  - Before calling `auth_service.login(...)`:
    ```python
    if config.is_captcha_configured() and not captcha.verify(cf_turnstile_response):
        return JSONResponse({"error": "CAPTCHA verification failed. Please try again."}, status_code=400)
    return auth_service.login(request, username, password)
    ```
  - The check sits **upstream of all credential logic**, so a failed CAPTCHA never reaches the lockout gate, bcrypt, or the DB, and writes no session. `auth_service.login()` is **unchanged**.
- **Template (`login.html`, modified — additive).**
  - Add the `{{turnstile_head}}` placeholder in `<head>` (after the stylesheet link).
  - Add the `{{turnstile_widget}}` placeholder inside `<form id="login-form">`, after the password `form-group` and before the Sign In button.
  - **No JS change is required:** the Turnstile script auto-injects a hidden `cf-turnstile-response` input into the enclosing form, so the existing `URLSearchParams(new FormData(form))` submit sends the token automatically; a `400 {"error": ...}` flows through the existing `errorDiv.textContent = data.error` path.
- **CSS (`styles.css`, modified — small additive block).** Append a minimal `.cf-turnstile { margin: 16px 0; }` (spacing only; theme-agnostic). No existing rule is modified.
- **`.env.example`.** Append a Turnstile block (its own section, since the secret key is a real secret like the Google/SMTP blocks) with `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` placeholders + the optional `TURNSTILE_HTTP_TIMEOUT`, and a short "where to get these" note (Cloudflare Turnstile dashboard → add `localhost` hostname → copy keys).
- **Docs.** Update `README.md` (move feature #8 to "Done (v2.0.0)"; add a v2.0.0 release row; add a "CAPTCHA on Login — Setup (optional)" section; note that **no** API endpoints change) and `CLAUDE.md` (integration subsection, Important-Rules entry, Specification-Hierarchy entry).

### 2.2 Out of Scope (Intentionally)

- **No CAPTCHA on signup, profile, change-password, the OAuth GET path, the QR-login routes, or the OTP/TOTP screens.** Only `POST /login` is gated this slice. (Signup is already gated by email-verification + rate-limit; the others are session-gated or capability-based.) Documented future hardening.
- **No risk-based / adaptive trigger** ("only show CAPTCHA after N failures"). A single always-on challenge is the chosen model. Adaptive triggering is a documented future option (it would compose with the lockout counter).
- **No alternative provider** (no Google reCAPTCHA, no hCaptcha) and **no self-hosted/homegrown CAPTCHA**. Cloudflare Turnstile is the chosen provider.
- **No new dependency.** The `siteverify` call uses stdlib `urllib`. `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged.
- **No database change, no in-memory store, no session field.** The token is stateless per request.
- **No change to the rate limiter, CSRF, session secret, bcrypt, lockout, mailer, OAuth, or QR-login.** Those middlewares/services stay byte-for-byte unchanged; the gated POST inherits their protection.
- **No `remoteip` in the verify call** (proxy-IP caveat, §2.1).
- **No template engine / JS framework.** The widget is a `<div class="cf-turnstile">` rendered by Cloudflare's script tag; no inline JS is added.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** this feature adds **no SQL** (it touches no DB). `auth_service.login()`'s parameterized queries are unchanged.
- **VULN-2 (Stored XSS):** the only value spliced into the page is `TURNSTILE_SITE_KEY`, a server-controlled config value, and it is `html.escape(..., quote=True)`-d before substitution into the `data-sitekey` attribute. The `{{turnstile_head}}`/`{{turnstile_widget}}` placeholders are replaced with fixed server-controlled markup or `""`.
- **VULN-3 (Reflected XSS):** the login-time Turnstile token is **never** reflected into any response body, URL, template, or log. The `400` CAPTCHA-failure message is a fixed, server-controlled string.
- **VULN-4 (Session Hijacking):** `main.py` is not modified; the session secret is untouched. Turnstile keys come from env/`.env` (the secret key never hardcoded, never committed). A failed CAPTCHA writes no session.
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged; bcrypt remains the sole password authenticator and runs **only after** the CAPTCHA passes (inside the unmodified `login()`). The CAPTCHA adds a filter; it does not weaken the password check.
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered and unchanged; `POST /login` is still throttled. The CAPTCHA is an **additional** layer (it runs inside the handler, after the middleware).
- **VULN-8 (CSRF):** `POST /login` keeps its hidden `csrf_token`; `CSRFMiddleware` still validates it. No route method/path changes; no new GET capability is added.

### 2.4 Explicit Non-Goals / Minimal Touch

- This feature does **not** modify `auth_service.login()` (or any service), `main.py`, `db/session.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/mailer.py`, or `core/qr_login.py`.
- The **only** edits to existing files are: two settings + one gate in `core/config.py`; the widget splice in `login_page` and the token check in `login_post` in `auth.py`; two placeholders in `login.html`; one small additive CSS block; and the three doc files (`.env.example`, `README.md`, `CLAUDE.md`).
- This feature persists **no** state. No Redis, no DB column, no in-memory map, no extra cookie, no session field.

---

## 3. Affected Files

The change MUST touch only the following files (beyond this spec/plan pair and the prompt docs).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/captcha.py` | **New** | `verify(token)` — stdlib `urllib` POST to Turnstile `siteverify`, fail-open, never logs the secret/token |
| `backend/app/core/config.py` | Modified | `TURNSTILE_SITE_KEY` + `TURNSTILE_SECRET_KEY` + `TURNSTILE_HTTP_TIMEOUT` + `is_captcha_configured()`; docstring note |
| `backend/app/api/routes/auth.py` | Modified | `login_page` splices the widget/script when configured; `login_post` verifies the token before `auth_service.login()` (`Form` alias for `cf-turnstile-response`) |
| `frontend/templates/login.html` | Modified | Additive `{{turnstile_head}}` (in `<head>`) + `{{turnstile_widget}}` (in the form); no JS change |
| `frontend/static/css/styles.css` | Modified | Small additive `.cf-turnstile` spacing block |
| `.env.example` | Modified | Turnstile key placeholders + optional timeout + "where to get these" note |
| `README.md` | Modified | Feature #8 → Done (v2.0.0); release row; "CAPTCHA on Login — Setup" section; note no API change |
| `CLAUDE.md` | Modified | Integration subsection, Important-Rules entry, hierarchy entry |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / `RATE_LIMIT_*` / port (VULN-4 / VULN-7 / VULN-8 closures). The CAPTCHA logic is core/route-layer; no middleware is added.
- `backend/app/db/session.py` — **no schema change** (the feature is stateless).
- `backend/app/services/auth_service.py` and every other service (`oauth_service.py`, `lockout_service.py`, `verification_service.py`, `otp_service.py`, `totp_service.py`) — the CAPTCHA gate is upstream in the route handler.
- `backend/app/core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/mailer.py`, `core/qr_login.py` — closures and unrelated modules stay as-is.
- All templates except `login.html` (`signup.html`, `dashboard.html`, `profile.html`, `otp_verify.html`, `totp_verify.html`, `qr_approve.html`, `check_email.html`, `verify_result.html`, `email_not_configured.html`, `oauth_not_configured.html`).
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` — **no dependency change**.

---

## 4. Functional Requirements

### FR-01: No Schema Change
- `backend/app/db/session.py` MUST NOT be modified. No column is added to `users`; `PRAGMA table_info(users)` is identical before and after this feature.

### FR-02: CAPTCHA Configuration
- `config.TURNSTILE_SITE_KEY` and `config.TURNSTILE_SECRET_KEY` MUST be read from the environment as strings, defaulting to `""`.
- `config.TURNSTILE_HTTP_TIMEOUT` MUST be read from the environment as a `float`, defaulting to `10.0`.
- `config.is_captcha_configured()` MUST return `True` only when both keys are non-empty (mirrors `is_google_configured()`).
- The secret key MUST come only from env/`.env` (never hardcoded); `.env` stays git-ignored and `.env.example` placeholder-only.

### FR-03: CAPTCHA Service (`captcha.py`)
- `verify(token)` MUST return `False` for an empty/missing token (no provider call needed).
- `verify(token)` MUST POST `secret` + `response` urlencoded to `TURNSTILE_VERIFY_URL` with `timeout=config.TURNSTILE_HTTP_TIMEOUT` and return the boolean `success` field from the JSON reply.
- `verify(token)` MUST treat any exception (network/timeout/parse/outage) as **allow** (`return True`, fail-OPEN) and log a warning.
- `verify(token)` MUST NOT include `remoteip`, MUST NOT raise, and MUST NOT log the secret key or the raw token.

### FR-04: Login Page Renders the Widget Only When Configured
- `login_page` MUST splice the Turnstile `<script>` and the `<div class="cf-turnstile" data-sitekey="...">` only when `config.is_captcha_configured()` is true; otherwise both placeholders MUST become `""` (no widget, no script).
- The site key MUST be `html.escape(..., quote=True)`-d before substitution.

### FR-05: Login Enforces the CAPTCHA Before Credentials (When Configured)
- `login_post` MUST read `cf_turnstile_response` via `Form("", alias="cf-turnstile-response")`.
- When `config.is_captcha_configured()` is true and `captcha.verify(cf_turnstile_response)` is false, `login_post` MUST return `JSONResponse({"error": "CAPTCHA verification failed. Please try again."}, status_code=400)` **without** calling `auth_service.login()` and **without** writing a session.
- When the CAPTCHA passes (or is unconfigured), `login_post` MUST call `auth_service.login(request, username, password)` and return its result unchanged.

### FR-06: Unconfigured Degrade (Login Unchanged)
- With neither key set, `GET /login` MUST render no widget/script and `POST /login` MUST behave byte-for-byte as the current implementation (no CAPTCHA check). The password flow MUST be unaffected on a fresh clone.

### FR-07: Fail-Open on Provider Error
- When Turnstile is configured but the `siteverify` call errors (network/timeout/outage/non-JSON), `verify` MUST return `True` and `login_post` MUST proceed to `auth_service.login()` (a warning is logged). A transient provider outage MUST NOT block legitimate logins.

### FR-08: `auth_service.login()` Unchanged
- `auth_service.login()` and every other service function MUST remain byte-for-byte unchanged. The CAPTCHA gate lives entirely in the route handler + `core/captcha.py`.

### FR-09: Token Never Reflected; Secret Never Logged (VULN-3 Preserved)
- The raw Turnstile token MUST NOT appear in any HTTP response body, URL, template, or log line. `TURNSTILE_SECRET_KEY` MUST NOT be logged. The `400` failure message MUST be a fixed, server-controlled string.

### FR-10: No New Dependency
- The `siteverify` call MUST use stdlib `urllib`. No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`. No reCAPTCHA/hCaptcha SDK, no `requests`/`httpx` import.

### FR-11: Untouched Functions / Files
- `signup()`, `change_password()`, `password_meets_policy()`, every service module, every route handler other than `login_page`/`login_post`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/mailer.py`, `core/qr_login.py`, `main.py`, `db/session.py`, every template other than `login.html`, and the dependency manifests MUST remain unchanged.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope
Exactly the files in §3 change (plus the spec/plan/prompt docs). No `main.py`, no `db/session.py`, no service module, no other `core/` module, no other template, no lockfile.

### NFR-02: Configuration, Not Hardcoded Keys
The site key, secret key, and timeout come from `core/config.py` (env/`.env`) with documented defaults, mirroring the Google OAuth block. The secret key is a real secret and is never committed or logged.

### NFR-03: Bot Filter, Not a Weaker Authenticator
The CAPTCHA gate runs strictly **before** `auth_service.login()`. A failed CAPTCHA never reaches the lockout gate, bcrypt, or the DB, so the CAPTCHA cannot become an authentication oracle and cannot weaken the password check. It only decides whether the credential flow runs at all.

### NFR-04: Fail-Open Filter (Deliberate, Bounded)
A configured-but-unreachable provider MUST fail open (allow + log), matching the rate-limiter/lockout rationale that a broken filter must not deny everyone — the opposite of `CSRFMiddleware`'s fail-closed integrity gate. The accepted risk (a bot exploiting a Cloudflare outage) is bounded by the unchanged password + lockout + per-IP rate-limit layers. This trade-off MUST be documented in code comments, `CLAUDE.md`, and this spec.

### NFR-05: Graceful, Zero-Config Degrade
With no keys, the feature is invisible and login is unchanged — a fresh clone always works, exactly like the Google/SMTP degrade. Configuring it is optional for running the app and required only to see/enforce the CAPTCHA.

### NFR-06: No Information Leakage
The login page and all CAPTCHA-failure responses are fixed, server-controlled strings — no token, no secret, no internal field is reflected. The verify call's exceptions are logged server-side, never surfaced to the client.

### NFR-07: Consistency With Existing Patterns
Outbound HTTP in `core/` (like `oauth.py`/`mailer.py`); env config via `core/config.py` with an `is_*_configured()` gate (like Google/SMTP); `html.escape(..., quote=True)` on the spliced value; the thin-route → unchanged-service shape; `Form(...)` parameters with defaults; the `{{...}}` `str.replace` splice (like `{{csrf_token}}`).

### NFR-08: Bounded Network Cost
`TURNSTILE_HTTP_TIMEOUT` bounds the worst-case verify latency (default 10 s), mirroring `OAUTH_HTTP_TIMEOUT`/`SMTP_TIMEOUT`. The synchronous `urllib` call inside the `async` handler is consistent with the existing synchronous `auth_service.login()` (sync sqlite) and the OAuth/SMTP calls in this single-worker teaching lab; the timeout prevents a hung endpoint from pinning a worker indefinitely. (Documented trade-off.)

---

## 6. Success Paths

### SP-01: Unconfigured — Login Unchanged
1. No `TURNSTILE_*` keys are set. `GET /login` renders no widget/script.
2. A correct-password `POST /login` (no `cf-turnstile-response` field) skips the CAPTCHA check and returns `200 {"success": true, "redirect": "/welcome"}` exactly as today.

### SP-02: Configured — Happy Path
1. With real keys, `GET /login` shows the Turnstile widget.
2. The user passes the widget (token injected into the form) and submits a correct password.
3. `login_post` → `captcha.verify(token)` returns `True` → `auth_service.login()` verifies the password → `200 {"success": true, "redirect": "/welcome"}`.

### SP-03: Configured — Bot / No Token
1. A scripted client POSTs to `/login` with no (or a garbage) `cf-turnstile-response`.
2. `captcha.verify` returns `False` → `400 {"error": "CAPTCHA verification failed. Please try again."}`. No bcrypt, no DB, no session.

### SP-04: Configured — Provider Unreachable (Fail-Open)
1. Cloudflare's `siteverify` is unreachable (outage / network error) while keys are set.
2. `captcha.verify` catches the exception, logs a warning, returns `True` → `login_post` proceeds to `auth_service.login()`; a legitimate correct-password login still succeeds.

---

## 7. Edge Cases

- **EC-01 — Configured, empty token:** `verify("")` returns `False` (no provider call) → `400`. This is a user failure (widget not solved), so it is **not** fail-open.
- **EC-02 — Configured, valid token, wrong password:** CAPTCHA passes; `auth_service.login()` returns its existing generic `401` (and lockout counting) exactly as today.
- **EC-03 — Configured, token already used / expired (Cloudflare `success:false`):** `verify` returns `False` → `400`. (Turnstile tokens are single-use; resolving the widget again issues a fresh token.)
- **EC-04 — Provider unreachable:** fail-open (SP-04); warning logged; login proceeds.
- **EC-05 — Unconfigured but a `cf-turnstile-response` field is somehow present:** `is_captcha_configured()` is false, so the check is skipped entirely; login behaves as today.
- **EC-06 — CAPTCHA passes but account is locked / unverified / 2FA-enabled:** the CAPTCHA only gates *reaching* `auth_service.login()`; all existing branches (locked `401`, `unverified` `401`, `otp_required` 2FA redirect) fire unchanged after it.
- **EC-07 — OAuth / QR / signup login:** not gated by the CAPTCHA (documented scope); those paths are unchanged.
- **EC-08 — Site key present but secret key missing (or vice-versa):** `is_captcha_configured()` is false (both required) → the feature stays off (degrade). No half-configured state.
- **EC-09 — Slow `siteverify`:** bounded by `TURNSTILE_HTTP_TIMEOUT`; on timeout, fail-open (EC-04).
- **EC-10 — Test keys:** Cloudflare's always-pass / always-fail / always-challenge test keys behave as their name implies and are documented as an optional CI convenience, not the default.

---

## 8. Acceptance Criteria

- **AC-01:** `PRAGMA table_info(users)` is unchanged by this feature (no schema change); `db/session.py` `git diff` is empty.
- **AC-02:** With no keys set, `GET /login` HTML contains no `cf-turnstile` widget and no Turnstile `<script>`; a correct-password `POST /login` returns `200 {"success": true}` (degrade).
- **AC-03:** With both keys set, `GET /login` HTML contains the Turnstile `<script>` and a `<div class="cf-turnstile" data-sitekey="...">` with the HTML-escaped site key.
- **AC-04:** With keys set, a `POST /login` carrying a valid token + correct password returns `200 {"success": true}`.
- **AC-05:** With keys set, a `POST /login` with an empty/invalid token returns `400 {"error": "CAPTCHA verification failed. Please try again."}` and writes no session (no bcrypt/DB).
- **AC-06:** With keys set but the verify endpoint unreachable, a correct-password `POST /login` still returns `200` (fail-open) and a warning is logged.
- **AC-07:** `auth_service.login()` and every other service module `git diff` is empty.
- **AC-08:** The Turnstile token never appears in any HTTP response body, URL, or log; `TURNSTILE_SECRET_KEY` never appears in any log.
- **AC-09:** No new dependency: `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` `git diff` is empty; `core/captcha.py` imports only stdlib + `app.core.config`.
- **AC-10:** `git diff` is empty for `main.py`, `db/session.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `core/mailer.py`, `core/qr_login.py`, every service, every template except `login.html`.
- **AC-11:** `uv run backend/app/main.py` boots with no traceback; a normal correct-password login still succeeds.
- **AC-12:** VULN-1…VULN-8 all remain closed (no new SQL; bcrypt intact and reached only after the CAPTCHA; rate-limit + CSRF + session middleware unchanged; no `/download/db`; env-sourced keys; no token reflection; escaped site-key splice).
- **AC-13:** `README.md` shows feature #8 as "Done (v2.0.0)", adds a v2.0.0 release row and a "CAPTCHA on Login — Setup" section, and notes no API-endpoint change. `CLAUDE.md` has the new subsection, rule, and hierarchy entry.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | No schema change | Repo checkout | `db/session.py` diff empty; `PRAGMA table_info(users)` unchanged |
| TC-02 | Unconfigured degrade (GET) | No keys | `GET /login` HTML has no `cf-turnstile`/Turnstile script |
| TC-03 | Unconfigured degrade (POST) | No keys | correct pw → `200 {"success":true}` |
| TC-04 | Widget rendered | Both keys set | `GET /login` HTML has the script + `data-sitekey` (escaped) |
| TC-05 | Happy path | Keys set, valid token | correct pw → `200 {"success":true}` |
| TC-06 | Missing token | Keys set, empty `cf-turnstile-response` | `400 {"error":"CAPTCHA verification failed. Please try again."}`; no session |
| TC-07 | Invalid token | Keys set, garbage token (`success:false`) | `400`; no session |
| TC-08 | Fail-open | Keys set, verify URL unreachable | correct pw → `200`; warning logged |
| TC-09 | Service untouched | Repo checkout | `auth_service.py` + all services diff empty |
| TC-10 | Token/secret not leaked | Keys set / logs | `/login` HTML + all JSON contain no token; no secret in logs |
| TC-11 | No new dep | Repo checkout | `pyproject`/`uv.lock` diff empty; `captcha.py` imports stdlib + config only |
| TC-12 | Untouched files | Repo checkout | `git diff --stat` empty for the forbidden list |
| TC-13 | App boots + normal login | Repo checkout | `uv run …` no traceback; correct pw → `200` |
| TC-14 | Docs updated | Repo checkout | feature #8 "Done (v2.0.0)"; v2.0.0 row; Setup section; no-API-change note; CLAUDE entries |

---

## 10. Verification Steps

Run from the repo root.

### 10.1 Unconfigured Degrade (AC-02, TC-02, TC-03)
```bash
# With no TURNSTILE_* in .env / env:
uv run backend/app/main.py &
curl -s http://localhost:3001/login | grep -c 'cf-turnstile'   # 0 (no widget)
# A normal correct-password login still returns {"success": true}.
```

### 10.2 Configured — Widget + Enforcement (AC-03…AC-05)
```bash
# With real TURNSTILE_SITE_KEY / TURNSTILE_SECRET_KEY in .env:
curl -s http://localhost:3001/login | grep -o 'class="cf-turnstile" data-sitekey="[^"]*"'   # widget present
# In a browser: solve the widget + correct password -> 200 {"success": true}.
# A scripted POST with no token:
TOKEN=$(curl -s -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -b jar.txt -X POST http://localhost:3001/login \
  --data-urlencode 'username=alice' --data-urlencode 'password=whatever' \
  --data-urlencode "csrf_token=$TOKEN" -w "\n%{http_code}\n"
# -> 400 {"error":"CAPTCHA verification failed. Please try again."}
```
> Cloudflare publishes test keys (always-pass `1x00000000000000000000AA` / always-fail `2x00000000000000000000AB`, secret `1x0000000000000000000000000000000AA`) — handy for exercising AC-04/AC-05 without a human. These are a **CI convenience only**, not the runtime default.

### 10.3 Fail-Open (AC-06, TC-08)
```bash
# Temporarily point the verify host at an unroutable address (e.g. /etc/hosts
# 127.0.0.1 challenges.cloudflare.com with nothing listening) or pull the
# network, then submit a valid-token + correct-password login:
#   -> still 200 {"success": true}; a warning is logged server-side.
```

### 10.4 File / Dependency Audit (AC-07, AC-09, AC-10, TC-09, TC-11, TC-12)
```bash
git diff --stat -- backend/app/main.py backend/app/db/session.py \
  backend/app/services/ backend/app/core/security.py backend/app/core/csrf.py \
  backend/app/core/rate_limit.py backend/app/core/oauth.py backend/app/core/mailer.py \
  backend/app/core/qr_login.py \
  frontend/templates/signup.html frontend/templates/dashboard.html \
  frontend/templates/profile.html frontend/templates/otp_verify.html \
  frontend/templates/totp_verify.html frontend/templates/qr_approve.html \
  pyproject.toml backend/pyproject.toml uv.lock     # all empty
```

Expected `git status --porcelain` (declared files + docs only):
```
?? backend/app/core/captcha.py
 M backend/app/core/config.py
 M backend/app/api/routes/auth.py
 M frontend/templates/login.html
 M frontend/static/css/styles.css
 M .env.example
 M README.md
 M CLAUDE.md
?? .claude/specs/captcha-on-login.md
?? .claude/specs/captcha-on-login-plan.md
?? docs/prompts/captcha-on-login-spec-prompt.txt
?? docs/prompts/captcha-on-login-plan-prompt.txt
?? docs/prompts/captcha-on-login-execution-prompt.txt
```
