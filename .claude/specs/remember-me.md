# Remember Me — Persistent Login Sessions

**Version:** 1.0.0
**Last Updated:** July 8, 2026
**Parent Document:** N/A (standalone additive feature)

---

## 1. Overview / Purpose

Add a "Remember Me" checkbox to the login form. When checked, the session cookie's `Max-Age` is extended to 30 days (2592000 seconds) instead of the default session-only expiry (no `Max-Age`). The extended expiry is applied ONLY after the full authentication chain completes — CAPTCHA (if configured), Account Lockout, bcrypt, email-verified gate, AND any active second factor (TOTP or Email OTP, whichever the user has enabled). A user who checks Remember Me and has 2FA enabled must complete the second-factor challenge before the long-lived cookie is issued. No new database columns, no new routes, no new dependencies.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

| Vulnerability | Relation |
|---------------|----------|
| VULN-4 (Session Hijacking) | Session management perimeter — extended cookie lifetime is a first-class session policy decision. Must not weaken the env-sourced secret key. |
| VULN-7 (No Rate Limiting) | Rate limiting must still apply to every POST (including login with Remember Me checked). The feature must not introduce an unratelimited path. |
| VULN-8 (CSRF) | Every POST hangs off the existing synchronizer-token CSRF middleware. The new `remember_me` form field is a regular POST field and does not bypass CSRF. |

### 2.2 Non-Goals (Intentionally Not Addressed)

The following vulnerabilities remain in their existing fixed state and are NOT modified, weakened, or re-introduced by this feature:

| Vulnerability | Status |
|---------------|--------|
| VULN-1 (SQL Injection) | Not affected. No new SQL in scope. |
| VULN-2 (Stored XSS) | Not affected. Dashboard still `html.escape()`s the username. |
| VULN-3 (Reflected XSS) | Not affected. Every output sink remains escaped. |
| VULN-5 (Weak Password Storage) | Not affected. Bcrypt unchanged. |
| VULN-6 (Exposed Database) | Not affected. `/download/db` route absent. |

---

## 3. Affected Files

- `frontend/templates/login.html` — add the "Remember Me" checkbox and associated HTML/labels after the password field, before the Turnstile widget (if configured) and the submit button.
- `backend/app/api/routes/auth.py` — (a) `login_post` handler reads the new `remember_me` form field and forwards it; (b) `auth_service.login()` applies the extended `Max-Age` on the no-2FA path; (c) `login_otp_post` and `login_totp_post` handlers apply the extended `Max-Age` after verifying the second factor.

No other files are modified. No new middleware, no database columns, no routes.

---

## 4. Functional Requirements

### FR-01: Remember Me Checkbox

- The login form in `login.html` MUST render a labelled checkbox `<input type="checkbox" name="remember_me" value="1">` after the password field and before the Turnstile widget (when configured) or the submit button.
- The checkbox MUST have an associated `<label>` with descriptive text, e.g. "Remember me" or "Stay signed in".
- The checkbox is NOT checked by default (opt-in).
- The form submits the field as `remember_me=1` (urlencoded) when checked; when unchecked the field is absent from the submission (standard HTML checkbox — unchecked boxes are not sent).

### FR-02: Extended Session Max-Age

- When `remember_me=1` is present and the full authentication chain succeeds, the server MUST ensure the session cookie's `Max-Age` attribute is set to 30 days (2592000 seconds).
- When `remember_me` is absent (unchecked), the session cookie MUST remain a session cookie — NO `Max-Age` attribute — preserving the current session-only expiry behavior.

### FR-03: Full-Auth-Chain Gate

The extended `Max-Age` MUST only be applied at the point the session is FULLY established, in this order:

1. CAPTCHA verification (if configured) — must succeed first
2. Account Lockout gate — account must not be locked
3. bcrypt `verify_password` — must succeed
4. Email-verified gate — account must be verified (or grandfathered)
5. **Either**: a) no 2FA → apply extended `Max-Age` NOW (session written immediately); b) TOTP or Email OTP 2FA → set `pending_remember_me = True` in the session alongside the 2FA pending marker, apply the extended `Max-Age` ONLY after the second factor is verified at `POST /login/totp` or `POST /login/otp`

### FR-04: No Weakening of Existing Protections

- The `CSRFMiddleware` MUST still validate the `csrf_token` on every POST. The `remember_me` field is an additional urlencoded field; the CSRF middleware's parser ignores unknown fields.
- The `RateLimitMiddleware` MUST still throttle every POST, including requests that carry `remember_me=1`.
- The Account Lockout gate MUST still refuse a locked account before bcrypt — `remember_me=1` on the request does not bypass the lock.
- The CAPTCHA gate MUST still verify the Turnstile token before `auth_service.login()` — `remember_me=1` does not skip the CAPTCHA.

---

## 5. Non-Functional Requirements

### NFR-01: No New Dependencies

The feature MUST NOT introduce any new third-party Python or JavaScript packages. Stdlib + existing `segno` (already present from v1.0.7/v1.0.8) only.

### NFR-02: No New Database Columns

The feature MUST NOT add columns to the `users` table or create any new table. The `remember_me` preference is ephemeral (per-login) and lives only in the signed session cookie and the response path.

### NFR-03: No New Routes

The feature MUST NOT add any new HTTP endpoints. The checkbox value flows through the existing `POST /login`, `POST /login/otp`, and `POST /login/totp` handlers.

### NFR-04: Session Cookie Is the Only Auth Mechanism

The signed session cookie remains the sole authentication carrier — no JWT, no access/refresh tokens, no separate cookie.

---

## 6. Success Paths

### SP-01: Login with Remember Me, No 2FA

1. User navigates to `/login`.
2. User enters valid credentials and checks "Remember Me".
3. Form submits via `fetch()` POST to `/login`.
4. CAPTCHA passes (if configured).
5. `auth_service.login()`: lockout gate → bcrypt passes → reset failures → verified gate passes → no 2FA enabled.
6. Handler writes `request.session["user_id"]`, `request.session["username"]`, `request.session["email"]`.
7. Extended `Max-Age` (30 days) is applied to the session cookie.
8. User is redirected to `/welcome`.
9. User closes browser, reopens it after restart → session cookie persists → `/welcome` renders without re-login.

### SP-02: Login with Remember Me + TOTP

1. User navigates to `/login`.
2. User enters valid credentials and checks "Remember Me".
3. CAPTCHA passes → bcrypt passes → TOTP branch: `pending_2fa_user_id` + `pending_2fa_method = "totp"` + `pending_remember_me = True` are stored in session.
4. Browser redirects to `/login/totp`.
5. User opens authenticator app, enters current TOTP code.
6. `POST /login/totp`: code verifies → session keys written (`user_id`, `username`, `email`).
7. Extended `Max-Age` (30 days) is applied to the session cookie.
8. User is redirected to `/welcome`.

### SP-03: Login with Remember Me + Email OTP

1. User navigates to `/login`.
2. User enters valid credentials and checks "Remember Me".
3. CAPTCHA passes → bcrypt passes → Email OTP branch: `pending_2fa_user_id` + `pending_2fa_method = "email"` + `pending_remember_me = True` stored in session; OTP code emailed.
4. Browser redirects to `/login/otp`.
5. User reads OTP from email, enters the 6-digit code.
6. `POST /login/otp`: code verifies → session keys written.
7. Extended `Max-Age` (30 days) is applied to the session cookie.
8. User is redirected to `/welcome`.

### SP-04: Login without Remember Me

1. User enters valid credentials, leaves "Remember Me" unchecked.
2. Full auth chain completes as normal.
3. Session cookie is set with NO `Max-Age` (session-only, current behavior).
4. User closes browser → session cookie deleted by browser → user must re-login on next visit.

---

## 7. Edge Cases

### EC-01: CAPTCHA Failure with Remember Me Checked

- `POST /login` with `remember_me=1` but a failed or absent Turnstile token.
- The CAPTCHA check in `login_post` returns `400` BEFORE `auth_service.login()` is called.
- No session is written, no lockout state is changed, no cookie is extended.
- Behaviour is identical to a CAPTCHA failure without Remember Me.

### EC-02: Account Lockout with Remember Me Checked

- `POST /login` with `remember_me=1` but the account is locked.
- `auth_service.login()` returns `401` at the lockout gate — before bcrypt.
- No session is written, no cookie is extended.
- Behaviour is identical to a locked login without Remember Me.

### EC-03: Remember Me + 2FA Session Expires Before 2FA Completes

- User logs in with Remember Me + TOTP/Email OTP, the pending markers are set in the session.
- The user walks away before completing the second factor.
- The session (with pending marker) has no `Max-Age` (it is a session cookie), so it expires on browser close.
- User returns the next day: pending markers are gone (browser closed), user starts again from `/login`.
- No extended cookie is ever issued. Security invariant maintained.

### EC-04: Unverified Email with Remember Me Checked

- `POST /login` with `remember_me=1` but the account has `is_verified=0`.
- `auth_service.login()` returns `401 {"error": "...", "unverified": True}` at the verification gate.
- No session is written, no cookie is extended.
- Behaviour is identical to the existing unverified login path.

### EC-05: Remember Me Checkbox Absent from Form (Bot/Client)

- A hand-crafted POST to `/login` WITHOUT the `remember_me` form field (or with `remember_me=0`, `remember_me=true`, etc.).
- `login_post` reads the field via `Form("")` — missing/unparseable fields default to empty string `""`.
- An empty/non-"1" value means "Remember Me NOT requested."
- Session cookie retains the default (no `Max-Age`). No edge-case bypass.

---

## 8. Acceptance Criteria

### AC-01: Remember Me Checkbox Present

- The login page at `GET /login` renders a labelled checkbox with `name="remember_me"` below the password field.

### AC-02: Extended Cookie with Remember Me, No 2FA

- A login with valid credentials + `remember_me=1` + no 2FA results in a session cookie with `Max-Age` close to 2592000 seconds (within clock-skew tolerance).

### AC-03: Extended Cookie with Remember Me + TOTP

- A login with valid credentials + `remember_me=1` + TOTP enabled does NOT set the extended cookie until the TOTP code is verified at `POST /login/totp`.
- After completing the TOTP step, the session cookie carries `Max-Age` ≈ 30 days.

### AC-04: Extended Cookie with Remember Me + Email OTP

- A login with valid credentials + `remember_me=1` + Email OTP enabled does NOT set the extended cookie until the OTP code is verified at `POST /login/otp`.
- After completing the OTP step, the session cookie carries `Max-Age` ≈ 30 days.

### AC-05: Session-Only Cookie without Remember Me

- A login with valid credentials + `remember_me` absent/unchecked results in a session cookie with NO `Max-Age` attribute (session-only, current behaviour).

### AC-06: Existing Protections Not Weakened

- CSRF validation still applies: a `POST /login` with `remember_me=1` but a missing/invalid `csrf_token` receives HTTP 403.
- Rate limiting still applies: 6+ rapid `POST /login` requests with `remember_me=1` from the same IP within 60 seconds receives HTTP 429.
- CAPTCHA (when configured) still applied: `POST /login` with `remember_me=1` and empty Turnstile token receives HTTP 400.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|-------------|-----------------|
| TC-01 | Login with Remember Me, no 2FA | Registered user with no 2FA, valid credentials | Session cookie carries `Max-Age` ≈ 2592000; redirect to `/welcome` |
| TC-02 | Login without Remember Me, no 2FA | Registered user with no 2FA, valid credentials | Session cookie has NO `Max-Age` (session-only); redirect to `/welcome` |
| TC-03 | Login with Remember Me + TOTP, 2FA pending | Registered user with TOTP enrolled, valid credentials | Extended `Max-Age` NOT set at password step; pending marker written; redirect to `/login/totp` |
| TC-04 | Login with Remember Me + TOTP, 2FA completed | TC-03 completed; valid TOTP code submitted at `POST /login/totp` | Session cookie carries `Max-Age` ≈ 2592000; session keys written; redirect to `/welcome` |
| TC-05 | Login with Remember Me + Email OTP, 2FA pending | Registered user with Email OTP enabled, valid credentials | Extended `Max-Age` NOT set at password step; pending marker written; OTP emailed; redirect to `/login/otp` |
| TC-06 | Login with Remember Me + Email OTP, 2FA completed | TC-05 completed; valid OTP code submitted at `POST /login/otp` | Session cookie carries `Max-Age` ≈ 2592000; session keys written; redirect to `/welcome` |
| TC-07 | CAPTCHA failure with Remember Me | Turnstile configured; `remember_me=1` + empty/invalid Turnstile token | HTTP 400; no session written; no cookie extended |
| TC-08 | Account Lockout with Remember Me | User's account is locked (too many failures); `remember_me=1` + correct credentials | HTTP 401 with `locked: true`; no session written; no cookie extended |
| TC-09 | Unverified account with Remember Me | User not verified; `remember_me=1` + correct credentials | HTTP 401 with `unverified: true`; no session written; no cookie extended |
| TC-10 | CSRF token still enforced with Remember Me | Valid credentials + `remember_me=1` + missing/forged `csrf_token` | HTTP 403 by `CSRFMiddleware` before handler runs |
| TC-11 | Rate limit still enforced with Remember Me | Same IP sends 6+ `POST /login` with `remember_me=1` in 60 seconds | 6th request receives HTTP 429; handler never invoked |
| TC-12 | Dashboard Stored XSS fix intact after feature | Session contains a malicious `<script>` username; user visits `/welcome` | Username is `html.escape()`'d in the rendered dashboard; no script execution |
| TC-13 | Reflected XSS fix intact after Remember Me | `GET /search?q=<script>alert(1)</script>` after a Remember-Me login | The query string is `html.escape()`'d in the search results page; no script execution |
| TC-14 | Session is the only auth mechanism | Remember Me login completes; inspect all cookies | Exactly one signed session cookie; no JWT, no access/refresh token, no extra cookie |

---

## 10. Verification Steps

```bash
# 1. Start the application (from the project root)
uv run backend/app/main.py

# 2. Open http://localhost:3001 in a browser
# 3. Navigate to /signup and register a new user
#    (if email is not configured, set up SMTP or skip email-verification
#     by manually setting is_verified=1 in the DB)

# 4. Visit GET /login
#    Verify the "Remember Me" checkbox renders below the password field
#    and above the Turnstile widget / submit button.

# 5. Login flow — no 2FA, Remember Me
#    - Enter valid credentials
#    - Check "Remember Me"
#    - Submit
#    - Use browser dev tools → Application → Cookies to inspect the "session" cookie
#    - Confirm its "Expires / Max-Age" column shows a date ~30 days from now

# 6. Login flow — no 2FA, no Remember Me
#    - Repeat step 5 WITHOUT checking "Remember Me"
#    - Confirm the "session" cookie has NO "Expires / Max-Age" (session cookie)
#    - Close the browser tab, re-open /welcome — redirected to /login

# 7. Login flow — TOTP + Remember Me
#    - Enable TOTP on the profile page (/profile/totp/setup + /profile/totp/confirm)
#    - Logout, then login with Remember Me checked
#    - Verify the pending step redirects to /login/totp
#    - Check the cookie BEFORE entering the TOTP code → no Max-Age
#    - Enter the TOTP code → verify cookie now has Max-Age ≈ 30 days

# 8. Login flow — Email OTP + Remember Me
#    - Enable Email OTP 2FA on the profile page (/profile/2fa)
#    - Logout, then login with Remember Me checked
#    - Verify the pending step redirects to /login/otp
#    - Check the cookie BEFORE entering the OTP → no Max-Age
#    - Enter the OTP → verify cookie now has Max-Age ≈ 30 days

# 9. CSRF + Remember Me
#    - Craft a POST request to /login with remember_me=1 but a missing csrf_token
#    - Verify HTTP 403

# 10. Rate limiting + Remember Me
#     - Send 6+ POST requests to /login in quick succession from the same IP
#     - Verify the 6th request returns HTTP 429
```

---

## 11. Implementation Notes

### 11.1 Session Max-Age Mechanism

Starlette's `SessionMiddleware` accepts a `max_age` parameter at construction time that sets the `Max-Age` attribute of the session cookie. By default (no `max_age`), the cookie is a session cookie with no `Max-Age`. The Remember Me feature needs CONDITIONAL max-age — 30 days when checked, session-only when unchecked.

Because `SessionMiddleware` does not natively support per-request `max_age`, the implementation MUST use one of the following strategies:

**Strategy A — Response-level set-cookie override:** After the handler writes session keys (in `auth_service.login()` for the no-2FA path, or in `login_otp_post`/`login_totp_post` for the 2FA paths), call `response.set_cookie("session", ..., max_age=REMEMBER_ME_MAX_AGE)` with the same value `SessionMiddleware` will sign. Because `SessionMiddleware` processes the response AFTER the handler returns, its own `set_cookie` invocation would win. Therefore the response must be post-processed after `SessionMiddleware` runs (e.g. via an ASGI wrapper or by returning a response that the middleware interprets).

**Strategy B — Session-backed max-age flag:** Write a flag into the session at the moment the full auth chain completes (e.g. `request.session["__max_age__"] = REMEMBER_ME_MAX_AGE` when `remember_me` is checked). The existing `SessionMiddleware` is then wrapped by a thin ASGI middleware (or patched) that, on the response path, reads `__max_age__` from the serialized session dict and overrides the cookie's `Max-Age` attribute before sending the `Set-Cookie` header. The flag is ephemeral — it is serialized into the cookie only for that one response.

**Strategy C — Custom session cookie via response headers:** After the session is written by `SessionMiddleware`, a wrapper re-reads the response headers, identifies the `Set-Cookie: session=...` header, appends `; Max-Age=2592000` if the session contains a `remember_me` marker, and replaces the header. This avoids modifying `SessionMiddleware` internals.

Of the three, **Strategy B** is recommended as the most idiomatic and least fragile: it keeps the `max_age` decision in the auth code (where the full-chain gate is maintained) and the cookie-manipulation logic in the middleware layer. Strategy B requires either a new ASGI middleware file (e.g. `backend/app/core/remember_me.py`) wired after `SessionMiddleware` in `main.py`, or a thin subclass/patch of Starlette's `SessionMiddleware`. The implementation team should decide based on the project's middleware pattern (see `core/rate_limit.py` and `core/csrf.py` for the existing ASGI middleware style).

### 11.2 TOTP and Email OTP Integration

When `auth_service.login()` dispatches to the TOTP or Email OTP branch (FR-03, steps 5b), it writes `pending_remember_me = True` into the session alongside `pending_2fa_user_id`. The 2FA completion handlers (`login_otp_post` and `login_totp_post`) check for this flag after verifying the code and writing the final session keys; when `True`, they apply the extended `Max-Age` and pop the pending flag. This guarantees the extended cookie is never issued until AFTER the second factor is verified.

### 11.3 REMEMBER_ME_MAX_AGE Configuration

The extended max-age value (default 30 days = 2592000 seconds) SHOULD be sourced from an environment variable (e.g. `REMEMBER_ME_MAX_AGE`) with the hardcoded default, following the precedent of `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_SECONDS`, `OTP_TTL_SECONDS`, etc. in `core/config.py`. This makes the value observable and tunable without a code change.
