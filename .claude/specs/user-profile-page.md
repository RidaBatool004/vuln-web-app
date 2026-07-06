# Software Specification Document — User Profile Page (Authenticated, Change-Password)

**Version:** 1.0.0
**Last Updated:** 2026-06-18
**Target Release Tag:** v1.0.2
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [User Profile Page — README "Feature Enhancements" #2](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the **User Profile Page** enhancement. It is item #2 in the README's "Feature Enhancements" table. The profile page is the first **authenticated account-settings surface** in the app: a logged-in user can visit `/profile`, see their account information, and change their password.

This release implements a **deliberately minimal** slice of the eventual profile page. It is the *foundation* that later authentication features (MFA, email verification, OAuth, etc.) will extend in their own future specs. For v1.0.2 the page does exactly three things:

1. **View account info** — render the logged-in user's `username` and `email` (read-only), HTML-escaped on output.
2. **Change password** — a form that takes the current password, a new password, and a confirm-new-password, verifies the current password with bcrypt, and updates the stored hash.
3. **Theme toggle** — the same frontend-only light/dark toggle that every other page already carries.

The feature is built on the project's existing primitives, with **no new dependency, no new middleware, and no database-schema change**:

- The two new routes (`GET /profile`, `POST /profile/password`) live in the existing `backend/app/api/routes/auth.py` and are gated on `request.session["user_id"]`, exactly like `GET /welcome`.
- The change-password business logic is a new `change_password()` function in the existing `backend/app/services/auth_service.py`, using a **parameterized** `UPDATE` (VULN-1 stays closed) and **bcrypt** hashing via the existing `core/security.py` helpers (VULN-5 stays closed).
- The change-password form carries the existing per-session **CSRF** hidden token (VULN-8 stays closed); the existing `CSRFMiddleware` validates it on POST, and the existing `RateLimitMiddleware` throttles it (VULN-7 stays closed). No middleware wiring changes, so `main.py` is **not** touched (VULN-4 stays closed).
- The displayed `username` / `email` are HTML-escaped with `html.escape(..., quote=True)` before being spliced into the template — the same output-encoding pattern as the dashboard `{{username}}` splice (VULN-2/VULN-3 posture preserved).

The feature does **not** change any of the eight closed vulnerabilities. After this change, all eight remain closed and the app gains its first post-fix authenticated feature page.

The implementation touches:

- A new template, `frontend/templates/profile.html`.
- The existing `backend/app/api/routes/auth.py` (two new handlers + one new import).
- The existing `backend/app/services/auth_service.py` (one new `change_password()` function).
- The existing `frontend/templates/dashboard.html` (one new "Profile" nav link).
- The existing `frontend/static/css/styles.css` (appended profile-page rules, using the existing CSS-custom-property theme pattern).
- `README.md` and `CLAUDE.md` (documentation).

**No other file is touched.** In particular, `backend/app/main.py`, `backend/app/db/session.py`, `backend/app/core/*`, `frontend/templates/login.html`, and `frontend/templates/signup.html` remain byte-for-byte unchanged.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Add `GET /profile` to `backend/app/api/routes/auth.py`:
  - Gated on `request.session.get("user_id")`; redirect to `/login` (302) when absent, mirroring `welcome_page`.
  - Load `frontend/templates/profile.html` from disk on every request (no caching, no template engine), splice in the per-session CSRF token via `get_or_create_csrf_token(request)`, and splice in the HTML-escaped `username` and `email` read from the session.
- Add `POST /profile/password` to `backend/app/api/routes/auth.py`:
  - Gated on `request.session.get("user_id")`.
  - Receives `current_password` and `new_password` via `Form("")`; forwards to `auth_service.change_password(request, current_password, new_password)`.
  - Returns the service's JSON response.
- Add `change_password(request, current_password, new_password)` to `backend/app/services/auth_service.py`:
  - Read `user_id` from `request.session`; if absent, return JSON 401.
  - Validate `current_password` and `new_password` are non-empty; if either is empty, return JSON 400.
  - Fetch the user row by `id` with a **parameterized** `SELECT`.
  - Verify `current_password` against the stored hash with `verify_password()`; on mismatch (or a legacy MD5 row), return JSON 401 with a generic "Current password is incorrect" body.
  - Hash `new_password` with `hash_password()` (bcrypt) and run a **parameterized** `UPDATE users SET password = ? WHERE id = ?`.
  - Return JSON `{"success": True, "message": "Password updated successfully"}` on success.
- Add a new template `frontend/templates/profile.html`:
  - Shared header (title + the same three org logos) and the same frontend-only theme-toggle button and theme scripts the other templates carry.
  - A read-only "Account Information" card showing `{{username}}` and `{{email}}`.
  - A "Change Password" card with a `<form id="change-password-form">` containing the hidden `csrf_token` input as its **first** child, then `current_password`, `new_password`, and `confirm_new_password` (the confirm field is client-side only — **no `name` attribute**, not sent to the server), an inline message area, and a submit button.
  - A small inline `<script>` that (a) checks `new_password === confirm_new_password` before submit and (b) submits via `fetch()` and renders the JSON result inline, mirroring the existing `login.html` fetch pattern.
  - A navigation affordance back to the dashboard (`/welcome`) and a logout link (`/logout`).
- Modify `frontend/templates/dashboard.html`: add a single "Profile" link (to `/profile`) in the hero-right area next to the existing Logout button. No other dashboard change.
- Append profile-page CSS rules to `frontend/static/css/styles.css`, reusing existing classes (`.header`, `.btn`, `.form-group`, `.form-input`, `.form-label`, the card patterns) where possible and using `var(--...)` custom properties so light/dark themes are handled automatically.
- Update `README.md`: move "User Profile Page" from a "Planned" row to a "Done (v1.0.2)" row in the Feature Enhancements table; add `GET /profile` and `POST /profile/password` to the API Endpoints table.
- Update `CLAUDE.md`: add a "User Profile Page" subsection under "Frontend-Backend Integration"; add an "Important Rules" entry; append the new spec/plan pair to the Specification Hierarchy.

### 2.2 Out of Scope (Intentionally)

- **No change-email.** Editing the email address is out of scope for v1.0.2. The email is shown read-only.
- **No "member-since" / account-creation date.** Displaying a join date would require a new `created_at` column — the **first-ever schema change** in the project, with a migration story for legacy rows. It is intentionally deferred to keep this feature schema-free. The `users` table is byte-for-byte unchanged.
- **No per-user theme persistence.** The dark-mode preference stays **frontend-only** (`localStorage`), exactly as it is on every other page. The profile page carries the *same* toggle button and the *same* pre-paint theme script; it does **not** push theme state into the session, the database, or any new column. The standing CLAUDE.md rule ("dark mode is purely frontend") is preserved.
- **No infra-dependent account features.** Email verification, OAuth ("Continue with Google/GitHub"), MFA/TOTP, email OTP, QR-code login, CAPTCHA, and account lockout are **not** shown on the page in any form — not even as disabled "coming soon" placeholders. Each is a separate future spec that will extend this page.
- **Strength policy on the new password (amended v1.0.2).** The new password MUST satisfy the same five criteria the signup strength meter advertises — length ≥ 8 plus at least one lowercase letter, one uppercase letter, one digit, and one special (non-alphanumeric) character. Unlike signup (where the meter is advisory and the backend accepts any non-empty password), `change_password()` ENFORCES this policy server-side via `password_meets_policy()` and the profile form mirrors it in JS for inline feedback. The strength-meter **widget** itself is intentionally NOT rendered on the profile form — only the rules apply.
- **No "new password must differ from current" rule.** Allowing a user to "change" to the same password is harmless for the lab and avoids an extra branch. Not enforced.
- **No account deletion, no username change, no avatar/upload, no bio/profile fields.** Only `username`/`email` view and password change.
- **No new middleware and no middleware re-ordering.** The existing `CSRFMiddleware` / `SessionMiddleware` / `RateLimitMiddleware` stack handles the new POST route automatically. `main.py` is not modified.
- **No new dependency.** `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged.
- **No database-schema change.** `backend/app/db/session.py` is unchanged; the `users` table keeps `(id, username, email, password)`.

### 2.3 Explicit Preservation Note — All Eight Closed Vulnerabilities Stay Closed

- **VULN-1 (SQL Injection):** the new `SELECT` and `UPDATE` in `change_password()` use parameterized `?` placeholders. `signup()` / `login()` and `/search` keep their parameterized queries byte-for-byte.
- **VULN-2 (Stored XSS):** `welcome_page` keeps escaping `{{username}}`. The new profile page escapes `{{username}}` **and** `{{email}}` with `html.escape(..., quote=True)` before splicing — the same output-encoding posture.
- **VULN-3 (Reflected XSS):** `/search` keeps escaping `q`, both row columns, and the exception text. Unaffected.
- **VULN-4 (Session Hijacking):** `main.py` keeps sourcing `SECRET_KEY` from the environment. `main.py` is not modified.
- **VULN-5 (Weak Password Storage):** `core/security.py` is unchanged; `change_password()` hashes the new password via the existing bcrypt `hash_password()` and verifies the current password via the existing `verify_password()` (which fails closed on legacy MD5 rows).
- **VULN-6 (Exposed Database):** no `/download/db` route exists; none is added.
- **VULN-7 (No Rate Limiting):** `RateLimitMiddleware` stays registered; the new `POST /profile/password` is throttled by it automatically (it is a POST). `main.py` / `core/rate_limit.py` are not modified.
- **VULN-8 (CSRF):** the new change-password form carries the hidden `csrf_token` input as the first child of the form; `GET /profile` issues the token via `get_or_create_csrf_token`; the existing `CSRFMiddleware` validates it on `POST /profile/password`. `core/csrf.py` is not modified.

### 2.4 Explicit Non-Goals

- This feature does **not** introduce a template engine, build step, or JS module system. The profile page uses the same `str.replace("{{...}}", ...)` splice pattern and inline `<script>` style as the rest of the app.
- This feature does **not** add a flash-message framework. Success/error feedback for the change-password form is rendered inline via the existing `fetch()` + JSON pattern (as on `login.html`).
- This feature does **not** log the user out after a password change. The session stays valid; only the stored hash changes. (Session invalidation on password change is a reasonable hardening step but is out of scope for this minimal slice.)
- This feature does **not** modify `signup()` or `login()` in `auth_service.py`. Only a new `change_password()` is added.
- This feature does **not** change `login.html` or `signup.html`.

---

## 3. Affected Files

The change MUST touch only the following files. No other repository file may be created or modified (beyond this spec/plan pair).

| Path | Change Type | Purpose |
|------|-------------|---------|
| `frontend/templates/profile.html` | **New** | The profile page: account-info card, change-password form (CSRF hidden field first), theme toggle, inline fetch script |
| `backend/app/api/routes/auth.py` | Modified | Add `GET /profile` (auth-gated render + CSRF/username/email splice) and `POST /profile/password` (auth-gated, forwards to service); add one import of `auth_service` is already present — add nothing else but the two handlers |
| `backend/app/services/auth_service.py` | Modified | Add `change_password(request, current_password, new_password)` (parameterized SELECT + bcrypt verify + parameterized UPDATE) and the `password_meets_policy()` helper (`import re` added); `signup()` / `login()` unchanged |
| `frontend/templates/dashboard.html` | Modified | Add one "Profile" link to `/profile` in the hero-right area |
| `frontend/static/css/styles.css` | Modified | Append profile-page rules using existing `var(--...)` theme custom properties |
| `README.md` | Modified | Move "User Profile Page" to a "Done (v1.0.2)" row; add the two new endpoints to the API table |
| `CLAUDE.md` | Modified | Add a "User Profile Page" integration subsection, an Important-Rules entry, and the spec/plan pair to the hierarchy |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / port (VULN-4 / VULN-7 / VULN-8 closures). The router auto-discovers the two new handlers, so no registration change is needed.
- `backend/app/db/session.py` — schema + connection layer. **No schema change** — the feature uses only the existing `(id, username, email, password)` columns.
- `backend/app/core/security.py` — bcrypt (VULN-5 closure).
- `backend/app/core/csrf.py` — CSRF middleware (VULN-8 closure).
- `backend/app/core/rate_limit.py` — rate-limit middleware (VULN-7 closure).
- `frontend/templates/login.html`, `frontend/templates/signup.html` — unaffected.
- `frontend/static/images/*` — no image change.
- `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and every prior spec/plan pair.
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock` — no dependency change.

---

## 4. Functional Requirements

### FR-01: `GET /profile` Is Authenticated

- `GET /profile` MUST read `request.session.get("user_id")`. If it is falsy (no session / not logged in), the handler MUST return `RedirectResponse(url="/login", status_code=302)` — identical to the gate in `welcome_page`.
- If `user_id` is present, the handler MUST render the profile page (FR-02 / FR-03).

### FR-02: Profile Page Renders Escaped Account Info

- The handler MUST read `username` and `email` from the session (`request.session.get("username", "")`, `request.session.get("email", "")`).
- It MUST load `frontend/templates/profile.html` from disk on every request (no caching), and splice the values via `str.replace`:
  - `page.replace("{{username}}", html.escape(username, quote=True))`
  - `page.replace("{{email}}", html.escape(email, quote=True))`
- The escape is mandatory (output encoding), mirroring the dashboard `{{username}}` splice — VULN-2 posture. A username or email containing HTML-significant characters MUST render as text, never as markup.

### FR-03: `GET /profile` Issues and Splices the CSRF Token

- The handler MUST call `get_or_create_csrf_token(request)` and splice the returned token via `page.replace("{{csrf_token}}", html.escape(token, quote=True))`, exactly as `login_page` / `signup_page` do.
- The token splice MUST happen before the `HTMLResponse` is returned.

### FR-04: Change-Password Form Structure

- `frontend/templates/profile.html` MUST contain a `<form id="change-password-form">` whose **first** child is `<input type="hidden" name="csrf_token" value="{{csrf_token}}">`.
- The form MUST contain, in document order after the hidden field:
  - A `current_password` field: `<input type="password" name="current_password" id="current_password" required>`.
  - A `new_password` field: `<input type="password" name="new_password" id="new_password" required>`.
  - A `confirm_new_password` field: `<input type="password" id="confirm_new_password" required>` — **no `name` attribute** (client-side only; not transmitted), mirroring the signup `confirm_password` convention.
  - An inline message area (e.g. `<div id="profile-message">`) hidden by default, used for both error and success feedback.
  - A submit `<button type="submit">` as the last child.
- The form's `action`/`method` are not relied upon (submission is via `fetch`), but the form MUST target `/profile/password` in the fetch call.

### FR-05: `POST /profile/password` Is Authenticated and Thin

- `POST /profile/password` MUST be a thin handler that takes `request: Request`, `current_password: str = Form("")`, and `new_password: str = Form("")`, and returns `auth_service.change_password(request, current_password, new_password)`.
- The handler MUST NOT contain business logic, SQL, or hashing. (The auth gate may live either in the handler or the service; per this spec it lives in the service — FR-06.1 — so the handler is a one-liner forward, consistent with `login_post`.)
- The hidden `csrf_token` field is POSTed but is consumed and validated by `CSRFMiddleware` before the handler runs; FastAPI's `Form()` ignores it.

### FR-06: `change_password()` Service Contract

`change_password(request, current_password, new_password)` MUST:

1. Read `user_id = request.session.get("user_id")`. If falsy, return `JSONResponse({"error": "Not authenticated"}, status_code=401)`.
2. If `current_password` or `new_password` is empty, return `JSONResponse({"error": "Current and new password are required"}, status_code=400)`.
2a. If `new_password` fails the strength policy (length ≥ 8 plus lower/upper/digit/special — see `password_meets_policy()`), return `JSONResponse({"error": "New password must be at least 8 characters and include an uppercase letter, a lowercase letter, a digit, and a special character"}, status_code=400)`.
3. Fetch the user row with a **parameterized** query: `SELECT * FROM users WHERE id = ?`, binding `user_id`.
4. If no row is found, return `JSONResponse({"error": "Not authenticated"}, status_code=401)` (defensive — should not happen for a valid session).
5. Verify the current password: `if not verify_password(current_password, row["password"]): return JSONResponse({"error": "Current password is incorrect"}, status_code=401)`. This also fails closed for legacy MD5 rows (they cannot change their password and must re-register — consistent with the login flow).
6. Hash the new password: `hashed = hash_password(new_password)`.
7. Run a **parameterized** `UPDATE users SET password = ? WHERE id = ?`, binding `[hashed, user_id]`, then commit.
8. Return `JSONResponse({"success": True, "message": "Password updated successfully"})`.
9. On any unexpected DB exception, return `JSONResponse({"error": "Could not update password"}, status_code=400)` without leaking the underlying error text.
10. The DB connection MUST be opened via `get_db()` and closed in a `finally`, matching the existing service functions.

### FR-07: JSON Response Shape (Fetch-Based, Mirrors Login)

- `POST /profile/password` MUST return JSON for every outcome (success and every failure), so the inline `fetch()` handler can render feedback without a page reload — the same interaction model as `POST /login`.
- Success body: `{"success": true, "message": "Password updated successfully"}` (HTTP 200).
- Failure bodies: `{"error": "..."}` with HTTP 400 (validation) or 401 (auth / wrong current password).

### FR-08: Client-Side Form Behavior

- The profile page's inline `<script>` MUST:
  1. Attach a `submit` listener to `#change-password-form` that first checks `new_password === confirm_new_password`; on mismatch it MUST `preventDefault()` and show an inline error, mirroring the signup password-match check.
  2. On match, `preventDefault()` and submit via `fetch("/profile/password", { method: "POST", body: new URLSearchParams(new FormData(form)) })`. The body MUST be wrapped in `URLSearchParams` (exactly as `login.html` does) so the browser sends `application/x-www-form-urlencoded` — `CSRFMiddleware` only parses urlencoded bodies and rejects raw `multipart/form-data` with 403. Because the hidden `csrf_token` is inside the form, it is included automatically — **no manual CSRF wiring**.
  3. Read the JSON response: on `success`, show the success message inline (and MAY clear the password inputs); on error, show `data.error` inline.
- No `localStorage`/`sessionStorage`/`document.cookie` writes are added by this script (other than the pre-existing theme toggle, FR-09).

### FR-09: Theme Toggle Is Frontend-Only (Same as Every Other Page)

- `profile.html` MUST carry the same pre-paint theme init script in `<head>` and the same `#theme-toggle` button + toggle script as `dashboard.html` / `login.html` / `signup.html`.
- The toggle MUST read/write only `localStorage["theme"]` and set `document.documentElement[data-theme]`. It MUST NOT send theme state to the server, write a theme to the session, or add a schema column. The standing "dark mode is purely frontend" rule is preserved.

### FR-10: Dashboard Navigation Link

- `frontend/templates/dashboard.html` MUST gain exactly one new anchor, `<a href="/profile" ...>Profile</a>`, placed in the `.hero-right` block adjacent to the existing Logout button. No other dashboard markup changes.

### FR-11: Parameterized SQL + Bcrypt (VULN-1 / VULN-5 Preserved)

- Every SQL statement in `change_password()` MUST use `?` placeholders with a separate parameter list. String concatenation into SQL is forbidden.
- Password hashing MUST use the existing `hash_password()` (bcrypt); verification MUST use the existing `verify_password()`. No new hashing primitive is introduced.

### FR-12: No Schema Change, No New Dependency

- `backend/app/db/session.py` MUST be unchanged. `change_password()` uses only the existing `(id, username, email, password)` columns.
- No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`.

### FR-13: Existing Service Functions Unchanged

- `signup()` and `login()` in `auth_service.py` MUST remain byte-for-byte unchanged. The additions are the new `change_password()` function and the `password_meets_policy()` helper, plus a single new `import re` (stdlib) for the policy regexes; the existing imports already cover `get_db`, `hash_password`, `verify_password`, `JSONResponse`, `Request`.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope

- Exactly seven files change (two new docs aside): `profile.html` (new), `auth.py`, `auth_service.py`, `dashboard.html`, `styles.css`, `README.md`, `CLAUDE.md`. No `main.py`, no `db/session.py`, no `core/*`, no `login.html`, no `signup.html`.

### NFR-02: Authentication Required

- Both `/profile` (GET) and `/profile/password` (POST) require a valid session. The GET redirects unauthenticated users to `/login`; the POST returns 401 from the service for a missing `user_id` (and, in practice, is also blocked at 403 by CSRF when there is no session at all — see EC-01).

### NFR-03: CSRF Enforced on the New POST (No New Wiring)

- `POST /profile/password` is covered by the existing `CSRFMiddleware` because it is a POST. The form carries the hidden token; the GET issues it. No middleware change is required or permitted.

### NFR-04: Rate Limiting Applies to the New POST (No New Wiring)

- `POST /profile/password` is covered by the existing per-IP `RateLimitMiddleware` because it is a POST. Rapid repeated password-change attempts from one IP are throttled at the configured limit (default 5 / 60 s) with HTTP 429, before the handler runs.

### NFR-05: No Schema Change, Zero Dependency Delta

- No `users`-table column is added, renamed, or removed. No third-party package is added. No `<script src=...>` to a CDN.

### NFR-06: No Information Leakage

- The wrong-current-password response is a generic `{"error": "Current password is incorrect"}` (HTTP 401). Unexpected DB errors return a generic `{"error": "Could not update password"}` (HTTP 400) — the underlying exception text is never reflected to the client.

### NFR-07: Output Encoding on Display

- The `username` and `email` rendered on the profile page are HTML-escaped with `html.escape(..., quote=True)` before splicing. The raw values stay in the session/DB; this is output encoding, not input filtering (same posture as VULN-2/VULN-3 closures).

### NFR-08: Theme Stays Frontend-Only

- The profile page introduces no backend theme state. The CLAUDE.md rule that dark mode is purely frontend remains true after this change.

### NFR-09: Fail-Safe Password Update

- A password change occurs **only** when the current password verifies. A wrong current password, an empty new password, or any DB error leaves the stored hash unchanged.

### NFR-10: Consistency With Existing Patterns

- The change-password flow reuses the established conventions: thin route handler → service function (like `login`), `fetch()` + JSON inline feedback (like `login.html`), confirm-field client-side-only check (like `signup.html`), `str.replace` template splice (like `welcome_page`), and `get_db()` + `try/finally` connection handling (like `signup`/`login`).

---

## 6. Success Paths

### SP-01: View Profile

1. A logged-in user requests `GET /profile`. `SessionMiddleware` decodes the session; `user_id` is present.
2. The handler reads `username`/`email` from the session, issues/reads the CSRF token, escapes all three, splices them into `profile.html`, and returns HTTP 200.
3. The page shows the account-info card (escaped username + email) and the change-password form with the hidden token populated.

### SP-02: Successful Password Change

1. On `/profile`, the user types the correct current password, a new password, and a matching confirm.
2. The submit handler confirms the two new-password fields match, then `fetch()`-POSTs `new URLSearchParams(new FormData(form))` (including `csrf_token`, sent as urlencoded) to `/profile/password`.
3. `RateLimitMiddleware` admits; `SessionMiddleware` decodes; `CSRFMiddleware` validates the token; the handler forwards to `change_password()`.
4. The service reads `user_id`, fetches the row, verifies the current password (bcrypt), hashes the new password (bcrypt), runs the parameterized `UPDATE`, commits, and returns `{"success": true, "message": "Password updated successfully"}` (HTTP 200).
5. The page shows the inline success message. The next login uses the new password.

### SP-03: Wrong Current Password Rejected

1. The user submits with an incorrect current password (correct CSRF token, matching new/confirm).
2. CSRF passes; `change_password()` fetches the row, `verify_password(current, row["password"])` returns `False`, and the service returns `{"error": "Current password is incorrect"}` (HTTP 401).
3. The stored hash is unchanged. The page shows the inline error.

### SP-04: New-Password Mismatch Blocked Client-Side

1. The user types a new password and a non-matching confirm.
2. The submit handler's match check fails, calls `preventDefault()`, shows the inline mismatch error, and does **not** issue the fetch. No request reaches the server.

### SP-05: Unauthenticated Access Redirects

1. A user with no session requests `GET /profile`. `user_id` is absent → `RedirectResponse(302, /login)`. The user sees the login page.

### SP-06: Theme Toggle on the Profile Page

1. The user clicks the theme toggle on `/profile`. `data-theme` flips and `localStorage["theme"]` updates, with no server round-trip — identical behavior to the other pages.

### SP-07: CSRF-Protected POST

1. The change-password form's hidden `csrf_token` matches the session token; the POST is admitted and processed.
2. A POST without a matching token (e.g., a forged cross-origin submission) is rejected with HTTP 403 by `CSRFMiddleware` before `change_password()` runs — no bcrypt verify, no DB write.

---

## 7. Edge Cases

### EC-01: Unauthenticated POST `/profile/password`

- A direct `POST /profile/password` with no session cookie: `SessionMiddleware` sets `request.session = {}`, so `CSRFMiddleware` reads `csrf_token = None` and rejects with **HTTP 403** before the handler runs. Even if CSRF somehow passed, `change_password()` reads `user_id = None` and returns **HTTP 401**. Defense in depth; the password is never changed.

### EC-02: Empty New Password

- `new_password == ""` → the service returns `{"error": "Current and new password are required"}` (HTTP 400). No update. (Mirrors signup's "all fields required" posture, but in JSON for the fetch flow.)

### EC-03: New Password Equals Current Password

- Allowed. The current password verifies, the "new" password is hashed and stored. No "must differ" rule is enforced (§2.4). Result is a successful no-op change.

### EC-04: Wrong Current Password

- `verify_password()` returns `False` → HTTP 401, generic message, no update (SP-03).

### EC-05: Username / Email Containing HTML Characters

- A user who registered with `username = "<b>x</b>"` sees it rendered as literal text on the profile card, because `html.escape(..., quote=True)` is applied before splicing. No markup executes. Same for a crafted email.

### EC-06: Legacy MD5 Row Attempts a Password Change

- If the stored hash is a legacy MD5 digest, `verify_password(current, hash)` returns `False` (it fails closed), so the change is rejected with "Current password is incorrect." The user cannot bootstrap out of a legacy hash via this page; they must re-register (consistent with the login flow). Documented, not a bug.

### EC-07: Session Has `user_id` but the Row Was Deleted

- `change_password()` fetches by `id`; if no row is found it returns HTTP 401 ("Not authenticated") rather than crashing. (This should not occur in normal operation since the app has no delete flow.)

### EC-08: Very Long New Password (bcrypt 72-byte limit)

- bcrypt hashes only the first 72 bytes of the input. A `new_password` longer than 72 bytes is silently truncated to 72 bytes for hashing — identical to the existing signup behavior. Documented as known bcrypt behavior, not introduced by this feature.

### EC-09: Rate Limit Hit on Rapid Change Attempts

- More than the configured number of `POST /profile/password` calls from one IP within the window returns HTTP 429 from `RateLimitMiddleware` before the handler runs. The fetch handler surfaces this as a generic error (it will not be `{"success": true}`), and no password change occurs for the throttled call.

### EC-10: JavaScript Disabled

- The change-password form will not submit via fetch (no JS) and the confirm-match check will not run. Because the form's submission path is JS-driven (like login), a no-JS user cannot change their password — acceptable for the lab, and no worse than the existing login page, which also requires JS. The account-info card still renders (it is server-rendered HTML).

### EC-11: Two Rapid Successful Changes

- Each successful change is an independent parameterized `UPDATE`. The second simply overwrites the hash from the first. Idempotent and safe.

---

## 8. Acceptance Criteria

### AC-01: Profile Route Renders for Authenticated Users

- After login, `GET /profile` returns HTTP 200 and HTML containing an "Account Information" section showing the user's username and email.

### AC-02: Profile Route Redirects Unauthenticated Users

- `GET /profile` with no session returns HTTP 302 to `/login`.

### AC-03: CSRF Hidden Field Present and First Child

- The rendered `/profile` HTML contains `<input type="hidden" name="csrf_token" value="...">` as the first child of `<form id="change-password-form">`, with a 43-char URL-safe token value.

### AC-04: Account Info Is HTML-Escaped

- A user whose username is `<script>x</script>` sees it rendered as escaped text on `/profile` (the page source contains `&lt;script&gt;`), proving output encoding (VULN-2 posture).

### AC-05: Successful Change Returns JSON Success

- A `POST /profile/password` from a logged-in session with the correct current password, a non-empty new password, and a valid CSRF token returns HTTP 200 with body `{"success": true, "message": "Password updated successfully"}`, and the user can subsequently log in with the new password.

### AC-06: Wrong Current Password Returns 401

- The same POST with an incorrect `current_password` returns HTTP 401 with `{"error": "Current password is incorrect"}`, and the old password still works for login.

### AC-07: Empty New Password Returns 400

- A POST with an empty `new_password` returns HTTP 400 with the "required" error and does not change the stored hash.

### AC-08: CSRF Still Enforced on the New POST

- `POST /profile/password` without a valid `csrf_token` returns HTTP 403 (from `CSRFMiddleware`), and no password change occurs.

### AC-09: Rate Limit Still Applies to the New POST

- The Nth+1 `POST /profile/password` from one IP within the window returns HTTP 429 (rate-limit gate fires before the handler).

### AC-10: Parameterized SQL in `change_password()`

- `backend/app/services/auth_service.py` contains `SELECT * FROM users WHERE id = ?` and `UPDATE users SET password = ? WHERE id = ?` (parameterized). No string concatenation into SQL is present in the new function.

### AC-11: Bcrypt Used for the New Password

- `change_password()` calls `hash_password()` for the new password and `verify_password()` for the current password; it does not introduce any other hashing primitive. `core/security.py` is unchanged.

### AC-12: No Schema Change

- `git diff --stat -- backend/app/db/session.py` reports zero changes. The `users` table still has exactly `(id, username, email, password)`.

### AC-13: No `main.py` Change

- `git diff --stat -- backend/app/main.py` reports zero changes. The two new routes are picked up via `include_router` automatically.

### AC-14: Existing Service Functions Unchanged

- `signup()` and `login()` in `auth_service.py` are byte-for-byte unchanged; only `change_password()` is added.

### AC-15: Dashboard Has a Profile Link

- `frontend/templates/dashboard.html` contains exactly one new `<a href="/profile">` in the hero-right area.

### AC-16: Theme Toggle Present and Frontend-Only

- `profile.html` carries the `#theme-toggle` button and the pre-paint theme script; it contains no server theme write and no schema column. `db/session.py` is unchanged (AC-12).

### AC-17: No New Dependency

- `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged.

### AC-18: Login and Signup Templates Untouched

- `git diff --stat -- frontend/templates/login.html frontend/templates/signup.html` reports zero changes.

### AC-19: Other Vulnerabilities Preserved

- VULN-1: parameterized queries throughout (`auth_service.py`, `auth.py`).
- VULN-2: `welcome_page` and the new profile page escape rendered user values.
- VULN-3: `/search` still escapes its sinks.
- VULN-4: `main.py` still env-sources `SECRET_KEY` (and is unchanged).
- VULN-5: bcrypt still in `core/security.py` (unchanged); `change_password()` uses it.
- VULN-6: `GET /download/db` still 404.
- VULN-7: `RateLimitMiddleware` still registered; new POST throttled.
- VULN-8: `CSRFMiddleware` still registered; new form carries and validates the token.

### AC-20: README and CLAUDE.md Updated

- `README.md`'s Feature Enhancements table shows "User Profile Page" as "Done (v1.0.2)", and the API Endpoints table lists `GET /profile` and `POST /profile/password`.
- `CLAUDE.md` has a "User Profile Page" integration subsection, an Important-Rules entry, and the spec/plan pair in the Specification Hierarchy.

### AC-21: Application Boots

- `uv run backend/app/main.py` starts with no traceback; `GET /profile` works after login.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Profile renders for logged-in user | App running, user logged in (cookie jar) | `GET /profile` → HTTP 200, HTML shows username + email |
| TC-02 | Profile redirects when unauthenticated | App running, no session | `GET /profile` → HTTP 302 to `/login` |
| TC-03 | CSRF hidden field is first child of the form | Repo checkout | `awk '/<form id="change-password-form"/{f=1;next} f&&/<input/{print;exit}' frontend/templates/profile.html` shows the `csrf_token` input |
| TC-04 | Account info escaped | App running, username = `<script>x</script>` | `GET /profile` source contains `&lt;script&gt;`, not raw `<script>` |
| TC-05 | Successful password change | Logged-in session, correct current pw + valid token | `POST /profile/password` → HTTP 200, `{"success":true,...}`; new pw logs in |
| TC-06 | Wrong current password | Logged-in session, wrong current pw + valid token | HTTP 401, `{"error":"Current password is incorrect"}`; old pw still logs in |
| TC-07 | Empty new password | Logged-in session, `new_password=` + valid token | HTTP 400, "required" error; hash unchanged |
| TC-08 | CSRF enforced | Logged-in session, no/invalid `csrf_token` | `POST /profile/password` → HTTP 403 |
| TC-09 | Rate limit enforced | App running | The 6th `POST /profile/password` from one IP in 60 s → HTTP 429 |
| TC-10 | Parameterized SQL present | Repo checkout | `grep -n 'UPDATE users SET password = ? WHERE id = ?' backend/app/services/auth_service.py` matches; `grep -n 'SELECT \* FROM users WHERE id = ?' backend/app/services/auth_service.py` matches |
| TC-11 | Bcrypt used | Repo checkout | `change_password` body references `hash_password(` and `verify_password(`; `core/security.py` diff empty |
| TC-12 | No schema change | Repo checkout | `git diff --stat -- backend/app/db/session.py` empty |
| TC-13 | No main.py change | Repo checkout | `git diff --stat -- backend/app/main.py` empty |
| TC-14 | signup/login unchanged | Repo checkout | `change_password` is the only added function; `signup`/`login` bodies byte-for-byte unchanged |
| TC-15 | Dashboard profile link | Repo checkout | `grep -c 'href="/profile"' frontend/templates/dashboard.html` → 1 |
| TC-16 | Theme toggle present | Repo checkout | `grep -c 'id="theme-toggle"' frontend/templates/profile.html` → 1 |
| TC-17 | No new dependency | Repo checkout | `git diff --stat -- pyproject.toml backend/pyproject.toml uv.lock` empty |
| TC-18 | login/signup templates untouched | Repo checkout | `git diff --stat -- frontend/templates/login.html frontend/templates/signup.html` empty |
| TC-19 | VULN-6 still closed | App running | `GET /download/db` → 404 |
| TC-20 | VULN-4 still closed | Repo checkout | `grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py` matches; main.py diff empty |
| TC-21 | App boots | Fresh checkout | `uv run backend/app/main.py` starts with no traceback |
| TC-22 | README updated | Repo checkout | `grep -n 'User Profile Page' README.md` shows a Done (v1.0.2) row + endpoints in API table |
| TC-23 | CLAUDE.md updated | Repo checkout | `grep -n 'User Profile Page' CLAUDE.md` shows the new subsection + rule + hierarchy entry |

---

## 10. Verification Steps

Run from the repository root. Start fresh so the test user has a known password.

### 10.1 Boot and Register a Test User

```bash
rm -f vulnerable_app.db jar.txt
uv run backend/app/main.py   # in one terminal
# in another terminal:
TOKEN=$(curl -s -c jar.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'signup=%{http_code}\n' -b jar.txt -c jar.txt -X POST http://localhost:3001/signup \
  --data-urlencode 'username=alice' --data-urlencode 'email=alice@test.com' \
  --data-urlencode 'password=oldpass1' --data-urlencode "csrf_token=$TOKEN"
```

Expected: `signup=302`.

### 10.2 Unauthenticated Profile Redirects (AC-02, TC-02)

```bash
curl -s -o /dev/null -w 'profile_noauth=%{http_code}\n' http://localhost:3001/profile
```

Expected: `profile_noauth=302`.

### 10.3 Log In, Then View Profile (AC-01, AC-03, TC-01, TC-03)

```bash
TOKEN=$(curl -s -b jar.txt -c jar.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'login=%{http_code}\n' -b jar.txt -c jar.txt -X POST http://localhost:3001/login \
  --data-urlencode 'username=alice' --data-urlencode 'password=oldpass1' --data-urlencode "csrf_token=$TOKEN"
curl -s -b jar.txt http://localhost:3001/profile | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"'
curl -s -b jar.txt http://localhost:3001/profile | grep -o 'alice@test.com'
```

Expected: `login=200`; one csrf_token line; the email appears in the page.

### 10.4 Wrong Current Password Rejected (AC-06, TC-06)

```bash
PTOKEN=$(curl -s -b jar.txt http://localhost:3001/profile | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o body -w 'wrongcur=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/profile/password \
  --data-urlencode 'current_password=NOTold' --data-urlencode 'new_password=newpass2' --data-urlencode "csrf_token=$PTOKEN"
cat body
```

Expected: `wrongcur=401`; body `{"error":"Current password is incorrect"}`.

### 10.5 Empty New Password Rejected (AC-07, TC-07)

```bash
PTOKEN=$(curl -s -b jar.txt http://localhost:3001/profile | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'emptynew=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/profile/password \
  --data-urlencode 'current_password=oldpass1' --data-urlencode 'new_password=' --data-urlencode "csrf_token=$PTOKEN"
```

Expected: `emptynew=400`.

### 10.6 CSRF Enforced on the New POST (AC-08, TC-08)

```bash
curl -s -o /dev/null -w 'nocsrf=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/profile/password \
  --data-urlencode 'current_password=oldpass1' --data-urlencode 'new_password=newpass2'
```

Expected: `nocsrf=403`.

### 10.7 Successful Password Change, Then Re-Login (AC-05, TC-05)

```bash
PTOKEN=$(curl -s -b jar.txt http://localhost:3001/profile | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o body -w 'change=%{http_code}\n' -b jar.txt -X POST http://localhost:3001/profile/password \
  --data-urlencode 'current_password=oldpass1' --data-urlencode 'new_password=newpass2' --data-urlencode "csrf_token=$PTOKEN"
cat body
# now log in fresh with the new password
rm -f jar2.txt
LTOKEN=$(curl -s -c jar2.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -w 'relogin=%{http_code}\n' -b jar2.txt -c jar2.txt -X POST http://localhost:3001/login \
  --data-urlencode 'username=alice' --data-urlencode 'password=newpass2' --data-urlencode "csrf_token=$LTOKEN"
```

Expected: `change=200`, body `{"success":true,"message":"Password updated successfully"}`, `relogin=200`.

### 10.8 Stored XSS Posture on the Profile Card (AC-04, TC-04)

```bash
# register a user whose username contains markup, log in, view profile
rm -f jarx.txt
XT=$(curl -s -c jarx.txt http://localhost:3001/signup | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -b jarx.txt -c jarx.txt -X POST http://localhost:3001/signup \
  --data-urlencode 'username=<script>x</script>' --data-urlencode 'email=x@x.com' \
  --data-urlencode 'password=p1' --data-urlencode "csrf_token=$XT"
XT=$(curl -s -b jarx.txt -c jarx.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -o /dev/null -b jarx.txt -c jarx.txt -X POST http://localhost:3001/login \
  --data-urlencode 'username=<script>x</script>' --data-urlencode 'password=p1' --data-urlencode "csrf_token=$XT"
curl -s -b jarx.txt http://localhost:3001/profile | grep -o '&lt;script&gt;'
```

Expected: `&lt;script&gt;` is present (escaped); raw `<script>x</script>` is not rendered as markup.

### 10.9 Vulnerability-Preservation + File-Audit Walkthrough (AC-10–AC-19, TC-10–TC-20)

```bash
grep -n 'UPDATE users SET password = ? WHERE id = ?' backend/app/services/auth_service.py
grep -n 'SELECT \* FROM users WHERE id = ?' backend/app/services/auth_service.py
grep -n 'hash_password(\|verify_password(' backend/app/services/auth_service.py
git diff --stat -- backend/app/db/session.py backend/app/main.py backend/app/core/security.py \
  backend/app/core/csrf.py backend/app/core/rate_limit.py \
  frontend/templates/login.html frontend/templates/signup.html \
  pyproject.toml backend/pyproject.toml uv.lock
grep -c 'href="/profile"' frontend/templates/dashboard.html      # expect 1
grep -c 'id="theme-toggle"' frontend/templates/profile.html      # expect 1
curl -s -o /dev/null -w 'download_db=%{http_code}\n' http://localhost:3001/download/db   # expect 404
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
```

Expected: the grep lines match; every `git diff --stat` path is empty; the two counts are `1`; `download_db=404`; the SECRET_KEY line matches.

### 10.10 Affected-Files Audit (TC-22, TC-23)

```bash
git status --porcelain
```

Expected — exactly the declared files plus the two new spec docs:

```
?? frontend/templates/profile.html
 M backend/app/api/routes/auth.py
 M backend/app/services/auth_service.py
 M frontend/templates/dashboard.html
 M frontend/static/css/styles.css
 M README.md
 M CLAUDE.md
?? .claude/specs/user-profile-page.md
?? .claude/specs/user-profile-page-plan.md
```

No other path. In particular, no entry for `main.py`, `db/session.py`, `core/*`, `login.html`, `signup.html`, or any pyproject/lock file.
