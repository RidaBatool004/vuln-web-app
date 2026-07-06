# Implementation Plan — User Profile Page (Authenticated, Change-Password)

**Version:** 1.0.0
**Last Updated:** 2026-06-18
**Target Release Tag:** v1.0.2
**Parent Spec:** [user-profile-page.md](./user-profile-page.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)

---

## 0. Plan Overview

This plan implements the feature specified in [user-profile-page.md](./user-profile-page.md): the first authenticated account-settings page. A logged-in user visits `/profile`, sees their (escaped) `username` and `email`, and can change their password through a CSRF-protected, rate-limited, bcrypt-backed form. The work is split into **seven phases** so the change is small, individually verifiable, and easy to revert.

The feature reuses every existing primitive and introduces **no new dependency, no new middleware, and no database-schema change**:

- New routes live in the existing `auth.py`; the router auto-discovers them, so `main.py` is untouched.
- The change-password logic is a new `change_password()` in the existing `auth_service.py`, using a **parameterized** `SELECT` + `UPDATE` (VULN-1) and **bcrypt** via the existing `core/security.py` helpers (VULN-5).
- The form carries the existing per-session **CSRF** token (VULN-8); the existing middleware validates it on POST and the existing rate-limiter throttles it (VULN-7). `SECRET_KEY` sourcing is untouched (VULN-4).
- Displayed `username`/`email` are HTML-escaped on output (VULN-2 posture).

**Two implementation realities, baked into this plan:**

1. **The fetch body MUST be `URLSearchParams`, not raw `FormData`.** `CSRFMiddleware` only parses `application/x-www-form-urlencoded` bodies; raw `new FormData(form)` sends `multipart/form-data`, which CSRF rejects with 403. `login.html` already solves this by wrapping the body in `new URLSearchParams(new FormData(form))`; the profile form copies that exactly.
2. **No schema change.** Change-password only `UPDATE`s the existing `password` column; the view only reads existing columns. `db/session.py` stays byte-for-byte. "Member-since" is deferred precisely because it would require the first `created_at` column.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Add `change_password()` to the service layer | `backend/app/services/auth_service.py` | Parameterized SELECT + bcrypt verify + parameterized UPDATE; JSON responses |
| 2 | Add `GET /profile` + `POST /profile/password` handlers | `backend/app/api/routes/auth.py` | Auth-gated render with CSRF/username/email splice; thin POST forwarder |
| 3 | Create the profile template | `frontend/templates/profile.html` | Account-info card, change-password form (CSRF hidden field first), theme toggle, inline fetch script |
| 4 | Add a Profile nav link to the dashboard | `frontend/templates/dashboard.html` | One `<a href="/profile">` in the hero-right block |
| 5 | Append profile-page CSS | `frontend/static/css/styles.css` | Card + field + message rules using existing `var(--...)` theme properties |
| 6 | Update docs | `README.md`, `CLAUDE.md` | Feature table, API table, integration subsection, rule, spec hierarchy |
| 7 | End-to-end verification + vulnerability-preservation audit | None (read-only) | Walk every Verification Step in spec §10 |

### Files Modified / Created (Authored)

Exactly the seven files declared in spec §3:

- **New** — `frontend/templates/profile.html`
- **Modified** — `backend/app/api/routes/auth.py`
- **Modified** — `backend/app/services/auth_service.py`
- **Modified** — `frontend/templates/dashboard.html`
- **Modified** — `frontend/static/css/styles.css`
- **Modified** — `README.md`
- **Modified** — `CLAUDE.md`

No dependency change, so no `pyproject.toml` / `uv.lock` edit (and no `uv sync`).

### Files That MUST NOT Be Modified

- `backend/app/main.py` — middleware wiring / `SECRET_KEY` / port (VULN-4 / VULN-7 / VULN-8). Routes are auto-included via the existing `include_router(router)`.
- `backend/app/db/session.py` — **no schema change**. The feature uses only `(id, username, email, password)`.
- `backend/app/core/security.py` — bcrypt (VULN-5).
- `backend/app/core/csrf.py` — CSRF middleware (VULN-8).
- `backend/app/core/rate_limit.py` — rate-limit middleware (VULN-7).
- `frontend/templates/login.html`, `frontend/templates/signup.html`.
- Any image under `frontend/static/images/`.
- `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, every prior spec/plan.
- `pyproject.toml`, `backend/pyproject.toml`, `uv.lock`.

### Vulnerability-Preservation Checklist (Carry Through Every Phase)

After every phase, re-confirm:

1. **SQL Injection (VULN-1).** New `change_password()` uses `SELECT * FROM users WHERE id = ?` and `UPDATE users SET password = ? WHERE id = ?`; `signup()`/`login()`/`/search` keep their `?` queries.
2. **Stored XSS (VULN-2).** `welcome_page` keeps escaping `{{username}}`; the profile page escapes `{{username}}` and `{{email}}`.
3. **Reflected XSS (VULN-3).** `/search` escapes are untouched.
4. **Session Hijacking (VULN-4).** `main.py` `SECRET_KEY` sourcing untouched (`main.py` not modified).
5. **Weak Password (VULN-5).** `core/security.py` untouched; `change_password()` uses `hash_password`/`verify_password`.
6. **Exposed DB (VULN-6).** No `/download/db` route added.
7. **No Rate Limiting (VULN-7).** `RateLimitMiddleware` registration untouched; the new POST is throttled automatically.
8. **CSRF (VULN-8).** The new form carries the hidden token; `GET /profile` issues it; `CSRFMiddleware` validates it. `core/csrf.py` untouched.

---

## Phase 1 — Add `change_password()` to `backend/app/services/auth_service.py`

### 1.1 Goal

Add a single new function `change_password(request, current_password, new_password)` after the existing `login()`. It reads `user_id` from the session, validates input, verifies the current password with bcrypt, hashes the new password with bcrypt, and runs a parameterized `UPDATE`. It returns JSON for every outcome, mirroring `login()`.

### 1.2 Imports

One new import is required: `import re` (stdlib) for the strength-policy regexes in `password_meets_policy()`. The file already imports `sqlite3`, `Request`, `JSONResponse` (alongside `RedirectResponse`, `HTMLResponse`), `get_db`, `hash_password`, and `verify_password` — every other symbol `change_password()` needs.

### 1.3 Function to Append (after `login()`)

A module-level helper `password_meets_policy()` is added near the top of the file (after the imports) and called from `change_password()`:

```python
def password_meets_policy(password: str) -> bool:
    """Return True when `password` satisfies the same five criteria the
    signup page's strength meter checks: length >= 8 plus at least one
    lowercase letter, one uppercase letter, one digit, and one special
    (non-alphanumeric) character.

    On signup the meter is advisory only (the server accepts any non-empty
    password). The change-password flow ENFORCES this policy server-side so
    a weak new password is rejected regardless of the client.
    """
    return (
        len(password) >= 8
        and re.search(r"[a-z]", password) is not None
        and re.search(r"[A-Z]", password) is not None
        and re.search(r"[0-9]", password) is not None
        and re.search(r"[^A-Za-z0-9]", password) is not None
    )
```

```python
def change_password(request: Request, current_password: str, new_password: str):
    """Change the logged-in user's password.

    Returns JSON for every outcome (mirrors login()) so the profile page's
    fetch() handler can render feedback inline without a reload:
    - 200 {"success": True, "message": "Password updated successfully"}
    - 401 {"error": "Not authenticated"}              (no session user_id / row gone)
    - 400 {"error": "Current and new password are required"}  (empty input)
    - 401 {"error": "Current password is incorrect"}  (bad/legacy current pw)
    - 400 {"error": "Could not update password"}       (unexpected DB error)

    Security posture (all preserved from the closed vulnerabilities):
    - VULN-1: the SELECT and UPDATE are parameterized -- never concatenate.
    - VULN-5: the current password is checked with verify_password() (bcrypt,
      fails closed on legacy MD5) and the new password is hashed with
      hash_password() (bcrypt) before storage.
    The CSRF token and per-IP rate limit are enforced by middleware before
    this function ever runs.
    """
    # Auth gate. The route also renders /profile only for sessions, and the
    # CSRF middleware already blocks a session-less POST at 403 -- this is
    # defense in depth so the service is safe to call directly.
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    if not current_password or not new_password:
        return JSONResponse(
            content={"error": "Current and new password are required"},
            status_code=400,
        )

    # Enforce the same strength policy the signup page advertises (length >= 8
    # plus lower/upper/digit/special). Unlike signup -- where the meter is
    # advisory and the server accepts anything -- this flow rejects a weak new
    # password server-side. The profile form runs the identical check in JS.
    if not password_meets_policy(new_password):
        return JSONResponse(
            content={
                "error": (
                    "New password must be at least 8 characters and include an "
                    "uppercase letter, a lowercase letter, a digit, and a special "
                    "character"
                )
            },
            status_code=400,
        )

    # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
    select_query = "SELECT * FROM users WHERE id = ?"
    # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
    update_query = "UPDATE users SET password = ? WHERE id = ?"

    conn = get_db()
    try:
        cursor = conn.execute(select_query, [user_id])
        user = cursor.fetchone()
        if not user:
            # Session references a row that no longer exists (no delete flow
            # exists, so this is defensive only).
            return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

        # FIXED: Weak Password Storage closed -- verify the CURRENT password
        # with bcrypt in Python. Returns False (never raises) on a legacy MD5
        # row, so such accounts cannot change their password here; they must
        # re-register, exactly like the login flow.
        if not verify_password(current_password, user["password"]):
            return JSONResponse(
                content={"error": "Current password is incorrect"},
                status_code=401,
            )

        # FIXED: Weak Password Storage closed -- hash the NEW password with
        # bcrypt before it touches the DB. The plaintext never persists.
        hashed = hash_password(new_password)
        conn.execute(update_query, [hashed, user_id])
        conn.commit()
        return JSONResponse(
            content={"success": True, "message": "Password updated successfully"}
        )
    except Exception:
        # Generic error -- never reflect the underlying DB exception text.
        return JSONResponse(
            content={"error": "Could not update password"},
            status_code=400,
        )
    finally:
        conn.close()
```

### 1.4 Line-by-Line Justification

| Block | Decision | Spec ref |
|---|---|---|
| `import re` added | Needed by `password_meets_policy()`; every other symbol (`Request`, `JSONResponse`, `get_db`, `hash_password`, `verify_password`) is already imported | FR-13 |
| `user_id = request.session.get("user_id")` → 401 if falsy | Auth gate at the service layer; defense-in-depth behind CSRF + the route's own gate | FR-06.1, NFR-02, EC-01 |
| `if not current_password or not new_password` → 400 | Non-empty validation for both fields | FR-06.2 |
| `if not password_meets_policy(new_password)` → 400 | Enforce the five-criteria signup strength policy server-side on the new password | FR-06.2a, §2.4 |
| `SELECT * FROM users WHERE id = ?` | Parameterized fetch by primary key — VULN-1 stays closed | FR-11, AC-10 |
| `if not user: 401` | Defensive — session points at a missing row | FR-06.4, EC-07 |
| `verify_password(current_password, user["password"])` | bcrypt check in Python; fails closed on legacy MD5 | FR-06.5, FR-11, EC-06 |
| `hash_password(new_password)` | bcrypt hash for the new password — VULN-5 stays closed | FR-06.6, FR-11, AC-11 |
| `UPDATE users SET password = ? WHERE id = ?` | Parameterized update — VULN-1 stays closed | FR-11, AC-10 |
| `except Exception: generic 400` | No DB-error leakage | FR-06.9, NFR-06 |
| `get_db()` + `try/finally: conn.close()` | Matches the connection-handling pattern in `signup`/`login` | FR-06.10, NFR-10 |

### 1.5 What NOT to Change in Phase 1

- **DO NOT** modify `signup()` or `login()` — byte-for-byte unchanged (spec §FR-13, AC-14).
- **DO NOT** concatenate any value into a SQL string. Both queries are parameterized (VULN-1).
- **DO NOT** introduce a new hashing primitive or touch `core/security.py` (VULN-5).
- **DO** enforce the five-criteria strength policy on `new_password` via `password_meets_policy()` (spec §2.4, FR-06.2a). Keep the JS check in `profile.html` in sync with this server-side gate. Do **not** weaken `signup()` to match — signup stays advisory.
- **DO NOT** clear the session or log the user out on success (out of scope — spec §2.4).
- **DO NOT** return an HTML response — `change_password()` returns JSON for every path (FR-07).
- **DO NOT** reflect the underlying DB exception text to the client (NFR-06).

### 1.6 Phase 1 Verification (Pre-Server)

```bash
grep -n 'def change_password' backend/app/services/auth_service.py
grep -n 'SELECT \* FROM users WHERE id = ?' backend/app/services/auth_service.py
grep -n 'UPDATE users SET password = ? WHERE id = ?' backend/app/services/auth_service.py
grep -n 'hash_password(\|verify_password(' backend/app/services/auth_service.py
# strength-policy helper + gate present
grep -n 'def password_meets_policy\|password_meets_policy(new_password)' backend/app/services/auth_service.py
# signup/login still present and unchanged in shape
grep -n 'def signup\|def login' backend/app/services/auth_service.py
# module imports cleanly + policy helper behaves
cd backend && uv run python -c "from app.services import auth_service as a; print(hasattr(a,'change_password')); print(a.password_meets_policy('weakpass'), a.password_meets_policy('NewPass2!'))" && cd ..
```

Expected: the function and both parameterized queries match; the bcrypt helpers and `password_meets_policy` are referenced; `signup`/`login` still present; the import check prints `True` then `False True`.

---

## Phase 2 — Add `GET /profile` and `POST /profile/password` to `backend/app/api/routes/auth.py`

### 2.1 Goal

Add two handlers after `welcome_page`: an auth-gated `GET /profile` that renders the template with the CSRF token + escaped username/email spliced in, and a thin `POST /profile/password` that forwards to `auth_service.change_password()`. No new import is required (`html`, `os`, `Request`, `Form`, `HTMLResponse`, `RedirectResponse`, `get_or_create_csrf_token`, `auth_service` are all already imported).

### 2.2 Handlers to Add (after `welcome_page`, before `logout`)

```python
@router.get("/profile")
async def profile_page(request: Request):
    """Render the authenticated profile page.

    Same auth gate as /welcome: no user_id in the session -> bounce to
    /login. Splices the per-session CSRF token (for the change-password
    form) plus the HTML-escaped username and email read from the session.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    username = request.session.get("username", "")
    email = request.session.get("email", "")

    with open(os.path.join(TEMPLATE_DIR, "profile.html"), "r") as f:
        page = f.read()

    # FIXED: CSRF closed -- issue/splice the per-session token for the form.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))

    # FIXED: Stored XSS closed -- escape every user-controlled value before
    # splicing (output encoding, same posture as the dashboard username).
    page = page.replace("{{username}}", html.escape(username, quote=True))
    page = page.replace("{{email}}", html.escape(email, quote=True))

    return HTMLResponse(content=page)


@router.post("/profile/password")
async def profile_password_post(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
):
    """Handle a change-password submission.

    Thin wrapper over auth_service.change_password() -- same shape as
    login_post(). The Request is forwarded so the service can read
    request.session["user_id"]. The CSRF token and per-IP rate limit are
    enforced by middleware before this handler runs; FastAPI's Form()
    ignores the extra csrf_token field.
    """
    return auth_service.change_password(request, current_password, new_password)
```

### 2.3 Line-by-Line Justification

| Block | Decision | Spec ref |
|---|---|---|
| `user_id = request.session.get("user_id")` → 302 `/login` | Same auth gate as `welcome_page` | FR-01, AC-02 |
| Load `profile.html` per request | No template engine / no caching — matches the app pattern | FR-02 |
| `get_or_create_csrf_token(request)` + splice | Issues the per-session token into the form's hidden field | FR-03, AC-03 |
| `html.escape(username/email, quote=True)` splices | Output encoding — VULN-2 posture | FR-02, NFR-07, AC-04 |
| `profile_password_post` takes `request` + two `Form("")` | `Form("")` defaults mean missing fields become empty strings (service returns 400), not 422 — matches `signup_post`/`login_post` | FR-05 |
| One-line forward to `auth_service.change_password` | Thin handler, business logic in the service | FR-05, NFR-10 |

### 2.4 Placement

Insert the two handlers between `welcome_page` and `logout` so the authenticated pages are grouped. Order does not affect routing.

### 2.5 What NOT to Change in Phase 2

- **DO NOT** add any import (everything needed is already imported).
- **DO NOT** modify `index`, `signup_page`, `signup_post`, `login_page`, `login_post`, `search_user`, `welcome_page`, or `logout` — byte-for-byte unchanged.
- **DO NOT** put business logic, SQL, or hashing in the handlers (FR-05).
- **DO NOT** register the routes in `main.py` — `include_router(router)` already covers them (spec §AC-13).
- **DO NOT** splice `{{username}}`/`{{email}}` without `html.escape` (VULN-2).

### 2.6 Phase 2 Verification (Pre-Server)

```bash
grep -n 'async def profile_page' backend/app/api/routes/auth.py
grep -n 'async def profile_password_post' backend/app/api/routes/auth.py
grep -n '@router.get("/profile")' backend/app/api/routes/auth.py
grep -n '@router.post("/profile/password")' backend/app/api/routes/auth.py
grep -n 'page.replace("{{email}}"' backend/app/api/routes/auth.py
# no new import line sneaked in (the import block is unchanged)
grep -n 'from app.core.csrf import get_or_create_csrf_token' backend/app/api/routes/auth.py
cd backend && uv run python -c "from app.main import app; print('boot ok')" && cd ..
```

Expected: all greps match; the boot smoke test prints `boot ok`.

---

## Phase 3 — Create `frontend/templates/profile.html`

### 3.1 Goal

Create the profile template: shared header with the frontend-only theme toggle, a hero banner with Dashboard + Logout links, an Account-Information card showing `{{username}}`/`{{email}}`, and a Change-Password card with a CSRF-protected fetch form. Reuse the existing class names (`header`, `hero-banner`, `dashboard-content`, `form-group`, `form-input`, `form-label`, `btn btn-primary`) so styling is mostly inherited.

### 3.2 File Contents

Create the file with exactly this content:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
        (function () {
            try {
                var saved = localStorage.getItem('theme');
                if (saved !== 'light' && saved !== 'dark') {
                    saved = null;
                }
                var theme = saved;
                if (!theme && window.matchMedia) {
                    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                }
                if (!theme) {
                    theme = 'light';
                }
                document.documentElement.setAttribute('data-theme', theme);
            } catch (e) {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        })();
    </script>
    <title>Profile - Security Vulnerability Lab</title>
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body class="dashboard-body">
    <!-- Shared Header -->
    <header class="header">
        <div class="header-title">Security Vulnerability Lab</div>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to dark mode">
            <span class="theme-toggle-icon" aria-hidden="true">🌙</span>
        </button>
        <div class="header-logos">
            <img src="/static/images/PUCIT_Logo.png" alt="PUCIT" class="header-logo">
            <img src="/static/images/excaliat-logo.png" alt="Excaliat" class="header-logo">
            <img src="/static/images/blue-logo-scl2.png" alt="FCCU" class="header-logo">
        </div>
    </header>

    <!-- Hero Banner -->
    <section class="hero-banner">
        <div class="hero-left">
            <h1 class="hero-title">My Profile</h1>
            <p class="hero-subtitle">View your account and manage your password</p>
        </div>
        <div class="hero-right">
            <a href="/welcome" class="btn btn-logout">Dashboard</a>
            <a href="/logout" class="btn btn-logout">Logout</a>
        </div>
    </section>

    <!-- Content Area -->
    <main class="dashboard-content profile-content">
        <!-- Account Information -->
        <div class="profile-card">
            <h2 class="section-title">Account Information</h2>
            <div class="profile-field">
                <span class="profile-field-label">Username</span>
                <span class="profile-field-value">{{username}}</span>
            </div>
            <div class="profile-field">
                <span class="profile-field-label">Email</span>
                <span class="profile-field-value">{{email}}</span>
            </div>
        </div>

        <!-- Change Password -->
        <div class="profile-card">
            <h2 class="section-title">Change Password</h2>
            <form id="change-password-form">
                <input type="hidden" name="csrf_token" value="{{csrf_token}}">
                <div class="form-group">
                    <label class="form-label" for="current_password">Current Password</label>
                    <input type="password" id="current_password" name="current_password" class="form-input" placeholder="Enter your current password" required>
                </div>
                <div class="form-group">
                    <label class="form-label" for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" class="form-input" placeholder="Enter a new password" required>
                </div>
                <div class="form-group">
                    <label class="form-label" for="confirm_new_password">Confirm New Password</label>
                    <input type="password" id="confirm_new_password" class="form-input" placeholder="Re-enter the new password" required>
                </div>
                <div id="profile-message" class="profile-message" role="status" aria-live="polite" style="display: none;"></div>
                <button type="submit" class="btn btn-primary">Update Password</button>
            </form>
        </div>
    </main>

    <script>
        const form = document.getElementById('change-password-form');
        const msg = document.getElementById('profile-message');

        function show(text, ok) {
            msg.textContent = text;
            msg.classList.remove('is-error', 'is-success');
            msg.classList.add(ok ? 'is-success' : 'is-error');
            msg.style.display = 'block';
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newPw = document.getElementById('new_password').value;
            const confirmPw = document.getElementById('confirm_new_password').value;

            if (newPw !== confirmPw) {
                show('New passwords do not match', false);
                return;
            }

            // Send as application/x-www-form-urlencoded (NOT multipart). The
            // CSRF middleware only parses urlencoded bodies, so wrapping the
            // FormData in URLSearchParams makes the browser set the matching
            // Content-Type and the csrf_token field is validated correctly.
            const body = new URLSearchParams(new FormData(form));
            try {
                const response = await fetch('/profile/password', { method: 'POST', body: body });
                const data = await response.json();
                if (data.success) {
                    show(data.message || 'Password updated successfully', true);
                    form.reset();
                } else {
                    show(data.error || 'Could not update password', false);
                }
            } catch (err) {
                show('Something went wrong. Please try again.', false);
            }
        });
    </script>

    <script>
        (function () {
            var toggle = document.getElementById('theme-toggle');
            if (!toggle) return;

            function reflect(theme) {
                var nextAction = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
                var icon = theme === 'dark' ? '☀' : '🌙';
                toggle.setAttribute('aria-label', nextAction);
                var iconEl = toggle.querySelector('.theme-toggle-icon');
                if (iconEl) iconEl.textContent = icon;
            }

            reflect(document.documentElement.getAttribute('data-theme') || 'light');

            toggle.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                try {
                    localStorage.setItem('theme', next);
                } catch (e) {
                    /* persistence unavailable — in-page state still flips */
                }
                reflect(next);
            });
        })();
    </script>
</body>
</html>
```

### 3.3 Line-by-Line Justification

| Block | Decision | Spec ref |
|---|---|---|
| Pre-paint theme `<script>` in `<head>` | Byte-identical to the other templates — avoids FOUC; reads only `localStorage`/`prefers-color-scheme` | FR-09, NFR-08 |
| `<body class="dashboard-body">` + `hero-banner` + `dashboard-content` | Reuses the post-login layout (this is an authenticated page like the dashboard), not the split `auth-container` | NFR-10 |
| Hero-right `Dashboard` + `Logout` links | Navigation back to `/welcome` and `/logout` | FR-04 (nav affordance) |
| `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` as **first** child of the form | Synchronizer-token field; first-child placement matches login/signup so `FormData` includes it | FR-04, AC-03 |
| `current_password`, `new_password` carry `name=`; `confirm_new_password` has **no `name`** | Confirm is client-side only and never transmitted — same convention as signup's `confirm_password` | FR-04 |
| `#profile-message` with `role="status"` `aria-live="polite"` | Inline success/error feedback, announced politely | FR-04, FR-08 |
| `new URLSearchParams(new FormData(form))` in the fetch | Sends urlencoded so CSRF accepts it — copies the login.html fix | FR-08, plan §0.1 |
| `new_password === confirm_new_password` check before fetch | Client-side match guard, mirrors signup; shows inline error, no request sent | FR-08, SP-04 |
| Five-criteria strength check before fetch | Mirrors the signup meter's rules (≥8, lower, upper, digit, special); shows which requirements are unmet inline, no request sent. The meter **widget** is not rendered — only the rules. Server re-checks via `password_meets_policy()` | FR-06.2a, §2.4 |
| `form.reset()` on success | Clears the password fields after a successful change | FR-08 |
| Theme-toggle `<script>` at the end | Byte-identical to the other pages | FR-09 |

### 3.4 What NOT to Change in Phase 3

- **DO NOT** put any field before the hidden `csrf_token` input (it must be the form's first child).
- **DO NOT** give `confirm_new_password` a `name` attribute (it must not be sent to the server).
- **DO NOT** submit raw `new FormData(form)` — it would send multipart and CSRF would 403. Wrap in `URLSearchParams`.
- **DO NOT** write theme state to the server, the session, or a cookie — only `localStorage` (frontend-only, VULN/CLAUDE.md rule).
- **DO** validate `new_password` against the five-criteria policy (≥8, lower, upper, digit, special) before the fetch, mirroring the server-side `password_meets_policy()` gate; show unmet requirements inline. **DO NOT** render the strength-meter widget/checklist UI (only the rules apply) or add a reveal toggle or any field beyond the three specified (scope — spec §2.4).
- **DO NOT** add `fetch`/`XMLHttpRequest` calls other than the single `/profile/password` POST.

### 3.5 Phase 3 Verification (Pre-Server)

```bash
# CSRF hidden input is the first child of the form
awk '/<form id="change-password-form"/{f=1; next} f && /<input/{print; exit}' frontend/templates/profile.html
# confirm field has no name attribute
grep -n 'id="confirm_new_password"' frontend/templates/profile.html
grep -n 'name="confirm_new_password"' frontend/templates/profile.html || echo '(confirm field has no name — preserved)'
# urlencoded body, not raw FormData
grep -n 'new URLSearchParams(new FormData(form))' frontend/templates/profile.html
# theme toggle present
grep -c 'id="theme-toggle"' frontend/templates/profile.html   # expect 1
# placeholders present
grep -c '{{username}}\|{{email}}\|{{csrf_token}}' frontend/templates/profile.html
```

Expected: the awk line prints the csrf_token input; the no-name grep prints its fallback; the URLSearchParams grep matches; the toggle count is `1`; the placeholders are present.

---

## Phase 4 — Add a Profile Link to `frontend/templates/dashboard.html`

### 4.1 Goal

Add a single "Profile" link to the dashboard's hero-right block, next to the existing Logout button, so logged-in users can reach `/profile`.

### 4.2 Edit

**Before** (hero-right block, ~L49–L52):

```html
        <div class="hero-right">
            <span class="hero-username">Logged in as <strong>{{username}}</strong></span>
            <a href="/logout" class="btn btn-logout">Logout</a>
        </div>
```

**After**:

```html
        <div class="hero-right">
            <span class="hero-username">Logged in as <strong>{{username}}</strong></span>
            <a href="/profile" class="btn btn-logout">Profile</a>
            <a href="/logout" class="btn btn-logout">Logout</a>
        </div>
```

One line added: the `Profile` anchor, reusing the existing `btn btn-logout` style for visual consistency with the adjacent Logout button.

### 4.3 What NOT to Change in Phase 4

- **DO NOT** alter the `{{username}}` span (VULN-2 escape is applied server-side in `welcome_page`; the template token stays).
- **DO NOT** touch the theme script, the vuln-card grid, the mission card, or the process-steps section.
- **DO NOT** change the Logout link.

### 4.4 Phase 4 Verification

```bash
grep -c 'href="/profile"' frontend/templates/dashboard.html   # expect 1
grep -c 'href="/logout"' frontend/templates/dashboard.html    # still 1
```

Expected: `1` and `1`.

---

## Phase 5 — Append Profile-Page CSS to `frontend/static/css/styles.css`

### 5.1 Goal

Append rules for the new classes (`.profile-content`, `.profile-card`, `.profile-field`, `.profile-field-label`, `.profile-field-value`, `.profile-message` + `.is-error`/`.is-success`) using the existing CSS-custom-property pattern so light and dark themes are handled automatically. Reuse existing variables; do **not** redefine the palette.

### 5.2 Approach

1. Open `styles.css` and identify the existing custom-property names used by the dashboard cards (e.g. card background, border, text, and the existing error-message colors). Reuse those variables in the new rules rather than introducing hex literals.
2. Append a clearly delimited block at the **end** of the file:

```css
/* ===================== User Profile Page ===================== */
.profile-content {
    display: flex;
    flex-direction: column;
    gap: 24px;
}

.profile-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 24px;
    box-shadow: var(--card-shadow);
}

.profile-field {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 0;
    border-bottom: 1px solid var(--card-border);
}

.profile-field:last-child {
    border-bottom: none;
}

.profile-field-label {
    font-weight: 600;
    color: var(--text-muted);
}

.profile-field-value {
    color: var(--text-primary);
    word-break: break-all;
}

.profile-message {
    border-radius: 8px;
    padding: 12px;
    margin-bottom: 16px;
    font-size: 0.9rem;
}

.profile-message.is-error {
    background: var(--error-bg);
    border: 1px solid var(--error-border);
    color: var(--error-text);
}

.profile-message.is-success {
    background: var(--success-bg, #dcfce7);
    border: 1px solid var(--success-border, #86efac);
    color: var(--success-text, #166534);
}
```

> **Note:** the exact variable names (`--card-bg`, `--card-border`, `--card-shadow`, `--text-muted`, `--text-primary`, `--error-bg`, `--error-border`, `--error-text`) MUST be matched to whatever the file already defines. If the file uses different names, substitute the real ones. If no success-color variables exist, define `--success-bg` / `--success-border` / `--success-text` under both `:root` and `[data-theme="dark"]` (the inline fallbacks above are a safety net but the theme-aware variables are preferred). Read the existing `:root` and `[data-theme="dark"]` blocks first and mirror their naming.

### 5.3 What NOT to Change in Phase 5

- **DO NOT** edit or remove any existing rule. Append only.
- **DO NOT** introduce a hardcoded hex palette where a theme variable already exists — reuse the variables so dark mode works for free.
- **DO NOT** add styles for `type="hidden"` inputs (unrendered by spec).
- **DO NOT** touch the password-strength-meter rules or any auth-page rule.

### 5.4 Phase 5 Verification

```bash
grep -n '.profile-card' frontend/static/css/styles.css
grep -n '.profile-message.is-success' frontend/static/css/styles.css
# confirm theme variables are reused (no stray hex in the new card rule body, aside from the documented success fallback)
grep -n 'var(--' frontend/static/css/styles.css | tail -20
```

Expected: the new selectors match; the new rules reference `var(--...)`.

---

## Phase 6 — Update `README.md` and `CLAUDE.md`

### 6.1 Goal

Document the feature: move it to "Done (v1.0.2)" in the README Feature Enhancements table, add the two endpoints to the README API table, and update CLAUDE.md (integration subsection, important rule, spec hierarchy).

### 6.2 Edit A — README Feature Enhancements Table

Change the User Profile Page row from `Planned` to `Done`, and trim the description to the shipped slice:

**Before:**

```
| 2 | User Profile Page | A page where authenticated users can view and save their personal information and account settings. This also moves the dark-mode preference from per-browser (`localStorage`) to **per-user** ... | Planned |
```

**After:**

```
| 2 | User Profile Page | Authenticated `/profile` page: view your username and email (read-only) and change your password (current-password check + bcrypt). CSRF-protected, rate-limited, no schema change. Dark-mode stays per-browser (`localStorage`). | **Done (v1.0.2)** |
```

### 6.3 Edit B — README API Endpoints Table

Add two rows to the API Endpoints table:

```
| GET | `/profile` | Authenticated profile page (view info + change password form) | Yes |
| POST | `/profile/password` | Change the logged-in user's password (returns JSON) | Yes |
```

### 6.4 Edit C — CLAUDE.md "Frontend-Backend Integration" Subsection

Add a bullet under the Frontend-Backend Integration section:

```
- **Profile / Change Password**: `GET /profile` (session-gated, like `/welcome`) renders `profile.html` with the CSRF token and HTML-escaped `{{username}}`/`{{email}}` spliced in. `POST /profile/password` is a thin handler over `auth_service.change_password()`, which verifies the current password with bcrypt and runs a parameterized `UPDATE`. The form submits via `fetch()` with the body wrapped in `URLSearchParams` (so the CSRF middleware's urlencoded parser accepts it), returning JSON for inline feedback. No schema change; the theme toggle stays frontend-only.
```

### 6.5 Edit D — CLAUDE.md "Important Rules" Entry

Add:

```
- The User Profile Page (`/profile`, `/profile/password`) is session-gated and must stay so. `change_password` in `auth_service.py` must keep its parameterized `SELECT`/`UPDATE` (VULN-1) and bcrypt verify/hash (VULN-5); the change-password form must keep its hidden `csrf_token` field (VULN-8) and submit urlencoded via `URLSearchParams`. Do not add a `created_at`/theme/profile column — the feature is intentionally schema-free, and dark mode stays frontend-only.
```

### 6.6 Edit E — CLAUDE.md Specification Hierarchy

Append:

```
12. `.claude/specs/user-profile-page.md` + `.claude/specs/user-profile-page-plan.md` — User Profile Page (v1.0.2 feature)
```

### 6.7 What NOT to Change in Phase 6

- **DO NOT** alter the Vulnerability Map or any vulnerability's status — this is a feature, no vuln changes.
- **DO NOT** edit the Bug Fixes table.
- **DO NOT** touch the password-strength-meter or dark-mode rows/subsections.

### 6.8 Phase 6 Verification

```bash
grep -n 'User Profile Page' README.md
grep -n '/profile/password' README.md
grep -n 'Profile / Change Password' CLAUDE.md
grep -n 'user-profile-page.md' CLAUDE.md
```

Expected: each grep matches.

---

## Phase 7 — End-to-End Verification + Vulnerability-Preservation Audit

Walk every Verification Step in spec §10 in order. **No edits** are made; if a step fails, return to the relevant earlier phase.

### 7.1 Boot + Register (spec §10.1)

```bash
rm -f vulnerable_app.db jar.txt
uv run backend/app/main.py   # one terminal; run the curl steps in another
```

Then run spec §10.1's signup, expecting `signup=302`.

### 7.2 Unauthenticated Redirect (spec §10.2 — AC-02, TC-02)

Expect `profile_noauth=302`.

### 7.3 Login + View Profile (spec §10.3 — AC-01, AC-03, TC-01, TC-03)

Expect `login=200`, one csrf_token line, and the email in the page.

### 7.4 Wrong Current Password (spec §10.4 — AC-06, TC-06)

Expect `wrongcur=401` and the generic error body.

### 7.5 Empty New Password (spec §10.5 — AC-07, TC-07)

Expect `emptynew=400`.

### 7.6 CSRF Enforced (spec §10.6 — AC-08, TC-08)

Expect `nocsrf=403`.

### 7.7 Successful Change + Re-Login (spec §10.7 — AC-05, TC-05)

Expect `change=200`, the success body, and `relogin=200`.

### 7.8 Stored-XSS Posture (spec §10.8 — AC-04, TC-04)

Expect `&lt;script&gt;` present, raw markup absent.

### 7.9 Preservation + File Audit (spec §10.9 — AC-10–AC-19, TC-10–TC-20)

Run the spec §10.9 block. Expect parameterized-SQL greps to match, every `git diff --stat` path to be empty (`main.py`, `db/session.py`, `core/*`, `login.html`, `signup.html`, pyproject/lock), the two counts `1`, `download_db=404`, and the SECRET_KEY line present.

### 7.10 Rate Limit on the New POST (AC-09, TC-09)

```bash
rm -f jarrl.txt
RT=$(curl -s -c jarrl.txt http://localhost:3001/login | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
# log in first so the session has user_id
curl -s -o /dev/null -b jarrl.txt -c jarrl.txt -X POST http://localhost:3001/login \
  --data-urlencode 'username=alice' --data-urlencode 'password=newpass2' --data-urlencode "csrf_token=$RT"
PT=$(curl -s -b jarrl.txt http://localhost:3001/profile | grep -Eo 'name="csrf_token" value="[A-Za-z0-9_-]{43}"' | sed -E 's/.*value="([^"]+)".*/\1/')
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "POST$i: %{http_code}\n" -b jarrl.txt -X POST http://localhost:3001/profile/password \
    --data-urlencode 'current_password=wrong' --data-urlencode 'new_password=x' --data-urlencode "csrf_token=$PT"
done
```

Expected: the first 5 return `401` (wrong current password) and the 6th returns `429` (rate-limit gate fires before the handler) — proving the new POST is throttled like every other POST.

### 7.11 Affected-Files Audit (spec §10.10 — TC-22, TC-23)

```bash
git status --porcelain
```

Expected — exactly the seven declared files plus the two new spec docs (see spec §10.10). No `main.py`, `db/session.py`, `core/*`, `login.html`, `signup.html`, or pyproject/lock entry.

### 7.12 Spec Acceptance Criteria Roll-Up

Tick every AC from spec §8:

- [ ] AC-01 Profile renders for authenticated users (7.3)
- [ ] AC-02 Profile redirects unauthenticated (7.2)
- [ ] AC-03 CSRF hidden field first child (7.3, 3.5)
- [ ] AC-04 Account info escaped (7.8)
- [ ] AC-05 Successful change → JSON success (7.7)
- [ ] AC-06 Wrong current pw → 401 (7.4)
- [ ] AC-07 Empty new pw → 400 (7.5)
- [ ] AC-08 CSRF enforced (7.6)
- [ ] AC-09 Rate limit applies (7.10)
- [ ] AC-10 Parameterized SQL (1.6, 7.9)
- [ ] AC-11 Bcrypt used (1.6, 7.9)
- [ ] AC-12 No schema change (7.9)
- [ ] AC-13 No main.py change (7.9)
- [ ] AC-14 signup/login unchanged (1.6)
- [ ] AC-15 Dashboard profile link (4.4)
- [ ] AC-16 Theme toggle frontend-only (3.5, 7.9)
- [ ] AC-17 No new dependency (7.9)
- [ ] AC-18 login/signup templates untouched (7.9)
- [ ] AC-19 Other vulnerabilities preserved (7.9)
- [ ] AC-20 README + CLAUDE.md updated (6.8)
- [ ] AC-21 App boots (7.1)

### 7.13 Stop the Server

`Ctrl+C` to stop. Plan complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Fetch sends raw `FormData` (multipart) → CSRF middleware rejects every legitimate change-password POST with 403 | High | High | Phase 3 uses `new URLSearchParams(new FormData(form))` (copies the login.html fix); spec §FR-08 + plan §0.1 call it out; Phase 7.7 exercises the legitimate path |
| Hidden `csrf_token` not the first child of the form → browser/`FormData` may omit it | Low | High | Phase 3 places it as the first child; Phase 3.5 awk check verifies it; Phase 7.6 confirms a no-token POST is 403 and 7.7 confirms a valid one succeeds |
| `confirm_new_password` accidentally given a `name` → sent to the server, ignored but messy | Low | Low | Phase 3 omits `name`; Phase 3.5 grep asserts no `name="confirm_new_password"` |
| String-concatenated SQL slips into `change_password` → re-opens VULN-1 | Low | High | Phase 1 uses parameterized `?`; Phase 1.6 + 7.9 greps assert the exact parameterized statements |
| `{{username}}`/`{{email}}` spliced without `html.escape` → re-opens VULN-2 on the profile card | Medium | High | Phase 2 escapes both with `quote=True`; spec §FR-02; Phase 7.8 verifies `&lt;script&gt;` |
| Editing `main.py` to "register" the routes → unnecessary, risks VULN-4/7/8 wiring | Low | High | Routes are auto-included; Phase 2.5 MUST-NOT; Phase 7.9 asserts `main.py` diff empty |
| Adding a `created_at`/theme/profile column → first schema change, migration headache, breaks "schema-free" goal | Medium | Medium | Spec §2.2 defers member-since; Phase 1/2 use only existing columns; Phase 7.9 asserts `db/session.py` diff empty |
| Pushing theme state to the backend (misreading the per-user-theme idea) → violates the standing dark-mode rule | Low | Medium | Decision locked to frontend-only toggle; Phase 3 writes only `localStorage`; spec §FR-09/NFR-08 |
| Modifying `signup()`/`login()` "while in here" → scope creep / regression | Low | Medium | Phase 1.5 MUST-NOT; Phase 1.6 confirms they remain; only `change_password` is added |
| Wrong-current-password message leaks whether the account exists | Very Low | Low | User is already authenticated (session-gated), so no enumeration surface; generic message used anyway (NFR-06) |
| Rate limit (5/60 s shared across all POSTs) locks a user out mid password-change after several logins | Low | Low | Documented behavior (EC-09); shared per-IP window is the existing VULN-7 design, not introduced here |

---

## Rollback Procedure

If a phase fails verification and cannot be repaired quickly:

```bash
git restore backend/app/api/routes/auth.py backend/app/services/auth_service.py \
  frontend/templates/dashboard.html frontend/static/css/styles.css README.md CLAUDE.md
rm -f frontend/templates/profile.html
```

The six modified files snap back to their pre-feature state and the new template is removed. No dependency, schema, or data migration is involved — `vulnerable_app.db`, the `users` table, and the session-cookie format are untouched by this feature.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

- **No change-email** — email is read-only this release.
- **No member-since / `created_at` column** — would be the first schema change; deferred.
- **No per-user theme** — dark mode stays frontend-only (`localStorage`); the profile page gets the same toggle as every other page.
- **No infra-dependent features** (email verification, OAuth, MFA, OTP, CAPTCHA, lockout) — not even disabled placeholders; each is a future spec that extends this page.
- **Strength gate on the new password (amended)** — the new password is enforced against the signup five-criteria policy server-side (`password_meets_policy()`) and mirrored in the profile form's JS. The strength-meter *widget* is not rendered. `signup()` itself stays advisory (unchanged).
- **No "new must differ from current" rule.**
- **No session invalidation / forced re-login after a password change.**
- **No new middleware, no middleware re-ordering, no `main.py` edit.**
- **No new dependency** — `pyproject.toml` / `uv.lock` untouched.
- **No database-schema change** — `db/session.py` untouched.
- **No change to `signup()` / `login()` / `search` / `welcome` / `logout` / `index`.**
- **No change to `login.html` / `signup.html`.**
- **No reversal of any prior fix** — VULN-1 through VULN-8 stay closed.
