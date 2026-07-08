# Implementation Plan — Remember Me (Persistent Login Sessions)

**Spec:** [remember-me.md](./remember-me.md)
**Target Release Tag:** v2.0.0
**Feature #:** (follows CAPTCHA; additive)

This plan turns the spec into ordered, surgical steps. It creates **one** new file (`core/remember_me.py`), edits **four** existing files (`core/config.py`, `main.py`, `api/routes/auth.py`, `login.html`). **No** database change, **no** new Python/JS dependency, **no** change to `auth_service.py` / `core/security.py` / `core/csrf.py` / `core/rate_limit.py` / any 2FA service.

## Key facts grounding this plan (verified against the current tree)

- `main.py:56-57` configures `SessionMiddleware` with `secret_key=SECRET_KEY` **(no `max_age`)** — the cookie is a session cookie (no `Max-Age` attribute).
- Starlette's `SessionMiddleware` does NOT support per-request `max_age`. To conditionally extend the cookie, a thin outer middleware patches the `Set-Cookie` header on the response path **after** `SessionMiddleware` has serialized the session.
- `POST /login` = `login_post` (auth.py:243-270) calls `auth_service.login(request, username, password)`.
- `auth_service.login()` (auth_service.py:135-321) is the full auth chain: lockout gate → bcrypt → verified gate → TOTP branch → Email OTP branch → no-2FA session write.
- `POST /login/otp` = `login_otp_post` (auth.py:467-504) writes session after OTP verify.
- `POST /login/totp` = `login_totp_post` (auth.py:672-708) writes session after TOTP verify.
- The TOTP and Email OTP branches set `pending_2fa_user_id` in the session; the no-2FA path sets `user_id`. `login_post` can distinguish them **without** touching `auth_service.py` by inspecting the session **after** `auth_service.login()` returns.
- `BaseHTTPMiddleware` (`starlette.middleware.base`) is the project's existing pattern for response-path logic (see `core/rate_limit.py`).
- `core/config.py` currently ends at the Turnstile block (~line 208); the `OTP_TTL_SECONDS` line is the template for the `REMEMBER_ME_MAX_AGE` setting.

---

## Step 0 — Precondition check

Before writing code, confirm what happens with the session cookie today by opening dev tools, logging in, and verifying there is **no** `Max-Age` / `Expires` on the `session` cookie. This establishes the baseline that the plan preserves when Remember Me is unchecked.

---

## Step 1 — `backend/app/core/config.py` (setting)

Append after the Turnstile block (~line 208), mirroring the `OTP_TTL_SECONDS` pattern:

```python
# --- Remember Me (persistent login sessions) ----------------------------------
# When a user checks "Remember Me" on the login form and the full auth chain
# succeeds, the session cookie's Max-Age is set to REMEMBER_ME_MAX_AGE seconds
# (default 30 days). When unchecked the cookie remains a session cookie (no
# Max-Age). Non-secret, env-tunable, safe default, no is_*_configured() gate.
REMEMBER_ME_MAX_AGE = int(os.environ.get("REMEMBER_ME_MAX_AGE", "2592000"))
```

Also add "Remember Me" to the module docstring's numbered feature list (point 8).

---

## Step 2 — `backend/app/core/remember_me.py` (NEW; BaseHTTPMiddleware, stdlib only)

Create `backend/app/core/remember_me.py`:

```python
"""Per-request session cookie Max-Age extension (stdlib only).

Supports the Remember Me feature. Registered as the OUTERMOST middleware so
that on the response path it runs AFTER SessionMiddleware has already set the
session cookie. If the ASGI scope's session dict contains a ``__max_age__``
key, this middleware patches the ``Set-Cookie: session=...`` header's
``Max-Age`` attribute before the response is sent to the client.

The ``__max_age__`` key is an ephemeral one-shot directive written by the
login handler (or the 2FA completion handlers) when the full authentication
chain has succeeded and the user checked "Remember Me". It is only meaningful
on the response that just established the session.
"""

import re
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger(__name__)

_SESSION_COOKIE_NAME = "session"


class RememberMeMiddleware(BaseHTTPMiddleware):
    """Outermost middleware that patches the session cookie's Max-Age when
    ``request.session["__max_age__"]`` is present."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # After the entire inner stack (including SessionMiddleware) has
        # processed, the ASGI scope carries the session dict.  If the
        # handler set __max_age__, patch the Set-Cookie header.
        max_age = request.session.get("__max_age__")
        if max_age is not None:
            self._patch_session_max_age(response, int(max_age))

        return response

    @staticmethod
    def _patch_session_max_age(response, max_age: int) -> None:
        """Replace or append ``Max-Age`` on the session cookie header."""
        new_headers: list[tuple[bytes, bytes]] = []
        target_prefix = (_SESSION_COOKIE_NAME + "=").encode("latin-1")

        for name, value in response.raw_headers:
            if name == b"set-cookie" and value.startswith(target_prefix):
                cookie = value.decode("latin-1")
                if "Max-Age=" in cookie:
                    cookie = re.sub(
                        r"Max-Age=\d+", f"Max-Age={max_age}", cookie
                    )
                else:
                    cookie = cookie.rstrip(";") + f"; Max-Age={max_age}"
                value = cookie.encode("latin-1")
            new_headers.append((name, value))

        response.raw_headers = new_headers
```

This file follows the same `BaseHTTPMiddleware` pattern as `core/rate_limit.py` and uses **only stdlib** (`re`, `logging`).

---

## Step 3 — `backend/app/main.py` (wire middleware)

Register `RememberMeMiddleware` as the **outermost** middleware by adding it **after** all existing `add_middleware` calls (Starlette's `add_middleware` prepends, so the last call is the outermost layer on the request path).

**After** the three existing `add_middleware` blocks (line ~67), append:

```python
# Remember Me (additive feature): outermost middleware patches the session
# cookie's Max-Age on the response path when the handler has set a
# __max_age__ directive in the session. This runs AFTER SessionMiddleware
# has already serialized and signed the cookie, so we just tweak the header.
from app.core.remember_me import RememberMeMiddleware
app.add_middleware(RememberMeMiddleware)
```

Also add the import at the top of the file alongside the other `from app.core.` imports (line 26-28):

```python
from app.core.remember_me import RememberMeMiddleware
```

Resulting middleware order (outer → inner on request path):
```
RememberMe → RateLimit → Session → CSRF → handler
```
Response path: `handler → CSRF → Session (sets cookie) → RateLimit → RememberMe (patches Max-Age)`

---

## Step 4 — `frontend/templates/login.html` (checkbox markup)

After the password `<div class="form-group">` block (line ~91) and **before** the Turnstile comment + widget (line ~92), insert:

```html
                    <div class="form-group form-group-checkbox">
                        <label class="form-label-checkbox">
                            <input type="checkbox" name="remember_me" value="1">
                            Remember me
                        </label>
                    </div>
```

The exact insertion point in the current template:

```
**BEFORE (login.html:89-99):**
                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Enter your password" required>
                    </div>
                    <!-- CAPTCHA on Login (v2.0.0): the Turnstile widget... -->
                    {{turnstile_widget}}
                    <button type="submit" class="btn btn-primary">Sign In</button>

**AFTER (login.html:89-101):**
                    <div class="form-group">
                        <label class="form-label" for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Enter your password" required>
                    </div>
                    <div class="form-group form-group-checkbox">
                        <label class="form-label-checkbox">
                            <input type="checkbox" name="remember_me" value="1">
                            Remember me
                        </label>
                    </div>
                    <!-- CAPTCHA on Login (v2.0.0): the Turnstile widget... -->
                    {{turnstile_widget}}
                    <button type="submit" class="btn btn-primary">Sign In</button>
```

The checkbox is an **opt-in** HTML checkbox — when unchecked, the browser sends no `remember_me` field at all. When checked, it sends `remember_me=1` urlencoded, which the existing `URLSearchParams(new FormData(form))` submit picks up **with zero JS changes**.

A small CSS class may be needed if the checkbox layout looks wrong. Add to `frontend/static/css/styles.css` (follow the existing `.form-group` and `.form-label` rules):

```css
.form-group-checkbox {
    margin-bottom: 16px;
}
.form-label-checkbox {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.9rem;
    color: var(--text-secondary, #475569);
    cursor: pointer;
}
.form-label-checkbox input[type="checkbox"] {
    width: 16px;
    height: 16px;
    cursor: pointer;
}
```

---

## Step 5 — `backend/app/api/routes/auth.py` (handler logic)

### 5a — `login_post` (auth.py:243-270)

Add a `remember_me` form field and conditional max-age / pending-marker logic **after** the `auth_service.login()` call.

**Current signature and body:**
```python
@router.post("/login")
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
):
    if config.is_captcha_configured() and not captcha.verify(cf_turnstile_response):
        return JSONResponse(
            {"error": "CAPTCHA verification failed. Please try again."},
            status_code=400,
        )
    return auth_service.login(request, username, password)
```

**After edit:**
```python
@router.post("/login")
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
    remember_me: str = Form(""),
):
    if config.is_captcha_configured() and not captcha.verify(cf_turnstile_response):
        return JSONResponse(
            {"error": "CAPTCHA verification failed. Please try again."},
            status_code=400,
        )
    response = auth_service.login(request, username, password)
    # Remember Me: the extended cookie may only be issued AFTER the full
    # authentication chain.  Distinguish three post-login states by
    # inspecting the session keys that auth_service.login() set:
    #   - pending_2fa_user_id → 2FA in progress (TOTP or Email OTP)
    #   - user_id             → no 2FA, session fully established
    #   - neither             → auth failed, session untouched
    if remember_me == "1":
        if request.session.get("pending_2fa_user_id"):
            # 2FA is pending — defer the extended cookie until the second
            # factor is verified (the completion handler checks this flag).
            request.session["pending_remember_me"] = True
        elif request.session.get("user_id"):
            # No 2FA — the full chain has completed.  The outermost
            # RememberMeMiddleware reads this key from scope["session"]
            # on the response path and patches the Set-Cookie header.
            request.session["__max_age__"] = config.REMEMBER_ME_MAX_AGE
    return response
```

**Why this works without touching `auth_service.py`:**

- After `auth_service.login()` returns, `request.session` has been mutated in place.
- For TOTP users: `login()` sets `pending_2fa_user_id` (never `user_id`). → `login_post` sees this and sets `pending_remember_me`.
- For Email OTP users: same — `pending_2fa_user_id` is set. → `pending_remember_me` deferred.
- For no-2FA users: `login()` sets `user_id`. → `__max_age__` set immediately.
- For failed logins (wrong password, locked, unverified): neither key is set. → No action, session unchanged.

### 5b — `login_otp_post` (auth.py:467-504)

In the `if result["status"] == "ok":` branch, **after** writing `user_id`/`username`/`email` and **before** the `return` statement, add:

```python
        # Remember Me: if the original login had the checkbox checked,
        # apply the extended session cookie now that 2FA is complete.
        if request.session.pop("pending_remember_me", None):
            request.session["__max_age__"] = config.REMEMBER_ME_MAX_AGE
```

**Before/after snippet (showing the `ok` branch only):**

**Before (auth.py:486-493):**
```python
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
```

**After:**
```python
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        # Remember Me: complete the deferred extended-cookie issuance
        # now that the second factor (Email OTP) has been verified.
        if request.session.pop("pending_remember_me", None):
            request.session["__max_age__"] = config.REMEMBER_ME_MAX_AGE
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
```

### 5c — `login_totp_post` (auth.py:672-708)

Same pattern as 5b. In the `if result["status"] == "ok":` branch, **after** writing session keys and clearing pending markers, **before** the `return`:

**Before (auth.py:691-699):**
```python
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session.pop("pending_2fa_method", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
```

**After:**
```python
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session.pop("pending_2fa_method", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        # Remember Me: complete the deferred extended-cookie issuance
        # now that the second factor (TOTP) has been verified.
        if request.session.pop("pending_remember_me", None):
            request.session["__max_age__"] = config.REMEMBER_ME_MAX_AGE
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
```

### 5d — import `config` if not already imported (auth.py:38)

The `config` module is already imported at the top of auth.py:
```python
from app.core import config
```
(line 38). No additional import needed.

---

## Step 6 — Security invariants (verification that nothing is weakened)

| Invariant | How the plan preserves it |
|-----------|--------------------------|
| **CSRF (VULN-8)** | `remember_me` is a regular urlencoded form field. The CSRF middleware validates the `csrf_token` before the handler runs — it parses all form fields and ignores unknown ones. |
| **Rate limit (VULN-7)** | `POST /login` with or without `remember_me=1` goes through the same `RateLimitMiddleware`. The new form field does not create a new endpoint or bypass path. |
| **CAPTCHA** | The CAPTCHA check in `login_post` runs **before** `auth_service.login()` and **before** the `remember_me` logic — an absent/invalid Turnstile token returns `400` before any session mutation. |
| **Account Lockout** | Account lockout is checked first in `auth_service.login()`. The `remember_me` form field has no influence on lockout state — a locked account gets the same `401` response regardless. |
| **Stored XSS (VULN-2)** | The `__max_age__` key contains an integer (the setting value), not user input. The `pending_remember_me` flag is a boolean, not user input. Neither is ever reflected into HTML. |
| **Reflected XSS (VULN-3)** | No user-controlled data from the `remember_me` field is reflected into any response — it is only compared as `remember_me == "1"`. |
| **No extra auth mechanism (NFR-04)** | The signed session cookie remains the sole authentication carrier. The `__max_age__` key is stripped by SessionMiddleware's serialization but remains as an inert key in the session data — it is never used as a session replacement or parallel cookie. |

---

## Verification Steps (from spec §10)

```bash
# 1. Start the application (from the project root)
uv run backend/app/main.py

# 2. Register a new user (signup at http://localhost:3001/signup)
#    (if email is not configured, set is_verified=1 in the DB or
#     configure SMTP per .env.example)

# 3. Verify the checkbox is present at GET /login
#    - Open http://localhost:3001/login
#    - Inspect the form: a labelled "Remember me" checkbox renders
#      between the password field and the Turnstile widget / submit button

# 4. Login flow — no 2FA, Remember Me checked (TC-01)
#    - Enter valid credentials, check "Remember Me", submit
#    - DevTools → Application → Cookies → "session"
#    - Confirm "Max-Age" ≈ 2592000 (or "Expires" = ~30 days from now)

# 5. Login flow — no 2FA, Remember Me UNCHECKED (TC-02)
#    - Logout, login again WITHOUT checking "Remember Me"
#    - Confirm "session" cookie has NO "Max-Age" / "Expires" (session cookie)
#    - Close browser tab, re-open /welcome → redirected to /login

# 6. Login flow — TOTP + Remember Me (TC-03 / TC-04)
#    - Enable TOTP on /profile/totp/setup + /profile/totp/confirm
#    - Logout
#    - Login with Remember Me checked → redirect to /login/totp
#    - BEFORE entering TOTP code: cookie has NO Max-Age
#    - Enter valid TOTP code → cookie now has Max-Age ≈ 2592000

# 7. Login flow — Email OTP + Remember Me (TC-05 / TC-06)
#    - Enable Email OTP 2FA on /profile/2fa
#    - Logout
#    - Login with Remember Me checked → redirect to /login/otp
#    - BEFORE entering OTP code: cookie has NO Max-Age
#    - Enter valid OTP code → cookie now has Max-Age ≈ 2592000

# 8. CSRF still enforced (TC-10)
#    - Craft a POST to /login with remember_me=1, valid password, but NO csrf_token
#    - Verify HTTP 403

# 9. Rate limit still enforced (TC-11)
#    - Send 6+ POST /login requests from the same IP within 60 seconds
#    - Verify the 6th returns HTTP 429

# 10. Existing XSS fixes intact (TC-12, TC-13)
#     - Login with Remember Me checked, then visit /search?q=<script>alert(1)</script>
#     - Confirm the query is html.escape()'d (no alert)
#     - Visit /welcome after the session is set; confirm username is html.escape()'d
```

---

## Summary of all file changes

| File | Action | Lines touched |
|------|--------|---------------|
| `backend/app/core/config.py` | Add setting | +4 (append after Turnstile block) |
| `backend/app/core/remember_me.py` | **NEW** | ~45 lines (class + module doc) |
| `backend/app/main.py` | Wire middleware | +3 (add_middleware call after RateLimit) |
| `frontend/templates/login.html` | Add checkbox | +5 (insert between password field and Turnstile comment) |
| `frontend/static/css/styles.css` | Add minimal checkbox styles | +10 (new CSS rules) |
| `backend/app/api/routes/auth.py` | Handle `remember_me` in three handlers | ~+15 (3 insertion sites) |

**No** schema change, **no** new dependency, **no** modification to `auth_service.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, or any 2FA service.
