# Implementation Plan — Email OTP Two-Factor Authentication (2FA)

**Spec:** [email-otp-2fa.md](./email-otp-2fa.md)
**Target Release Tag:** v1.0.6
**Branch:** `feature/email-otp-2fa`

This plan sequences the work so the app boots after every step and the eight closed vulnerabilities stay closed throughout. Backend primitives land first (config → schema → mailer → OTP service), then the login branch, then the routes, then the two template edits + the new template, then docs. The session/CSRF/rate-limit/bcrypt middlewares, the OAuth path, and the lockout/verification services are **not** touched.

---

## Step 0 — Preconditions

- Confirm branch `feature/email-otp-2fa` is checked out (it already is).
- Confirm `secrets`, `time`, `threading`, `logging`, `smtplib`, `email` are stdlib (no dependency change).
- No edits at any point to `main.py`, `core/rate_limit.py`, `core/csrf.py`, `core/security.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, `verification_service.py`, `signup.html`, `dashboard.html`, `styles.css`, or any lockfile.

---

## Step 1 — `backend/app/core/config.py` (OTP settings)

Append a new block below the account-lockout block:

```python
# --- Email OTP 2FA settings (env-tunable, non-secret) ------------------------
# When a user enables Email OTP 2FA, a correct password issues a 6-digit code
# emailed to them; login completes only after the code is verified. These are
# NOT secrets (no is_*_configured() gate of their own -- OTP delivery reuses
# is_email_configured()); they have safe defaults and can be lowered for demos,
# e.g. OTP_TTL_SECONDS=30 OTP_RESEND_COOLDOWN_SECONDS=5.
OTP_LENGTH = 6  # fixed: the feature is specified as a 6-digit code (not env-tunable).
OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", "300"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", "60"))
```

Update the module docstring's opening sentence to mention Email OTP 2FA alongside Google + email verification + account lockout. No behaviour change to existing settings or gates.

**Check:** `python -c "from app.core import config; print(config.OTP_LENGTH, config.OTP_TTL_SECONDS, config.OTP_MAX_ATTEMPTS, config.OTP_RESEND_COOLDOWN_SECONDS)"` → `6 300 5 60`.

---

## Step 2 — `backend/app/db/session.py` (additive migration, 5 columns)

In `CREATE TABLE IF NOT EXISTS users (...)` add the five columns (after `locked_until`):

```
two_factor_enabled         INTEGER DEFAULT 0,
otp_code                   TEXT,
otp_expires                REAL,
otp_attempts               INTEGER DEFAULT 0,
otp_last_sent              REAL
```

In the `migrations` dict, add the five entries (no grandfather step — defaults are already correct):

```python
migrations = {
    # ... existing google + verification + lockout columns ...
    # Email OTP 2FA feature (v1.0.6): five columns. Defaults (0 / NULL) already
    # mean "2FA off, no challenge outstanding", so NO grandfather UPDATE is needed.
    "two_factor_enabled": "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0",
    "otp_code": "ALTER TABLE users ADD COLUMN otp_code TEXT",
    "otp_expires": "ALTER TABLE users ADD COLUMN otp_expires REAL",
    "otp_attempts": "ALTER TABLE users ADD COLUMN otp_attempts INTEGER DEFAULT 0",
    "otp_last_sent": "ALTER TABLE users ADD COLUMN otp_last_sent REAL",
}
```

Update the `init_db()` docstring's schema notes for the five new columns (mirroring the `is_verified` / `locked_until` notes).

**Check:** `rm vulnerable_app.db`, boot, `PRAGMA table_info(users)` shows all five; on an old DB copy, existing rows read `0`/`NULL`, 2FA off.

---

## Step 3 — `backend/app/core/mailer.py` (add `send_otp_email`)

Add a second public function beside `send_verification_email`, reusing the same STARTTLS/implicit-TLS structure and fail-safe contract. The code is a server-generated digit string; the username is `html.escape`'d into the HTML part.

```python
def send_otp_email(to_email: str, username: str, code: str) -> bool:
    """Send a one-time login passcode. Returns True on success, else False.

    Same fail-safe contract as send_verification_email -- never raises; every
    failure path returns False so the login/resend flow stays robust. The 6-digit
    code is server-generated (no escaping concern); the username is escaped before
    entering the HTML part (VULN-2 posture).
    """
    if not config.is_email_configured():
        logger.warning("SMTP not configured; skipping OTP email to %s", to_email)
        return False

    safe_username = html.escape(username or "", quote=True)

    msg = EmailMessage()
    msg["Subject"] = "Your login verification code - Security Vulnerability Lab"
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Hi {username},\n\n"
        f"Your one-time login code is: {code}\n\n"
        f"It is valid for {config.OTP_TTL_SECONDS // 60} minutes. "
        "If you did not try to log in, you can ignore this email."
    )
    msg.add_alternative(
        f"<p>Hi {safe_username},</p>"
        "<p>Your one-time login code for the <strong>Security Vulnerability "
        "Lab</strong> is:</p>"
        f'<p style="font-size:24px;font-weight:bold;letter-spacing:3px;">{code}</p>'
        f"<p>It is valid for {config.OTP_TTL_SECONDS // 60} minutes. "
        "If you did not try to log in, you can ignore this email.</p>",
        subtype="html",
    )

    try:
        if config.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT) as server:
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT) as server:
                server.starttls()
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
        logger.info("OTP email sent to %s", to_email)
        return True
    except Exception:
        logger.exception("Failed to send OTP email to %s", to_email)
        return False
```

> Note: the code is logged **only** as "OTP email sent to <email>" — never the digits (VULN-3 / FR-10).

**Check:** `send_otp_email` returns `False` (logged) when SMTP is unset; never raises.

---

## Step 4 — `backend/app/services/otp_service.py` (new)

Stdlib-only module importable by `auth_service` and the route layer (imports `secrets`, `time`, `threading`, `logging`, `core.config`, `core.mailer`, `db.session` — no cycle).

```python
"""Email OTP 2FA helpers (issue / verify / resend / toggle).

Implements README "Feature Enhancements" #6 (OTP via Email, v1.0.6). When a user
enables 2FA, a correct password does not complete login: this module issues a
6-digit one-time code (emailed via core.mailer), and login finishes only after
the code is verified on the /login/otp screen.

Security posture:
- VULN-1 (SQL Injection): every statement here is parameterized.
- VULN-3 (Reflected XSS): the code is never returned to the client; it is emailed
  and compared server-side with secrets.compare_digest (constant-time).
- VULN-5: this runs AFTER bcrypt in login() -- it is a second factor, not a
  password check. A wrong password never reaches OTP issuance.
- Low-entropy (6-digit) codes are bounded by an attempt cap, a short expiry, and
  a per-account resend cooldown, on top of the unchanged per-IP rate limiter.
- Email send is FAIL-SAFE (mailer returns False, never raises); a failed send
  never crashes login or silently completes it (login fails closed if email is
  unconfigured).
"""

import logging
import secrets
import threading
import time

from app.core import config, mailer
from app.db.session import get_db

logger = logging.getLogger(__name__)


def _generate_code() -> str:
    """Uniform OTP_LENGTH-digit code, zero-padded (no modulo bias)."""
    return f"{secrets.randbelow(10 ** config.OTP_LENGTH):0{config.OTP_LENGTH}d}"


def set_two_factor(user_id: int, enabled: bool) -> bool:
    """Turn 2FA on/off for user_id. Disabling also clears any pending OTP.

    Returns True on success, False on a DB error (route reports a 400).
    """
    conn = get_db()
    try:
        if enabled:
            conn.execute(
                "UPDATE users SET two_factor_enabled = 1 WHERE id = ?", [user_id]
            )
        else:
            conn.execute(
                "UPDATE users SET two_factor_enabled = 0, otp_code = NULL, "
                "otp_expires = NULL, otp_attempts = 0, otp_last_sent = NULL "
                "WHERE id = ?",
                [user_id],
            )
        conn.commit()
        return True
    except Exception:
        logger.exception("set_two_factor failed for user_id=%s", user_id)
        return False
    finally:
        conn.close()


def start_challenge(user_id, username, email, background: bool = False) -> bool:
    """Issue a fresh OTP for user_id and email it.

    Persists the code + expiry + zeroed attempt count + send timestamp
    (parameterized, synchronous so state is saved before any send), then sends.
    background=True (login): daemon-thread send, return True immediately.
    background=False (resend): synchronous send, return the mailer's boolean.
    A new call overwrites any prior code (only the latest verifies).
    """
    code = _generate_code()
    now = time.time()
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET otp_code = ?, otp_expires = ?, otp_attempts = 0, "
            "otp_last_sent = ? WHERE id = ?",
            [code, now + config.OTP_TTL_SECONDS, now, user_id],
        )
        conn.commit()
    finally:
        conn.close()

    if background:
        threading.Thread(
            target=mailer.send_otp_email, args=(email, username, code), daemon=True
        ).start()
        return True
    return mailer.send_otp_email(email, username, code)


def seconds_until_resend(row) -> int:
    """Seconds left on the resend cooldown for a fetched row (0 = may resend)."""
    last = row["otp_last_sent"]
    if last is None:
        return 0
    remaining = int(float(last) + config.OTP_RESEND_COOLDOWN_SECONDS - time.time())
    return remaining if remaining > 0 else 0


def verify(user_id: int, code: str) -> dict:
    """Validate a submitted OTP. Returns {"status": <str>, "user": <dict|None>}.

    status: "ok" | "no_challenge" | "expired" | "too_many" | "invalid".
    On ok the OTP columns are cleared (single-use). On expired/too_many the code
    is cleared. On invalid the attempt count is incremented (and the code cleared
    if the increment reaches OTP_MAX_ATTEMPTS).
    """
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, otp_code, otp_expires, otp_attempts "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
        if not row or row["otp_code"] is None:
            return {"status": "no_challenge", "user": None}

        if row["otp_expires"] is None or time.time() > float(row["otp_expires"]):
            conn.execute(
                "UPDATE users SET otp_code = NULL, otp_expires = NULL WHERE id = ?",
                [user_id],
            )
            conn.commit()
            return {"status": "expired", "user": None}

        if (row["otp_attempts"] or 0) >= config.OTP_MAX_ATTEMPTS:
            conn.execute(
                "UPDATE users SET otp_code = NULL, otp_expires = NULL WHERE id = ?",
                [user_id],
            )
            conn.commit()
            return {"status": "too_many", "user": None}

        if code and secrets.compare_digest(str(row["otp_code"]), str(code)):
            conn.execute(
                "UPDATE users SET otp_code = NULL, otp_expires = NULL, "
                "otp_attempts = 0, otp_last_sent = NULL WHERE id = ?",
                [user_id],
            )
            conn.commit()
            return {
                "status": "ok",
                "user": {"id": row["id"], "username": row["username"], "email": row["email"]},
            }

        # Wrong code: count the miss; invalidate if the cap is now reached.
        attempts = (row["otp_attempts"] or 0) + 1
        if attempts >= config.OTP_MAX_ATTEMPTS:
            conn.execute(
                "UPDATE users SET otp_code = NULL, otp_expires = NULL, "
                "otp_attempts = ? WHERE id = ?",
                [attempts, user_id],
            )
            conn.commit()
            return {"status": "too_many", "user": None}
        conn.execute(
            "UPDATE users SET otp_attempts = ? WHERE id = ?", [attempts, user_id]
        )
        conn.commit()
        return {"status": "invalid", "user": None}
    except Exception:
        logger.exception("otp verify failed for user_id=%s", user_id)
        return {"status": "invalid", "user": None}
    finally:
        conn.close()
```

**Check:** `_generate_code()` returns a 6-char digit string; `verify` clears columns on success; all SQL parameterized; no code is ever returned in a non-`ok` status.

---

## Step 5 — `backend/app/services/auth_service.py` (`login()` branch only)

- Add imports: `from app.core import config` and `from app.services import otp_service` (no cycle — `otp_service` imports neither `auth_service` nor `verification_service`).
- The existing `SELECT *` already returns `two_factor_enabled`, so no query change.
- Keep the lockout gate, bcrypt verify, `lockout_service.reset(user["id"])`, and the `is_verified` gate **exactly as they are**. Then, in the success branch, **replace** the three `request.session[...] = ...` writes + the `return` with the 2FA branch:

```python
# Second factor (Email OTP 2FA, v1.0.6): if the user enabled it, do NOT create
# the session yet. Stash a short-lived pending marker (NOT user_id, so /welcome
# stays gated), email a 6-digit code, and tell the page to go to the OTP screen.
# This runs AFTER bcrypt + the verified gate, so only a fully authenticated-by-
# password, verified user reaches it.
if user["two_factor_enabled"]:
    if not config.is_email_configured():
        # Fail closed: 2FA is on but we cannot deliver the code. Never bypass
        # the second factor by silently completing login.
        return JSONResponse(
            content={
                "error": "Two-factor authentication is enabled but email "
                         "delivery is unavailable. Please contact the administrator."
            },
            status_code=401,
        )
    request.session["pending_2fa_user_id"] = user["id"]
    request.session["pending_2fa_username"] = user["username"]
    otp_service.start_challenge(
        user["id"], user["username"], user["email"], background=True
    )
    return JSONResponse(content={"otp_required": True, "redirect": "/login/otp"})

# No 2FA: complete the login exactly as before.
request.session["user_id"] = user["id"]
request.session["username"] = user["username"]
request.session["email"] = user["email"]
return JSONResponse(content={"success": True, "redirect": "/welcome"})
```

- **Do not touch** `signup()`, `change_password()`, `password_meets_policy()`, the lockout gate, or the verified gate.

**Check:** non-2FA correct login still `200 {"success":true}`; 2FA correct login `200 {"otp_required":true}` with `pending_2fa_user_id` (no `user_id`) in the session.

---

## Step 6 — `backend/app/api/routes/auth.py` (4 new routes + profile read)

- Add `from app.services import otp_service` to the imports.
- In `profile_page`, after the auth gate, read the 2FA flag for the session user and splice it (plus an email-configured flag) into the template:

```python
conn = get_db()
try:
    row = conn.execute(
        "SELECT two_factor_enabled FROM users WHERE id = ?", [user_id]
    ).fetchone()
finally:
    conn.close()
twofa_enabled = bool(row["two_factor_enabled"]) if row else False

# ... after loading profile.html and splicing csrf/username/email ...
page = page.replace("{{twofa_enabled}}", "1" if twofa_enabled else "0")
page = page.replace("{{email_configured}}", "1" if config.is_email_configured() else "0")
```

- Add the four handlers (thin; same shape as `login_post` / `verify_resend`):

```python
@router.post("/profile/2fa")
async def profile_2fa_post(request: Request, enable: str = Form("")):
    """Enable/disable Email OTP 2FA for the logged-in user (session-gated).

    Session-gate only (no password re-prompt -- product-owner choice). The CSRF
    token and per-IP rate limit are enforced by middleware before this runs.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    want_enable = enable == "1"
    if want_enable and not config.is_email_configured():
        return JSONResponse(
            content={"error": "Email delivery is not configured, so OTP 2FA can't be enabled."},
            status_code=400,
        )
    if not otp_service.set_two_factor(user_id, want_enable):
        return JSONResponse(content={"error": "Could not update the 2FA setting."}, status_code=400)
    return JSONResponse(content={
        "success": True,
        "two_factor_enabled": want_enable,
        "message": "Two-factor authentication " + ("enabled." if want_enable else "disabled."),
    })


@router.get("/login/otp")
async def login_otp_page(request: Request):
    """Render the OTP entry screen -- only mid-2FA-login (pending marker set)."""
    if not request.session.get("pending_2fa_user_id"):
        return RedirectResponse(url="/login", status_code=302)
    page = _load_template("otp_verify.html")
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    return HTMLResponse(content=page)


@router.post("/login/otp")
async def login_otp_post(request: Request, otp: str = Form("")):
    """Verify the OTP and complete the login by writing the full session."""
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )
    result = otp_service.verify(user_id, otp)
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
    messages = {
        "invalid": "Incorrect code. Please try again.",
        "too_many": "Too many incorrect attempts. Request a new code.",
        "expired": "This code has expired. Request a new one.",
        "no_challenge": "No active code. Please sign in again.",
    }
    return JSONResponse(
        content={"error": messages.get(result["status"], messages["invalid"])},
        status_code=401,
    )


@router.post("/login/otp/resend")
async def login_otp_resend(request: Request):
    """Re-send the OTP during a pending 2FA login, honouring the cooldown."""
    user_id = request.session.get("pending_2fa_user_id")
    username = request.session.get("pending_2fa_username", "")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT email, otp_last_sent FROM users WHERE id = ?", [user_id]
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return JSONResponse(content={"error": "Please sign in again."}, status_code=401)
    wait = otp_service.seconds_until_resend(row)
    if wait > 0:
        return JSONResponse(content={"error": f"Please wait {wait} seconds before requesting another code."}, status_code=429)
    if otp_service.start_challenge(user_id, username, row["email"], background=False):
        return JSONResponse(content={"success": True, "message": "Verification code sent. Check your inbox."})
    return JSONResponse(content={"error": "Could not send the code. Please try again later."}, status_code=400)
```

> Note `_load_template`, `get_or_create_csrf_token`, `html`, `config`, and `get_db` are already imported at the top of `auth.py`. The OAuth handlers, `login_post`, `welcome_page`, `search_user`, etc. are **not** modified.

**Check:** `GET /login/otp` 302s to `/login` with no pending marker; the three POSTs return JSON; correct OTP writes `user_id` and 302-able redirect.

---

## Step 7 — `frontend/templates/login.html` (one additive branch)

In the existing fetch handler, after the `if (data.success) { window.location.href = data.redirect; }` block, add the OTP-required branch (before/within the `else`). Minimal diff:

```javascript
if (data.success) {
    window.location.href = data.redirect;
} else if (data.otp_required) {
    // 2FA is on: password was correct, a code was emailed -- go enter it.
    window.location.href = data.redirect;   // /login/otp
} else {
    errorDiv.textContent = data.error;
    errorDiv.style.display = 'block';
    if (data.unverified) { resendArea.style.display = 'block'; }
}
```

No other change to `login.html` (the Google button, resend-verification affordance, theme toggle stay as-is).

**Check:** a 2FA user's correct login navigates to `/login/otp`; a non-2FA user still goes to `/welcome`.

---

## Step 8 — `frontend/templates/otp_verify.html` (new)

Model on `login.html`'s structure: the pre-render theme IIFE, shared header with `#theme-toggle`, the theme-toggle script block at the bottom, and `/static/css/styles.css`. Body: a card with a heading ("Enter your verification code"), a generic subtitle ("We sent a 6-digit code to your email."), an error/status element, and a form:

```html
<form id="otp-form">
    <input type="hidden" name="csrf_token" value="{{csrf_token}}">
    <div class="form-group">
        <label class="form-label" for="otp">6-digit code</label>
        <input type="text" id="otp" name="otp" class="form-input"
               inputmode="numeric" autocomplete="one-time-code" maxlength="6"
               pattern="[0-9]*" placeholder="123456" required>
    </div>
    <button type="submit" class="btn btn-primary">Verify</button>
</form>
<button type="button" id="resend-btn" class="btn btn-google">Resend code</button>
```

Inline script (urlencoded `URLSearchParams`, same CSRF reasoning as login):

```javascript
const form = document.getElementById('otp-form');
const errorDiv = document.getElementById('error-message');
const resendBtn = document.getElementById('resend-btn');
const csrf = form.querySelector('input[name="csrf_token"]').value;

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorDiv.style.display = 'none';
    const body = new URLSearchParams(new FormData(form));
    const res = await fetch('/login/otp', { method: 'POST', body });
    const data = await res.json();
    if (data.success) { window.location.href = data.redirect; }
    else { errorDiv.textContent = data.error; errorDiv.style.display = 'block'; }
});

let cooldown = 0;
function tick() {
    if (cooldown > 0) {
        resendBtn.disabled = true;
        resendBtn.textContent = 'Resend code (' + cooldown + 's)';
        cooldown -= 1;
        setTimeout(tick, 1000);
    } else {
        resendBtn.disabled = false;
        resendBtn.textContent = 'Resend code';
    }
}

resendBtn.addEventListener('click', async () => {
    errorDiv.style.display = 'none';
    const body = new URLSearchParams({ csrf_token: csrf });
    const res = await fetch('/login/otp/resend', { method: 'POST', body });
    const data = await res.json();
    errorDiv.textContent = data.message || data.error || 'Could not resend.';
    errorDiv.style.display = 'block';
    cooldown = 60; tick();   // mirrors OTP_RESEND_COOLDOWN_SECONDS default
});
```

The screen reflects **no** user input (no email, no code) — fixed strings only (VULN-3). The resend body needs only the CSRF token (the user is identified by the session's pending marker).

**Check:** page renders only mid-login; correct code redirects to `/welcome`; resend button disables for ~60 s.

---

## Step 9 — `frontend/templates/profile.html` (2FA card)

Add a new `profile-card` after the Change Password card:

```html
<div class="profile-card">
    <h2 class="section-title">Two-Factor Authentication</h2>
    <p class="notice-text" id="twofa-status">Email OTP 2FA is currently <strong id="twofa-state">…</strong>.</p>
    <div id="twofa-message" class="profile-message" role="status" aria-live="polite" style="display:none;"></div>
    <form id="twofa-form">
        <input type="hidden" name="csrf_token" value="{{csrf_token}}">
        <input type="hidden" name="enable" id="twofa-enable-field" value="">
        <button type="submit" class="btn btn-primary" id="twofa-btn">…</button>
    </form>
</div>
```

Inline script reads the server-spliced flags and wires the toggle:

```javascript
(function () {
    var enabled = '{{twofa_enabled}}' === '1';
    var emailOk = '{{email_configured}}' === '1';
    var btn = document.getElementById('twofa-btn');
    var state = document.getElementById('twofa-state');
    var field = document.getElementById('twofa-enable-field');
    var form = document.getElementById('twofa-form');
    var msg = document.getElementById('twofa-message');

    function render() {
        state.textContent = enabled ? 'enabled' : 'disabled';
        if (!emailOk && !enabled) {
            btn.textContent = 'Enable (requires email setup)';
            btn.disabled = true;
        } else {
            btn.disabled = false;
            btn.textContent = enabled ? 'Disable 2FA' : 'Enable 2FA';
        }
        field.value = enabled ? '0' : '1';
    }
    render();

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        msg.style.display = 'none';
        var body = new URLSearchParams(new FormData(form));
        try {
            var res = await fetch('/profile/2fa', { method: 'POST', body: body });
            var data = await res.json();
            if (data.success) {
                enabled = data.two_factor_enabled;
                msg.textContent = data.message; msg.classList.remove('is-error'); msg.classList.add('is-success');
            } else {
                msg.textContent = data.error || 'Could not update 2FA.'; msg.classList.remove('is-success'); msg.classList.add('is-error');
            }
        } catch (err) {
            msg.textContent = 'Something went wrong. Please try again.'; msg.classList.add('is-error');
        }
        msg.style.display = 'block';
        render();
    });
})();
```

`{{twofa_enabled}}` / `{{email_configured}}` are server-controlled `"0"`/`"1"` flags spliced by `profile_page` (Step 6) — not user input. The existing Change Password card, account-info card, and theme toggle are unchanged.

**Check:** card shows the correct initial state; Enable/Disable flips it and persists; Enable is disabled with a hint when SMTP is unset.

---

## Step 10 — `.env.example` (append placeholders)

```
# Email OTP 2FA (v1.0.6) — env-tunable, NOT secrets.
#
# When a user enables Email OTP 2FA on their profile, a correct password emails a
# 6-digit code; login completes only after the code is verified. OTP delivery
# reuses the SMTP settings above (no separate gate). The app works with these
# unset — the defaults shown apply. Lower them to demo quickly, e.g.
# OTP_TTL_SECONDS=30 and OTP_RESEND_COOLDOWN_SECONDS=5.
# OTP_TTL_SECONDS=300
# OTP_MAX_ATTEMPTS=5
# OTP_RESEND_COOLDOWN_SECONDS=60
```

---

## Step 11 — `README.md`

- **Feature Enhancements table:** change row #6 (OTP via Email) Status to **Done (v1.0.6)** and flesh out the description: opt-in per user on the profile; a correct password emails a 6-digit code (5-min expiry, 5-attempt cap, 60-s resend cooldown — env-tunable); login completes only after OTP verification; session-only (no JWT); fourth DB-schema change (5 columns); stdlib only.
- **Done-features sentence** (above the table): add "Email OTP 2FA (v1.0.6)".
- **Releases & Versions table:** add a **v1.0.6** row.
- **API Endpoints table:** add `POST /profile/2fa`, `GET /login/otp`, `POST /login/otp`, `POST /login/otp/resend`.
- No change to the Intentional-Vulnerabilities table (all eight stay closed).

---

## Step 12 — `CLAUDE.md`

- **Frontend-Backend Integration:** add an "Email OTP 2FA (v1.0.6)" subsection: the five `users` columns; `otp_service.py` helpers; the `login()` branch (after bcrypt + verified gate) that issues the challenge and stashes `pending_2fa_user_id` instead of `user_id`; the `/login/otp` GET/POST + resend routes; the session-only completion (no JWT); the session-gated profile toggle; the raw-code-plus-attempt-cap posture; OTP-never-reflected; reuse of `is_email_configured()` + the mailer; env tunables.
- **Important Rules:** add an entry — keep `otp_service.py` SQL parameterized (VULN-1); the OTP branch stays **after** bcrypt + the verified gate (VULN-5 stays the password authenticator); never reflect the OTP (VULN-3); keep auth session-only (no JWT/extra cookie); `main.py`/`csrf.py`/`rate_limit.py`/`security.py`/the OAuth path are **not** modified; the pending marker stays in the signed session; the migration stays additive/idempotent (5 columns, no grandfather); the toggle is session-gated by design; OTP settings come from env via `core/config.py`; the mailer stays stdlib-only and fail-safe; login fails closed if 2FA is on but email is unconfigured.
- **Specification Hierarchy:** append entry #17 for this spec/plan pair.

---

## Step 13 — `docs/prompts/`

Save the generating prompts, mirroring the per-feature convention:
`email-otp-2fa-spec-prompt.txt`, `email-otp-2fa-spec-plan-prompt.txt`, `email-otp-2fa-spec-execution-prompt.txt`. (Documentation only.)

---

## Step 14 — Verification

Run the spec's §10 steps:
1. Schema: all five columns present on a fresh DB; old DB migrates to `0`/`NULL`, 2FA off.
2. Enable 2FA on `/profile`; log out + back in → `{"otp_required": true}`; `/welcome` still 302s while only the pending marker is set.
3. Correct OTP completes login (`user_id` written, OTP columns cleared); wrong OTP increments and caps; expiry invalidates; resend honours the cooldown.
4. Toggle: enable blocked when SMTP unset; disable clears OTP columns.
5. File audit: `git diff --stat` empty for the forbidden files (`main.py`, `core/rate_limit.py`, `core/csrf.py`, `core/security.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, `verification_service.py`, `signup.html`, `dashboard.html`, `styles.css`, lockfiles); `git status --porcelain` matches the declared set.
6. `uv run backend/app/main.py` boots clean; a normal (non-2FA) login still succeeds.

---

## Risk / Rollback

- **Risk — user locked out of their own account if they lose email access** after enabling 2FA (no backup codes this slice). Mitigated operationally: an admin can clear `two_factor_enabled` in the DB; documented as a non-goal with backup codes as future work.
- **Risk — session-gated toggle** lets an already-hijacked session disable 2FA (NFR-09). Bounded: obtaining the session already cleared the first factor (and a prior OTP). Documented; a future hardening can require the current password to disable.
- **Risk — low-entropy 6-digit code.** Bounded by attempt cap + expiry + resend cooldown + the per-IP rate limiter (NFR-04); the per-OTP guess budget is far below 10⁶.
- **Risk — background send fails silently** at login. The login holds in the pending state (no session granted), and the user can resend (which reports failure) or restart. Auth fails closed when email is entirely unconfigured.
- **Rollback:** the feature is additive. Reverting the branch leaves the five nullable/defaulted columns in any already-migrated DB (harmless), or `rm vulnerable_app.db`. No destructive migration runs; the password flow, rate limiter, CSRF, and lockout — untouched — keep working on their own.
```