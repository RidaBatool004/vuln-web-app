# Implementation Plan — Email Verification on Signup

**Spec:** [email-verification-on-signup.md](./email-verification-on-signup.md)
**Target Release Tag:** v1.0.4
**Branch:** `feature/email-verification-on-signup`

This plan sequences the work so the app boots after every step and the eight closed vulnerabilities stay closed throughout. Backend primitives land first (config → schema → mailer → service), then the route wiring, then the templates/CSS, then docs.

> **Amendment (v1.0.4 final):** the shipped feature **blocks login until
> verified** instead of "allow login, restrict app". Concretely: `login()`
> returns `401 {"unverified": true}` and writes no session for an unverified
> local account; there is **no dashboard banner** (Step 8's banner and Step 9's
> `.verify-banner` CSS were removed, and Step 7's `/welcome` change was
> reverted); and **resend is credential-based** —
> `verification_service.resend_for_credentials(username, password)` re-checks
> the password with bcrypt, driven by a "Resend verification email" button on
> `login.html` (shown on the `unverified` response). The `POST /verify/resend`
> handler takes `username`/`password` form fields instead of a session. All
> other steps are as written below.

---

## Step 0 — Preconditions

- Confirm branch `feature/email-verification-on-signup` is checked out.
- Confirm `secrets`, `smtplib`, `email`, `time`, `re`, `logging` are stdlib (no dependency change).
- No edits to `main.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/oauth.py`, `login.html`, `signup.html`, or any lockfile at any point.

---

## Step 1 — `backend/app/core/config.py` (SMTP settings + gate)

Append below the Google block:

```python
# --- SMTP / Email-verification settings (all from the environment) -----------
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "") or SMTP_USER
SMTP_TIMEOUT = float(os.environ.get("SMTP_TIMEOUT", "10"))

# Public base URL used to build the verification link in the email body.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:3001").rstrip("/")

# Verification-token lifetime (seconds). Default 1 hour.
EMAIL_VERIFICATION_TTL_SECONDS = int(os.environ.get("EMAIL_VERIFICATION_TTL_SECONDS", "3600"))


def is_email_configured() -> bool:
    """True only when host + user + password are all present."""
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)
```

Update the module docstring to mention email verification (no behavior change to the Google logic).

**Check:** `python -c "from app.core import config; print(config.is_email_configured())"` → `False` with no env, `True` with the three set.

---

## Step 2 — `backend/app/db/session.py` (additive migration + grandfather)

In `CREATE TABLE IF NOT EXISTS users (...)` add the three columns:

```
is_verified                INTEGER DEFAULT 0,
verification_token         TEXT,
verification_token_expires REAL
```

In the migration block, extend the `migrations` dict and add the grandfather step:

```python
migrations = {
    # ... existing google columns ...
    "is_verified": "ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0",
    "verification_token": "ALTER TABLE users ADD COLUMN verification_token TEXT",
    "verification_token_expires": "ALTER TABLE users ADD COLUMN verification_token_expires REAL",
}
for column, ddl in migrations.items():
    if column not in existing:
        conn.execute(ddl)
        if column == "is_verified":
            # Grandfather: rows that predate this feature are treated as verified
            # so they are not retroactively locked behind the banner. Runs once.
            conn.execute("UPDATE users SET is_verified = 1")
```

Update the `init_db()` docstring's schema notes for the three new columns.

**Check:** delete `vulnerable_app.db`, boot, then `PRAGMA table_info(users)` shows the three columns; on an old DB copy, existing rows read `is_verified = 1`.

---

## Step 3 — `backend/app/core/mailer.py` (new, stdlib SMTP)

```python
"""Verification-email sender (stdlib smtplib + email, no third-party dep)."""
import logging, smtplib, html
from email.message import EmailMessage
from app.core import config

logger = logging.getLogger(__name__)

def send_verification_email(to_email: str, username: str, verify_url: str) -> bool:
    if not config.is_email_configured():
        logger.warning("SMTP not configured; skipping verification email.")
        return False
    safe_user = html.escape(username, quote=True)   # email body is HTML → escape
    safe_url = html.escape(verify_url, quote=True)
    msg = EmailMessage()
    msg["Subject"] = "Verify your email — Security Vulnerability Lab"
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Hi {username},\n\nConfirm your email by opening this link "
        f"(valid 1 hour):\n{verify_url}\n\nIf you didn't sign up, ignore this email."
    )
    msg.add_alternative(
        f"<p>Hi {safe_user},</p><p>Confirm your email by clicking the link below "
        f"(valid 1 hour):</p><p><a href=\"{safe_url}\">Verify my email</a></p>"
        f"<p>If you didn't sign up, you can ignore this email.</p>",
        subtype="html",
    )
    try:
        if config.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT) as s:
                s.login(config.SMTP_USER, config.SMTP_PASSWORD)
                s.send_message(msg)
        else:
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT) as s:
                s.starttls()
                s.login(config.SMTP_USER, config.SMTP_PASSWORD)
                s.send_message(msg)
        logger.info("Verification email sent to %s", to_email)
        return True
    except Exception:
        logger.exception("Failed to send verification email to %s", to_email)
        return False
```

**Check:** import-safe with no SMTP env (returns `False`, no raise).

---

## Step 4 — `backend/app/services/verification_service.py` (new)

Public functions per FR-05 / FR-06 / FR-07:

```python
import logging, secrets, time
from fastapi.responses import JSONResponse
from app.db.session import get_db
from app.core import config, mailer

logger = logging.getLogger(__name__)

def start_verification(user_id, username, email) -> bool:
    token = secrets.token_urlsafe(32)
    expires = time.time() + config.EMAIL_VERIFICATION_TTL_SECONDS
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET verification_token = ?, verification_token_expires = ? WHERE id = ?",
            [token, expires, user_id],
        )
        conn.commit()
    finally:
        conn.close()
    return mailer.send_verification_email(email, username, f"{config.APP_BASE_URL}/verify?token={token}")

def verify_email_token(token) -> str:   # 'ok' | 'expired' | 'invalid'
    if not token:
        return "invalid"
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, verification_token_expires FROM users WHERE verification_token = ?",
            [token],
        ).fetchone()
        if not row:
            return "invalid"
        expires = row["verification_token_expires"]
        if expires is None or time.time() > float(expires):
            return "expired"
        conn.execute(
            "UPDATE users SET is_verified = 1, verification_token = NULL, "
            "verification_token_expires = NULL WHERE id = ?",
            [row["id"]],
        )
        conn.commit()
        return "ok"
    except Exception:
        logger.exception("verify_email_token failed")
        return "invalid"
    finally:
        conn.close()

def resend_for_user(user_id) -> JSONResponse:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, is_verified FROM users WHERE id = ?", [user_id]
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if row["is_verified"]:
        return JSONResponse({"success": True, "message": "Your email is already verified."})
    if start_verification(row["id"], row["username"], row["email"]):
        return JSONResponse({"success": True, "message": "Verification email sent. Check your inbox."})
    return JSONResponse(
        {"error": "Could not send the verification email. Please try again later."}, status_code=400
    )
```

**Check:** unit-callable without FastAPI; all SQL parameterized.

---

## Step 5 — `backend/app/services/auth_service.py` (`signup()` only)

- Add `from app.services import verification_service` (top-level import; no circular dependency — `verification_service` does not import `auth_service`).
- INSERT lists `is_verified` explicitly: `INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, ?, 0)`.
- Capture `cursor = conn.execute(query, [...])` then `user_id = cursor.lastrowid` **before** `conn.close()`.
- On the success path, after `conn.commit()` (and `finally: conn.close()`), call `verification_service.start_verification(user_id, username, email)` (ignore the boolean — a failed send must not fail signup) and `return RedirectResponse(url="/check-email", status_code=302)`.
- Leave the empty-field `400`, `IntegrityError` `400`, and generic-exception `400` branches intact. **Do not touch `login()`, `change_password()`, or `password_meets_policy()`.**

**Check:** signup success now lands on `/check-email`; duplicate username still `400`.

---

## Step 6 — `backend/app/services/oauth_service.py` (auto-verify)

- New-account INSERT: add `is_verified` → `... auth_provider, is_verified) VALUES (?, ?, NULL, ?, ?, ?, 'google', 1)`.
- Link-to-local UPDATE: add `is_verified = 1` to the `SET` list.
- SQL stays parameterized; `password` stays `NULL`. No other change.

**Check:** a Google create/link row reads `is_verified = 1`.

---

## Step 7 — `backend/app/api/routes/auth.py` (gate + 3 handlers + banner)

- Add `from app.services import verification_service` (config already imported).
- **`GET /signup`** and **`POST /signup`**: at the top, `if not config.is_email_configured(): return HTMLResponse(open(email_not_configured.html).read())`. (Helper to load a template by name keeps it DRY.)
- **`GET /check-email`**: load + return `check_email.html`.
- **`GET /verify`**: `token = request.query_params.get("token")`; `result = verification_service.verify_email_token(token)`; map result → `(title, message)`; load `verify_result.html`, splice `{{title}}`/`{{message}}` with `html.escape(..., quote=True)`; return `HTMLResponse`.
- **`POST /verify/resend`**: `user_id = request.session.get("user_id")`; `401` JSON if absent; else `return verification_service.resend_for_user(user_id)`.
- **`GET /welcome`**: after the auth gate, `SELECT is_verified FROM users WHERE id = ?`; `token = get_or_create_csrf_token(request)`; splice `{{username}}` (escaped, unchanged), `{{csrf_token}}` (escaped), and `{{verify_banner_hidden}}` = `""` if unverified else `"hidden"`.

**Check:** all routes reachable; `/verify` body never contains the raw token.

---

## Step 8 — `frontend/templates/` (3 new + dashboard banner)

- **`check_email.html`** (new): shared header + theme scripts; a `notice-card` with "Check your inbox", a short explanation, and a "Back to Login" button. No reflected input.
- **`verify_result.html`** (new): shared header + theme scripts; a `notice-card` with `<h2>{{title}}</h2>`, `<p>{{message}}</p>`, and "Go to Dashboard" (`/welcome`) + "Login" (`/login`) buttons.
- **`email_not_configured.html`** (new): mirror `oauth_not_configured.html` text — "Email verification isn't set up; copy `.env.example` to `.env` and set `SMTP_*` (see the README's *Email Verification — Setup*)." Static.
- **`dashboard.html`** (modified): as the first child of `<main class="dashboard-content">`, add:
  ```html
  <div id="verify-banner" class="verify-banner" {{verify_banner_hidden}}>
    <span class="verify-banner-text"><strong>Verify your email.</strong> We sent a confirmation link to your inbox — some features stay limited until you confirm.</span>
    <form id="resend-form" class="verify-banner-form">
      <input type="hidden" name="csrf_token" value="{{csrf_token}}">
      <button type="submit" class="btn btn-primary verify-resend-btn">Resend email</button>
    </form>
    <span id="resend-message" class="verify-banner-message" aria-live="polite"></span>
  </div>
  ```
  Add an inline `<script>` (sibling of the theme script) that binds `#resend-form` submit → `preventDefault()` → `fetch("/verify/resend", {method:"POST", body:new URLSearchParams(new FormData(form))})` → render `data.message`/`data.error` into `#resend-message` (toggle an `is-error`/`is-success` class).

**Check:** verified user → banner has `hidden`; unverified → visible with a 43-char token.

---

## Step 9 — `frontend/static/css/styles.css` (append)

Add theme-aware rules using existing custom properties:

```css
/* Email-verification banner (dashboard) */
.verify-banner { display:flex; align-items:center; gap:16px; flex-wrap:wrap;
  background:var(--color-bg-surface); border:1px solid var(--color-border-soft);
  border-left:4px solid var(--color-brand-secondary); border-radius:10px;
  padding:16px 20px; margin-bottom:24px; }
.verify-banner[hidden] { display:none; }
.verify-banner-text { color:var(--color-text-secondary); font-size:0.9rem; flex:1; min-width:240px; }
.verify-banner-form { margin:0; }
.verify-resend-btn { width:auto; padding:8px 18px; }
.verify-banner-message { font-size:0.85rem; }
.verify-banner-message.is-error { color:var(--color-error-text); }
.verify-banner-message.is-success { color:var(--color-success-text); }
```

(`check_email.html` / `verify_result.html` reuse the existing `.notice-wrap` / `.notice-card` / `.notice-text` classes — no new rules needed beyond the banner.)

---

## Step 10 — `.env.example` (append placeholders)

```
# --- Email Verification on Signup (SMTP) — copy to .env and fill in ----------
# Gmail: enable 2-Step Verification, then create an App Password.
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-address@gmail.com
SMTP_PASSWORD=your-16-char-app-password
SMTP_FROM=your-address@gmail.com
APP_BASE_URL=http://localhost:3001
# Optional: token lifetime in seconds (default 3600 = 1 hour)
# EMAIL_VERIFICATION_TTL_SECONDS=3600
```

Placeholders only; the real `.env` stays git-ignored.

---

## Step 11 — `README.md`

- **Feature Enhancements table:** change row #3 Status to **Done (v1.0.4)** and flesh out the description (stdlib SMTP, 1-hour single-use token, allow-login-but-restrict banner + resend, Google auto-verified, graceful not-configured page).
- **Done-features sentence** (above the table): add "Email Verification on Signup (v1.0.4)".
- **Releases & Versions table:** add a **v1.0.4** row.
- **API Endpoints table:** add `GET /check-email`, `GET /verify`, and `POST /verify/resend` (the last Auth-required).
- **New section "Email Verification — Setup"** (after "Continue with Google — Setup"): the Gmail App-Password steps + `.env` keys.
- **Remove** the two Continue-with-Google blockquote notes (the `🔒 .env is git-ignored…` note and the `📖 plain-English walkthrough…` note), per the explicit request.

---

## Step 12 — `CLAUDE.md`

- **Vulnerability Map:** add a note that the resend POST is covered by the existing rate-limit + CSRF middleware and that `/verify` is an intentionally GET token endpoint.
- **Frontend-Backend Integration:** add an "Email Verification on Signup (v1.0.4)" subsection summarizing the flow, the schema delta, the stdlib mailer, the not-configured degrade, and the Google auto-verify.
- **Important Rules:** add an entry — keep `verification_service.py` SQL parameterized (VULN-1); never log/leak the token or reflect it on `/verify` (VULN-3); SMTP secrets only in git-ignored `.env` (VULN-4); resend stays POST behind CSRF + rate-limit (VULN-7/8); `main.py` not modified; the migration stays additive/idempotent and keeps grandfathering.
- **Specification Hierarchy:** append entry #15 for this spec/plan pair.

---

## Step 13 — `docs/prompts/`

Save the generating prompts: `email-verification-spec-prompt.txt`, `email-verification-spec-plan-prompt.txt`, `email-verification-spec-execution-prompt.txt` (mirrors the existing per-feature prompt convention).

---

## Step 14 — Verification

Run the spec's §10 steps:
1. Unconfigured: `GET /signup` → not-configured page; 0 rows.
2. Configured: signup → `302 /check-email`; row `is_verified=0` + token; click link → `200` + `is_verified=1`, token cleared.
3. Banner + resend (`200`); resend without csrf → `403`.
4. File audit: `git diff --stat` empty for the forbidden files + lockfiles; `git status --porcelain` matches the declared set.
5. `uv run backend/app/main.py` boots clean configured **and** unconfigured.

---

## Risk / Rollback

- **Risk:** a bad SMTP App Password → signup succeeds but no email arrives. Mitigated by the resend banner and server-side logging; not a code defect.
- **Risk:** `APP_BASE_URL` mismatch → broken links. Documented in `.env.example` + README.
- **Rollback:** the feature is additive. Reverting the branch leaves the three nullable columns in any already-migrated DB (harmless) or one can `rm vulnerable_app.db`. No destructive migration is ever run.
