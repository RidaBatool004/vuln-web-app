# Implementation Plan — MFA via Authenticator App (TOTP)

**Spec:** [mfa-via-authenticator-app.md](./mfa-via-authenticator-app.md)
**Target Release Tag:** v1.0.7
**Branch:** `feature/mfa-via-authenticator-app`

This plan sequences the work so the app boots after every step and the eight closed vulnerabilities stay closed throughout. The one new dependency (`segno`) lands first, then backend primitives (config → schema → TOTP service), then the login branch, then the routes, then the profile-card edit + the new template, then docs. The session/CSRF/rate-limit/bcrypt middlewares, the OAuth path, the mailer, and the lockout/verification/**Email-OTP** services are **not** touched (except a single one-line `pending_2fa_method` marker added to `login()`'s existing Email-OTP branch — see Step 5).

---

## Step 0 — Preconditions

- Confirm branch `feature/mfa-via-authenticator-app` is checked out (it already is).
- Confirm `base64`, `hashlib`, `hmac`, `secrets`, `struct`, `time`, `urllib.parse`, `logging` are stdlib (no dependency change for the TOTP math).
- `segno` is the **only** new dependency, and only for QR-image rendering.
- No edits at any point to `main.py`, `core/rate_limit.py`, `core/csrf.py`, `core/security.py`, `core/mailer.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, `verification_service.py`, `otp_service.py`, `login.html`, `otp_verify.html`, `signup.html`, `dashboard.html`, or `styles.css`.

---

## Step 1 — Add the `segno` dependency

`pyproject.toml` — add to `dependencies`:
```toml
"segno>=1.6.0",
```
`backend/pyproject.toml` — add the same line to its `dependencies`.

Then regenerate the lockfile:
```bash
uv sync   # (or `uv lock`) — pulls segno into uv.lock
```

**Check:** `python -c "import segno; print(segno.__version__)"` succeeds. `uv.lock` now contains `segno` and **no** `pyotp`/`qrcode`/`pillow`.

---

## Step 2 — `backend/app/core/config.py` (TOTP settings)

Append a new block below the Email-OTP-2FA block:

```python
# --- MFA via Authenticator App (TOTP) settings (env-tunable, non-secret) ------
# When a user enrolls an authenticator app, a correct password issues a TOTP
# challenge instead of completing login. These are NOT secrets and have NO
# is_*_configured() gate -- TOTP needs neither SMTP nor Google, so the feature is
# always available with safe defaults. The per-user shared secret is generated
# at enrollment (secrets.token_bytes) and stored on the users row.
TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "Security Vulnerability Lab")
TOTP_PERIOD_SECONDS = int(os.environ.get("TOTP_PERIOD_SECONDS", "30"))
TOTP_SKEW_STEPS = int(os.environ.get("TOTP_SKEW_STEPS", "1"))
TOTP_DIGITS = 6        # fixed: authenticator-app default (not env-tunable).
TOTP_SECRET_BYTES = 20 # fixed: 160-bit secret (RFC 6238 norm), base32 in the QR.
```

Update the module docstring's opening sentence to mention TOTP alongside the existing features. No behaviour change to existing settings or gates.

**Check:** `python -c "from app.core import config; print(config.TOTP_ISSUER, config.TOTP_PERIOD_SECONDS, config.TOTP_SKEW_STEPS, config.TOTP_DIGITS, config.TOTP_SECRET_BYTES)"` → `Security Vulnerability Lab 30 1 6 20`.

---

## Step 3 — `backend/app/db/session.py` (additive migration, 3 columns)

In `CREATE TABLE IF NOT EXISTS users (...)` add the three columns (after `otp_last_sent`):

```
totp_secret                TEXT,
totp_enabled               INTEGER DEFAULT 0,
totp_last_step             INTEGER
```

In the `migrations` dict, add the three entries (no grandfather step — defaults already correct):

```python
migrations = {
    # ... existing google + verification + lockout + email-otp columns ...
    # MFA via Authenticator App (TOTP) feature (v1.0.7): three columns. Defaults
    # (NULL / 0 / NULL) already mean "no secret, TOTP off, never used", so -- like
    # the lockout/otp columns -- NO grandfather UPDATE is needed.
    "totp_secret": "ALTER TABLE users ADD COLUMN totp_secret TEXT",
    "totp_enabled": "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
    "totp_last_step": "ALTER TABLE users ADD COLUMN totp_last_step INTEGER",
}
```

Update the `init_db()` docstring's schema notes for the three new columns (mirroring the `otp_*` notes):
- `totp_secret`: base32 TOTP shared secret; set as *pending* on enrollment, persists while enrolled, NULL when off.
- `totp_enabled`: 1 only after a confirm code validated the secret; 0 while disabled or pending.
- `totp_last_step`: last accepted TOTP time-step counter (replay protection), NULL until first verify.

**Check:** `rm vulnerable_app.db`, boot, `PRAGMA table_info(users)` shows all three; on an old DB copy, existing rows read `NULL`/`0`/`NULL`, TOTP off.

---

## Step 4 — `backend/app/services/totp_service.py` (new)

Stdlib HOTP/TOTP + `segno` QR + parameterized SQL. Module docstring mirrors `otp_service.py` (security posture, replay note). Sketch:

```python
"""Authenticator-app TOTP 2FA helpers (enroll / confirm / verify / disable).

Implements README "Feature Enhancements" #5 (MFA via Authenticator App, v1.0.7).
TOTP math is RFC 4226/6238 in pure stdlib (hmac+hashlib+struct); only the QR
image uses `segno`. This is the only module that touches the totp_* columns. It
is the authenticator-app sibling of otp_service.py (Email OTP, v1.0.6); at login
TOTP takes precedence over Email OTP.

Security posture (all preserved from the closed vulnerabilities):
- VULN-1: every SELECT/UPDATE is parameterized.
- VULN-3: the login-time code is never returned to the client; it is compared
  server-side with secrets.compare_digest (constant-time). The enrollment secret
  is shown ONLY to the authenticated owner during setup (never logged).
- VULN-5: this runs AFTER bcrypt in login() -- a SECOND factor, not a password
  check. A wrong password never reaches the TOTP challenge.

A 6-digit code is low-entropy, so safety comes from: the small validity window,
the +/-TOTP_SKEW_STEPS tolerance, a replay guard (totp_last_step), and the
unchanged per-IP rate limiter. The 160-bit secret itself is infeasible to guess.
"""

import base64
import hashlib
import hmac
import logging
import secrets
import struct
import time
import urllib.parse

import segno

from app.core import config
from app.db.session import get_db

logger = logging.getLogger(__name__)


def generate_secret() -> str:
    """Uppercase, unpadded base32 secret from a 160-bit CSPRNG draw."""
    return base64.b32encode(secrets.token_bytes(config.TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 + dynamic truncation, zero-padded to TOTP_DIGITS."""
    # base32 decode needs correct padding; the secret is uppercase.
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** config.TOTP_DIGITS)).zfill(config.TOTP_DIGITS)


def _current_step(now: float | None = None) -> int:
    return int((now if now is not None else time.time()) // config.TOTP_PERIOD_SECONDS)


def _code_matches(secret: str, code: str) -> int | None:
    """Return the matched step (current +/- skew) for a valid code, else None.

    Constant-time compare against each candidate so a near-miss reveals nothing.
    """
    if not code or not secret:
        return None
    current = _current_step()
    for step in range(current - config.TOTP_SKEW_STEPS, current + config.TOTP_SKEW_STEPS + 1):
        if step < 0:
            continue
        if secrets.compare_digest(_hotp(secret, step), str(code)):
            return step
    return None


def provisioning_uri(secret: str, username: str) -> str:
    """otpauth://totp/<issuer>:<user>?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30"""
    label = urllib.parse.quote(f"{config.TOTP_ISSUER}:{username}")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": config.TOTP_ISSUER,
        "algorithm": "SHA1",
        "digits": config.TOTP_DIGITS,
        "period": config.TOTP_PERIOD_SECONDS,
    })
    return f"otpauth://totp/{label}?{params}"


def qr_data_uri(uri: str):
    """PNG data: URI for the otpauth URI via segno; None on any render error."""
    try:
        return segno.make(uri).png_data_uri(scale=5)
    except Exception:
        logger.exception("QR render failed")
        return None


def start_enrollment(user_id, username):
    """Generate + persist a PENDING secret (enabled stays 0); return QR/secret/URI."""
    secret = generate_secret()
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_last_step = NULL WHERE id = ?",
            [secret, user_id],
        )
        conn.commit()
    except Exception:
        logger.exception("totp start_enrollment failed for user_id=%s", user_id)
        return None
    finally:
        conn.close()
    uri = provisioning_uri(secret, username)
    return {"secret": secret, "otpauth_uri": uri, "qr_data_uri": qr_data_uri(uri)}


def confirm(user_id, code) -> dict:
    """Activate a pending secret if `code` is valid. {"status": ok|invalid|no_pending}."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT totp_secret FROM users WHERE id = ?", [user_id]
        ).fetchone()
        if not row or row["totp_secret"] is None:
            return {"status": "no_pending"}
        step = _code_matches(row["totp_secret"], code)
        if step is None:
            return {"status": "invalid"}
        conn.execute(
            "UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?",
            [step, user_id],
        )
        conn.commit()
        return {"status": "ok"}
    except Exception:
        logger.exception("totp confirm failed for user_id=%s", user_id)
        return {"status": "invalid"}
    finally:
        conn.close()


def verify(user_id, code) -> dict:
    """Login-time check. {"status": ok|invalid|no_challenge, "user": {...}|None}.

    Accepts only a code matching the current step +/- skew whose step is strictly
    greater than totp_last_step (replay guard); records the matched step on ok.
    """
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, totp_secret, totp_enabled, totp_last_step "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
        if not row or not row["totp_enabled"] or row["totp_secret"] is None:
            return {"status": "no_challenge", "user": None}
        step = _code_matches(row["totp_secret"], code)
        last = row["totp_last_step"]
        if step is None or (last is not None and step <= int(last)):
            return {"status": "invalid", "user": None}
        conn.execute(
            "UPDATE users SET totp_last_step = ? WHERE id = ?", [step, user_id]
        )
        conn.commit()
        return {"status": "ok", "user": {"id": row["id"], "username": row["username"], "email": row["email"]}}
    except Exception:
        logger.exception("totp verify failed for user_id=%s", user_id)
        return {"status": "invalid", "user": None}
    finally:
        conn.close()


def disable(user_id) -> bool:
    """Clear secret/flag/last-step. Returns False (not raise) on a DB error."""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL WHERE id = ?",
            [user_id],
        )
        conn.commit()
        return True
    except Exception:
        logger.exception("totp disable failed for user_id=%s", user_id)
        return False
    finally:
        conn.close()
```

**Check:** in a REPL, `s = generate_secret(); print(_code_matches(s, _hotp(s, _current_step())))` prints the current step (a non-None int); a wrong code prints `None`.

---

## Step 5 — `backend/app/services/auth_service.py` (`login()` TOTP branch)

Add `from app.services import totp_service` to the imports.

Inside `login()`, immediately **after** the `is_verified` gate and **before** the existing Email-OTP (`two_factor_enabled`) branch, insert the TOTP branch so it takes precedence:

```python
# Second factor #1 -- Authenticator App TOTP (v1.0.7): if the user enrolled an
# authenticator app, do NOT create the session yet. Stash the pending marker (NOT
# user_id, so /welcome and /profile stay gated) and send them to the TOTP screen.
# This runs AFTER bcrypt + the verified gate (true second factor) and BEFORE the
# Email-OTP branch, so TOTP takes precedence and NO email is sent. Auth stays
# session-only (no JWT): the session is promoted only after POST /login/totp.
if user["totp_enabled"]:
    request.session["pending_2fa_user_id"] = user["id"]
    request.session["pending_2fa_username"] = user["username"]
    request.session["pending_2fa_method"] = "totp"
    return JSONResponse(content={"otp_required": True, "redirect": "/login/totp"})
```

Then, in the existing Email-OTP branch (`if user["two_factor_enabled"]:`), add one line alongside the existing pending-marker writes so the screens can disambiguate (behaviour otherwise unchanged):

```python
request.session["pending_2fa_method"] = "email"
```

**Check:** with `totp_enabled=1`, a correct-password login returns `{"otp_required": true, "redirect": "/login/totp"}` and no email is sent; with `totp_enabled=0, two_factor_enabled=1`, the Email-OTP path is byte-identical to v1.0.6 (now also sets `pending_2fa_method="email"`).

---

## Step 6 — `backend/app/api/routes/auth.py` (5 new routes + profile read)

Add `from app.services import totp_service` to the imports.

**6a. `profile_page` — read TOTP state.** Extend the existing parameterized SELECT (or add one) to also fetch `totp_enabled`, and splice a `{{totp_enabled}}` flag (server-controlled `"0"`/`"1"`, like `{{twofa_enabled}}`):

```python
row = conn.execute(
    "SELECT two_factor_enabled, totp_enabled FROM users WHERE id = ?", [user_id]
).fetchone()
...
page = page.replace("{{totp_enabled}}", "1" if (row and row["totp_enabled"]) else "0")
```

**6b. Enrollment routes** (session-gated; CSRF + rate-limit ride the middleware):

```python
@router.post("/profile/totp/setup")
async def profile_totp_setup(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    username = request.session.get("username", "")
    # Re-enroll only after disabling, so an active secret is never overwritten mid-use.
    conn = get_db()
    try:
        row = conn.execute("SELECT totp_enabled FROM users WHERE id = ?", [user_id]).fetchone()
    finally:
        conn.close()
    if row and row["totp_enabled"]:
        return JSONResponse(
            content={"error": "Authenticator 2FA is already enabled. Disable it first to re-enroll."},
            status_code=400,
        )
    data = totp_service.start_enrollment(user_id, username)
    if not data:
        return JSONResponse(content={"error": "Could not start enrollment."}, status_code=400)
    return JSONResponse(content={"success": True, **data})


@router.post("/profile/totp/confirm")
async def profile_totp_confirm(request: Request, code: str = Form("")):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    result = totp_service.confirm(user_id, code)
    if result["status"] == "ok":
        return JSONResponse(content={"success": True, "message": "Authenticator app enabled."})
    msgs = {
        "invalid": "That code didn't match. Make sure your authenticator is set up and try the current code.",
        "no_pending": "Start setup first, then enter the code from your authenticator app.",
    }
    return JSONResponse(content={"error": msgs.get(result["status"], msgs["invalid"])}, status_code=400)


@router.post("/profile/totp/disable")
async def profile_totp_disable(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    if not totp_service.disable(user_id):
        return JSONResponse(content={"error": "Could not update the setting."}, status_code=400)
    return JSONResponse(content={"success": True, "message": "Authenticator app disabled."})
```

**6c. Login-time TOTP screen + verify** (mirrors `/login/otp`, gated on method):

```python
@router.get("/login/totp")
async def login_totp_page(request: Request):
    if not request.session.get("pending_2fa_user_id") or request.session.get("pending_2fa_method") != "totp":
        return RedirectResponse(url="/login", status_code=302)
    page = _load_template("totp_verify.html")
    token = get_or_create_csrf_token(request)   # FIXED: CSRF closed.
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    return HTMLResponse(content=page)


@router.post("/login/totp")
async def login_totp_post(request: Request, code: str = Form("")):
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )
    result = totp_service.verify(user_id, code)
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session.pop("pending_2fa_method", None)
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
    msgs = {
        "invalid": "Incorrect code. Open your authenticator app and try again.",
        "no_challenge": "No active authenticator challenge. Please sign in again.",
    }
    return JSONResponse(content={"error": msgs.get(result["status"], msgs["invalid"])}, status_code=401)
```

**Check:** routes appear in the OpenAPI/`/docs`; deep-linking `GET /login/totp` without the pending marker 302s to `/login`.

---

## Step 7 — `frontend/templates/totp_verify.html` (new)

Copy `otp_verify.html`'s structure (head theme IIFE, shared header, theme-toggle script) but: change the title/prompt to the authenticator-app wording, point the form at `/login/totp` with a `code` field, and **remove the resend button and its script** (no resend for TOTP). Core body:

```html
<main class="notice-wrap">
  <div class="notice-card">
    <h2 class="form-title">Enter your authenticator code</h2>
    <p class="form-subtitle">Open your authenticator app and enter the current 6-digit code to finish signing in.</p>
    <div id="error-message" class="error-message" style="display: none;"></div>
    <form id="totp-form">
      <input type="hidden" name="csrf_token" value="{{csrf_token}}">
      <div class="form-group">
        <label class="form-label" for="code">6-digit code</label>
        <input type="text" id="code" name="code" class="form-input" inputmode="numeric"
               autocomplete="one-time-code" maxlength="6" pattern="[0-9]*" placeholder="123456" required>
      </div>
      <button type="submit" class="btn btn-primary">Verify</button>
    </form>
    <p class="form-link"><a href="/login">Back to login</a></p>
  </div>
</main>
```

The submit handler is the `otp_verify.html` one minus resend: `URLSearchParams(new FormData(form))` → `fetch('/login/totp', {method:'POST', body})` → `data.success ? location = data.redirect : show error`.

**Check:** `/login/totp` (with a pending TOTP marker) renders the screen; the page source contains no secret/code.

---

## Step 8 — `frontend/templates/profile.html` (Authenticator-App card)

Add a third `profile-card` after the Email-OTP "Two-Factor Authentication" card (do **not** alter the existing cards). The card shows status + an Enable/Disable button; on Enable it reveals the QR `<img>`, the manual-entry key, and a confirm-code input. Initial state from the server-spliced `{{totp_enabled}}` flag.

```html
<!-- Authenticator App (TOTP, v1.0.7) -->
<div class="profile-card">
  <h2 class="section-title">Authenticator App (TOTP)</h2>
  <p class="notice-text" id="totp-status">Authenticator-app 2FA is currently <strong id="totp-state">…</strong>.</p>
  <p class="form-subtitle">Scan the QR with Google Authenticator, Authy, or similar, then confirm a code. No email needed.</p>
  <div id="totp-message" class="profile-message" role="status" aria-live="polite" style="display:none;"></div>

  <div id="totp-enroll" style="display:none;">
    <img id="totp-qr" alt="Authenticator QR code" style="max-width:200px;">
    <p class="form-subtitle">Manual key: <code id="totp-secret"></code></p>
    <form id="totp-confirm-form">
      <input type="hidden" name="csrf_token" value="{{csrf_token}}">
      <div class="form-group">
        <label class="form-label" for="totp-code">Enter the 6-digit code</label>
        <input type="text" id="totp-code" name="code" class="form-input" inputmode="numeric"
               maxlength="6" pattern="[0-9]*" placeholder="123456">
      </div>
      <button type="submit" class="btn btn-primary">Confirm &amp; enable</button>
    </form>
  </div>

  <form id="totp-toggle-form">
    <input type="hidden" name="csrf_token" value="{{csrf_token}}">
    <button type="submit" class="btn btn-primary" id="totp-btn">…</button>
  </form>
</div>
```

Add one inline `<script>` (sibling to the Email-OTP one) that:
- reads `var enabled = '{{totp_enabled}}' === '1';` and renders state/button (`Disable 2FA` when enabled, `Set up authenticator` when not);
- on the toggle submit: if enabled → POST `/profile/totp/disable` (urlencoded, hidden `csrf_token`) and flip to disabled; if disabled → POST `/profile/totp/setup`, then on success show `#totp-enroll`, set `#totp-qr` `src` to `data.qr_data_uri` (fall back to showing only the manual key when `null`), and set `#totp-secret` text to `data.secret`;
- on the confirm-form submit: POST `/profile/totp/confirm` with the `code`; on success hide `#totp-enroll`, set `enabled = true`, re-render.

All POSTs use `new URLSearchParams(new FormData(form))` so the CSRF middleware's urlencoded parser accepts them (same pattern as the change-password and Email-OTP forms). No CSS change — reuse `profile-card`, `form-group`, `btn`, `profile-message`.

**Check:** the card shows "disabled" → Set up reveals a scannable QR + key → entering the app's code flips it to "enabled"; reload shows "enabled" with a Disable button.

---

## Step 9 — `.env.example`

Append commented placeholders with defaults (values, not secrets):

```bash
# --- MFA via Authenticator App (TOTP), optional (v1.0.7) ---
# TOTP needs no SMTP/Google; these only tune the label and tolerances.
# TOTP_ISSUER="Security Vulnerability Lab"
# TOTP_PERIOD_SECONDS=30
# TOTP_SKEW_STEPS=1
```

---

## Step 10 — Docs (`README.md`, `CLAUDE.md`)

`README.md`:
- Move "Feature Enhancements" row #5 (MFA via Authenticator App) to **Done (v1.0.7)** with a description mirroring the other Done rows (independent of Email OTP, TOTP wins; QR enrollment via `segno`; confirm-code step; no recovery codes; fifth schema change, 3 columns; one new dependency).
- Add a **v1.0.7** anchor row to the "Releases & Versions" table and the incremental note below it.
- Add the five routes to the API-endpoints table (`POST /profile/totp/setup|confirm|disable`, `GET`/`POST /login/totp`).
- Note the `segno` dependency (the first since Authlib) and a one-line "Authenticator App (TOTP) — Setup" mention that it needs no SMTP/Google.

`CLAUDE.md`:
- Add a **"MFA via Authenticator App (TOTP)" (v1.0.7)** bullet to the Frontend-Backend Integration list (mirroring the Email-OTP bullet: routes, columns, login precedence, session-only, stdlib-TOTP + `segno`-for-QR-only, parameterized SQL, code-never-reflected, secret-owner-only, no-recovery non-goal, session-gated toggle, files not modified).
- Add an **Important-Rules** entry capturing the permanent invariants: parameterized SQL; TOTP branch stays **after** bcrypt + verified gate and **before** Email OTP; secret via `secrets.token_bytes`, stored on `users`, never reflected/logged; login code never reflected; session-only (no JWT), `pending_2fa_user_id`/`pending_2fa_method` handshake; replay guard via `totp_last_step`; enrollment requires a confirm code; `segno` is the only new dep (no `pyotp`); do **not** modify `main.py`/`security.py`/`csrf.py`/`rate_limit.py`/`mailer.py`/the OAuth path/`otp_service.py`; the migration stays additive/idempotent (no grandfather).
- Add the spec/plan pair to the **Specification Hierarchy** list (item 18).

---

## Step 11 — Full Verification (spec §8 / §9 / §10)

1. `rm vulnerable_app.db`; `uv run backend/app/main.py` boots with no traceback (AC-16).
2. `PRAGMA table_info(users)` shows the three new columns at defaults (AC-01).
3. Non-2FA login still returns `200 …/welcome` (AC-03).
4. Setup → scan → confirm flips `totp_enabled=1` (AC-04, AC-05); login then routes to `/login/totp` with no email (AC-06); `/welcome` is gated while only the pending marker is set (AC-07); a valid app code completes login and updates `totp_last_step` (AC-08); a wrong/replayed code is refused (AC-09).
5. With both factors on, login goes to `/login/totp` (AC-10); disable clears the columns (AC-11).
6. Grep the running logs + responses: no secret in logs, no code in any response/page (AC-12).
7. `git diff --stat` empty for all forbidden files (AC-14); only `segno` added to the manifests (AC-15); SQL is parameterized (AC-13).
8. README/CLAUDE updated (AC-18).

---

## Sequencing Rationale

- **Dependency first (Step 1)** so every later step can `import segno`.
- **Config → schema → service (Steps 2–4)** are pure additions; the app boots unchanged after each.
- **Login branch (Step 5)** only activates for rows with `totp_enabled=1`, which none have yet, so existing logins are unaffected until a user enrolls.
- **Routes (Step 6)** expose enrollment/verify; **templates (Steps 7–8)** make them usable.
- **Docs (Steps 9–10)** last, once behaviour is final.
- At no point is a forbidden file touched, and the eight closed vulnerabilities remain closed throughout (parameterized SQL, bcrypt-before-second-factor, unchanged middlewares, no code reflection).
```
