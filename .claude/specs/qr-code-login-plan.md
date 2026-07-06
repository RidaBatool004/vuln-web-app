# Implementation Plan — QR Code Login

**Spec:** [qr-code-login.md](./qr-code-login.md)
**Target Release Tag:** v1.0.8
**Branch:** `feature/qr-code-login`

This plan sequences the work so the app boots after every step and the eight closed vulnerabilities stay closed throughout. There is **no new dependency** (QR images reuse `segno`, present since v1.0.7) and **no schema change** (state is in-memory + signed session). Order: config → in-memory store → routes → templates (login panel + approve page) → CSS → docs. `main.py`, `db/session.py`, `auth_service.py`, every middleware, and every other service/template are **not** touched.

---

## Step 0 — Preconditions

- Confirm branch `feature/qr-code-login` is checked out (it already is).
- Confirm `secrets`, `time`, `threading`, `logging` are stdlib (no dependency change) and `segno` is already a dependency (from v1.0.7) — `python -c "import segno"` succeeds.
- No edits at any point to `main.py`, `db/session.py`, `auth_service.py`, `core/security.py`, `core/csrf.py`, `core/rate_limit.py`, `core/mailer.py`, `core/oauth.py`, `oauth_service.py`, `lockout_service.py`, `verification_service.py`, `otp_service.py`, `totp_service.py`, or any template except `login.html` / the new `qr_approve.html`.

---

## Step 1 — `backend/app/core/config.py` (QR settings)

Append a new block below the TOTP block:

```python
# --- QR Code Login settings (env-tunable, non-secret) ------------------------
# An unauthenticated browser is shown a QR on /login; an already-authenticated
# device scans it and approves, logging the first browser in. State is in-memory
# (core/qr_login.py) and the signed session -- NO DB schema change, NO new
# dependency (the QR image reuses `segno`). These are NOT secrets and have NO
# is_*_configured() gate -- QR login needs no SMTP/Google. The scannable URL is
# built from the existing APP_BASE_URL (set it to an address the scanner can
# reach for a real cross-device test; on localhost use a second logged-in browser).
QR_LOGIN_TTL_SECONDS = int(os.environ.get("QR_LOGIN_TTL_SECONDS", "120"))
QR_LOGIN_POLL_INTERVAL_SECONDS = int(os.environ.get("QR_LOGIN_POLL_INTERVAL_SECONDS", "2"))
```

Update the module docstring's opening sentence to mention QR Code Login alongside the existing features. `APP_BASE_URL` is reused as-is (no redefinition).

**Check:** `python -c "from app.core import config; print(config.QR_LOGIN_TTL_SECONDS, config.QR_LOGIN_POLL_INTERVAL_SECONDS, config.APP_BASE_URL)"` → `120 2 http://localhost:3001`.

---

## Step 2 — `backend/app/core/qr_login.py` (new, in-memory store)

Mirrors `core/rate_limit.py`'s "module-level dict + lock + lazy purge" style. Stdlib only + `segno` for the QR image. Sketch:

```python
"""In-memory store for QR Code Login (README "Feature Enhancements" #7, v1.0.8).

An unauthenticated browser (the *desktop*) is shown a QR on /login and polls for
approval; an already-authenticated device (the *phone*) scans it and approves,
and the desktop is then logged in via the SAME signed session cookie the password
flow uses. This module is the ephemeral pairing store -- the same "module-level
dict guarded by a lock, reset on restart" pattern as core/rate_limit.py.

Security posture (all preserved from the closed vulnerabilities):
- No SQL at all (state is in-memory + the signed session) -- nothing to inject.
- Tokens are secrets.token_urlsafe(32) (256-bit), single-use (claim() deletes),
  and short-lived (config.QR_LOGIN_TTL_SECONDS).
- Owner-binding (enforced in the route layer): only the browser that created a
  token can be promoted by it -- closes the login-CSRF / session-fixation vector.
- The raw token is never reflected as executable markup; the only QR use of the
  `segno` dependency is rendering the scannable image.
"""

import logging
import secrets
import threading
import time

import segno

from app.core import config

logger = logging.getLogger(__name__)

_STORE = {}                 # token -> {status, user_id, username, email, expires}
_LOCK = threading.Lock()


def _purge_locked(now: float) -> None:
    expired = [t for t, e in _STORE.items() if e["expires"] <= now]
    for t in expired:
        del _STORE[t]


def create_token() -> str:
    """Mint a pending token valid for QR_LOGIN_TTL_SECONDS."""
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        _STORE[token] = {
            "status": "pending",
            "user_id": None,
            "username": None,
            "email": None,
            "expires": now + config.QR_LOGIN_TTL_SECONDS,
        }
    return token


def approve(token: str, user_id, username: str, email: str) -> bool:
    """pending -> approved with the approver's identity. False on any other case."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        e = _STORE.get(token)
        if not e or e["status"] != "pending":
            return False
        e.update(status="approved", user_id=user_id, username=username, email=email)
        return True


def reject(token: str) -> bool:
    """pending -> rejected. False on any other case."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        e = _STORE.get(token)
        if not e or e["status"] != "pending":
            return False
        e["status"] = "rejected"
        return True


def status(token: str) -> str:
    """'pending'|'approved'|'rejected' for live tokens, else 'expired'/'invalid'. No mutation."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        e = _STORE.get(token)
        return e["status"] if e else "invalid"


def get(token: str):
    """Snapshot copy of the entry (for the scan route to validate) or None."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        e = _STORE.get(token)
        return dict(e) if e else None


def claim(token: str):
    """Single-use: if approved, delete and return {user_id, username, email}; else None."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        e = _STORE.get(token)
        if not e or e["status"] != "approved":
            return None
        del _STORE[token]
        return {"user_id": e["user_id"], "username": e["username"], "email": e["email"]}


def render_qr(text: str):
    """PNG data: URI for `text` via segno; None on any render error (page falls back to the URL)."""
    try:
        return segno.make(text).png_data_uri(scale=5)
    except Exception:
        logger.exception("QR render failed")
        return None
```

**Check:** in a REPL: `t = create_token(); print(status(t))` → `pending`; `approve(t, 1, "alice", "a@x.com")` → `True`; `print(status(t))` → `approved`; `print(claim(t))` → the dict; `print(status(t))` → `invalid` (consumed).

---

## Step 3 — `backend/app/api/routes/auth.py` (5 new routes)

Add `from app.core import qr_login` to the imports (alongside the existing `from app.core import config`).

**3a. Create + owner-binding** (GET; unauthenticated capability vendor):

```python
@router.get("/qr/create")
async def qr_create(request: Request):
    """Vend a fresh QR-login token, bound to THIS browser's session.

    GET on purpose: it vends an unauthenticated capability that is useless until an
    authenticated device approves it. Binding the token to request.session
    ("qr_login_token") is what later lets ONLY this browser be logged in by it
    (owner-binding -- closes login-CSRF). The QR encodes APP_BASE_URL/qr/scan/<token>
    so the same image works for a second browser (localhost) or a real phone (deployed).
    """
    token = qr_login.create_token()
    request.session["qr_login_token"] = token
    qr_url = f"{config.APP_BASE_URL}/qr/scan/{token}"
    return JSONResponse(content={
        "token": token,
        "qr_url": qr_url,
        "qr_data_uri": qr_login.render_qr(qr_url),
        "poll_interval": config.QR_LOGIN_POLL_INTERVAL_SECONDS,
        "expires_in": config.QR_LOGIN_TTL_SECONDS,
    })
```

**3b. Status poll completes the login (owner-bound)** (GET):

```python
@router.get("/qr/status")
async def qr_status(request: Request, token: str = ""):
    """Desktop poll. Owner-bound: only the browser that created `token` is promoted.

    On 'approved' it claims the (single-use) token, writes the SAME session keys as
    auth_service.login() (so /welcome/ /profile open), and returns a redirect. A
    GET that promotes the session -- justified like the OAuth/verify GET callbacks,
    and additionally gated by the unguessable token AND owner-binding, so a cross-site
    GET in a victim's browser (no matching qr_login_token) is ignored (VULN-4/CSRF).
    """
    if not token or request.session.get("qr_login_token") != token:
        return JSONResponse(content={"status": "invalid"})
    st = qr_login.status(token)
    if st == "approved":
        identity = qr_login.claim(token)
        if not identity:
            return JSONResponse(content={"status": "expired"})
        request.session.pop("qr_login_token", None)
        request.session["user_id"] = identity["user_id"]
        request.session["username"] = identity["username"]
        request.session["email"] = identity["email"]
        return JSONResponse(content={"status": "approved", "redirect": "/welcome"})
    return JSONResponse(content={"status": st})
```

**3c. Scan landing (phone, session-gated)** (GET):

```python
@router.get("/qr/scan/{token}")
async def qr_scan(request: Request, token: str):
    """Phone landing page the QR encodes. Must be logged in to approve a device.

    Renders qr_approve.html with the HTML-escaped approver username, the token, and a
    CSRF token. An unknown/expired/acted-on token renders a fixed "no longer valid"
    state with the buttons hidden (the raw token is never reflected -- VULN-3).
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    username = request.session.get("username", "")
    entry = qr_login.get(token)
    valid = bool(entry and entry["status"] == "pending")
    page = _load_template("qr_approve.html")
    csrf = get_or_create_csrf_token(request)   # FIXED: CSRF closed.
    page = page.replace("{{csrf_token}}", html.escape(csrf, quote=True))
    page = page.replace("{{token}}", html.escape(token, quote=True))
    page = page.replace("{{username}}", html.escape(username, quote=True))
    page = page.replace("{{valid}}", "1" if valid else "0")
    return HTMLResponse(content=page)
```

**3d. Approve / Reject** (POST; session-gated; CSRF + rate-limit via middleware):

```python
@router.post("/qr/approve")
async def qr_approve_post(request: Request, token: str = Form("")):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    ok = qr_login.approve(
        token, user_id,
        request.session.get("username", ""), request.session.get("email", ""),
    )
    if ok:
        return JSONResponse(content={"success": True, "message": "Login approved. Return to the other device."})
    return JSONResponse(content={"error": "This QR code has expired or was already used."}, status_code=400)


@router.post("/qr/reject")
async def qr_reject_post(request: Request, token: str = Form("")):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    qr_login.reject(token)
    return JSONResponse(content={"success": True, "message": "Login request denied."})
```

> Route-ordering note: declare `/qr/create` and `/qr/status` (static paths) and `/qr/scan/{token}` (dynamic) so the static ones are not shadowed. FastAPI matches in declaration order; keeping `scan/{token}` under a distinct `/qr/scan/` prefix avoids any collision with `/qr/create` and `/qr/status`.

**Check:** the five routes appear in `/docs`; `GET /qr/scan/x` while logged out 302s to `/login`; `GET /qr/status?token=x` with no owned token returns `{"status": "invalid"}`.

---

## Step 4 — `frontend/templates/qr_approve.html` (new)

Copy another notice page's structure (head theme IIFE, shared header, theme-toggle script). Body: a card naming the account, with an Approve/Reject form. Spliced `{{valid}}` flag hides the form when the token is no longer valid.

```html
<main class="notice-wrap">
  <div class="notice-card">
    <h2 class="form-title">Approve sign-in?</h2>
    <p class="form-subtitle">A device is trying to sign in as <strong>{{username}}</strong>.
       Approve only if this is you.</p>
    <div id="qr-message" class="profile-message" role="status" aria-live="polite" style="display:none;"></div>

    <div id="qr-actions" data-valid="{{valid}}">
      <form id="qr-approve-form">
        <input type="hidden" name="csrf_token" value="{{csrf_token}}">
        <input type="hidden" name="token" value="{{token}}">
        <button type="submit" class="btn btn-primary">Approve</button>
      </form>
      <form id="qr-reject-form">
        <input type="hidden" name="csrf_token" value="{{csrf_token}}">
        <input type="hidden" name="token" value="{{token}}">
        <button type="submit" class="btn btn-secondary">Reject</button>
      </form>
    </div>

    <p id="qr-invalid" style="display:none;">This QR code is no longer valid. Generate a new one on the other device.</p>
    <p class="form-link"><a href="/welcome">Back to dashboard</a></p>
  </div>
</main>
```

Inline `<script>`: if `#qr-actions[data-valid] === "0"` → hide the forms and show `#qr-invalid`. Otherwise wire both forms: `new URLSearchParams(new FormData(form))` → `fetch('/qr/approve' | '/qr/reject', {method:'POST', body})` → on success hide the forms and show the returned message in `#qr-message`. Same `URLSearchParams` + hidden `csrf_token` pattern as the profile/OTP forms.

**Check:** scanning a valid token shows Approve/Reject; an invalid token shows the "no longer valid" message; the page source contains no raw, unescaped username.

---

## Step 5 — `frontend/templates/login.html` (additive QR panel)

Below the existing password form and the "Continue with Google" block (do **not** alter either), add the panel:

```html
<div class="qr-panel">
  <div class="divider"><span>or scan to sign in</span></div>
  <img id="qr-image" alt="Login QR code" style="display:none;">
  <p id="qr-hint" class="form-subtitle">Loading QR…</p>
  <p id="qr-url" class="form-subtitle" style="word-break:break-all;"></p>
  <button type="button" id="qr-refresh" class="btn btn-secondary" style="display:none;">Show new QR</button>
</div>
```

Add one inline `<script>` that:
- `async function newQr()` → `fetch('/qr/create')` → set `#qr-image.src = data.qr_data_uri` (show it), put `data.qr_url` text in `#qr-url`, hide `#qr-refresh`, store `token` + `poll_interval`, and start polling;
- `poll()` → `fetch('/qr/status?token=' + encodeURIComponent(token))` →
  - `approved` → `location = data.redirect`;
  - `pending` → `setTimeout(poll, poll_interval*1000)`;
  - `rejected`/`expired`/`invalid` → stop, set `#qr-hint` to a message, show `#qr-refresh`;
- `#qr-refresh` click → `newQr()`; call `newQr()` once on load.

No change to the password/Google scripts. (If `data.qr_data_uri` is `null`, leave `#qr-image` hidden and rely on the `#qr-url` text — EC-09.)

**Check:** `/login` shows a QR that, once approved from another logged-in browser, navigates the page to `/welcome`; letting it expire shows "Show new QR".

---

## Step 6 — `frontend/static/css/styles.css` (additive `.qr-panel`)

Append a small block (no existing rule edited), reusing theme custom properties so it works in light/dark:

```css
/* QR Code Login panel (v1.0.8) -- additive; reuses theme variables. */
.qr-panel { margin-top: 1.5rem; text-align: center; }
.qr-panel #qr-image { max-width: 200px; margin: 0.5rem auto; display: block; }
```

(If `.divider` already exists from the Google block, reuse it; otherwise the panel degrades gracefully without it.)

**Check:** the QR panel is centered and themed in both light and dark mode; no other component shifts.

---

## Step 7 — `.env.example`

Append commented placeholders with defaults (values, not secrets):

```bash
# --- QR Code Login, optional tuning (v1.0.8) ---
# No SMTP/Google needed. For a real cross-device scan, set APP_BASE_URL (above) to
# an address the scanning device can reach (LAN IP or public origin), not localhost.
# QR_LOGIN_TTL_SECONDS=120
# QR_LOGIN_POLL_INTERVAL_SECONDS=2
```

---

## Step 8 — Docs (`README.md`, `CLAUDE.md`)

`README.md`:
- Move "Feature Enhancements" row #7 (QR Code Login) to **Done (v1.0.8)** with a description mirroring the other Done rows (scan-to-login from an already-authenticated device; in-memory store, **no schema change**; **no new dependency** — QR reuses `segno`; short-lived single-use token; owner-binding closes login-CSRF; 2FA satisfied on the approving device; session-only, no JWT).
- Add a **v1.0.8** anchor row to the "Releases & Versions" table and the incremental note below it.
- Add the five routes to the API-endpoints table (`GET /qr/create`, `GET /qr/status`, `GET /qr/scan/{token}`, `POST /qr/approve`, `POST /qr/reject`).
- A one-line "QR Code Login — Setup" mention that it needs no SMTP/Google but, for a real phone scan, `APP_BASE_URL` must be reachable from the phone.

`CLAUDE.md`:
- Add a **"QR Code Login" (v1.0.8)** bullet to the Frontend-Backend Integration list (routes; in-memory `core/qr_login.py` store like `rate_limit.py`; **no schema change, no new dependency**; owner-binding; session-only; confirm-step + session-gated approval; 2FA-on-approver model; files not modified).
- Add an **Important-Rules** entry capturing the permanent invariants: QR-login state stays **in-memory + signed session** (no DB column, no `db/session.py` change); tokens are `secrets.token_urlsafe(32)`, single-use, short-TTL; **owner-binding** (`qr_login_token` in the creator's session) MUST gate `GET /qr/status` promotion (login-CSRF defense — do not remove); approve/reject stay **session-gated POSTs** behind CSRF; the scan page MUST `html.escape` the username and never reflect the raw token; auth stays **session-only** (no JWT) and `auth_service.login()` is **not** modified; QR images reuse **`segno`** (no new dependency); do **not** modify `main.py`/`db/session.py`/the middlewares/the OAuth/OTP/TOTP paths.
- Add the spec/plan pair to the **Specification Hierarchy** list (item 19).

---

## Step 9 — Full Verification (spec §8 / §9 / §10)

1. `uv run backend/app/main.py` boots with no traceback; a normal password login still succeeds (AC-13).
2. `git diff` empty for `db/session.py` and all forbidden files (AC-01, AC-12); no new dependency added (AC-12, TC-19).
3. `GET /qr/create` returns the token/url/data-uri/interval/expiry and sets `qr_login_token` (AC-03).
4. Scan logged-out → `302 /login`; logged-in → confirm page with escaped username + CSRF (AC-04).
5. Approve → token `approved`; desktop poll flips to `{"status":"approved","redirect":"/welcome"}` and writes `user_id`; second poll → `invalid` (AC-05, AC-07, single-use).
6. Reject → poll `rejected`; expiry → poll `expired`; "Show new QR" re-creates (AC-06, AC-09).
7. Owner-binding: a non-owner poll of an approved token → `invalid`, no login (AC-08, SP-05).
8. No raw token reflected; username escaped; fixed JSON messages (AC-10); tokens are `token_urlsafe(32)`, single-use, TTL-bound (AC-11).
9. CSRF on the two POSTs (`403` without token); rate-limited like any POST (`429`) (AC-14, TC-16, TC-17).
10. README/CLAUDE updated (AC-15).

---

## Sequencing Rationale

- **Config → store (Steps 1–2)** are pure additions; the app boots unchanged after each.
- **Routes (Step 3)** are inert until the front-end calls them; no existing route changes.
- **Templates + CSS (Steps 4–6)** make the flow usable; `login.html`'s change is strictly additive (password/Google untouched).
- **Docs (Steps 7–8)** last, once behaviour is final.
- At no point is a forbidden file touched, `db/session.py` is never modified (no schema change), no new dependency is added, and the eight closed vulnerabilities remain closed throughout (no SQL added, bcrypt/session/CSRF/rate-limit middlewares unchanged, no `/download/db`, env-sourced config, no token reflection, owner-binding closing login-CSRF).
```
