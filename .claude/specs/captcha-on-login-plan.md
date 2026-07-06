# Implementation Plan — CAPTCHA on Login (Cloudflare Turnstile)

**Spec:** [captcha-on-login.md](./captcha-on-login.md)
**Target Release Tag:** v2.0.0
**Feature #:** 8 (README "Feature Enhancements")

This plan turns the spec into ordered, surgical steps. It adds **one** new file (`core/captcha.py`), edits **two** code files (`core/config.py`, `api/routes/auth.py`), one template (`login.html`), one CSS file, and three doc files. **No** database change, **no** new dependency, and **no** edit to `auth_service.py` / `main.py` / the middleware modules.

Key facts grounding this plan (verified against the current tree):
- `GET /login` = `login_page` (`auth.py:209-221`) loads `login.html`, splices `{{csrf_token}}` via `html.escape(..., quote=True)`.
- `POST /login` = `login_post` (`auth.py:224-237`) just calls `return auth_service.login(request, username, password)`.
- `login.html` submits via `URLSearchParams(new FormData(form))` (`login.html:141`) and shows errors via `errorDiv.textContent = data.error` (`login.html:155`).
- `core/config.py` ends at the QR block (line ~182); the Google block (`config.py:69-87`) is the template for the Turnstile block + gate.
- Cloudflare's Turnstile script auto-injects a hidden `cf-turnstile-response` input into the enclosing `<form>`, so the existing submit picks the token up with **no JS change**.

---

## Step 0 — Branch & preconditions
- Work on `feature/captcha` (already checked out).
- Confirm the user's real `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` live in the git-ignored `.env` (they do). `.env.example` gets placeholders only.

## Step 1 — `backend/app/core/config.py` (settings + gate)
Append after the QR block (~line 182), mirroring the Google block:
```python
# --- Cloudflare Turnstile CAPTCHA settings (site key public; secret key IS a secret) ---
# Always-on CAPTCHA on POST /login when both keys are present; with neither set the
# login page renders no widget and the POST performs no check (graceful degrade,
# like the Google/SMTP blocks). The secret key is a real secret -- env/.env only,
# never committed, never logged. siteverify uses stdlib urllib (no new dependency).
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")
TURNSTILE_HTTP_TIMEOUT = float(os.environ.get("TURNSTILE_HTTP_TIMEOUT", "10"))


def is_captcha_configured() -> bool:
    """Return True only when both the site and secret keys are present.

    The login route uses this to decide whether to render + enforce the Turnstile
    widget or skip it entirely. Mirrors is_google_configured() / is_email_configured().
    """
    return bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY)
```
Also add CAPTCHA to the module docstring's numbered feature list (point 7).

## Step 2 — `backend/app/core/captcha.py` (new; stdlib siteverify, fail-open)
```python
"""Cloudflare Turnstile verification (stdlib urllib -- no new dependency).

The login route calls verify() BEFORE auth_service.login(), so a request that
fails the CAPTCHA never reaches the lockout gate, bcrypt, or the DB. Posture:

- Empty/missing token  -> block (False): the user did not solve the widget.
- success == true      -> allow (True).
- success == false     -> block (False): a definitive bot/invalid verdict.
- Any error (network/timeout/outage/non-JSON) -> ALLOW (True), fail-OPEN + warn.
  A CAPTCHA is a bot filter, not the authenticator; a transient provider outage
  must not lock out every legitimate user (same rationale as the rate limiter /
  account lockout; the OPPOSITE of CSRFMiddleware's fail-closed integrity gate).

remoteip is intentionally omitted (behind a proxy the client IP is the proxy's;
sending it is worse than sending none -- same stance as the rate limiter).
Never raises; never logs the secret key or the raw token.
"""
import json
import logging
import urllib.parse
import urllib.request

from app.core import config

logger = logging.getLogger(__name__)

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def verify(token: str) -> bool:
    if not token:
        return False
    data = urllib.parse.urlencode(
        {"secret": config.TURNSTILE_SECRET_KEY, "response": token}
    ).encode("utf-8")
    req = urllib.request.Request(
        TURNSTILE_VERIFY_URL,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=config.TURNSTILE_HTTP_TIMEOUT) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        return bool(result.get("success", False))
    except Exception:
        # Fail OPEN: a broken/unreachable provider must not deny all logins.
        logger.warning("Turnstile siteverify unreachable; failing open (allowing login).")
        return True
```

## Step 3 — `backend/app/api/routes/auth.py` (splice + gate)
- Add to the `core` imports near the top: `from app.core import captcha`.
- **`login_page` (GET):** after the existing `{{csrf_token}}` splice, add:
  ```python
  if config.is_captcha_configured():
      head = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
      widget = ('<div class="cf-turnstile" data-sitekey="'
                + html.escape(config.TURNSTILE_SITE_KEY, quote=True) + '"></div>')
  else:
      head = widget = ""
  page = page.replace("{{turnstile_head}}", head).replace("{{turnstile_widget}}", widget)
  ```
  (Confirm `config` is already imported in this module — it is, used by the OAuth/email routes.)
- **`login_post` (POST):** add the aliased Form param and the pre-check:
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
  (Confirm `JSONResponse` and `Form` are already imported in this module — they are, used by the OTP/2FA routes.)

## Step 4 — `frontend/templates/login.html` (additive placeholders, no JS change)
- In `<head>`, after `<link rel="stylesheet" ...>` (line 27): add a line `    {{turnstile_head}}`.
- Inside `<form id="login-form">`, after the password `form-group` (closes at line 88) and before the Sign In button (line 89): add `                    {{turnstile_widget}}`.
- Leave the submit JS untouched — Turnstile injects the hidden `cf-turnstile-response` field into the form and `URLSearchParams(new FormData(form))` already sends it; the `400` error renders via the existing `errorDiv` path.

## Step 5 — `frontend/static/css/styles.css` (small additive block)
Append:
```css
/* Cloudflare Turnstile widget (v2.0.0) -- additive; spacing only, theme-agnostic. */
.cf-turnstile {
    margin: 16px 0;
}
```

## Step 6 — `.env.example` (Turnstile block)
Append a block (its own section; the secret key is a real secret like the Google/SMTP blocks):
```bash
# CAPTCHA on Login (Cloudflare Turnstile, v2.0.0) — copy to `.env` and fill in.
#
# Adds a Turnstile widget to the login form; POST /login is verified server-side
# before any password check. With these UNSET the login page shows no widget and
# login works exactly as today (graceful degrade). The SITE key is public; the
# SECRET key is a real secret — the real `.env` is git-ignored, never commit it.
#
# Where to get these (free, no domain needed):
#   https://dash.cloudflare.com → Turnstile → Add widget
#   Hostname: localhost   (add your real domain for production)
#   Widget mode: Managed  → copy the Site Key and Secret Key below.
TURNSTILE_SITE_KEY=your-turnstile-site-key
TURNSTILE_SECRET_KEY=your-turnstile-secret-key

# Optional: siteverify network timeout in seconds (default 10).
# TURNSTILE_HTTP_TIMEOUT=10
```

## Step 7 — `README.md`
- **Releases table:** add a `v2.0.0` row (reference + CAPTCHA on Login).
- **Feature Enhancements table:** change row #8 status to **Done** and tag **v2.0.0**; update the "X are done … remaining are planned" prose above the table.
- Add a **"CAPTCHA on Login — Setup (optional)"** section (sibling to the Google/Email setup sections): Cloudflare steps (create widget → `localhost` hostname → Managed → copy keys → `.env`), plus a one-line production note (real-domain hostname + keys as host env vars; site/secret separation).
- Explicitly state **no API-endpoints-table change** (no new routes; `POST /login` path/method unchanged).
- Leave the Intentional-Vulnerabilities / Bug-Fixes tables unchanged (no vuln added/removed).

## Step 8 — `CLAUDE.md`
- **Frontend-Backend Integration:** add a **"CAPTCHA on Login (shipped in v2.0.0)"** bullet — Turnstile, always-on `POST /login` when configured, `core/captcha.py` stdlib-`urllib` `siteverify`, `is_captcha_configured()` degrade, **fail-OPEN** on provider error (rationale + bounded risk), `remoteip` omitted, **no schema change**, **no new dependency**, `auth_service.login()` untouched, all 8 vulns intact.
- **Important Rules:** add an entry pinning the invariants — verify stays **before** `auth_service.login()`; stdlib `urllib` only / no new dep; keys from env/`.env` only (secret never committed/logged); `.env` git-ignored + `.env.example` placeholder-only; site key `html.escape`-d on splice (VULN-2); token never reflected/logged (VULN-3); degrade-when-unconfigured + fail-open-on-error are deliberate; do **not** modify `main.py`/`db/session.py`/`auth_service.py`/`security.py`/`csrf.py`/`rate_limit.py`/`oauth.py`/`mailer.py`/`qr_login.py`.
- **Specification Hierarchy:** add item **20. `.claude/specs/captcha-on-login.md` + `-plan.md`**.

## Step 9 — Prompt docs
Create the three `docs/prompts/` files (spec / plan / execution prompts) per the naming convention.

## Step 10 — Verify (per spec §10)
1. **Unconfigured:** no keys → `GET /login` has no widget; correct pw → `200`.
2. **Configured happy path:** widget shown; solved + correct pw → `200`. (Use Cloudflare test keys for an automated pass/fail check.)
3. **Configured, no token:** scripted POST → `400 {"error": "CAPTCHA verification failed. Please try again."}`, no session.
4. **Fail-open:** verify host unreachable → correct pw still `200`, warning logged.
5. **Audits:** `git diff --stat` empty for the MUST-NOT list; `pyproject`/`uv.lock` unchanged; `PRAGMA table_info(users)` unchanged; `uv run backend/app/main.py` boots clean; all 8 vulns closed.

---

## Ordering rationale
Config (Step 1) before the service (Step 2) so `captcha.py` can import the settings; service before the route (Step 3) so the import resolves; route before the template (Step 4) so the placeholders have a producer; CSS/docs (5–9) are independent. Each step is individually testable and reversible.

## Risk notes
- **Blocking call in async handler:** the sync `urllib` verify runs inside `async login_post`; bounded by `TURNSTILE_HTTP_TIMEOUT` and consistent with the existing sync `auth_service.login()`/OAuth/SMTP calls in this single-worker lab (documented in NFR-08). If it ever matters, wrap in `starlette.concurrency.run_in_threadpool` — out of scope here.
- **Field-name alias:** `cf-turnstile-response` has hyphens, so the `Form(alias=...)` is required; without it FastAPI would look for `cf_turnstile_response` and always see `""` → every login would 400 when configured.
- **Both-keys gate:** `is_captcha_configured()` requires both keys, preventing a half-configured state from rendering a widget that can never verify (or verifying with no widget).
