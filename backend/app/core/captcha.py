"""Cloudflare Turnstile verification (stdlib urllib -- no new dependency).

The login route calls verify() BEFORE auth_service.login(), so a request that
fails the CAPTCHA never reaches the account-lockout gate, bcrypt, or the DB.

Posture:
- Empty/missing token  -> block (False): the user did not solve the widget. This
  is a USER failure, not a provider failure, so it is NOT fail-open.
- success == true       -> allow (True).
- success == false      -> block (False): a definitive bot/invalid verdict.
- Any error (network/timeout/outage/non-JSON) -> ALLOW (True), FAIL-OPEN + warn.
  A CAPTCHA is a bot filter, not the authenticator; a transient provider outage
  must not lock out every legitimate user (same rationale as the rate limiter /
  account lockout -- and the OPPOSITE of CSRFMiddleware's fail-closed integrity gate).

`remoteip` is intentionally omitted: behind a reverse proxy the request's client
IP is the proxy's, and sending a wrong IP is worse than sending none (same stance
as the rate limiter's "do not trust proxy headers blindly").

This module never raises and never logs the secret key or the raw token (VULN-3).
"""

import json
import logging
import urllib.parse
import urllib.request

from app.core import config

logger = logging.getLogger(__name__)

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def verify(token: str) -> bool:
    """Return True to ALLOW the login to proceed, False to BLOCK it.

    Callers should invoke this only when config.is_captcha_configured() is true.
    """
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
        # FAIL OPEN: a broken/unreachable provider must not deny all logins.
        # (Do not log the secret or token.)
        logger.warning(
            "Turnstile siteverify unreachable; failing open (allowing login)."
        )
        return True
