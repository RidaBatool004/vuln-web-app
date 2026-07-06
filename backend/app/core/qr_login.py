"""In-memory store for QR Code Login (README "Feature Enhancements" #7, v1.0.8).

An unauthenticated browser (the *desktop*) is shown a QR on ``/login`` and polls
for approval; an already-authenticated device (the *phone*) scans it and
approves, and the desktop is then logged in via the SAME signed session cookie
the password flow uses (the WhatsApp-Web pattern). This module is the ephemeral
pairing store -- the same "module-level dict guarded by a lock, reset on restart"
shape as ``core/rate_limit.py``. There is no DB row and no schema change.

Lifecycle of a token::

    create_token() -> "pending"
        approve(...) -> "approved"   (records the approver's identity)
        reject(...)  -> "rejected"
    claim() consumes an "approved" token (single-use) and returns the identity.
    Any token older than config.QR_LOGIN_TTL_SECONDS is purged lazily on access.

Security posture (all preserved from the closed vulnerabilities):
- **No SQL at all** -- state is in-memory + the signed session, so there is
  nothing to inject (VULN-1 is N/A here, not relaxed).
- Tokens are ``secrets.token_urlsafe(32)`` (256-bit), **single-use** (``claim``
  deletes), and short-lived (``config.QR_LOGIN_TTL_SECONDS``).
- **Owner-binding** is enforced in the route layer (``GET /qr/status``): only the
  browser that created a token can be promoted by it, which closes the login-CSRF
  / session-fixation vector a naive scan-to-login design would open.
- The raw token is never reflected into a page as executable markup; the only use
  of the ``segno`` dependency here is rendering the scannable QR image.

This module is intentionally process-local: a restart (or a second worker)
empties the store, so pending QRs read as expired/invalid and the page simply
shows a fresh one. That is acceptable for the lab and needs no Redis/disk.
"""

import logging
import secrets
import threading
import time

import segno

from app.core import config

logger = logging.getLogger(__name__)

# token -> {"status", "user_id", "username", "email", "expires"}.
# "expires" is a time.monotonic() deadline (immune to wall-clock changes).
_STORE = {}
_LOCK = threading.Lock()


def _purge_locked(now: float) -> None:
    """Drop every entry past its expiry. Caller MUST hold ``_LOCK``."""
    for token in [t for t, e in _STORE.items() if e["expires"] <= now]:
        del _STORE[token]


def create_token() -> str:
    """Mint a fresh ``pending`` token valid for ``QR_LOGIN_TTL_SECONDS``."""
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
    """``pending`` -> ``approved`` with the approver's identity.

    Returns ``True`` on success, ``False`` for an unknown / expired / already-acted
    token (the approver must be authenticated -- the route enforces that).
    """
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        entry = _STORE.get(token)
        if not entry or entry["status"] != "pending":
            return False
        entry.update(
            status="approved", user_id=user_id, username=username, email=email
        )
        return True


def reject(token: str) -> bool:
    """``pending`` -> ``rejected``. Returns ``True``/``False``."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        entry = _STORE.get(token)
        if not entry or entry["status"] != "pending":
            return False
        entry["status"] = "rejected"
        return True


def status(token: str) -> str:
    """Return the live status, or ``"invalid"`` for unknown/expired. No mutation."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        entry = _STORE.get(token)
        return entry["status"] if entry else "invalid"


def get(token: str):
    """Return a snapshot copy of the entry (for the scan route) or ``None``."""
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        entry = _STORE.get(token)
        return dict(entry) if entry else None


def claim(token: str):
    """Single-use consume of an ``approved`` token.

    Returns ``{"user_id", "username", "email"}`` and **deletes** the token so it
    cannot be replayed; returns ``None`` if the token is not currently approved.
    """
    now = time.monotonic()
    with _LOCK:
        _purge_locked(now)
        entry = _STORE.get(token)
        if not entry or entry["status"] != "approved":
            return None
        del _STORE[token]
        return {
            "user_id": entry["user_id"],
            "username": entry["username"],
            "email": entry["email"],
        }


def render_qr(text: str):
    """PNG ``data:`` URI for ``text`` via ``segno``; ``None`` on any render error.

    The only use of the ``segno`` dependency in this module. Fail-safe: a render
    error returns ``None`` so the login page can fall back to showing the URL.
    """
    try:
        return segno.make(text).png_data_uri(scale=5)
    except Exception:
        logger.exception("QR render failed")
        return None
