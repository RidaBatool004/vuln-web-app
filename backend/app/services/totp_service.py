"""Authenticator-app TOTP 2FA helpers (enroll / confirm / verify / disable).

Implements README "Feature Enhancements" #5 (MFA via Authenticator App, v1.0.7).
When a user enrolls an authenticator app, a correct password does NOT complete
login: this module verifies the current time-based code (RFC 6238) from the app
on the ``/login/totp`` screen, and login finishes only after it matches.

TOTP math (RFC 4226 HOTP + RFC 6238 TOTP) is implemented in PURE STDLIB
(``hmac`` + ``hashlib`` + ``struct`` + ``base64``) -- there is no ``pyotp``. The
ONLY third-party dependency used here is ``segno``, and ONLY to render the
enrollment QR-code image (a capability the stdlib cannot provide), exactly as
Authlib was added for OAuth.

This is the only module that touches the ``totp_*`` columns on the ``users``
table. It is the authenticator-app sibling of ``otp_service.py`` (Email OTP,
v1.0.6); at login TOTP takes PRECEDENCE over Email OTP (see ``auth_service.login``).

Security posture (all preserved from the closed vulnerabilities):
- VULN-1 (SQL Injection): every SELECT/UPDATE here is parameterized -- never
  concatenate.
- VULN-3 (Reflected XSS): the login-time code is never returned to the client; it
  is compared server-side with ``secrets.compare_digest`` (constant-time). The
  enrollment secret/QR are returned ONLY to the authenticated owner during their
  own setup (that is the point of enrollment) and are NEVER logged.
- VULN-5: this runs AFTER bcrypt in ``login()`` -- it is a SECOND factor, not a
  password check. A wrong password never reaches the TOTP challenge.

A 6-digit code is low-entropy, so its safety comes from: the small validity
window, the +/- ``TOTP_SKEW_STEPS`` clock-drift tolerance, a replay guard
(``totp_last_step`` -- an accepted code cannot be reused inside its window), and
the unchanged per-IP rate limiter. The 160-bit secret itself is infeasible to
guess.
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
    """Uppercase, unpadded base32 secret from a 160-bit CSPRNG draw.

    ``secrets.token_bytes`` is a cryptographically secure source; base32 is the
    encoding authenticator apps expect. We strip ``=`` padding for a cleaner
    ``otpauth://`` URI and re-pad on decode.
    """
    raw = secrets.token_bytes(config.TOTP_SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 + dynamic truncation, zero-padded to TOTP_DIGITS.

    ``counter`` is the time-step for TOTP. base32 decoding needs the padding we
    stripped in ``generate_secret`` restored, hence the ``=`` re-pad.
    """
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** config.TOTP_DIGITS)).zfill(config.TOTP_DIGITS)


def _current_step(now=None) -> int:
    """The current TOTP time-step counter (``floor(unix_time / period)``)."""
    t = time.time() if now is None else now
    return int(t // config.TOTP_PERIOD_SECONDS)


def _code_matches(secret: str, code: str):
    """Return the matched time-step for a valid ``code`` (current +/- skew), else None.

    Each candidate is compared with ``secrets.compare_digest`` (constant-time) so
    a near-miss leaks no timing signal. Returns the matched step so callers can
    persist it for the replay guard.
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
    """Build the ``otpauth://totp/...`` URI an authenticator app imports.

    Format: ``otpauth://totp/<issuer>:<user>?secret=...&issuer=...&algorithm=SHA1
    &digits=6&period=30``. The label and issuer are URL-encoded; the username is
    the account's own value (encoded defensively all the same).
    """
    label = urllib.parse.quote(f"{config.TOTP_ISSUER}:{username}")
    params = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": config.TOTP_ISSUER,
            "algorithm": "SHA1",
            "digits": config.TOTP_DIGITS,
            "period": config.TOTP_PERIOD_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{params}"


def qr_data_uri(uri: str):
    """Render ``uri`` to a PNG ``data:`` URI via ``segno``; None on any error.

    The ONLY use of the ``segno`` dependency. Fail-safe: a render error returns
    None so the route can still offer the manual-entry key (enrollment stays
    possible without the image).
    """
    try:
        return segno.make(uri).png_data_uri(scale=5)
    except Exception:
        logger.exception("TOTP QR render failed")
        return None


def start_enrollment(user_id, username):
    """Generate + persist a PENDING secret (``totp_enabled`` stays 0); return QR/secret/URI.

    The secret is written first (parameterized UPDATE), then the QR is built from
    it. ``totp_last_step`` is reset to NULL so a fresh enrollment accepts the next
    code. Returns ``{"secret", "otpauth_uri", "qr_data_uri"}`` or ``None`` on a DB
    error (the route reports a 400). The secret is NOT logged.
    """
    secret = generate_secret()
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_last_step = NULL "
            "WHERE id = ?",
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
    """Activate a pending secret iff ``code`` is currently valid.

    Returns ``{"status": <str>}`` where status is one of:
    - ``"ok"``         -- the pending secret produced ``code``; ``totp_enabled`` is
                          set to 1 and ``totp_last_step`` recorded.
    - ``"no_pending"`` -- there is no secret to confirm (run setup first).
    - ``"invalid"``    -- the code did not match the pending secret.

    Requiring a confirm code proves the authenticator was provisioned correctly,
    preventing self-lockout from a mis-scanned QR.
    """
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT totp_secret FROM users WHERE id = ?", [user_id]
        ).fetchone()
        if not row or row["totp_secret"] is None:
            return {"status": "no_pending"}
        step = _code_matches(row["totp_secret"], code)
        if step is None:
            return {"status": "invalid"}
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
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
    """Login-time check. Returns ``{"status": <str>, "user": <dict|None>}``.

    status is one of:
    - ``"ok"``           -- ``totp_enabled`` is set, a code within the current
                            step +/- skew matched, and its step is strictly newer
                            than ``totp_last_step`` (replay guard); the matched
                            step is persisted and ``user`` carries
                            ``{id, username, email}`` so the route can write the
                            full session.
    - ``"no_challenge"`` -- TOTP is not enabled / no secret; the user must restart
                            login.
    - ``"invalid"``      -- wrong, expired-window, or replayed code.

    The code is compared with ``secrets.compare_digest`` (constant-time) and is
    NEVER reflected back to the caller (VULN-3 posture).
    """
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT id, username, email, totp_secret, totp_enabled, totp_last_step "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
        if not row or not row["totp_enabled"] or row["totp_secret"] is None:
            return {"status": "no_challenge", "user": None}

        step = _code_matches(row["totp_secret"], code)
        last = row["totp_last_step"]
        # Replay guard: reject a code whose step was already accepted, even if it
        # still displays in the app this window.
        if step is None or (last is not None and step <= int(last)):
            return {"status": "invalid", "user": None}

        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET totp_last_step = ? WHERE id = ?", [step, user_id]
        )
        conn.commit()
        return {
            "status": "ok",
            "user": {
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
            },
        }
    except Exception:
        logger.exception("totp verify failed for user_id=%s", user_id)
        return {"status": "invalid", "user": None}
    finally:
        conn.close()


def disable(user_id) -> bool:
    """Clear the secret, the flag, and the last-step. Returns True/False.

    Returns ``False`` (never raises) on a DB error so the route can report a 400.
    After disable the account is password-only again (or Email OTP, if separately
    enabled).
    """
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0, "
            "totp_last_step = NULL WHERE id = ?",
            [user_id],
        )
        conn.commit()
        return True
    except Exception:
        logger.exception("totp disable failed for user_id=%s", user_id)
        return False
    finally:
        conn.close()
