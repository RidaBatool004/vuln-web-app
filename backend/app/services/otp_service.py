"""Email OTP 2FA helpers (issue / verify / resend / toggle).

Implements README "Feature Enhancements" #6 (OTP via Email, v1.0.6). When a user
enables 2FA, a correct password does NOT complete login: this module issues a
6-digit one-time code (emailed via ``core.mailer``), and login finishes only
after the code is verified on the ``/login/otp`` screen.

This is the only module that touches the OTP columns on the ``users`` table. It
is the OTP analog of ``verification_service.py``: the route layer in
``api/routes/auth.py`` (and ``auth_service.login``) call these functions and
render / redirect on the result.

Security posture (all preserved from the closed vulnerabilities):
- VULN-1 (SQL Injection): every SELECT/UPDATE here is parameterized -- never
  concatenate.
- VULN-3 (Reflected XSS): the code is never returned to the client; it is emailed
  and compared server-side with ``secrets.compare_digest`` (constant-time). No
  status other than ``ok`` carries the code, and ``ok`` returns only id/username/
  email.
- VULN-5: this runs AFTER bcrypt in ``login()`` -- it is a SECOND factor, not a
  password check. A wrong password never reaches OTP issuance.

A 6-digit code has only ~10**6 possibilities, so its safety comes from layered
bounds: a per-OTP attempt cap (``OTP_MAX_ATTEMPTS``), a short expiry
(``OTP_TTL_SECONDS``), and a per-account resend cooldown
(``OTP_RESEND_COOLDOWN_SECONDS``) -- on top of the unchanged per-IP rate limiter.
Email send is FAIL-SAFE (the mailer returns False, never raises); a failed send
never crashes login or silently completes it (login fails closed when email is
entirely unconfigured).
"""

import logging
import secrets
import threading
import time

from app.core import config, mailer
from app.db.session import get_db

logger = logging.getLogger(__name__)


def _generate_code() -> str:
    """Uniform ``OTP_LENGTH``-digit code, zero-padded.

    ``secrets.randbelow(10**n)`` draws uniformly from ``0 .. 10**n - 1`` (no
    modulo bias), and the ``0{n}d`` format keeps leading zeros so the code is
    always exactly ``OTP_LENGTH`` digits.
    """
    return f"{secrets.randbelow(10 ** config.OTP_LENGTH):0{config.OTP_LENGTH}d}"


def set_two_factor(user_id: int, enabled: bool) -> bool:
    """Turn 2FA on/off for ``user_id``. Disabling also clears any pending OTP.

    Returns ``True`` on success, ``False`` on a DB error (the route reports a
    400). Clearing the OTP columns on disable means a half-finished challenge
    cannot linger after the user opts out.
    """
    conn = get_db()
    try:
        if enabled:
            # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
            conn.execute(
                "UPDATE users SET two_factor_enabled = 1 WHERE id = ?", [user_id]
            )
        else:
            # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
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
    """Issue a fresh OTP for ``user_id`` and email it.

    Persists the code + expiry + zeroed attempt count + send timestamp with a
    parameterized UPDATE (always synchronous, so the code is saved before any
    send), then sends the email.

    ``background=True`` (login challenge): hand the SMTP send to a daemon thread
    and return ``True`` immediately, so the login response is not blocked on the
    Gmail handshake. The code is already in the DB, so a slow/failed send never
    loses state -- the user can resend from the OTP screen.

    ``background=False`` (resend): send synchronously and return the mailer's
    success boolean, so the caller can report an accurate "sent / failed".

    Each call overwrites any prior code and resets the attempt count, so only the
    most recent code verifies.
    """
    code = _generate_code()
    now = time.time()

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET otp_code = ?, otp_expires = ?, otp_attempts = 0, "
            "otp_last_sent = ? WHERE id = ?",
            [code, now + config.OTP_TTL_SECONDS, now, user_id],
        )
        conn.commit()
    finally:
        conn.close()

    if background:
        # Fire-and-forget: the login response returns without waiting on SMTP.
        # The thread only touches the network (no DB), so there is no SQLite
        # cross-thread concern. The mailer is fail-safe, so it cannot crash it.
        threading.Thread(
            target=mailer.send_otp_email,
            args=(email, username, code),
            daemon=True,
        ).start()
        return True

    return mailer.send_otp_email(email, username, code)


def seconds_until_resend(row) -> int:
    """Seconds left on the resend cooldown for a fetched row (0 = may resend).

    Pure: reads ``row["otp_last_sent"]`` only -- no DB access. A NULL last-sent
    (no code ever issued) means a resend is allowed.
    """
    last = row["otp_last_sent"]
    if last is None:
        return 0
    remaining = int(float(last) + config.OTP_RESEND_COOLDOWN_SECONDS - time.time())
    return remaining if remaining > 0 else 0


def verify(user_id: int, code: str) -> dict:
    """Validate a submitted OTP. Returns ``{"status": <str>, "user": <dict|None>}``.

    status is one of:
    - ``"ok"``           -- an outstanding, unexpired code matched and the attempt
                            cap was not exhausted; the OTP columns are cleared
                            (single-use) and ``user`` carries ``{id, username,
                            email}`` so the route can write the full session.
    - ``"no_challenge"`` -- no code is outstanding (NULL ``otp_code``); the user
                            must restart login.
    - ``"expired"``      -- a code exists but is past its expiry; the code is
                            cleared.
    - ``"too_many"``     -- the attempt cap is already reached (or this miss
                            reaches it); the code is cleared.
    - ``"invalid"``      -- wrong code with attempts remaining; ``otp_attempts``
                            is incremented.

    The code is compared with ``secrets.compare_digest`` (constant-time) and is
    NEVER reflected back to the caller (VULN-3 posture).
    """
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT id, username, email, otp_code, otp_expires, otp_attempts "
            "FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
        if not row or row["otp_code"] is None:
            return {"status": "no_challenge", "user": None}

        # Expired: invalidate the code so it cannot be brute-forced past expiry.
        if row["otp_expires"] is None or time.time() > float(row["otp_expires"]):
            conn.execute(
                "UPDATE users SET otp_code = NULL, otp_expires = NULL WHERE id = ?",
                [user_id],
            )
            conn.commit()
            return {"status": "expired", "user": None}

        # Attempt cap already reached on a prior request: code is dead.
        if (row["otp_attempts"] or 0) >= config.OTP_MAX_ATTEMPTS:
            conn.execute(
                "UPDATE users SET otp_code = NULL, otp_expires = NULL WHERE id = ?",
                [user_id],
            )
            conn.commit()
            return {"status": "too_many", "user": None}

        # Correct code: clear the challenge (single-use) and report success.
        if code and secrets.compare_digest(str(row["otp_code"]), str(code)):
            conn.execute(
                "UPDATE users SET otp_code = NULL, otp_expires = NULL, "
                "otp_attempts = 0, otp_last_sent = NULL WHERE id = ?",
                [user_id],
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

        # Wrong code: count the miss; invalidate the code if this reaches the cap.
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
        # Never surface DB internals; the route maps "invalid" to a generic
        # "incorrect code" message.
        logger.exception("otp verify failed for user_id=%s", user_id)
        return {"status": "invalid", "user": None}
    finally:
        conn.close()
