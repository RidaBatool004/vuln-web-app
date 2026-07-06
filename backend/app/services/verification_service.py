"""Email-verification business logic (token issue / verify / resend).

This is the only module that touches the verification columns on the ``users``
table. It is the email-verification analog of ``oauth_service.py``: the route
layer in ``api/routes/auth.py`` calls these functions and renders/redirects on
the result.

Security posture (all preserved from the closed vulnerabilities):
- VULN-1 (SQL Injection): every SELECT/UPDATE here is parameterized -- never
  concatenate.
- VULN-3 (Reflected XSS): the token is never reflected back to the client; the
  /verify route renders a fixed outcome message, not the token.
- VULN-7 / VULN-8: the resend entry point is reached only via ``POST
  /verify/resend``, which the existing rate-limit + CSRF middleware already
  guard. This module adds no new auth surface of its own.

Token model (Option A -- stateful):
- ``secrets.token_urlsafe(32)`` (256-bit) stored raw in ``verification_token``.
- ``verification_token_expires`` is ``time.time()`` + TTL (default 1 hour).
- A successful verify clears both columns, making the link single-use.
"""

import logging
import secrets
import threading
import time

from fastapi.responses import JSONResponse

from app.db.session import get_db
from app.core import config, mailer
from app.core.security import verify_password
from app.services import lockout_service

logger = logging.getLogger(__name__)


def start_verification(
    user_id: int, username: str, email: str, background: bool = False
) -> bool:
    """Issue a fresh token for ``user_id`` and email the verification link.

    Writes the token + expiry with a parameterized UPDATE (always synchronous,
    so the token is persisted before this returns), then sends the email.

    ``background=False`` (resend): send synchronously and return the mailer's
    success boolean, so the caller can report an accurate "sent / failed".

    ``background=True`` (signup): hand the SMTP send to a daemon thread and
    return ``True`` immediately. The SMTP handshake to Gmail can take several
    seconds; doing it inline would block the signup response (and the event
    loop). The token is already in the DB, so a slow/failed send never loses
    state -- the user can resend from the login page. The mailer is fail-safe
    (logs and returns False on error), so the thread can't crash the server.

    Each call overwrites any prior token, so only the most recent link verifies.
    """
    token = secrets.token_urlsafe(32)
    expires = time.time() + config.EMAIL_VERIFICATION_TTL_SECONDS

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET verification_token = ?, verification_token_expires = ? "
            "WHERE id = ?",
            [token, expires, user_id],
        )
        conn.commit()
    finally:
        conn.close()

    verify_url = f"{config.APP_BASE_URL}/verify?token={token}"

    if background:
        # Fire-and-forget: the signup response returns without waiting on SMTP.
        # The thread only touches the network (no DB), so there is no SQLite
        # cross-thread concern.
        threading.Thread(
            target=mailer.send_verification_email,
            args=(email, username, verify_url),
            daemon=True,
        ).start()
        return True

    return mailer.send_verification_email(email, username, verify_url)


def verify_email_token(token: str) -> dict:
    """Validate a verification token and mark the account verified on success.

    Returns a dict ``{"status": <str>, "user": <dict|None>}`` where status is:
    - ``"ok"``      -- token matched and was unexpired; the row is now
                       is_verified = 1 with both token columns cleared
                       (single-use). ``user`` carries ``{id, username, email}``
                       so the route can log the user straight in (clicking the
                       emailed link proves control of the address).
    - ``"expired"`` -- token matched but is past its expiry; no state change.
    - ``"invalid"`` -- missing/blank token, no matching row (covers an
                       already-consumed token), or any DB error.

    The token is looked up by exact match -- it is never reflected back to the
    caller (VULN-3 posture).
    """
    if not token:
        return {"status": "invalid", "user": None}

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized lookup by token value.
        row = conn.execute(
            "SELECT id, username, email, verification_token_expires FROM users "
            "WHERE verification_token = ?",
            [token],
        ).fetchone()
        if not row:
            # No outstanding token matches (never issued, or already consumed).
            return {"status": "invalid", "user": None}

        expires = row["verification_token_expires"]
        if expires is None or time.time() > float(expires):
            return {"status": "expired", "user": None}

        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        # Clearing both token columns makes the link single-use.
        conn.execute(
            "UPDATE users SET is_verified = 1, verification_token = NULL, "
            "verification_token_expires = NULL WHERE id = ?",
            [row["id"]],
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
        # Never surface DB internals; the route maps "invalid" to a generic page.
        logger.exception("verify_email_token failed")
        return {"status": "invalid", "user": None}
    finally:
        conn.close()


def resend_for_credentials(username: str, password: str) -> JSONResponse:
    """Re-issue + re-send the verification email, gated on valid credentials.

    Because login is BLOCKED until verification (v1.0.4 posture), an unverified
    user has no session, so resend cannot be session-gated. Instead the login
    page calls this with the same username + password the user just entered:
    the correct password is the authorization, which (a) stops anyone spamming
    a stranger's inbox and (b) resists username enumeration (a wrong
    username/password gets the same generic 401 as a failed login).

    Returns JSON for every outcome (mirrors ``auth_service.login``) so the
    login page's fetch() handler can render feedback inline:
    - 401 {"error": "Invalid username or password"}        (bad creds)
    - 200 {"success": True, "message": "...already verified..."}
    - 200 {"success": True, "message": "Verification email sent. ..."}
    - 400 {"error": "Could not send the verification email. ..."}

    The caller (``POST /verify/resend``) is a POST, so the existing CSRF and
    rate-limit middleware already guard it.
    """
    if not username or not password:
        return JSONResponse(
            content={"error": "Invalid username or password"}, status_code=401
        )

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by username.
        # Also fetch the lockout columns so this credential-checking endpoint
        # shares the SAME per-account counter as login (v1.0.5) -- an attacker
        # must not get a fresh allowance by pivoting from /login to here.
        row = conn.execute(
            "SELECT id, username, email, password, is_verified, "
            "failed_login_attempts, locked_until FROM users WHERE username = ?",
            [username],
        ).fetchone()
    finally:
        conn.close()

    # Account-lockout gate (v1.0.5): mirror login -- if the account is locked,
    # refuse BEFORE bcrypt, so resend cannot be used as a brute-force oracle to
    # bypass the lock. Only an existing row can be locked.
    if row:
        remaining = lockout_service.seconds_remaining(row)
        if remaining > 0:
            return JSONResponse(
                content={
                    "error": lockout_service.lock_message(remaining),
                    "locked": True,
                    "retry_after": remaining,
                },
                status_code=401,
            )

    # Same generic 401 for "no such user" and "wrong password" (enumeration
    # resistance, matching auth_service.login). verify_password fails closed.
    if not row or not verify_password(password, row["password"]):
        # Wrong password for an existing account counts toward the shared
        # lockout threshold; lock (and surface the countdown) if this trips it.
        if row:
            remaining = lockout_service.register_failure(
                row["id"], row["failed_login_attempts"]
            )
            if remaining > 0:
                return JSONResponse(
                    content={
                        "error": lockout_service.lock_message(remaining),
                        "locked": True,
                        "retry_after": remaining,
                    },
                    status_code=401,
                )
        return JSONResponse(
            content={"error": "Invalid username or password"}, status_code=401
        )

    # Correct password: clear any accumulated failure count / stale lock.
    lockout_service.reset(row["id"])

    if row["is_verified"]:
        # Already verified -- a no-op success, never re-issuing/un-verifying.
        return JSONResponse(
            content={
                "success": True,
                "message": "Your email is already verified. You can log in.",
            }
        )

    if start_verification(row["id"], row["username"], row["email"]):
        return JSONResponse(
            content={
                "success": True,
                "message": "Verification email sent. Check your inbox.",
            }
        )

    return JSONResponse(
        content={
            "error": "Could not send the verification email. Please try again later."
        },
        status_code=400,
    )
