"""Account-lockout state helpers (shared by login and resend).

Implements README "Feature Enhancements" #9 (v1.0.5). After a configured number
of CONSECUTIVE failed credential checks against one account, the account is
locked for a cooldown window; the lock then expires on its own (time-based, no
admin action).

This is the per-ACCOUNT companion to the per-IP RateLimitMiddleware (VULN-7):
the rate limiter throttles a flooding IP, while lockout stops a single account
being ground down across many IPs / over time. Both layers stay in force --
lockout is additive defense in depth, NOT a replacement (main.py and
core/rate_limit.py are unchanged).

The module is deliberately neutral so both auth_service and verification_service
can import it without a circular dependency -- it imports only `time`,
`core.config`, and `db.session`.

Security posture:
- VULN-1 (SQL Injection): every UPDATE here is parameterized -- never concatenate.
- VULN-5: callers run the lock check BEFORE bcrypt, so a locked account never
  triggers the (intentionally slow) hash and cannot be used as a bcrypt-CPU
  oracle. bcrypt stays the sole authenticator on the unlocked path.
- Bookkeeping writes (register_failure / reset) FAIL OPEN (log + proceed) on a
  DB error: a broken lockout must never deny every login -- same rationale as
  RateLimitMiddleware's fail-open posture (contrast CSRFMiddleware, which fails
  closed, because a missing CSRF check re-opens the vulnerability).
"""

import logging
import time

from app.core import config
from app.db.session import get_db

logger = logging.getLogger(__name__)


def seconds_remaining(row) -> int:
    """Remaining lock seconds for a fetched ``users`` row (0 if unlocked/expired).

    Pure: reads ``row["locked_until"]`` only -- no DB access. A NULL or
    already-past value means "not locked". Callers pass the row they already
    SELECTed, so this never opens a second connection. A stale past timestamp is
    treated as unlocked (and gets cleared on the next successful login).
    """
    locked_until = row["locked_until"]
    if locked_until is None:
        return 0
    remaining = int(float(locked_until) - time.time())
    return remaining if remaining > 0 else 0


def register_failure(user_id: int, current_attempts) -> int:
    """Record one failed credential check. Returns the lock duration in seconds
    if THIS failure triggered a lock (> 0), else 0.

    On the threshold failure we set ``locked_until`` AND zero
    ``failed_login_attempts`` in the same UPDATE, so that when the lock expires
    the account gets a full fresh allowance instead of re-locking on the next
    single miss. Fails open: a bookkeeping error returns 0 (no lock) rather than
    propagating into the login handler.
    """
    attempts = (current_attempts or 0) + 1
    conn = get_db()
    try:
        if attempts >= config.ACCOUNT_LOCKOUT_MAX_ATTEMPTS:
            locked_until = time.time() + config.ACCOUNT_LOCKOUT_DURATION_SECONDS
            # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
            conn.execute(
                "UPDATE users SET locked_until = ?, failed_login_attempts = 0 WHERE id = ?",
                [locked_until, user_id],
            )
            conn.commit()
            return int(config.ACCOUNT_LOCKOUT_DURATION_SECONDS)
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
            [attempts, user_id],
        )
        conn.commit()
        return 0
    except Exception:
        # Fail open: a bookkeeping error must not block the login flow.
        logger.exception("lockout register_failure failed for user_id=%s", user_id)
        return 0
    finally:
        conn.close()


def reset(user_id: int) -> None:
    """Clear the failure counter and any lock (called after a correct password).

    Fails open: a DB error here is logged but never raised into the caller, so a
    successful authentication still proceeds to create its session.
    """
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            [user_id],
        )
        conn.commit()
    except Exception:
        logger.exception("lockout reset failed for user_id=%s", user_id)
    finally:
        conn.close()


def lock_message(remaining_seconds: int) -> str:
    """Fixed, server-controlled lock message with a minute-granularity countdown.

    Contains no attacker input -- only a computed minute count -- so it is safe
    to surface in the login page's error element (VULN-3 posture: nothing
    reflected). Rounds up so a sub-minute remainder still reads "1 minute".
    """
    minutes = max(1, (remaining_seconds + 59) // 60)
    unit = "minute" if minutes == 1 else "minutes"
    return (
        "Account locked due to too many failed login attempts. "
        f"Try again in about {minutes} {unit}."
    )
