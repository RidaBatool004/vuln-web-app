# Implementation Plan — Account Lockout

**Spec:** [account-lockout.md](./account-lockout.md)
**Target Release Tag:** v1.0.5
**Branch:** `feature/account-lockout`

This plan sequences the work so the app boots after every step and the eight closed vulnerabilities stay closed throughout. Backend primitives land first (config → schema → lockout service), then the two callers (login → resend), then docs. The rate limiter, bcrypt, CSRF middleware, all routes, and all templates are **not** touched.

---

## Step 0 — Preconditions

- Confirm branch `feature/account-lockout` is checked out (it already is).
- Confirm `time`, `logging` are stdlib (no dependency change).
- No edits to `main.py`, `core/rate_limit.py`, `core/security.py`, `core/csrf.py`, `core/oauth.py`, `core/mailer.py`, `oauth_service.py`, `api/routes/auth.py`, any template, `styles.css`, or any lockfile at any point.

---

## Step 1 — `backend/app/core/config.py` (lockout settings)

Append a new block below the SMTP block:

```python
# --- Account-lockout settings (env-tunable, non-secret) ----------------------
# After ACCOUNT_LOCKOUT_MAX_ATTEMPTS consecutive failed credential checks against
# a single account, it is locked for ACCOUNT_LOCKOUT_DURATION_SECONDS. These are
# NOT secrets (no is_*_configured() gate); they have safe defaults and can be
# lowered for demos, e.g. ACCOUNT_LOCKOUT_MAX_ATTEMPTS=3 ACCOUNT_LOCKOUT_DURATION_SECONDS=30.
ACCOUNT_LOCKOUT_MAX_ATTEMPTS = int(os.environ.get("ACCOUNT_LOCKOUT_MAX_ATTEMPTS", "6"))
ACCOUNT_LOCKOUT_DURATION_SECONDS = int(
    os.environ.get("ACCOUNT_LOCKOUT_DURATION_SECONDS", "3600")
)
```

Update the module docstring's opening line to mention account lockout alongside Google + email verification. No behaviour change to existing settings.

**Check:** `python -c "from app.core import config; print(config.ACCOUNT_LOCKOUT_MAX_ATTEMPTS, config.ACCOUNT_LOCKOUT_DURATION_SECONDS)"` → `6 3600`.

---

## Step 2 — `backend/app/db/session.py` (additive migration, 2 columns)

In `CREATE TABLE IF NOT EXISTS users (...)` add the two columns (after the verification columns):

```
failed_login_attempts      INTEGER DEFAULT 0,
locked_until               REAL
```

In the `migrations` dict, add the two entries (no grandfather step — defaults are already correct):

```python
migrations = {
    # ... existing google + verification columns ...
    # Account-Lockout feature (v1.0.5): two columns, defaults already mean
    # "no failures, not locked", so NO grandfather UPDATE is needed.
    "failed_login_attempts": "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0",
    "locked_until": "ALTER TABLE users ADD COLUMN locked_until REAL",
}
```

Update the `init_db()` docstring's schema notes for the two new columns (mirroring the `is_verified` / `verification_token_expires` notes).

**Check:** `rm vulnerable_app.db`, boot, `PRAGMA table_info(users)` shows both columns; on an old DB copy, existing rows read `0` / `NULL` and none are locked.

---

## Step 3 — `backend/app/services/lockout_service.py` (new)

Neutral module importable by both `auth_service` and `verification_service` (imports only `time`, `core.config`, `db.session` — no circular dependency).

```python
"""Account-lockout state helpers (shared by login and resend).

Implements README "Feature Enhancements" #9. After a configured number of
CONSECUTIVE failed credential checks against one account, the account is locked
for a cooldown window; the lock then expires on its own (time-based).

This is the per-ACCOUNT companion to the per-IP RateLimitMiddleware (VULN-7):
the rate limiter throttles a flooding IP, while lockout stops a single account
being ground down across many IPs / over time. Both layers stay in force.

Security posture:
- VULN-1 (SQL Injection): every UPDATE here is parameterized -- never concatenate.
- The lock is checked BEFORE bcrypt in the callers, so a locked account never
  triggers the (slow) hash and cannot be used as a bcrypt-CPU oracle.
- Bookkeeping writes FAIL OPEN (log + proceed) on a DB error: a broken lockout
  must never deny every login (same rationale as RateLimitMiddleware's fail-open;
  contrast CSRFMiddleware, which fails closed).
"""

import logging
import time

from app.core import config
from app.db.session import get_db

logger = logging.getLogger(__name__)


def seconds_remaining(row) -> int:
    """Remaining lock seconds for a fetched users row (0 if unlocked/expired).

    Pure: reads row["locked_until"] only -- no DB access. A NULL or past value
    means "not locked". Callers pass the row they already SELECTed.
    """
    locked_until = row["locked_until"]
    if locked_until is None:
        return 0
    remaining = int(float(locked_until) - time.time())
    return remaining if remaining > 0 else 0


def register_failure(user_id: int, current_attempts) -> int:
    """Record one failed credential check. Returns the lock duration in seconds
    if THIS failure triggered a lock (> 0), else 0.

    On the threshold failure we set locked_until AND zero the counter in the
    same UPDATE, so that when the lock expires the account gets a full fresh
    allowance instead of re-locking on the next single miss. Fails open.
    """
    attempts = (current_attempts or 0) + 1
    conn = get_db()
    try:
        if attempts >= config.ACCOUNT_LOCKOUT_MAX_ATTEMPTS:
            locked_until = time.time() + config.ACCOUNT_LOCKOUT_DURATION_SECONDS
            conn.execute(
                "UPDATE users SET locked_until = ?, failed_login_attempts = 0 WHERE id = ?",
                [locked_until, user_id],
            )
            conn.commit()
            return int(config.ACCOUNT_LOCKOUT_DURATION_SECONDS)
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
    """Clear the failure counter and any lock (called after a correct password)."""
    conn = get_db()
    try:
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

    Contains no attacker input (only a computed minute count), so it is safe to
    reflect into the login page's error element.
    """
    minutes = max(1, (remaining_seconds + 59) // 60)
    unit = "minute" if minutes == 1 else "minutes"
    return (
        "Account locked due to too many failed login attempts. "
        f"Try again in about {minutes} {unit}."
    )
```

**Check:** `seconds_remaining` returns 0 for a row with `locked_until=None`; import-safe with no DB writes at import time; all SQL parameterized.

---

## Step 4 — `backend/app/services/auth_service.py` (`login()` only)

- Add `from app.services import lockout_service` (top-level; no circular import — `lockout_service` imports neither `auth_service` nor `verification_service`).
- The `SELECT *` already returns `failed_login_attempts` and `locked_until`, so no query change.
- Insert the **lock gate** after `fetchone()` / `conn.close()` and **before** the `verify_password` branch:

```python
# Account-lockout gate (v1.0.5): if the account is currently locked, refuse
# immediately -- BEFORE bcrypt -- even if the password is correct. Only existing
# accounts can be locked; a missing row falls through to the generic 401 below.
if user:
    remaining = lockout_service.seconds_remaining(user)
    if remaining > 0:
        return JSONResponse(
            content={
                "error": lockout_service.lock_message(remaining),
                "locked": True,
                "retry_after": remaining,
            },
            status_code=401,
        )
```

- In the **success** branch (`if user and verify_password(...)`), call `lockout_service.reset(user["id"])` as the first statement (before the `is_verified` gate), so a correct password clears the counter even when the account is unverified.
- In the **else** branch, before returning the generic `401`, record the failure for an existing user and lock if it crosses the threshold:

```python
else:
    # Wrong password. For an existing account, count this toward the lockout
    # threshold; a non-existent username has no row to touch.
    if user:
        remaining = lockout_service.register_failure(user["id"], user["failed_login_attempts"])
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
        content={"error": "Invalid username or password"},
        status_code=401,
    )
```

- **Do not touch** `signup()`, `change_password()`, `password_meets_policy()`, or the imports beyond adding `lockout_service`.

**Check:** correct password → `200` and counter reset; 6th wrong password → locked `401`; correct password while locked → locked `401`.

---

## Step 5 — `backend/app/services/verification_service.py` (`resend_for_credentials()` only)

- Add `from app.services import lockout_service` (top-level; no cycle).
- Extend the `SELECT` to also fetch the lockout columns:

```python
row = conn.execute(
    "SELECT id, username, email, password, is_verified, "
    "failed_login_attempts, locked_until FROM users WHERE username = ?",
    [username],
).fetchone()
```

- After the row is fetched (and the connection closed), add the **same lock gate** as login, before the `verify_password` check:

```python
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
```

- In the bad-credentials branch (`if not row or not verify_password(...)`), register a failure for an existing row and lock if crossed, then fall through to the existing generic `401`:

```python
if not row or not verify_password(password, row["password"]):
    if row:
        remaining = lockout_service.register_failure(row["id"], row["failed_login_attempts"])
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
```

- On the correct-password path (just before the `is_verified` / re-issue branches), call `lockout_service.reset(row["id"])`.
- **Do not touch** `start_verification()` or `verify_email_token()`.

Because the counter lives on the shared `users` row, login and resend failures accumulate together — an attacker cannot get a fresh allowance by switching endpoints.

**Check:** alternating login/resend wrong passwords lock the account at the combined 6th failure.

---

## Step 6 — `.env.example` (append placeholders)

```
# --- Account Lockout (v1.0.5) -- env-tunable, NOT secrets --------------------
# Lock an account after this many consecutive failed logins, for this long.
# Lower both to demo quickly, e.g. 3 attempts / 30 seconds.
ACCOUNT_LOCKOUT_MAX_ATTEMPTS=6
ACCOUNT_LOCKOUT_DURATION_SECONDS=3600
```

(These are defaults shown for discoverability; the app works with none set.)

---

## Step 7 — `README.md`

- **Feature Enhancements table:** change row #9 (Account Lockout) Status to **Done (v1.0.5)** and flesh out the description: per-account lock after 6 consecutive failed logins for 1 hour (env-tunable), checked before bcrypt, shared by login + resend, **complementing — not replacing — the per-IP rate limiter (VULN-7)**.
- **Done-features sentence** (above the table): add "Account Lockout (v1.0.5)".
- **Releases & Versions table:** add a **v1.0.5** row.
- **(Optional) Intentional Vulnerabilities / VULN-7 row:** add a parenthetical that account lockout (v1.0.5) adds a per-account layer on top of the per-IP rate limit. Do **not** change the VULN-7 "Closed" status or its mechanism text.
- No API-endpoint table change (no new routes).

---

## Step 8 — `CLAUDE.md`

- **Frontend-Backend Integration:** add an "Account Lockout (v1.0.5)" subsection: the two `users` columns, the `lockout_service.py` helpers, the before-bcrypt gate in `login()` and `resend_for_credentials()`, the shared counter, the env settings, the fail-open posture, the deliberate enumeration trade-off, and the fact that it layers on top of (does not replace) the rate limiter.
- **Important Rules:** add an entry — keep `lockout_service.py` SQL parameterized (VULN-1); the lock gate stays **before** `verify_password` (VULN-5 stays the unlocked-path authenticator); the rate-limit middleware and `main.py` are **not** modified (VULN-7 stays closed and lockout is additive); thresholds come from env via `core/config.py` (no hardcoded business secret); the migration stays additive/idempotent (two columns, no grandfather); the lock message is the only deliberate enumeration relaxation and must reflect no attacker input (VULN-3).
- **Specification Hierarchy:** append entry #16 for this spec/plan pair.
- **Vulnerability Map (optional note):** under VULN-7, note that v1.0.5 adds a complementary per-account lockout; VULN-7 remains closed by the unchanged middleware.

---

## Step 9 — `docs/prompts/`

Save the generating prompts, mirroring the existing per-feature convention:
`account-lockout-spec-prompt.txt`, `account-lockout-spec-plan-prompt.txt`, `account-lockout-spec-execution-prompt.txt`. (Drop in the actual prompt text used; this step is documentation only.)

---

## Step 10 — Verification

Run the spec's §10 steps:
1. Schema: both columns present on a fresh DB; old DB migrates to `0`/`NULL`, nothing locked.
2. Lock: 6th wrong `POST /login` → `401 {"locked": true, "retry_after": ...}` (raise `RATE_LIMIT_MAX` or space requests so the per-IP limiter doesn't `429` first — that interplay is expected).
3. Locked refuses the correct password; after `ACCOUNT_LOCKOUT_DURATION_SECONDS` it unlocks and `200`s; row back to `0`/`NULL`.
4. Shared counter: combined login + resend failures lock at the 6th.
5. File audit: `git diff --stat` empty for the forbidden files (`main.py`, `core/rate_limit.py`, `core/security.py`, `core/csrf.py`, routes, templates, CSS, lockfiles); `git status --porcelain` matches the declared set.
6. `uv run backend/app/main.py` boots clean and a normal correct-password login still succeeds.

---

## Risk / Rollback

- **Risk — self-inflicted DoS:** because the lock message reveals existence and anyone can trip a lock, a griefer can lock a known account for up to 1 hour with 6 bad passwords. Accepted product trade-off; mitigated by the per-IP rate limiter slowing mass-locking and by the duration being env-tunable (drop it for demos). Documented in the spec (NFR-03) and CLAUDE.md.
- **Risk — off-by-one near the threshold under concurrent failures:** single-process SQLite makes this rare and at worst shifts the lock by one attempt (EC-06). Acceptable for the lab.
- **Rollback:** the feature is additive. Reverting the branch leaves the two nullable/defaulted columns in any already-migrated DB (harmless) or one can `rm vulnerable_app.db`. No destructive migration is ever run, and the rate limiter — untouched — continues to protect every POST on its own.
```