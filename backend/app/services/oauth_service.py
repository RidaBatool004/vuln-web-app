"""Find-or-create business logic for Google sign-in.

This is the only place the Continue-with-Google feature touches the database.
It resolves a verified Google identity to a row in the existing `users` table,
in this order (all SQL parameterized -- VULN-1 stays closed):

  1. Returning Google user -> SELECT WHERE google_id = ?      (log them in)
  2. Existing local account -> SELECT WHERE email = ?          (link Google to it)
  3. Brand-new user        -> INSERT (password NULL, auth_provider 'google')

OAuth accounts store ``password = NULL``: there is no weak hash to leak, and the
unchanged password ``login()`` fails closed for them (``verify_password(pw,
None)`` returns ``False``). bcrypt (VULN-5) and ``auth_service.py`` are untouched.

The route layer calls :func:`find_or_create_google_user` and treats a ``None``
return as "missing user information" (it then bounces the user back to /login).
"""

import logging
import re

from app.db.session import get_db

logger = logging.getLogger(__name__)


def _sanitize(base: str) -> str:
    """Reduce an email local-part (or name) to a safe username seed.

    Keeps only ``[A-Za-z0-9_]`` and never returns empty -- falls back to
    ``"user"`` so the unique-username search always has something to work with.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", (base or "").split("@")[0])
    return cleaned or "user"


def _unique_username(conn, base: str) -> str:
    """Return ``base`` -- or ``base`` + smallest free integer -- as a username.

    De-collides a generated username against the ``UNIQUE(username)`` constraint
    using a parameterized existence check (``alice`` -> ``alice1`` -> ``alice2``).
    """
    candidate = base
    suffix = 1
    while conn.execute(
        "SELECT 1 FROM users WHERE username = ?", [candidate]
    ).fetchone():
        candidate = f"{base}{suffix}"
        suffix += 1
    return candidate


def find_or_create_google_user(
    google_id: str, email: str, name: str, picture: str
):
    """Resolve a Google identity to a ``users`` row, creating/linking as needed.

    Args:
        google_id: the Google subject id (``sub`` claim) -- required.
        email: the verified Google email -- required.
        name: the Google display name (may be empty).
        picture: the Google avatar URL (may be empty).

    Returns:
        A ``dict`` of the resolved/created user row, or ``None`` when
        ``google_id`` or ``email`` is missing (caller treats ``None`` as
        "missing user information").
    """
    if not google_id or not email:
        logger.warning("Google sign-in missing google_id or email; rejecting.")
        return None

    conn = get_db()
    try:
        # 1) Returning Google user: match on the stable subject id.
        row = conn.execute(
            "SELECT * FROM users WHERE google_id = ?", [google_id]
        ).fetchone()
        if row:
            # Opportunistically refresh display fields (parameterized).
            conn.execute(
                "UPDATE users SET name = ?, picture = ? WHERE id = ?",
                [name, picture, row["id"]],
            )
            conn.commit()
            logger.info("Google sign-in: existing google user id=%s", row["id"])
            return dict(row)

        # 2) Existing LOCAL account with the same email -> link Google to it.
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", [email]
        ).fetchone()
        if row:
            # is_verified = 1: Google has already verified the address, so a
            # linked account needs no separate email-verification step
            # (Email-Verification feature, v1.0.4).
            conn.execute(
                "UPDATE users SET google_id = ?, name = ?, picture = ?, "
                "auth_provider = ?, is_verified = 1 WHERE id = ?",
                [google_id, name, picture, "google", row["id"]],
            )
            conn.commit()
            logger.info("Google sign-in: linked google to local account id=%s", row["id"])
            return dict(
                conn.execute(
                    "SELECT * FROM users WHERE id = ?", [row["id"]]
                ).fetchone()
            )

        # 3) Brand-new Google account. password is NULL (no bcrypt hash) and
        #    is_verified is 1 -- Google has already verified the email, so no
        #    separate verification step is needed (Email-Verification, v1.0.4).
        username = _unique_username(conn, _sanitize(email or name))
        cur = conn.execute(
            "INSERT INTO users (username, email, password, google_id, name, "
            "picture, auth_provider, is_verified) "
            "VALUES (?, ?, NULL, ?, ?, ?, 'google', 1)",
            [username, email, google_id, name, picture],
        )
        conn.commit()
        logger.info("Google sign-in: created new account id=%s", cur.lastrowid)
        return dict(
            conn.execute(
                "SELECT * FROM users WHERE id = ?", [cur.lastrowid]
            ).fetchone()
        )
    except Exception:
        # Never leak DB internals; the route turns a None into a /login bounce.
        logger.exception("Google sign-in DB error for google_id=%s", google_id)
        return None
    finally:
        conn.close()
