"""Per-request session cookie Max-Age extension (stdlib only).

Supports the Remember Me feature. Registered as the OUTERMOST middleware so
that on the response path it runs AFTER SessionMiddleware has already set the
session cookie. If the ASGI scope's session dict contains a ``__max_age__``
key, this middleware patches the ``Set-Cookie: session=...`` header's
``Max-Age`` attribute before the response is sent to the client.

The ``__max_age__`` key is an ephemeral one-shot directive written by the
login handler (or the 2FA completion handlers) when the full authentication
chain has succeeded and the user checked "Remember Me". It is only meaningful
on the response that just established the session.
"""

import re
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger(__name__)

_SESSION_COOKIE_NAME = "session"


class RememberMeMiddleware(BaseHTTPMiddleware):
    """Outermost middleware that patches the session cookie's Max-Age when
    ``request.session["__max_age__"]`` is present."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # After the entire inner stack (including SessionMiddleware) has
        # processed, the ASGI scope carries the session dict.  If the
        # handler set __max_age__, patch the Set-Cookie header.
        max_age = request.session.pop("__max_age__", None)
        if max_age is not None:
            self._patch_session_max_age(response, int(max_age))

        return response

    @staticmethod
    def _patch_session_max_age(response, max_age: int) -> None:
        """Replace or append ``Max-Age`` on the session cookie header."""
        new_headers: list[tuple[bytes, bytes]] = []
        target_prefix = (_SESSION_COOKIE_NAME + "=").encode("latin-1")

        for name, value in response.raw_headers:
            if name == b"set-cookie" and value.startswith(target_prefix):
                cookie = value.decode("latin-1")
                if "Max-Age=" in cookie:
                    cookie = re.sub(
                        r"Max-Age=\d+", f"Max-Age={max_age}", cookie
                    )
                else:
                    cookie = cookie.rstrip(";") + f"; Max-Age={max_age}"
                value = cookie.encode("latin-1")
            new_headers.append((name, value))

        response.raw_headers = new_headers
