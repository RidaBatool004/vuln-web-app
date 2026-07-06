"""Authlib OAuth client for Google (OpenID Connect).

Registers a single ``google`` provider on a module-level Authlib ``OAuth()``
using Google's OIDC discovery document. Authlib then handles, on our behalf:
the authorization + token endpoints, the JWKS fetch, and full ID-token
verification (signature + ``iss`` / ``aud`` / ``exp`` / ``nonce``).

Security note: the OAuth ``state`` parameter that Authlib stores in the session
is the CSRF defense for the GET callback. The app's POST-only ``CSRFMiddleware``
does not -- and should not -- touch these GET routes.

Import safety: this module registers the client even when credentials are
absent (empty strings). Importing it never raises, so a fresh clone boots
fine; the route's ``is_google_configured()`` gate is what prevents an actual
redirect to Google with blank credentials.
"""

import logging

from authlib.integrations.starlette_client import OAuth

from app.core import config

logger = logging.getLogger(__name__)

# Google's well-known discovery document. Authlib reads every endpoint and the
# JWKS URL from here, so we never hardcode individual Google URLs.
_GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

oauth = OAuth()

oauth.register(
    name="google",
    server_metadata_url=_GOOGLE_DISCOVERY_URL,
    client_id=config.GOOGLE_CLIENT_ID,
    client_secret=config.GOOGLE_CLIENT_SECRET,
    client_kwargs={
        # openid + email + profile gives us sub, email, name, and picture.
        "scope": "openid email profile",
        # Bound network calls so a slow/hung Google endpoint cannot pin a
        # worker indefinitely (forwarded to the underlying httpx client).
        "timeout": config.OAUTH_HTTP_TIMEOUT,
    },
)

if config.is_google_configured():
    logger.info("Google OAuth client registered (Continue with Google enabled).")
else:
    logger.info(
        "Google OAuth not configured -- the 'Continue with Google' button will "
        "show the setup page until GOOGLE_CLIENT_ID/SECRET are set."
    )
