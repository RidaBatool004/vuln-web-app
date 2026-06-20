"""Transactional email senders for the Email-Verification and Email-OTP-2FA
features.

Stdlib only -- ``smtplib`` + ``email.message`` -- so the features add no new
dependency, mirroring the stdlib-only posture of ``core/csrf.py`` and
``core/rate_limit.py``. All SMTP settings come from ``core/config.py`` (env /
git-ignored ``.env``); no secret is hardcoded here (VULN-4 posture).

Public surface: ``send_verification_email`` (signup link) and ``send_otp_email``
(login one-time code). Both are deliberately FAIL-SAFE -- they return ``False``
(never raise) when SMTP is unconfigured or any connect/login/send error occurs,
logging the cause server-side. A failed send must never crash a request handler
nor change auth state: the caller treats ``False`` as "couldn't send" and the
user can resend.

Security note: the HTML alternative part splices the username and the
verification URL with ``html.escape(..., quote=True)`` before they enter the
markup (VULN-2 posture -- output encoding), so a username containing HTML
cannot inject into the email body.
"""

import html
import logging
import smtplib
from email.message import EmailMessage

from app.core import config

logger = logging.getLogger(__name__)


def send_verification_email(to_email: str, username: str, verify_url: str) -> bool:
    """Send the signup verification email. Returns True on success, else False.

    Builds a multipart text+HTML message and delivers it over SMTP using
    STARTTLS (port 587) or implicit TLS (port 465). Never raises -- every
    failure path returns False so signup/resend stay robust.
    """
    if not config.is_email_configured():
        # Should not happen (the signup routes gate on this), but stay safe if
        # called directly: no creds means no send.
        logger.warning("SMTP not configured; skipping verification email to %s", to_email)
        return False

    # Output-encode the two attacker-influenced values before they enter HTML.
    safe_username = html.escape(username or "", quote=True)
    safe_url = html.escape(verify_url, quote=True)

    msg = EmailMessage()
    msg["Subject"] = "Verify your email - Security Vulnerability Lab"
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_email

    # Plain-text fallback (no escaping needed -- it is not interpreted as markup).
    msg.set_content(
        f"Hi {username},\n\n"
        "Confirm your email address for the Security Vulnerability Lab by "
        "opening the link below (valid for 1 hour):\n\n"
        f"{verify_url}\n\n"
        "If you did not sign up, you can safely ignore this email."
    )
    # HTML alternative (escaped sinks).
    msg.add_alternative(
        f"<p>Hi {safe_username},</p>"
        "<p>Confirm your email address for the <strong>Security Vulnerability "
        "Lab</strong> by clicking the link below (valid for 1 hour):</p>"
        f'<p><a href="{safe_url}">Verify my email</a></p>'
        "<p>If you did not sign up, you can safely ignore this email.</p>",
        subtype="html",
    )

    try:
        if config.SMTP_PORT == 465:
            # Implicit TLS from the first byte.
            with smtplib.SMTP_SSL(
                config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT
            ) as server:
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            # Opportunistic TLS: connect plain, then upgrade with STARTTLS
            # before authenticating (the Gmail 587 path).
            with smtplib.SMTP(
                config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT
            ) as server:
                server.starttls()
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
        logger.info("Verification email sent to %s", to_email)
        return True
    except Exception:
        # Fail closed for the caller: log the real cause, surface only a bool.
        logger.exception("Failed to send verification email to %s", to_email)
        return False


def send_otp_email(to_email: str, username: str, code: str) -> bool:
    """Send a one-time login passcode (Email OTP 2FA). Returns True/False.

    Same fail-safe contract as send_verification_email -- never raises; every
    failure path returns False so the login / resend flow stays robust. The
    6-digit ``code`` is server-generated (no escaping concern); the username is
    html.escape()'d before entering the HTML part (VULN-2 posture). The raw code
    is NEVER logged (VULN-3 posture) -- only "OTP email sent to <email>".
    """
    if not config.is_email_configured():
        # Should not happen (login fails closed and the toggle gates on this),
        # but stay safe if called directly: no creds means no send.
        logger.warning("SMTP not configured; skipping OTP email to %s", to_email)
        return False

    safe_username = html.escape(username or "", quote=True)
    minutes = max(1, config.OTP_TTL_SECONDS // 60)

    msg = EmailMessage()
    msg["Subject"] = "Your login verification code - Security Vulnerability Lab"
    msg["From"] = config.SMTP_FROM
    msg["To"] = to_email

    # Plain-text fallback (no escaping needed -- not interpreted as markup).
    msg.set_content(
        f"Hi {username},\n\n"
        f"Your one-time login code is: {code}\n\n"
        f"It is valid for {minutes} minutes. If you did not try to log in, "
        "you can safely ignore this email."
    )
    # HTML alternative (escaped username; the code is a server-generated digit
    # string shown prominently).
    msg.add_alternative(
        f"<p>Hi {safe_username},</p>"
        "<p>Your one-time login code for the <strong>Security Vulnerability "
        "Lab</strong> is:</p>"
        f'<p style="font-size:24px;font-weight:bold;letter-spacing:3px;">{code}</p>'
        f"<p>It is valid for {minutes} minutes. If you did not try to log in, "
        "you can safely ignore this email.</p>",
        subtype="html",
    )

    try:
        if config.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(
                config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT
            ) as server:
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(
                config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT
            ) as server:
                server.starttls()
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
        logger.info("OTP email sent to %s", to_email)
        return True
    except Exception:
        logger.exception("Failed to send OTP email to %s", to_email)
        return False
