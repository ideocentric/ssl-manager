# ==============================================================================
# FILE:           app/mail.py
# DESCRIPTION:    SMTP email helper. Reads SmtpConfig from the DB and sends
#                 email via stdlib smtplib — no Flask-Mail dependency.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

# Defer annotation evaluation so PEP 604 unions (e.g. `str | None`) below are
# treated as strings and do NOT execute at import time. Without this, importing
# this module on Python 3.9 (the RHEL 9 runtime) raises TypeError on the
# `str | None` annotation and gunicorn workers fail to boot.
from __future__ import annotations

import base64
import datetime
import json
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app


class MailNotConfigured(Exception):
    """Raised when SMTP is not enabled or the config row is missing."""


def _fernet() -> Fernet:
    """Derive a Fernet key from SECRET_KEY via HKDF-SHA256."""
    secret = current_app.config["SECRET_KEY"].encode()
    key_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ssl-manager-smtp-encryption",
    ).derive(secret)
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def _get_config():
    from .models import SmtpConfig
    cfg = SmtpConfig.query.first()
    if cfg is None or not cfg.enabled:
        raise MailNotConfigured("SMTP is not configured or not enabled.")
    return cfg


def _token_request(url: str, data: dict) -> dict:
    """POST to an OAuth token endpoint using stdlib urllib; return parsed JSON."""
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=encoded, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read())
        except Exception:
            return {"error": str(exc)}


def _get_google_access_token(cfg, f) -> str:
    """Return a valid Google access token, refreshing via refresh_token if needed."""
    now = datetime.datetime.utcnow()
    if cfg.oauth_token_expiry and cfg.oauth_token_expiry > now + datetime.timedelta(seconds=60):
        token = cfg.decrypt_access_token(f)
        if token:
            return token
    result = _token_request("https://oauth2.googleapis.com/token", {
        "client_id":     cfg.oauth_client_id,
        "client_secret": cfg.decrypt_oauth_secret(f),
        "refresh_token": cfg.decrypt_refresh_token(f),
        "grant_type":    "refresh_token",
    })
    if "access_token" not in result:
        raise RuntimeError(
            f"Google token refresh failed: {result.get('error_description', result.get('error', 'unknown'))}"
        )
    cfg.encrypt_access_token(result["access_token"], f)
    cfg.oauth_token_expiry = now + datetime.timedelta(seconds=result.get("expires_in", 3600))
    from .extensions import db
    db.session.commit()
    return result["access_token"]


def _get_microsoft_access_token(cfg, f) -> str:
    """Return a valid Microsoft access token, refreshing via refresh_token if needed."""
    now = datetime.datetime.utcnow()
    if cfg.oauth_token_expiry and cfg.oauth_token_expiry > now + datetime.timedelta(seconds=60):
        token = cfg.decrypt_access_token(f)
        if token:
            return token
    tenant = cfg.oauth_tenant_id or "common"
    result = _token_request(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        {
            "client_id":     cfg.oauth_client_id,
            "client_secret": cfg.decrypt_oauth_secret(f),
            "refresh_token": cfg.decrypt_refresh_token(f),
            "grant_type":    "refresh_token",
            "scope":         "https://outlook.office365.com/SMTP.Send offline_access",
        },
    )
    if "access_token" not in result:
        raise RuntimeError(
            f"Microsoft token refresh failed: {result.get('error_description', result.get('error', 'unknown'))}"
        )
    cfg.encrypt_access_token(result["access_token"], f)
    cfg.oauth_token_expiry = now + datetime.timedelta(seconds=result.get("expires_in", 3600))
    if "refresh_token" in result:
        cfg.encrypt_refresh_token(result["refresh_token"], f)
    from .extensions import db
    db.session.commit()
    return result["access_token"]


def _send_via_xoauth2(cfg, msg, to: str, access_token: str) -> None:
    """Send a pre-built MIME message via SMTP using the XOAUTH2 mechanism."""
    if cfg.use_ssl:
        smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=10)
    else:
        smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=10)
        smtp.starttls()
    smtp.ehlo()
    auth_string = f"user={cfg.username}\x01auth=Bearer {access_token}\x01\x01"
    encoded = base64.b64encode(auth_string.encode()).decode()
    smtp.docmd("AUTH", f"XOAUTH2 {encoded}")
    smtp.sendmail(cfg.from_address, [to], msg.as_string())
    smtp.quit()


def send_email(to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
    """Send an email using the stored SmtpConfig.

    Raises MailNotConfigured if SMTP is disabled.
    Raises RuntimeError (with original exception chained) on connection/send failure.
    Never exposes raw SMTP error details to callers — those are logged here.
    """
    cfg = _get_config()
    f = _fernet()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg.from_address
    msg["To"] = to
    msg.attach(MIMEText(body_text, "plain"))
    if body_html:
        msg.attach(MIMEText(body_html, "html"))

    try:
        if cfg.auth_type == "oauth":
            if cfg.provider == "gmail":
                access_token = _get_google_access_token(cfg, f)
            elif cfg.provider == "m365":
                access_token = _get_microsoft_access_token(cfg, f)
            else:
                raise RuntimeError(f"OAuth not supported for provider {cfg.provider!r}")
            _send_via_xoauth2(cfg, msg, to, access_token)
        else:
            if cfg.use_ssl:
                smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=10)
            else:
                smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=10)
                if cfg.use_tls:
                    smtp.starttls()
            if cfg.auth_method in ("plain", "login"):
                smtp.login(cfg.username, cfg.decrypt_password(f))
            smtp.sendmail(cfg.from_address, [to], msg.as_string())
            smtp.quit()
    except Exception as exc:
        current_app.logger.error(f"Email send failed to {to!r}: {exc!r}")
        raise RuntimeError("Email send failed — check server logs.") from exc


def send_test_email(to: str) -> None:
    send_email(
        to=to,
        subject="SSL Manager — SMTP test",
        body_text="This is a test email from SSL Manager. Your SMTP configuration is working correctly.",
        body_html="<p>This is a test email from <strong>SSL Manager</strong>. Your SMTP configuration is working correctly.</p>",
    )