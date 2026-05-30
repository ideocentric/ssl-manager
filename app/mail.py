# ==============================================================================
# FILE:           app/mail.py
# DESCRIPTION:    SMTP email helper. Reads SmtpConfig from the DB and sends
#                 email via stdlib smtplib — no Flask-Mail dependency.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import base64
import smtplib
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
        current_app.logger.error(f"SMTP send failed to {to!r}: {exc!r}")
        raise RuntimeError("SMTP connection failed — check server logs.") from exc


def send_test_email(to: str) -> None:
    send_email(
        to=to,
        subject="SSL Manager — SMTP test",
        body_text="This is a test email from SSL Manager. Your SMTP configuration is working correctly.",
        body_html="<p>This is a test email from <strong>SSL Manager</strong>. Your SMTP configuration is working correctly.</p>",
    )