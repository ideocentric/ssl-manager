# ==============================================================================
# FILE:           app/routes/smtp.py
# DESCRIPTION:    SMTP configuration routes (superadmin only).
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from ..extensions import db
from ..mail import MailNotConfigured, _fernet, send_test_email
from ..models import SmtpConfig
from ..security import _audit, superadmin_required
from ..validators import _clean, _validate_email

bp = Blueprint("smtp", __name__)

_PROVIDERS    = ("m365", "gmail", "custom")
_AUTH_METHODS = ("plain", "login", "none")


@bp.route("/settings/smtp", methods=["GET", "POST"])
@superadmin_required
def smtp_config():
    """GET/POST /settings/smtp — View and save SMTP configuration."""
    cfg = SmtpConfig.query.first()
    if cfg is None:
        cfg = SmtpConfig()
        db.session.add(cfg)
        db.session.flush()

    if request.method == "POST":
        provider = request.form.get("provider", "custom")
        if provider not in _PROVIDERS:
            provider = "custom"

        host = _clean(request.form.get("host", ""), 256)

        try:
            port = int(request.form.get("port", 587))
            if not (1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            port = 587

        username     = _clean(request.form.get("username",     ""), 256)
        from_address = _clean(request.form.get("from_address", ""), 256)
        auth_method  = request.form.get("auth_method", "login")
        if auth_method not in _AUTH_METHODS:
            auth_method = "login"

        use_tls = bool(request.form.get("use_tls"))
        use_ssl = bool(request.form.get("use_ssl"))
        enabled = bool(request.form.get("enabled"))

        error = None
        if enabled and not host:
            error = "Host is required when SMTP is enabled."
        elif use_tls and use_ssl:
            error = "STARTTLS and Implicit SSL cannot both be enabled at the same time."
        elif from_address:
            error = _validate_email(from_address)

        if error:
            flash(error, "error")
            return render_template("smtp_config.html", cfg=cfg)

        cfg.provider     = provider
        cfg.host         = host
        cfg.port         = port
        cfg.username     = username
        cfg.from_address = from_address
        cfg.auth_method  = auth_method
        cfg.use_tls      = use_tls
        cfg.use_ssl      = use_ssl
        cfg.enabled      = enabled

        new_password = request.form.get("password", "")
        if new_password:
            cfg.encrypt_password(new_password, _fernet())

        db.session.commit()
        _audit("smtp_config_updated", "smtp_config", cfg.id, "success",
               f"provider={provider!r} host={host!r} enabled={enabled}")
        flash("SMTP settings saved.", "success")
        return redirect(url_for("smtp.smtp_config"))

    return render_template("smtp_config.html", cfg=cfg)


@bp.route("/settings/smtp/test", methods=["POST"])
@superadmin_required
def smtp_test():
    """POST /settings/smtp/test — Send a test email to the current superadmin."""
    try:
        send_test_email(current_user.email)
        _audit("smtp_test_email", "smtp_config", None, "success",
               f"to={current_user.email!r}")
        flash(f"Test email sent to {current_user.email}.", "success")
    except MailNotConfigured:
        flash("SMTP is not configured or not enabled. Save your settings first.", "error")
    except RuntimeError:
        _audit("smtp_test_email", "smtp_config", None, "failure",
               f"to={current_user.email!r}")
        flash("Test email failed — check server logs for details.", "error")
    return redirect(url_for("smtp.smtp_config"))