# ==============================================================================
# FILE:           app/routes/smtp.py
# DESCRIPTION:    SMTP / OAuth email configuration routes (superadmin only).
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import secrets
import urllib.parse

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user

from ..extensions import db
from ..mail import MailNotConfigured, _fernet, _token_request, send_test_email
from ..models import SmtpConfig
from ..security import _audit, superadmin_required
from ..validators import _clean, _validate_email

bp = Blueprint("smtp", __name__)

_PROVIDERS    = ("m365", "gmail", "custom")
_AUTH_METHODS = ("plain", "login", "none")
_AUTH_TYPES   = ("smtp", "oauth")
_OAUTH_PROVIDERS = {"gmail", "m365"}

_OAUTH_PRESETS = {
    "gmail": {"host": "smtp.gmail.com",     "port": 587, "use_tls": True,  "use_ssl": False},
    "m365":  {"host": "smtp.office365.com", "port": 587, "use_tls": True,  "use_ssl": False},
}

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_SCOPE    = "https://www.googleapis.com/auth/gmail.send"

_MS_AUTH_URL_TPL   = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
_MS_TOKEN_URL_TPL  = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_MS_SCOPE          = "https://outlook.office365.com/SMTP.Send offline_access"


@bp.route("/settings/smtp", methods=["GET", "POST"])
@superadmin_required
def smtp_config():
    """GET/POST /settings/smtp — View and save email configuration."""
    cfg = SmtpConfig.query.first()
    if cfg is None:
        cfg = SmtpConfig()
        db.session.add(cfg)
        db.session.flush()

    if request.method == "POST":
        provider = request.form.get("provider", "custom")
        if provider not in _PROVIDERS:
            provider = "custom"

        auth_type = request.form.get("auth_type", "smtp")
        if auth_type not in _AUTH_TYPES:
            auth_type = "smtp"

        # OAuth providers in OAuth mode: host/port/tls are fixed server-side
        if auth_type == "oauth" and provider in _OAUTH_PROVIDERS:
            preset = _OAUTH_PRESETS[provider]
            host    = preset["host"]
            port    = preset["port"]
            use_tls = preset["use_tls"]
            use_ssl = preset["use_ssl"]
        else:
            host = _clean(request.form.get("host", ""), 256)
            try:
                port = int(request.form.get("port", 587))
                if not (1 <= port <= 65535):
                    raise ValueError
            except (ValueError, TypeError):
                port = 587
            use_tls = bool(request.form.get("use_tls"))
            use_ssl = bool(request.form.get("use_ssl"))

        username     = _clean(request.form.get("username",     ""), 256)
        from_address = _clean(request.form.get("from_address", ""), 256)
        auth_method  = request.form.get("auth_method", "login")
        if auth_method not in _AUTH_METHODS:
            auth_method = "login"

        enabled = bool(request.form.get("enabled"))

        # OAuth-specific fields
        oauth_client_id = _clean(request.form.get("oauth_client_id", ""), 512)
        oauth_tenant_id = _clean(request.form.get("oauth_tenant_id", ""), 256)
        new_oauth_secret = request.form.get("oauth_client_secret", "")

        error = None
        if auth_type == "smtp":
            if enabled and not host:
                error = "Host is required when email is enabled."
            elif use_tls and use_ssl:
                error = "STARTTLS and Implicit SSL cannot both be enabled at the same time."
        elif auth_type == "oauth":
            if enabled and not oauth_client_id:
                error = "Client ID is required when OAuth is enabled."
            elif enabled and not cfg.oauth_client_secret_enc and not new_oauth_secret:
                error = "Client Secret is required when OAuth is enabled."

        if not error and from_address:
            error = _validate_email(from_address)

        if error:
            flash(error, "error")
            return render_template("smtp_config.html", cfg=cfg)

        cfg.provider     = provider
        cfg.auth_type    = auth_type
        cfg.host         = host
        cfg.port         = port
        cfg.username     = username
        cfg.from_address = from_address
        cfg.auth_method  = auth_method
        cfg.use_tls      = use_tls
        cfg.use_ssl      = use_ssl
        cfg.enabled      = enabled
        cfg.oauth_client_id  = oauth_client_id
        cfg.oauth_tenant_id  = oauth_tenant_id

        f = _fernet()
        if auth_type == "smtp":
            new_password = request.form.get("password", "")
            if new_password:
                cfg.encrypt_password(new_password, f)
        if new_oauth_secret:
            cfg.encrypt_oauth_secret(new_oauth_secret, f)

        db.session.commit()
        _audit("smtp_config_updated", "smtp_config", cfg.id, "success",
               f"provider={provider!r} auth_type={auth_type!r} enabled={enabled}")
        flash("Email settings saved.", "success")
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
        flash("Email is not configured or not enabled. Save your settings first.", "error")
    except RuntimeError:
        _audit("smtp_test_email", "smtp_config", None, "failure",
               f"to={current_user.email!r}")
        flash("Test email failed — check server logs for details.", "error")
    return redirect(url_for("smtp.smtp_config"))


# ---------------------------------------------------------------------------
# OAuth authorize / callback routes
# ---------------------------------------------------------------------------

@bp.route("/settings/smtp/oauth/google/authorize")
@superadmin_required
def oauth_google_authorize():
    """Redirect the admin to Google's OAuth consent screen."""
    cfg = SmtpConfig.query.first()
    if not cfg or not cfg.oauth_client_id:
        flash("Save your Google Client ID and Client Secret first, then connect.", "error")
        return redirect(url_for("smtp.smtp_config"))

    state = secrets.token_urlsafe(32)
    session["smtp_oauth_state"] = state

    callback_url = url_for("smtp.oauth_google_callback", _external=True)
    params = {
        "client_id":     cfg.oauth_client_id,
        "redirect_uri":  callback_url,
        "response_type": "code",
        "scope":         _GOOGLE_SCOPE,
        "access_type":   "offline",
        "prompt":        "consent",
        "state":         state,
    }
    return redirect(_GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params))


@bp.route("/settings/smtp/oauth/google/callback")
@superadmin_required
def oauth_google_callback():
    """Handle Google OAuth callback: exchange code for tokens and store them."""
    if request.args.get("state") != session.pop("smtp_oauth_state", None):
        flash("OAuth state mismatch — possible CSRF attack. Please try again.", "error")
        return redirect(url_for("smtp.smtp_config"))

    error = request.args.get("error")
    if error:
        flash(f"Google authorization denied: {error}", "error")
        return redirect(url_for("smtp.smtp_config"))

    code = request.args.get("code")
    if not code:
        flash("No authorization code returned by Google.", "error")
        return redirect(url_for("smtp.smtp_config"))

    cfg = SmtpConfig.query.first()
    f = _fernet()
    callback_url = url_for("smtp.oauth_google_callback", _external=True)

    result = _token_request("https://oauth2.googleapis.com/token", {
        "code":          code,
        "client_id":     cfg.oauth_client_id,
        "client_secret": cfg.decrypt_oauth_secret(f),
        "redirect_uri":  callback_url,
        "grant_type":    "authorization_code",
    })

    if "refresh_token" not in result:
        detail = result.get("error_description") or result.get("error") or "no refresh_token in response"
        flash(f"Google token exchange failed: {detail}", "error")
        return redirect(url_for("smtp.smtp_config"))

    import datetime
    cfg.auth_type = "oauth"
    cfg.encrypt_refresh_token(result["refresh_token"], f)
    cfg.encrypt_access_token(result.get("access_token", ""), f)
    cfg.oauth_token_expiry = (
        datetime.datetime.utcnow() + datetime.timedelta(seconds=result.get("expires_in", 3600))
    )

    # Auto-apply Gmail SMTP preset so host/port are set correctly
    preset = _OAUTH_PRESETS["gmail"]
    cfg.host    = preset["host"]
    cfg.port    = preset["port"]
    cfg.use_tls = preset["use_tls"]
    cfg.use_ssl = preset["use_ssl"]

    db.session.commit()
    _audit("smtp_oauth_connected", "smtp_config", cfg.id, "success", "provider=gmail")
    flash("Google account connected successfully.", "success")
    return redirect(url_for("smtp.smtp_config"))


@bp.route("/settings/smtp/oauth/microsoft/authorize")
@superadmin_required
def oauth_microsoft_authorize():
    """Redirect the admin to Microsoft's OAuth consent screen."""
    cfg = SmtpConfig.query.first()
    if not cfg or not cfg.oauth_client_id:
        flash("Save your Microsoft Client ID and Client Secret first, then connect.", "error")
        return redirect(url_for("smtp.smtp_config"))

    state = secrets.token_urlsafe(32)
    session["smtp_oauth_state"] = state

    tenant = cfg.oauth_tenant_id or "common"
    callback_url = url_for("smtp.oauth_microsoft_callback", _external=True)
    params = {
        "client_id":     cfg.oauth_client_id,
        "redirect_uri":  callback_url,
        "response_type": "code",
        "scope":         _MS_SCOPE,
        "state":         state,
    }
    auth_url = _MS_AUTH_URL_TPL.format(tenant=tenant)
    return redirect(auth_url + "?" + urllib.parse.urlencode(params))


@bp.route("/settings/smtp/oauth/microsoft/callback")
@superadmin_required
def oauth_microsoft_callback():
    """Handle Microsoft OAuth callback: exchange code for tokens and store them."""
    if request.args.get("state") != session.pop("smtp_oauth_state", None):
        flash("OAuth state mismatch — possible CSRF attack. Please try again.", "error")
        return redirect(url_for("smtp.smtp_config"))

    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", error)
        flash(f"Microsoft authorization denied: {desc}", "error")
        return redirect(url_for("smtp.smtp_config"))

    code = request.args.get("code")
    if not code:
        flash("No authorization code returned by Microsoft.", "error")
        return redirect(url_for("smtp.smtp_config"))

    cfg = SmtpConfig.query.first()
    f = _fernet()
    tenant = cfg.oauth_tenant_id or "common"
    callback_url = url_for("smtp.oauth_microsoft_callback", _external=True)

    result = _token_request(_MS_TOKEN_URL_TPL.format(tenant=tenant), {
        "code":          code,
        "client_id":     cfg.oauth_client_id,
        "client_secret": cfg.decrypt_oauth_secret(f),
        "redirect_uri":  callback_url,
        "grant_type":    "authorization_code",
        "scope":         _MS_SCOPE,
    })

    if "refresh_token" not in result:
        detail = result.get("error_description") or result.get("error") or "no refresh_token in response"
        flash(f"Microsoft token exchange failed: {detail}", "error")
        return redirect(url_for("smtp.smtp_config"))

    import datetime
    cfg.auth_type = "oauth"
    cfg.encrypt_refresh_token(result["refresh_token"], f)
    cfg.encrypt_access_token(result.get("access_token", ""), f)
    cfg.oauth_token_expiry = (
        datetime.datetime.utcnow() + datetime.timedelta(seconds=result.get("expires_in", 3600))
    )

    # Auto-apply M365 SMTP preset
    preset = _OAUTH_PRESETS["m365"]
    cfg.host    = preset["host"]
    cfg.port    = preset["port"]
    cfg.use_tls = preset["use_tls"]
    cfg.use_ssl = preset["use_ssl"]

    db.session.commit()
    _audit("smtp_oauth_connected", "smtp_config", cfg.id, "success", "provider=m365")
    flash("Microsoft account connected successfully.", "success")
    return redirect(url_for("smtp.smtp_config"))


@bp.route("/settings/smtp/oauth/disconnect", methods=["POST"])
@superadmin_required
def oauth_disconnect():
    """POST /settings/smtp/oauth/disconnect — Clear stored OAuth tokens."""
    cfg = SmtpConfig.query.first()
    if cfg:
        provider = cfg.provider
        cfg.auth_type               = "smtp"
        cfg.oauth_refresh_token_enc = ""
        cfg.oauth_access_token_enc  = ""
        cfg.oauth_token_expiry      = None
        db.session.commit()
        _audit("smtp_oauth_disconnected", "smtp_config", cfg.id, "success",
               f"provider={provider!r}")
        flash("OAuth connection removed. Switch to SMTP or reconnect to send email.", "warning")
    return redirect(url_for("smtp.smtp_config"))