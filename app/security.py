# ==============================================================================
# FILE:           app/security.py
# DESCRIPTION:    CSRF protection, audit logging, the superadmin decorator,
#                 and before/after request hooks.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import os
import secrets
from functools import wraps

from flask import abort, current_app, flash, redirect, request, session, url_for
from flask_login import current_user, login_required

from .extensions import db
from .models import AuditLog, User


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

def _get_csrf_token():
    """Return the session CSRF token, generating one if it doesn't exist."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _static_url(filename):
    """Return a cache-busting URL for a static file using its mtime as a version."""
    path = os.path.join(current_app.static_folder, filename)
    try:
        v = str(int(os.path.getmtime(path)))
    except OSError:
        v = "0"
    return url_for("static", filename=filename, v=v)


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _get_client_ip():
    """Return the client IP; trusts X-Real-IP set by the nginx proxy."""
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"


def _audit(action, resource_type=None, resource_id=None, result="success", detail=None):
    """Persist an audit event to the database and emit it via the system logger."""
    username = None
    uid = None
    try:
        if current_user and current_user.is_authenticated:
            username = current_user.username
            uid = current_user.id
    except Exception:
        pass

    ip = _get_client_ip()

    entry = AuditLog(
        username=username,
        user_id=uid,
        ip_address=ip,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        detail=(detail or "")[:512],
    )
    try:
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

    log_parts = [f"action={action}", f"result={result}", f"user={username!r}", f"ip={ip}"]
    if resource_type:
        log_parts.append(f"resource={resource_type}:{resource_id}")
    if detail:
        log_parts.append(f"detail={detail!r}")
    msg = " ".join(log_parts)
    if result == "failure":
        current_app.logger.warning(msg)
    else:
        current_app.logger.info(msg)


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def superadmin_required(f):
    """Decorator that restricts a route to authenticated superadmin users."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_superadmin:
            flash("Superadmin access required.", "error")
            return redirect(url_for("certificates.certificates"))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated


# ---------------------------------------------------------------------------
# Request hooks (registered on the app in app/__init__.py)
# ---------------------------------------------------------------------------

def security_checks():
    """First-run redirect and CSRF enforcement."""
    if request.endpoint == "static":
        return

    if request.endpoint not in (None, "auth.setup", "auth.login", "auth.logout"):
        if User.query.count() == 0:
            return redirect(url_for("auth.setup"))

    if not current_app.testing and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        session_token = session.get("csrf_token")
        submitted = (
            request.headers.get("X-CSRFToken", "")
            if request.is_json
            else request.form.get("csrf_token", "")
        )
        if not session_token or not submitted or not secrets.compare_digest(session_token, submitted):
            _audit("csrf_failure", result="failure", detail=f"endpoint={request.endpoint} method={request.method}")
            if request.is_json:
                abort(403)
            flash("Your request could not be verified. Please try again.", "error")
            return redirect(request.referrer or url_for("certificates.certificates"))


def set_security_headers(response):
    """Apply security-related HTTP response headers."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "font-src 'self' cdn.jsdelivr.net data:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response