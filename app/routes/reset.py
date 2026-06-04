# ==============================================================================
# FILE:           app/routes/reset.py
# DESCRIPTION:    Self-service password reset: forgot-password and reset-password
#                 flows. All routes are unauthenticated.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import hashlib
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from sqlalchemy import func

from ..extensions import db
from ..mail import MailNotConfigured, send_email
from ..models import PasswordResetAttempt, PasswordResetToken, User
from ..security import _audit, _get_client_ip
from ..validators import _clean, _validate_email

bp = Blueprint("reset", __name__)

_RATE_LIMIT_MAX    = 3
_RATE_LIMIT_WINDOW = timedelta(minutes=15)
_TOKEN_EXPIRY      = timedelta(hours=1)


def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _check_and_record_attempt(ip: str) -> bool:
    """Record this attempt, prune stale rows, return True if rate limit is exceeded."""
    now    = datetime.utcnow()
    cutoff = now - _RATE_LIMIT_WINDOW

    PasswordResetAttempt.query.filter(
        PasswordResetAttempt.created_at < cutoff
    ).delete(synchronize_session=False)

    count = PasswordResetAttempt.query.filter(
        PasswordResetAttempt.ip_address == ip,
        PasswordResetAttempt.created_at >= cutoff,
    ).count()

    db.session.add(PasswordResetAttempt(ip_address=ip, created_at=now))
    db.session.commit()

    return count >= _RATE_LIMIT_MAX


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """GET/POST /forgot-password — Request a password reset email."""
    if request.method == "POST":
        email = _clean(request.form.get("email", ""), 256)
        ip    = _get_client_ip()

        rate_limited = _check_and_record_attempt(ip)

        if rate_limited:
            current_app.logger.warning(f"Password reset rate limit hit ip={ip}")
        elif not _validate_email(email):
            user = User.query.filter(
                func.lower(User.email) == func.lower(email),
                User.active == True,  # noqa: E712
            ).first()
            if user:
                raw        = secrets.token_hex(32)
                now        = datetime.utcnow()
                expires_at = now + _TOKEN_EXPIRY
                db.session.add(PasswordResetToken(
                    user_id=user.id,
                    token_hash=_token_hash(raw),
                    created_at=now,
                    expires_at=expires_at,
                ))
                db.session.commit()

                reset_url = url_for("reset.reset_password_form", token=raw, _external=True)
                try:
                    send_email(
                        to=user.email,
                        subject="SSL Manager — Password Reset",
                        body_text=(
                            f"You requested a password reset for your SSL Manager account.\n\n"
                            f"Click the link below to set a new password. "
                            f"This link expires in 1 hour.\n\n"
                            f"{reset_url}\n\n"
                            f"If you did not request this, you can safely ignore this email."
                        ),
                        body_html=(
                            f"<p>You requested a password reset for your SSL Manager account.</p>"
                            f"<p>Click the link below to set a new password. "
                            f"This link expires in <strong>1 hour</strong>.</p>"
                            f'<p><a href="{reset_url}">{reset_url}</a></p>'
                            f"<p>If you did not request this, you can safely ignore this email.</p>"
                        ),
                    )
                    _audit("password_reset_requested", "user", user.id, "success", f"ip={ip}")
                except (MailNotConfigured, RuntimeError) as exc:
                    current_app.logger.error(f"Reset email failed user={user.id} {exc!r}")
                    _audit("password_reset_requested", "user", user.id, "failure",
                           f"mail error ip={ip}")

        # Always show the same message — do not reveal whether the email exists
        flash(
            "If that email address is registered and active, "
            "you will receive a reset link shortly.",
            "info",
        )
        return redirect(url_for("reset.forgot_password"))

    return render_template("forgot_password.html")


@bp.route("/reset-password/<token>", methods=["GET"])
def reset_password_form(token):
    """GET /reset-password/<token> — Show the new-password form if the token is valid."""
    tok = PasswordResetToken.query.filter_by(token_hash=_token_hash(token)).first()
    if tok is None or tok.used_at is not None or tok.expires_at <= datetime.utcnow():
        flash("This password reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))
    return render_template("reset_password.html", token=token)


@bp.route("/reset-password/<token>", methods=["POST"])
def reset_password_submit(token):
    """POST /reset-password/<token> — Validate token, update password, invalidate sessions."""
    tok = PasswordResetToken.query.filter_by(token_hash=_token_hash(token)).first()
    now = datetime.utcnow()
    ip  = _get_client_ip()

    if tok is None or tok.used_at is not None or tok.expires_at <= now:
        flash("This password reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))

    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return render_template("reset_password.html", token=token)
    if password != confirm:
        flash("Passwords do not match.", "error")
        return render_template("reset_password.html", token=token)

    user = db.session.get(User, tok.user_id)
    if user is None or not user.active:
        flash("This password reset link is no longer valid.", "error")
        return redirect(url_for("auth.login"))

    user.set_password(password)
    user.session_version = (user.session_version or 0) + 1
    tok.used_at = now
    db.session.commit()

    _audit("password_reset", "user", user.id, "success", f"ip={ip}")
    flash("Your password has been reset. Please sign in.", "success")
    return redirect(url_for("auth.login"))