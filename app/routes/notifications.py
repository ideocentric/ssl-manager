# ==============================================================================
# FILE:           app/routes/notifications.py
# DESCRIPTION:    Expiry notification settings route (superadmin only).
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..extensions import db
from ..models import NotificationConfig
from ..security import _audit, superadmin_required
from ..validators import _clean, _validate_email

bp = Blueprint("notifications", __name__)


@bp.route("/settings/notifications", methods=["GET", "POST"])
@superadmin_required
def notification_config():
    """GET/POST /settings/notifications — View and save expiry notification settings."""
    cfg = NotificationConfig.query.first()
    if cfg is None:
        cfg = NotificationConfig()
        db.session.add(cfg)
        db.session.flush()

    if request.method == "POST":
        enabled              = bool(request.form.get("enabled"))
        notify_certificates  = bool(request.form.get("notify_certificates"))
        notify_cas           = bool(request.form.get("notify_cas"))
        notify_intermediates = bool(request.form.get("notify_intermediates"))

        try:
            days_threshold = int(request.form.get("days_threshold", 30))
            if not (1 <= days_threshold <= 365):
                raise ValueError
        except (ValueError, TypeError):
            days_threshold = 30

        raw_emails = _clean(request.form.get("recipient_emails", ""), 1024)

        error = None
        if enabled:
            if not raw_emails:
                error = "At least one recipient email is required when notifications are enabled."
            else:
                for addr in [e.strip() for e in raw_emails.split(",") if e.strip()]:
                    err = _validate_email(addr)
                    if err:
                        error = f"Invalid email address: {addr}"
                        break
            if not error and not (notify_certificates or notify_cas or notify_intermediates):
                error = "At least one certificate type must be selected."

        if error:
            flash(error, "error")
            return render_template("notifications.html", cfg=cfg)

        cfg.enabled              = enabled
        cfg.days_threshold       = days_threshold
        cfg.recipient_emails     = raw_emails
        cfg.notify_certificates  = notify_certificates
        cfg.notify_cas           = notify_cas
        cfg.notify_intermediates = notify_intermediates

        db.session.commit()
        _audit("notification_config_updated", "notification_config", cfg.id, "success",
               f"enabled={enabled} days={days_threshold}")
        flash("Notification settings saved.", "success")
        return redirect(url_for("notifications.notification_config"))

    return render_template("notifications.html", cfg=cfg)