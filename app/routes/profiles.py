# ==============================================================================
# FILE:           app/routes/profiles.py
# DESCRIPTION:    Certificate-subject profile routes: list, create, edit,
#                 delete, set-default.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..extensions import db
from ..models import Settings
from ..security import _audit
from ..validators import _clean, _validate_country, _validate_email

bp = Blueprint("profiles", __name__)


def _save_profile_from_form(profile):
    """Validate and apply POST form data to a Settings profile object.

    Returns an error string if validation fails, or ``None`` on success.
    """
    name    = _clean(request.form.get("name", ""), 128)
    country = _clean(request.form.get("country", ""), 2).upper()
    email   = _clean(request.form.get("email", ""), 256)

    if not name:
        return "Profile name is required."

    existing = Settings.query.filter(Settings.name == name, Settings.id != profile.id).first()
    if existing:
        return f"A profile named \"{name}\" already exists."

    error = _validate_country(country) or _validate_email(email)
    if error:
        return error

    try:
        key_size = int(request.form.get("key_size", 2048))
    except (ValueError, TypeError):
        key_size = 2048

    profile.name     = name
    profile.key_size = key_size if key_size in (2048, 4096) else 2048
    profile.country  = country
    profile.state    = _clean(request.form.get("state",    ""), 128)
    profile.city     = _clean(request.form.get("city",     ""), 128)
    profile.org_name = _clean(request.form.get("org_name", ""), 256)
    profile.org_unit = _clean(request.form.get("org_unit", ""), 256)
    profile.email    = email
    return None


@bp.route("/settings")
@login_required
def settings():
    """GET /settings — Redirect to the profiles list (backwards-compat URL)."""
    return redirect(url_for("profiles.profiles"))


@bp.route("/profiles")
@login_required
def profiles():
    """GET /profiles — List all certificate-subject profiles."""
    all_profiles = Settings.query.order_by(Settings.name.asc()).all()
    return render_template("profiles.html", profiles=all_profiles)


@bp.route("/profiles/new", methods=["GET", "POST"])
@login_required
def profile_new():
    """GET/POST /profiles/new — Create a new certificate-subject profile."""
    profile = Settings(name="", key_size=2048)
    if request.method == "POST":
        err = _save_profile_from_form(profile)
        if err:
            flash(err, "error")
            return render_template("profile_form.html", profile=profile, action="new")
        if Settings.query.count() == 0:
            profile.is_default = True
        db.session.add(profile)
        db.session.commit()
        _audit("profile_created", "settings", profile.id, "success", f"name={profile.name!r}")
        flash(f"Profile \"{profile.name}\" created.", "success")
        return redirect(url_for("profiles.profiles"))
    return render_template("profile_form.html", profile=profile, action="new")


@bp.route("/profiles/<int:profile_id>/edit", methods=["GET", "POST"])
@login_required
def profile_edit(profile_id):
    """GET/POST /profiles/<profile_id>/edit — Edit an existing certificate-subject profile."""
    profile = db.get_or_404(Settings, profile_id)
    if request.method == "POST":
        err = _save_profile_from_form(profile)
        if err:
            flash(err, "error")
            return render_template("profile_form.html", profile=profile, action="edit")
        db.session.commit()
        _audit("profile_updated", "settings", profile.id, "success", f"name={profile.name!r}")
        flash(f"Profile \"{profile.name}\" saved.", "success")
        return redirect(url_for("profiles.profiles"))
    return render_template("profile_form.html", profile=profile, action="edit")


@bp.route("/profiles/<int:profile_id>/delete", methods=["POST"])
@login_required
def profile_delete(profile_id):
    """POST /profiles/<profile_id>/delete — Delete a profile; blocked when only one remains."""
    profile = db.get_or_404(Settings, profile_id)
    if Settings.query.count() <= 1:
        flash("Cannot delete the last profile.", "error")
        return redirect(url_for("profiles.profiles"))
    name = profile.name
    was_default = profile.is_default
    db.session.delete(profile)
    db.session.flush()
    if was_default:
        new_default = Settings.query.order_by(Settings.name.asc()).first()
        if new_default:
            new_default.is_default = True
    db.session.commit()
    _audit("profile_deleted", "settings", profile_id, "success", f"name={name!r}")
    flash(f"Profile \"{name}\" deleted.", "success")
    return redirect(url_for("profiles.profiles"))


@bp.route("/profiles/<int:profile_id>/set-default", methods=["POST"])
@login_required
def profile_set_default(profile_id):
    """POST /profiles/<profile_id>/set-default — Promote a profile to the default."""
    profile = db.get_or_404(Settings, profile_id)
    Settings.query.filter_by(is_default=True).update({"is_default": False})
    profile.is_default = True
    db.session.commit()
    _audit("profile_set_default", "settings", profile.id, "success", f"name={profile.name!r}")
    flash(f"Profile \"{profile.name}\" is now the default.", "success")
    return redirect(url_for("profiles.profiles"))