# ==============================================================================
# FILE:           app/routes/users.py
# DESCRIPTION:    User management routes (superadmin only): list, create,
#                 edit, update, delete.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from ..extensions import db
from ..models import User, _superadmin_count
from ..security import _audit, superadmin_required
from ..validators import _clean, _validate_email, _validate_username

bp = Blueprint("users", __name__)


@bp.route("/users")
@superadmin_required
def users():
    """GET /users — List all users (superadmin only)."""
    all_users = User.query.order_by(User.created_at.asc()).all()
    return render_template("users.html", users=all_users)


@bp.route("/users/new", methods=["GET", "POST"])
@superadmin_required
def user_new():
    """GET/POST /users/new — Display and process the new-user creation form (superadmin only)."""
    if request.method == "POST":
        username = _clean(request.form.get("username", ""), 64)
        email    = _clean(request.form.get("email", ""), 256)
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "user")
        if role not in ("superadmin", "user"):
            role = "user"
        error = (
            _validate_username(username)
            or _validate_email(email) or (None if email else "Email is required.")
            or (None if len(password) >= 8 else "Password must be at least 8 characters.")
            or (None if password == confirm else "Passwords do not match.")
            or (None if not User.query.filter_by(username=username).first() else f"Username '{username}' is already taken.")
            or (None if not User.query.filter_by(email=email).first() else f"Email '{email}' is already registered.")
        )
        if error:
            flash(error, "error")
            return render_template("user_form.html", user=None, roles=["superadmin", "user"])
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        _audit("user_created", "user", user.id, "success", f"username={username!r} role={role}")
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("users.users"))
    return render_template("user_form.html", user=None, roles=["superadmin", "user"])


@bp.route("/users/<int:user_id>/edit")
@superadmin_required
def user_edit(user_id):
    """GET /users/<user_id>/edit — Show the edit form for an existing user (superadmin only)."""
    user = db.get_or_404(User, user_id)
    return render_template("user_form.html", user=user, roles=["superadmin", "user"])


@bp.route("/users/<int:user_id>/update", methods=["POST"])
@superadmin_required
def user_update(user_id):
    """POST /users/<user_id>/update — Save edits to an existing user (superadmin only)."""
    user = db.get_or_404(User, user_id)
    username = _clean(request.form.get("username", ""), 64)
    email    = _clean(request.form.get("email", ""), 256)
    role     = request.form.get("role", "user")
    active   = request.form.get("active") == "1"
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    if role not in ("superadmin", "user"):
        role = "user"
    dup_user  = User.query.filter(User.username == username, User.id != user_id).first()
    dup_email = User.query.filter(User.email == email, User.id != user_id).first()
    error = (
        _validate_username(username)
        or _validate_email(email) or (None if email else "Email is required.")
        or (None if not dup_user  else f"Username '{username}' is already taken.")
        or (None if not dup_email else f"Email '{email}' is already registered.")
    )
    if not error and (role != "superadmin" or not active):
        if user.role == "superadmin" and user.active:
            if _superadmin_count() <= 1:
                error = "Cannot demote or deactivate the last active superadmin."
    if error:
        flash(error, "error")
        return render_template("user_form.html", user=user, roles=["superadmin", "user"])
    if password:
        if len(password) < 8:
            flash("New password must be at least 8 characters.", "error")
            return render_template("user_form.html", user=user, roles=["superadmin", "user"])
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("user_form.html", user=user, roles=["superadmin", "user"])
        user.set_password(password)
    user.username = username
    user.email    = email
    user.role     = role
    user.active   = active
    db.session.commit()
    _audit("user_updated", "user", user_id, "success", f"username={username!r} role={role} active={active}")
    flash(f"User '{username}' updated.", "success")
    return redirect(url_for("users.users"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@superadmin_required
def user_delete(user_id):
    """POST /users/<user_id>/delete — Delete a user account (superadmin only)."""
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users.users"))
    if user.role == "superadmin" and _superadmin_count() <= 1:
        flash("Cannot delete the last superadmin.", "error")
        return redirect(url_for("users.users"))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    _audit("user_deleted", "user", user_id, "success", f"username={username!r}")
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("users.users"))