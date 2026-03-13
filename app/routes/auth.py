# ==============================================================================
# FILE:           app/routes/auth.py
# DESCRIPTION:    Authentication routes: first-run setup, login, logout.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ..extensions import db
from ..models import User
from ..security import _audit
from ..validators import _clean, _validate_email, _validate_username

bp = Blueprint("auth", __name__)


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run setup — only accessible when no users exist."""
    if User.query.count() > 0:
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        username = _clean(request.form.get("username", ""), 64)
        email    = _clean(request.form.get("email", ""), 256)
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        error = (
            _validate_username(username)
            or _validate_email(email) or (None if email else "Email is required.")
            or (None if len(password) >= 8 else "Password must be at least 8 characters.")
            or (None if password == confirm else "Passwords do not match.")
        )
        if error:
            _audit("setup_failed", result="failure", detail=error)
            flash(error, "error")
            return render_template("setup.html")
        user = User(username=username, email=email, role="superadmin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        _audit("setup", "user", user.id, "success", f"superadmin created: {username}")
        flash(f"Welcome, {username}! Your admin account has been created.", "success")
        return redirect(url_for("certificates.certificates"))
    return render_template("setup.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    """GET/POST /login — Display the login form and authenticate the user."""
    if current_user.is_authenticated:
        return redirect(url_for("certificates.certificates"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            _audit("login_failed", "user", None, "failure", f"username={username!r}")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        if not user.active:
            _audit("login_failed", "user", user.id, "failure", "account deactivated")
            flash("This account has been deactivated.", "error")
            return render_template("login.html")
        login_user(user, remember=remember)
        _audit("login", "user", user.id, "success")
        next_page = request.args.get("next")
        return redirect(next_page or url_for("certificates.certificates"))
    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    """GET /logout — Log out the current user and redirect to the login page."""
    _audit("logout", "user", current_user.id, "success")
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))