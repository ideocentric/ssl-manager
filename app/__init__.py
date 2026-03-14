# ==============================================================================
# FILE:           app/__init__.py
# DESCRIPTION:    Flask application factory for SSL certificate lifecycle
#                 management.  Wires together extensions, blueprints, Jinja
#                 globals, request hooks, error handlers, and the database
#                 initialization / migration logic.
#
# USAGE:          python wsgi.py                       # local dev server
#                 gunicorn --bind unix:/run/ssl-manager/ssl-manager.sock wsgi:app
#
# DEPENDENCIES:   Flask, Flask-SQLAlchemy, Flask-Login, cryptography, pyjks,
#                 gunicorn, openssl (system binary, required for P7B export)
# REQUIREMENTS:   Python 3.10+
#
# AUTHOR:         Matt Comeione <matt@ideocentric.com>
# ORGANIZATION:   ideocentric
# GITHUB:         https://github.com/ideocentric/ssl-manager
# CREATED:        2026-03-12
# LAST MODIFIED:  2026-03-13
# VERSION:        1.2.0
#
# CHANGELOG:
#   1.2.0 - 2026-03-13 - Converted to Flask package layout (app/ package)
#   1.1.0 - 2026-03-13 - Refactored into modular package structure
#   1.0.0 - 2026-03-12 - Initial release
#
# NOTES:
#   In production, run behind nginx (loopback only) with SSH port forwarding
#   for remote access.  See README.md and install.sh for full deployment
#   instructions.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ==============================================================================

import logging
import logging.handlers
import os

from flask import Flask, render_template, request

from .extensions import db, login_manager
from .security import _audit, _get_csrf_token, _static_url, security_checks, set_security_headers


def create_app(test_config=None):
    """Create and configure the Flask application.

    Args:
        test_config: Optional dict of config values that override the defaults.
                     Used by the test suite to inject an in-memory database and
                     disable CSRF enforcement without touching environment variables.
    """
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///ssl_manager.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "ssl-manager-secret-key-change-in-prod")
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB upload limit

    if test_config is not None:
        app.config.update(test_config)

    # ---------------------------------------------------------------------------
    # Extensions
    # ---------------------------------------------------------------------------
    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    # ---------------------------------------------------------------------------
    # Logging / audit setup
    # ---------------------------------------------------------------------------
    app.logger.setLevel(logging.INFO)
    if os.path.exists("/dev/log"):
        try:
            _syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
            _syslog_handler.setFormatter(logging.Formatter("ssl-manager: %(message)s"))
            app.logger.addHandler(_syslog_handler)
        except (OSError, AttributeError):
            # /dev/log exists but is not connectable — console logging only
            pass

    # ---------------------------------------------------------------------------
    # Blueprints
    # ---------------------------------------------------------------------------
    from .routes.auth import bp as auth_bp
    from .routes.users import bp as users_bp
    from .routes.certificates import bp as certificates_bp
    from .routes.profiles import bp as profiles_bp
    from .routes.chains import bp as chains_bp
    from .routes.cas import bp as cas_bp
    from .routes.admin import bp as admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(certificates_bp)
    app.register_blueprint(profiles_bp)
    app.register_blueprint(chains_bp)
    app.register_blueprint(cas_bp)
    app.register_blueprint(admin_bp)

    # ---------------------------------------------------------------------------
    # Jinja globals
    # ---------------------------------------------------------------------------
    app.jinja_env.globals["csrf_token"] = _get_csrf_token
    app.jinja_env.globals["static_url"] = _static_url

    # ---------------------------------------------------------------------------
    # Request / response hooks
    # ---------------------------------------------------------------------------
    app.before_request(security_checks)
    app.after_request(set_security_headers)

    # ---------------------------------------------------------------------------
    # Error handlers
    # ---------------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        """Render a custom 404 page and log the missing-path event."""
        _audit("not_found", result="failure", detail=f"path={request.path!r}")
        return render_template("404.html"), 404

    @app.errorhandler(403)
    def forbidden(e):
        """Render a custom 403 page and log the forbidden-access event."""
        _audit("forbidden", result="failure", detail=f"path={request.path!r}")
        return render_template("403.html"), 403

    # ---------------------------------------------------------------------------
    # Database initialisation and schema migrations
    # ---------------------------------------------------------------------------
    _ALLOWED_MIGRATIONS = {
        ("intermediate_cert", "chain_id INTEGER REFERENCES cert_chain(id)"),
        ("certificate",       "chain_id INTEGER REFERENCES cert_chain(id)"),
        ("certificate",       "profile_id INTEGER REFERENCES settings(id)"),
        ("settings",          "name TEXT NOT NULL DEFAULT 'Default'"),
        ("settings",          "is_default INTEGER NOT NULL DEFAULT 0"),
    }

    def _add_column_if_missing(engine, table, column_def):
        """Add a column to an existing SQLite table if it doesn't already exist.

        Only whitelisted (table, column_def) pairs are permitted to prevent
        accidental or malicious schema changes.
        """
        if (table, column_def) not in _ALLOWED_MIGRATIONS:
            raise ValueError(f"Unrecognised migration: {table!r} / {column_def!r}")
        from sqlalchemy import inspect as sa_inspect, text
        inspector = sa_inspect(engine)
        cols = [c["name"] for c in inspector.get_columns(table)]
        if column_def.split()[0] not in cols:
            with engine.connect() as conn:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column_def}"))
                conn.commit()

    with app.app_context():
        # Import models to ensure they are registered with SQLAlchemy before
        # create_all() is called.
        from .models import Certificate, CertChain, CertificateAuthority, IntermediateCert, Settings  # noqa: F401

        db.create_all()
        # Ensure new columns exist on databases created before this schema version
        _add_column_if_missing(db.engine, "intermediate_cert", "chain_id INTEGER REFERENCES cert_chain(id)")
        _add_column_if_missing(db.engine, "certificate", "chain_id INTEGER REFERENCES cert_chain(id)")
        _add_column_if_missing(db.engine, "certificate", "profile_id INTEGER REFERENCES settings(id)")
        _add_column_if_missing(db.engine, "settings", "name TEXT NOT NULL DEFAULT 'Default'")
        _add_column_if_missing(db.engine, "settings", "is_default INTEGER NOT NULL DEFAULT 0")
        # Seed initial profile or migrate legacy singleton
        if Settings.query.first() is None:
            db.session.add(Settings(name="Default", is_default=True, key_size=2048))
            db.session.commit()
        else:
            # Ensure exactly one profile is marked as the default
            if not Settings.query.filter_by(is_default=True).first():
                first = Settings.query.order_by(Settings.id.asc()).first()
                first.is_default = True
                db.session.commit()
        # Backfill profile_id for certificates created before profiles were introduced
        try:
            default_p = Settings.query.filter_by(is_default=True).first()
            if default_p:
                Certificate.query.filter_by(profile_id=None).update({"profile_id": default_p.id})
                db.session.commit()
        except Exception:
            db.session.rollback()
        # Migrate intermediates that pre-date named chains into a "Default Chain"
        try:
            orphans = IntermediateCert.query.filter_by(chain_id=None).all()
            if orphans:
                default_chain = CertChain.query.filter_by(name="Default Chain").first()
                if default_chain is None:
                    default_chain = CertChain(name="Default Chain",
                                              description="Migrated from previous version")
                    db.session.add(default_chain)
                    db.session.flush()
                for ic in orphans:
                    ic.chain_id = default_chain.id
                db.session.commit()
        except Exception:
            db.session.rollback()

    return app