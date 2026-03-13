# ==============================================================================
# FILE:           conftest.py
# DESCRIPTION:    Shared pytest fixtures for the ssl-manager test suite.
#                 Provides the Flask application instance, database lifecycle
#                 management, and HTTP test clients via the application factory.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import pytest
from sqlalchemy.pool import StaticPool

from app import create_app
from app.extensions import db
from app.models import Settings, User

TEST_ADMIN_USERNAME = "admin"
TEST_ADMIN_PASSWORD = "testpassword123"


@pytest.fixture(scope="session")
def flask_app():
    """Single Flask app instance for the whole test session.

    Calls the application factory with an in-memory SQLite database via
    StaticPool so all connections share the same data.  CSRF enforcement
    is disabled for the test run.  The factory runs db.create_all() and
    seeds the default Settings profile; this fixture then adds the test
    superadmin user.
    """
    _app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        },
        "SECRET_KEY": "test-secret",
        "WTF_CSRF_ENABLED": False,
    })

    with _app.app_context():
        admin = User(username=TEST_ADMIN_USERNAME, email="admin@test.com", role="superadmin")
        admin.set_password(TEST_ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        yield _app
        db.drop_all()


@pytest.fixture(autouse=True)
def clean_db(flask_app):
    """Truncate all tables and re-seed Settings + admin user after each test."""
    yield
    with flask_app.app_context():
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        admin = User(username=TEST_ADMIN_USERNAME, email="admin@test.com", role="superadmin")
        admin.set_password(TEST_ADMIN_PASSWORD)
        db.session.add(Settings(key_size=2048))
        db.session.add(admin)
        db.session.commit()
    # Clear Flask-Login's cached user from the persistent app context's g object.
    # Because flask_app holds an app_context open for the whole session,
    # Flask reuses it for all requests, making g._login_user persist across tests.
    from flask.globals import _cv_app
    app_ctx = _cv_app.get(None)
    if app_ctx is not None and hasattr(app_ctx, "g"):
        app_ctx.g.pop("_login_user", None)


@pytest.fixture()
def client(flask_app):
    """Test client pre-authenticated as the test superadmin."""
    with flask_app.test_client() as c:
        c.post("/login", data={
            "username": TEST_ADMIN_USERNAME,
            "password": TEST_ADMIN_PASSWORD,
        }, follow_redirects=True)
        yield c


@pytest.fixture()
def anon_client(flask_app):
    """Unauthenticated test client."""
    return flask_app.test_client(use_cookies=True)