# ==============================================================================
# FILE:           extensions.py
# DESCRIPTION:    Shared Flask extension instances (SQLAlchemy, LoginManager)
#                 and SQLite connection hardening.  Defined here — separate from
#                 app.py — so that models and other modules can import them
#                 without triggering circular imports.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import sqlite3 as _sqlite3

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event as _sa_event
from sqlalchemy.engine import Engine as _Engine

db = SQLAlchemy()
login_manager = LoginManager()


# ---------------------------------------------------------------------------
# SQLite connection hardening
# ---------------------------------------------------------------------------
# Listen on the SQLAlchemy Engine *class* (not an instance) so the handler
# fires for every SQLite connection regardless of when the engine is created.
# The isinstance guard ensures this is a no-op for any non-SQLite backend.

@_sa_event.listens_for(_Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Apply safety and performance PRAGMAs on every new SQLite connection.

    * ``journal_mode=WAL`` — Write-Ahead Log eliminates the brief window
      where a power-loss can corrupt the database under the default DELETE
      journal.  WAL also allows readers and writers to proceed concurrently,
      which is important when multiple gunicorn workers are active.

    * ``synchronous=NORMAL`` — Flushes to disk at the most critical moments
      (WAL checkpoints) without a full ``fsync`` on every commit.  Safe with
      WAL mode; provides a good balance between durability and performance.

    * ``foreign_keys=ON`` — Enforces referential integrity at the SQLite
      layer so that cascades and SET NULL actions always fire, even if a
      query bypasses the ORM.
    """
    if not isinstance(dbapi_connection, _sqlite3.Connection):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()