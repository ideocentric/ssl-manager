# ==============================================================================
# FILE:           wsgi.py
# DESCRIPTION:    WSGI entry point.  Imports the application factory from the
#                 app package and creates the app instance used by gunicorn
#                 and the development server.
#
# USAGE:          python wsgi.py                              # dev server
#                 gunicorn --bind unix:/run/ssl-manager/ssl-manager.sock wsgi:app
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)