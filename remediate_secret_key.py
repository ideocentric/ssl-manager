#!/usr/bin/env python3
# ==============================================================================
# FILE:           remediate_secret_key.py
# DESCRIPTION:    Detect and clean up SMTP/OAuth secrets that can no longer be
#                 decrypted after the SECRET_KEY changed.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================
"""
SECRET_KEY is the root of the Fernet key (HKDF-SHA256) that encrypts the SMTP
password and all OAuth client-secret/refresh/access tokens in the smtp_config
table. If SECRET_KEY is rotated — for example, a fresh re-install regenerated
it instead of preserving the existing key — those stored values can no longer
be decrypted. Because every decrypt_*() helper swallows the error and returns
an empty string, email then fails *silently*: the configuration still looks
enabled and populated, but authentication uses an empty secret.

This tool finds such orphaned secrets. By default it only reports them. With
--apply it clears them and disables SMTP so the operator knows to re-enter the
credentials. If you still have the *previous* SECRET_KEY, pass --old-secret-key
to decrypt with it and re-encrypt under the current key (true recovery) instead
of clearing.

Run on the server, with the same environment the service uses:

    # Report only (safe, read-only):
    /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_secret_key.py

    # Clear the dead secrets and disable SMTP, then re-enter via the UI:
    /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_secret_key.py --apply

    # Recover, if you still have the old key:
    /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_secret_key.py \\
        --old-secret-key <previous-hex-key> --apply

Exit codes: 0 = nothing to remediate (or recovery succeeded); 1 = orphaned
secrets found/remain (dry-run, or recovery could not decrypt some fields).
"""

import argparse
import base64
import logging
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Bootstrap — load the environment file so Flask builds its config the same way
# gunicorn does, then make the app package importable. Mirrors notify_expiry.py.
# ---------------------------------------------------------------------------
APP_DIR = Path(__file__).parent
ENV_FILE = Path("/etc/ssl-manager/env")

if ENV_FILE.exists():
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())

sys.path.insert(0, str(APP_DIR))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [remediate_secret_key] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# Encrypted columns on SmtpConfig, in priority order for reporting.
SECRET_FIELDS = [
    "_password_encrypted",
    "oauth_client_secret_enc",
    "oauth_refresh_token_enc",
    "oauth_access_token_enc",
]


def _fernet_from_secret(secret: str) -> Fernet:
    """Derive the SMTP/OAuth Fernet from an arbitrary SECRET_KEY.

    Mirrors app.mail._fernet so a previous key can be supplied for recovery.
    Must stay in sync with that function's HKDF parameters.
    """
    key_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ssl-manager-smtp-encryption",
    ).derive(secret.encode())
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remediate SMTP/OAuth secrets orphaned by a SECRET_KEY change.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Make changes (default: report only, no writes).",
    )
    parser.add_argument(
        "--old-secret-key", metavar="KEY",
        help="Previous SECRET_KEY. If given, re-encrypt recoverable secrets "
             "under the current key instead of clearing them.",
    )
    args = parser.parse_args()

    from app import create_app
    from app.extensions import db
    from app.mail import _fernet
    from app.models import AuditLog, SmtpConfig

    app = create_app()
    with app.app_context():
        cfg = SmtpConfig.query.first()
        if cfg is None:
            log.info("No SMTP configuration row exists — nothing to remediate.")
            return 0

        current = _fernet()
        old = _fernet_from_secret(args.old_secret_key) if args.old_secret_key else None

        # A field is orphaned if it holds ciphertext that the current key cannot
        # decrypt. Empty fields and fields that decrypt cleanly are left alone.
        broken = []
        for field in SECRET_FIELDS:
            value = getattr(cfg, field) or ""
            if not value:
                continue
            try:
                current.decrypt(value.encode())
            except InvalidToken:
                broken.append(field)

        if not broken:
            log.info("All stored SMTP/OAuth secrets decrypt cleanly with the "
                     "current SECRET_KEY. Nothing to remediate.")
            return 0

        log.warning("%d stored secret(s) cannot be decrypted with the current "
                    "SECRET_KEY: %s", len(broken), ", ".join(broken))

        # ---- Recovery path: re-encrypt with the current key using the old one ----
        if old is not None:
            recovered, failed = [], []
            for field in broken:
                try:
                    plaintext = old.decrypt(getattr(cfg, field).encode())
                except InvalidToken:
                    failed.append(field)
                    continue
                if args.apply:
                    setattr(cfg, field, current.encrypt(plaintext).decode())
                recovered.append(field)

            if failed:
                log.error("The provided --old-secret-key could not decrypt: %s. "
                          "It is not the key these secrets were encrypted with.",
                          ", ".join(failed))

            if args.apply and recovered:
                db.session.add(AuditLog(
                    username="system", user_id=None, ip_address=None,
                    action="smtp_secrets_rekeyed", resource_type="smtp_config",
                    resource_id=cfg.id, result="success",
                    detail=f"fields={','.join(recovered)}",
                ))
                db.session.commit()
                log.info("Re-encrypted %d secret(s) under the current key: %s",
                         len(recovered), ", ".join(recovered))
            elif recovered:
                log.info("[dry-run] Would re-encrypt under the current key: %s. "
                         "Re-run with --apply.", ", ".join(recovered))

            return 1 if failed else 0

        # ---- No old key: the secrets are unrecoverable; clear and disable -------
        if args.apply:
            for field in broken:
                setattr(cfg, field, "")
            cfg.enabled = False
            db.session.add(AuditLog(
                username="system", user_id=None, ip_address=None,
                action="smtp_secrets_cleared", resource_type="smtp_config",
                resource_id=cfg.id, result="success",
                detail=f"cleared={','.join(broken)} reason='SECRET_KEY rotated'",
            ))
            db.session.commit()
            log.info("Cleared %d undecryptable secret(s) and disabled SMTP.",
                     len(broken))
            log.info("Action required: re-enter the SMTP/OAuth credentials at "
                     "Settings -> SMTP, then re-enable email.")
            return 0

        log.warning("[dry-run] No changes made. Re-run with --apply to clear the "
                    "dead secret(s) and disable SMTP,")
        log.warning("          or pass --old-secret-key <previous key> to recover "
                    "them if you still have it.")
        return 1


if __name__ == "__main__":
    sys.exit(main())