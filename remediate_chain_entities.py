#!/usr/bin/env python3
# ==============================================================================
# FILE:           remediate_chain_entities.py
# DESCRIPTION:    Repair certificate-chain PEM corrupted by HTML-entity escaping
#                 (e.g. literal '&#10;' instead of newlines) on installs that ran
#                 a build predating the data-ic-pem render fix.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================
"""
An earlier build rendered chain intermediate PEM into an HTML attribute with a
filter that double-escaped newlines, so the edit modal could persist PEM in
which real newlines had become the literal text '&#10;' (and '&' -> '&amp;').
Such a value is not loadable as a certificate and leaks into exported
fullchain.pem files. The render bug is fixed in app/templates/chain_detail.html,
but rows that were already saved corrupted stay corrupted — this tool repairs
them in place.

It only rewrites rows that DO NOT currently parse as a certificate but DO parse
once HTML entities are decoded. Clean rows are left untouched, and rows that are
broken for any other reason are reported, never rewritten.

Run on the server, with the same environment the service uses. Take a database
backup first, and run this AFTER upgrading so the render fix is in place and
nothing re-corrupts:

    bash /opt/ssl-manager/backup.sh                      # back up first

    # Report only (safe, read-only):
    /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_chain_entities.py

    # Repair the corrupted rows in place:
    /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_chain_entities.py --apply

    # Also scan leaf certificates (certificate.signed_cert_pem):
    /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_chain_entities.py --include-leaf --apply

Exit codes: 0 = nothing to repair, or repaired successfully with no leftovers;
1 = repairable rows found in a dry-run, or unrepairable rows remain.
"""

import argparse
import html
import logging
import os
import sys
from pathlib import Path

from cryptography import x509

# ---------------------------------------------------------------------------
# Bootstrap — load the env file so Flask builds config like gunicorn does, then
# make the app package importable. Mirrors remediate_secret_key.py.
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
    format="%(asctime)s [remediate_chain_entities] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def decode_entities(s: str) -> str:
    """Reverse HTML-entity corruption, repeatedly until the string is stable.

    Handles both single ('&#10;') and double ('&amp;#10;') escaping by applying
    html.unescape until it no longer changes. A clean PEM contains no '&', so
    this is a no-op on uncorrupted data.
    """
    prev, out = None, s
    for _ in range(6):
        if out == prev:
            break
        prev, out = out, html.unescape(out)
    return out


def _parses(pem: str) -> bool:
    try:
        x509.load_pem_x509_certificate(pem.encode())
        return True
    except Exception:
        return False


def remediate(apply: bool = False, include_leaf: bool = False):
    """Scan and (optionally) repair entity-corrupted PEM. Runs in an app context.

    Only rewrites a row when it fails to parse as stored but parses after entity
    decoding. Returns (repaired, unrepairable) lists of human-readable labels.
    """
    from app.extensions import db
    from app.models import AuditLog, Certificate, IntermediateCert

    targets = [(
        IntermediateCert, "pem_data", "intermediate_cert",
        lambda r: f"intermediate id={r.id} name={r.name!r} chain_id={r.chain_id}",
    )]
    if include_leaf:
        targets.append((
            Certificate, "signed_cert_pem", "certificate",
            lambda r: f"certificate id={r.id} domain={r.domain!r}",
        ))

    repaired, unrepairable, repaired_ids = [], [], []
    for model, column, rtype, label in targets:
        for row in model.query.all():
            pem = getattr(row, column) or ""
            if not pem.strip():
                continue
            if _parses(pem):
                continue  # already clean — never touched
            fixed = decode_entities(pem).strip()
            if not _parses(fixed):
                unrepairable.append(label(row))
                continue
            repaired.append(label(row))
            repaired_ids.append(f"{rtype}:{row.id}")
            if apply:
                setattr(row, column, fixed)

    if apply and repaired:
        db.session.add(AuditLog(
            username="system", user_id=None, ip_address=None,
            action="chain_pem_remediated", resource_type="intermediate_cert",
            resource_id=None, result="success",
            detail=f"repaired={','.join(repaired_ids)}",
        ))
        db.session.commit()

    return repaired, unrepairable


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Repair chain PEM corrupted by HTML-entity escaping ('&#10;').",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Make changes (default: report only, no writes).",
    )
    parser.add_argument(
        "--include-leaf", action="store_true",
        help="Also scan certificate.signed_cert_pem (leaf certs).",
    )
    args = parser.parse_args()

    from app import create_app

    app = create_app()
    with app.app_context():
        repaired, unrepairable = remediate(apply=args.apply, include_leaf=args.include_leaf)

        if not repaired and not unrepairable:
            log.info("No entity-corrupted PEM found. Nothing to remediate.")
            return 0

        if repaired:
            verb = "Repaired" if args.apply else "[dry-run] Would repair"
            log.info("%s %d corrupted row(s):", verb, len(repaired))
            for r in repaired:
                log.info("    %s", r)
            if not args.apply:
                log.warning("No changes made. Re-run with --apply to repair them.")

        if unrepairable:
            log.error("%d corrupted row(s) could NOT be recovered by entity "
                      "decoding (manual review needed):", len(unrepairable))
            for r in unrepairable:
                log.error("    %s", r)

        # Non-zero if a dry-run found work to do, or unrepairable rows remain.
        if unrepairable or (repaired and not args.apply):
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(main())