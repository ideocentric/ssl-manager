#!/usr/bin/env python3
"""
notify_expiry.py — Daily expiry digest for SSL Manager.

Queries all certificates, CAs, and intermediates whose expiry date falls
within the configured threshold, then sends a single digest email to the
configured recipient(s).  No email is sent when nothing is expiring.

Run:
    /opt/ssl-manager/venv/bin/python /opt/ssl-manager/notify_expiry.py

Invoked automatically by ssl-manager-notify.timer (daily at 08:00).
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap — find the app root and load the environment file so Flask can
# construct its config the same way gunicorn does.
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
    format="%(asctime)s [notify_expiry] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Create Flask app and run inside its context
# ---------------------------------------------------------------------------

from app import create_app  # noqa: E402

app = create_app()

with app.app_context():
    from app.extensions import db
    from app.mail import MailNotConfigured, send_email
    from app.models import (
        AuditLog, Certificate, CertificateAuthority,
        IntermediateCert, NotificationConfig, SmtpConfig,
    )

    # ── Load config ──────────────────────────────────────────────────────────

    cfg = NotificationConfig.query.first()
    if cfg is None or not cfg.enabled:
        log.info("Expiry notifications disabled — nothing to do.")
        sys.exit(0)

    smtp = SmtpConfig.query.first()
    if smtp is None or not smtp.enabled:
        log.warning("Expiry notifications enabled but SMTP is not configured/enabled.")
        sys.exit(0)

    recipients = cfg.recipients()
    if not recipients:
        log.warning("Expiry notifications enabled but no recipient emails configured.")
        sys.exit(0)

    threshold = cfg.days_threshold

    # ── Collect expiring items ────────────────────────────────────────────────

    expiring = []   # list of (days_until_expiry, label, type_label, expiry_date)

    if cfg.notify_certificates:
        for cert in Certificate.query.all():
            days = cert.days_until_expiry
            if days is not None and days <= threshold:
                expiring.append((days, cert.common_name or cert.domain, "Certificate",
                                 cert.expiry_date))

    if cfg.notify_cas:
        for ca in CertificateAuthority.query.all():
            days = ca.days_until_expiry
            if days is not None and days <= threshold:
                expiring.append((days, ca.name, "Certificate Authority", ca.expiry_date))

    if cfg.notify_intermediates:
        for ic in IntermediateCert.query.all():
            days = ic.days_until_expiry
            if days is not None and days <= threshold:
                expiring.append((days, ic.friendly_name or ic.subject, "Intermediate", ic.expiry_date))

    if not expiring:
        log.info("No items expiring within %d days — no email sent.", threshold)
        sys.exit(0)

    expiring.sort(key=lambda x: x[0])

    # ── Build email body ─────────────────────────────────────────────────────

    count = len(expiring)
    subject = (
        f"SSL Manager — {count} item{'s' if count != 1 else ''} "
        f"expiring within {threshold} days"
    )

    # Plain text
    lines_txt = [
        f"SSL Manager — Expiry Digest",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        f"{count} item{'s' if count != 1 else ''} expiring within {threshold} days:",
        "",
        f"{'Days':>6}  {'Type':<22}  {'Name':<40}  Expiry",
        "-" * 90,
    ]
    for days, name, type_label, expiry in expiring:
        expiry_str = expiry.strftime("%Y-%m-%d") if expiry else "unknown"
        status = "EXPIRED" if days < 0 else f"{days}d"
        lines_txt.append(f"{status:>6}  {type_label:<22}  {name:<40}  {expiry_str}")
    lines_txt += ["", "Log in to SSL Manager to review and renew these items."]
    body_text = "\n".join(lines_txt)

    # HTML
    rows_html = ""
    for days, name, type_label, expiry in expiring:
        expiry_str = expiry.strftime("%Y-%m-%d") if expiry else "unknown"
        if days < 0:
            badge = '<span style="background:#dc3545;color:#fff;padding:2px 7px;border-radius:4px;font-size:12px">EXPIRED</span>'
        elif days <= 7:
            badge = f'<span style="background:#dc3545;color:#fff;padding:2px 7px;border-radius:4px;font-size:12px">{days}d</span>'
        elif days <= 14:
            badge = f'<span style="background:#fd7e14;color:#fff;padding:2px 7px;border-radius:4px;font-size:12px">{days}d</span>'
        else:
            badge = f'<span style="background:#ffc107;color:#212529;padding:2px 7px;border-radius:4px;font-size:12px">{days}d</span>'
        rows_html += (
            f"<tr>"
            f"<td style='padding:6px 10px'>{badge}</td>"
            f"<td style='padding:6px 10px;color:#666'>{type_label}</td>"
            f"<td style='padding:6px 10px;font-weight:500'>{name}</td>"
            f"<td style='padding:6px 10px;color:#666'>{expiry_str}</td>"
            f"</tr>\n"
        )

    body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family:system-ui,-apple-system,sans-serif;font-size:14px;color:#1a1a1a;max-width:700px;margin:0 auto;padding:20px">
  <h2 style="color:#0d1117;border-bottom:2px solid #0d6efd;padding-bottom:8px">
    SSL Manager — Expiry Digest
  </h2>
  <p style="color:#666">{count} item{'s' if count != 1 else ''} expiring within {threshold} days
    &nbsp;·&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
  <table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead>
      <tr style="background:#f0f3f6">
        <th style="padding:8px 10px;text-align:left;border-bottom:1px solid #dee2e6">Days</th>
        <th style="padding:8px 10px;text-align:left;border-bottom:1px solid #dee2e6">Type</th>
        <th style="padding:8px 10px;text-align:left;border-bottom:1px solid #dee2e6">Name</th>
        <th style="padding:8px 10px;text-align:left;border-bottom:1px solid #dee2e6">Expiry Date</th>
      </tr>
    </thead>
    <tbody>
{rows_html}    </tbody>
  </table>
  <p style="margin-top:20px;color:#666;font-size:12px">
    Log in to SSL Manager to review and renew these items.
  </p>
</body>
</html>"""

    # ── Send ─────────────────────────────────────────────────────────────────

    errors = []
    for recipient in recipients:
        try:
            send_email(recipient, subject, body_text, body_html)
            log.info("Digest sent to %s (%d items).", recipient, count)
        except MailNotConfigured:
            log.error("SMTP not configured — cannot send to %s.", recipient)
            errors.append(recipient)
        except RuntimeError as exc:
            log.error("Failed to send to %s: %s", recipient, exc)
            errors.append(recipient)

    # ── Audit log ────────────────────────────────────────────────────────────

    result = "failure" if errors else "success"
    detail = f"items={count} threshold={threshold}d recipients={len(recipients)}"
    if errors:
        detail += f" failed={','.join(errors)}"

    entry = AuditLog(
        username="system",
        user_id=None,
        ip_address=None,
        action="expiry_notification_sent",
        resource_type="notification_config",
        resource_id=cfg.id,
        result=result,
        detail=detail,
    )
    db.session.add(entry)
    db.session.commit()

    if errors:
        log.error("Digest completed with errors. Failed recipients: %s", errors)
        sys.exit(1)

    log.info("Done — %d item(s) reported to %d recipient(s).", count, len(recipients))