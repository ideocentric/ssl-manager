# ==============================================================================
# FILE:           app/routes/cas.py
# DESCRIPTION:    Certificate Authority management routes: list, create, detail,
#                 delete, CA cert download, and CSR signing.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from io import BytesIO

from flask import Blueprint, flash, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from ..crypto import generate_ca_key_and_cert, get_default_profile, parse_cert_expiry, sign_csr_with_ca
from ..extensions import db
from ..models import Certificate, CertificateAuthority, Settings
from ..security import _audit
from ..validators import _clean, _validate_country, _validate_email

bp = Blueprint("cas", __name__)


@bp.route("/cas")
@login_required
def cas():
    """GET /cas — List all certificate authorities."""
    authorities = CertificateAuthority.query.order_by(CertificateAuthority.name.asc()).all()
    return render_template("cas.html", authorities=authorities)


@bp.route("/cas/new", methods=["GET", "POST"])
@login_required
def ca_new():
    """GET/POST /cas/new — Display and process the new CA form."""
    all_profiles = Settings.query.order_by(Settings.name.asc()).all()
    default_profile = get_default_profile()

    if request.method == "POST":
        name        = _clean(request.form.get("name", ""), 256)
        description = _clean(request.form.get("description", ""), 512)
        country  = _clean(request.form.get("country",  default_profile.country  or ""), 2).upper()
        state    = _clean(request.form.get("state",    default_profile.state    or ""), 128)
        city     = _clean(request.form.get("city",     default_profile.city     or ""), 128)
        org_name = _clean(request.form.get("org_name", default_profile.org_name or ""), 256)
        org_unit = _clean(request.form.get("org_unit", default_profile.org_unit or ""), 256)
        email    = _clean(request.form.get("email",    default_profile.email    or ""), 256)

        try:
            key_size = int(request.form.get("key_size", 4096))
            if key_size not in (2048, 4096):
                key_size = 4096
        except (ValueError, TypeError):
            key_size = 4096

        try:
            validity_days = int(request.form.get("validity_days", 3650))
            if validity_days <= 0:
                validity_days = 3650
        except (ValueError, TypeError):
            validity_days = 3650

        errors = []
        if not name:
            errors.append("CA name is required.")
        err = _validate_country(country)
        if err:
            errors.append(err)
        err = _validate_email(email)
        if err:
            errors.append(err)
        if CertificateAuthority.query.filter_by(name=name).first():
            errors.append(f"A CA named '{name}' already exists.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template(
                "ca_form.html",
                all_profiles=all_profiles,
                default_profile=default_profile,
                form=request.form,
            )

        try:
            private_key_pem, cert_pem = generate_ca_key_and_cert(
                common_name=name,
                key_size=key_size,
                validity_days=validity_days,
                country=country,
                state=state,
                city=city,
                org_name=org_name,
                org_unit=org_unit,
                email=email,
            )
            ca = CertificateAuthority(
                name=name,
                description=description,
                key_size=key_size,
                private_key_pem=private_key_pem,
                cert_pem=cert_pem,
            )
            db.session.add(ca)
            db.session.commit()
            _audit("ca_create", "ca", ca.id, "success", f"CA '{name}' created")
            flash(f"Certificate Authority '{name}' created successfully.", "success")
            return redirect(url_for("cas.ca_detail", ca_id=ca.id))
        except Exception as exc:
            db.session.rollback()
            _audit("ca_create", "ca", None, "failure", str(exc))
            flash(f"Failed to create CA: {exc}", "danger")

    return render_template(
        "ca_form.html",
        all_profiles=all_profiles,
        default_profile=default_profile,
        form=None,
    )


@bp.route("/cas/<int:ca_id>")
@login_required
def ca_detail(ca_id):
    """GET /cas/<ca_id> — Show CA details and pending certificates that can be signed."""
    ca = db.get_or_404(CertificateAuthority, ca_id)
    pending_certs = Certificate.query.filter_by(status="pending_signing").order_by(Certificate.domain.asc()).all()
    return render_template("ca_detail.html", ca=ca, pending_certs=pending_certs)


@bp.route("/cas/<int:ca_id>/delete", methods=["POST"])
@login_required
def ca_delete(ca_id):
    """POST /cas/<ca_id>/delete — Delete a CA."""
    ca = db.get_or_404(CertificateAuthority, ca_id)
    name = ca.name
    db.session.delete(ca)
    db.session.commit()
    _audit("ca_delete", "ca", ca_id, "success", f"CA '{name}' deleted")
    flash(f"Certificate Authority '{name}' deleted.", "success")
    return redirect(url_for("cas.cas"))


@bp.route("/cas/<int:ca_id>/download/cert")
@login_required
def ca_download_cert(ca_id):
    """GET /cas/<ca_id>/download/cert — Download the CA public certificate as PEM."""
    ca = db.get_or_404(CertificateAuthority, ca_id)
    safe_name = ca.name.replace(" ", "_").replace("/", "_")
    _audit("ca_download", "ca", ca_id, "success", f"CA cert downloaded for '{ca.name}'")
    return send_file(
        BytesIO(ca.cert_pem.encode()),
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{safe_name}_ca.pem",
    )


@bp.route("/cas/<int:ca_id>/sign/<int:cert_id>", methods=["POST"])
@login_required
def ca_sign_cert(ca_id, cert_id):
    """POST /cas/<ca_id>/sign/<cert_id> — Sign a pending certificate with this CA."""
    ca = db.get_or_404(CertificateAuthority, ca_id)
    cert = db.get_or_404(Certificate, cert_id)

    if cert.status != "pending_signing":
        flash("Certificate is not in pending_signing state.", "danger")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))

    try:
        validity_days = int(request.form.get("validity_days", 365))
        if validity_days <= 0:
            validity_days = 365
    except (ValueError, TypeError):
        validity_days = 365

    try:
        signed_pem = sign_csr_with_ca(
            csr_pem=cert.csr_pem,
            ca_cert_pem=ca.cert_pem,
            ca_key_pem=ca.private_key_pem,
            validity_days=validity_days,
        )
        expiry = parse_cert_expiry(signed_pem)
        cert.signed_cert_pem = signed_pem
        cert.status = "active"
        cert.expiry_date = expiry
        db.session.commit()
        _audit("cert_sign", "certificate", cert_id, "success",
               f"Signed by CA '{ca.name}', valid {validity_days} days")
        flash(f"Certificate for {cert.domain} signed successfully.", "success")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    except Exception as exc:
        db.session.rollback()
        _audit("cert_sign", "certificate", cert_id, "failure", str(exc))
        flash(f"Signing failed: {exc}", "danger")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))