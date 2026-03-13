# ==============================================================================
# FILE:           app/routes/certificates.py
# DESCRIPTION:    Certificate management routes: list, create, renew, detail,
#                 upload signed cert, delete, and all download formats
#                 (CSR, fullchain PEM, ZIP components, PKCS#12, JKS, P7B, DER).
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

import json
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, flash, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from ..crypto import (
    create_components_zip,
    create_jks,
    create_p7b,
    create_pkcs12,
    generate_key_and_csr,
    get_chain_intermediates,
    get_default_profile,
    parse_cert_expiry,
)
from ..extensions import db
from ..models import Certificate, CertChain, Settings
from ..security import _audit
from ..validators import (
    _clean,
    _validate_country,
    _validate_domain,
    _validate_email,
    _validate_san_list,
    normalize_alias,
)

bp = Blueprint("certificates", __name__)


@bp.route("/")
@login_required
def index():
    """GET / — Redirect the root URL to the certificates list."""
    return redirect(url_for("certificates.certificates"))


@bp.route("/certificates")
@login_required
def certificates():
    """GET /certificates — List all certificates ordered by creation date descending."""
    certs = Certificate.query.order_by(Certificate.created_at.desc()).all()
    return render_template("certificates.html", certs=certs)


@bp.route("/certificates/new", methods=["GET", "POST"])
@login_required
def certificate_new():
    """GET/POST /certificates/new — Display and process the new-certificate form."""
    all_profiles = Settings.query.order_by(Settings.name.asc()).all()
    default_profile = get_default_profile()
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    if request.method == "POST":
        try:
            chosen_profile_id = int(request.form.get("profile_id", ""))
            chosen_profile = db.session.get(Settings, chosen_profile_id) or default_profile
        except (ValueError, TypeError):
            chosen_profile = default_profile

        domain = _clean(request.form.get("domain", ""), 253)
        san_raw = request.form.get("san_domains", "")
        country = _clean(request.form.get("country", chosen_profile.country or ""), 2).upper()
        state    = _clean(request.form.get("state",    chosen_profile.state    or ""), 128)
        city     = _clean(request.form.get("city",     chosen_profile.city     or ""), 128)
        org_name = _clean(request.form.get("org_name", chosen_profile.org_name or ""), 256)
        org_unit = _clean(request.form.get("org_unit", chosen_profile.org_unit or ""), 256)
        email    = _clean(request.form.get("email",    chosen_profile.email    or ""), 256)

        san_list, san_err = _validate_san_list(san_raw)
        error = (
            _validate_domain(domain)
            or san_err
            or _validate_country(country)
            or _validate_email(email)
        )
        if error:
            flash(error, "error")
            return render_template("cert_new.html", profiles=all_profiles,
                                   default_profile=default_profile, chains=chains)

        try:
            key_size = int(request.form.get("key_size", chosen_profile.key_size))
        except (ValueError, TypeError):
            key_size = 2048
        if key_size not in (2048, 4096):
            key_size = 2048

        chain_id_raw = request.form.get("chain_id", "")
        try:
            chain_id = int(chain_id_raw) if chain_id_raw else None
        except ValueError:
            chain_id = None

        try:
            private_key_pem, csr_pem = generate_key_and_csr(
                domain, san_list, key_size, country, state, city, org_name, org_unit, email
            )
        except Exception as e:
            flash(f"Error generating key/CSR: {e}", "error")
            return render_template("cert_new.html", profiles=all_profiles,
                                   default_profile=default_profile, chains=chains)

        cert = Certificate(
            domain=domain,
            san_domains=json.dumps(san_list),
            key_size=key_size,
            private_key_pem=private_key_pem,
            csr_pem=csr_pem,
            status="pending_signing",
            country=country,
            state=state,
            city=city,
            org_name=org_name,
            org_unit=org_unit,
            email=email,
            chain_id=chain_id,
            profile_id=chosen_profile.id if chosen_profile else None,
        )
        db.session.add(cert)
        db.session.commit()
        _audit("certificate_created", "certificate", cert.id, "success", f"domain={domain!r}")
        flash(f"RSA key and CSR generated for {domain}.", "success")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert.id))

    return render_template("cert_new.html", profiles=all_profiles,
                           default_profile=default_profile, chains=chains)


@bp.route("/certificates/<int:cert_id>/renew")
@login_required
def certificate_renew(cert_id):
    """GET /certificates/<cert_id>/renew — Show the new-certificate form pre-populated for renewal."""
    cert = db.get_or_404(Certificate, cert_id)
    all_profiles = Settings.query.order_by(Settings.name.asc()).all()
    default_profile = get_default_profile()
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    return render_template("cert_new.html", profiles=all_profiles,
                           default_profile=default_profile, renew_from=cert, chains=chains)


@bp.route("/certificates/<int:cert_id>")
@login_required
def certificate_detail(cert_id):
    """GET /certificates/<cert_id> — Show full details for a single certificate."""
    cert = db.get_or_404(Certificate, cert_id)
    intermediates = get_chain_intermediates(cert.chain_id)
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    return render_template("cert_detail.html", cert=cert, intermediates=intermediates, chains=chains)


@bp.route("/certificates/<int:cert_id>/set-chain", methods=["POST"])
@login_required
def certificate_set_chain(cert_id):
    """POST /certificates/<cert_id>/set-chain — Assign or clear the certificate's trust chain."""
    cert = db.get_or_404(Certificate, cert_id)
    chain_id_raw = request.form.get("chain_id", "")
    try:
        cert.chain_id = int(chain_id_raw) if chain_id_raw else None
    except ValueError:
        cert.chain_id = None
    db.session.commit()
    chain_name = cert.chain.name if cert.chain else "None"
    flash(f"Certificate chain updated to: {chain_name}.", "success")
    return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))


@bp.route("/certificates/<int:cert_id>/upload", methods=["POST"])
@login_required
def certificate_upload(cert_id):
    """POST /certificates/<cert_id>/upload — Upload a signed certificate PEM."""
    cert = db.get_or_404(Certificate, cert_id)

    uploaded = request.files.get("cert_file")
    if uploaded and uploaded.filename:
        try:
            signed_pem = uploaded.read().decode("utf-8", errors="replace").strip()
        except Exception as e:
            flash(f"Could not read uploaded file: {e}", "error")
            return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    else:
        signed_pem = request.form.get("signed_cert_pem", "").strip()

    if not signed_pem:
        flash("No certificate PEM provided.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))

    try:
        expiry = parse_cert_expiry(signed_pem)
    except Exception as e:
        flash(f"Invalid certificate PEM: {e}", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))

    cert.signed_cert_pem = signed_pem
    cert.status = "active"
    if expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)
    cert.expiry_date = expiry
    db.session.commit()
    _audit("certificate_signed", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    flash("Signed certificate uploaded successfully.", "success")
    return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))


@bp.route("/certificates/<int:cert_id>/delete", methods=["POST"])
@login_required
def certificate_delete(cert_id):
    """POST /certificates/<cert_id>/delete — Permanently delete a certificate record."""
    cert = db.get_or_404(Certificate, cert_id)
    domain = cert.domain
    db.session.delete(cert)
    db.session.commit()
    _audit("certificate_deleted", "certificate", cert_id, "success", f"domain={domain!r}")
    flash(f"Certificate for {domain} deleted.", "success")
    return redirect(url_for("certificates.certificates"))


# ---- Certificate Downloads ----

@bp.route("/certificates/<int:cert_id>/download/csr")
@login_required
def download_csr(cert_id):
    """GET — Download the certificate's CSR as a PEM file."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.csr_pem:
        flash("No CSR available.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    buf = BytesIO(cert.csr_pem.encode())
    _audit("download_csr", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(buf, mimetype="application/x-pem-file", as_attachment=True,
                     download_name=f"{cert.safe_domain}.csr")


@bp.route("/certificates/<int:cert_id>/download/fullchain")
@login_required
def download_fullchain(cert_id):
    """GET — Download private key + signed cert + intermediates as a PEM bundle."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    intermediates = get_chain_intermediates(cert.chain_id)
    parts = [cert.private_key_pem, cert.signed_cert_pem] + [ic.pem_data for ic in intermediates]
    fullchain = "\n".join(p.strip() for p in parts if p and p.strip()) + "\n"
    buf = BytesIO(fullchain.encode())
    _audit("download_fullchain", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(buf, mimetype="application/x-pem-file", as_attachment=True,
                     download_name=f"{cert.safe_domain}-fullchain.pem")


@bp.route("/certificates/<int:cert_id>/download/components")
@login_required
def download_components(cert_id):
    """GET — Download a ZIP containing individual PEM component files."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    intermediates = get_chain_intermediates(cert.chain_id)
    buf = create_components_zip(cert.domain, cert.signed_cert_pem, cert.private_key_pem,
                                [ic.pem_data for ic in intermediates], csr_pem=cert.csr_pem)
    _audit("download_components", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name=f"{cert.safe_domain}-certs.zip")


@bp.route("/certificates/<int:cert_id>/download/pkcs12", methods=["POST"])
@login_required
def download_pkcs12(cert_id):
    """POST — Generate and download a PKCS#12 (.p12) bundle."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    password      = request.form.get("password", "")
    friendly_name = request.form.get("friendly_name", "").strip() or normalize_alias(cert.domain)
    intermediates = get_chain_intermediates(cert.chain_id)
    try:
        p12_bytes = create_pkcs12(cert.signed_cert_pem, cert.private_key_pem,
                                   [ic.pem_data for ic in intermediates], password, name=friendly_name)
    except Exception as e:
        flash(f"Error creating PKCS#12: {e}", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    _audit("download_pkcs12", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(BytesIO(p12_bytes), mimetype="application/x-pkcs12", as_attachment=True,
                     download_name=f"{cert.safe_domain}.p12")


@bp.route("/certificates/<int:cert_id>/download/jks", methods=["POST"])
@login_required
def download_jks(cert_id):
    """POST — Generate and download a Java KeyStore (.jks) file."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    password = request.form.get("password", "changeit")
    alias = request.form.get("alias", "").strip() or normalize_alias(cert.domain)
    intermediates = get_chain_intermediates(cert.chain_id)
    try:
        jks_bytes = create_jks(cert.signed_cert_pem, cert.private_key_pem,
                                [ic.pem_data for ic in intermediates], password, alias=alias)
    except Exception as e:
        flash(f"Error creating JKS: {e}", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    _audit("download_jks", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(BytesIO(jks_bytes), mimetype="application/octet-stream", as_attachment=True,
                     download_name=f"{cert.safe_domain}.jks")


@bp.route("/certificates/<int:cert_id>/download/p7b")
@login_required
def download_p7b(cert_id):
    """GET — Generate and download a PKCS#7 (.p7b) bundle via OpenSSL."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    intermediates = get_chain_intermediates(cert.chain_id)
    p7b_bytes = create_p7b([cert.signed_cert_pem] + [ic.pem_data for ic in intermediates])
    if p7b_bytes is None:
        flash("P7B creation failed. Ensure OpenSSL is installed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    _audit("download_p7b", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(BytesIO(p7b_bytes), mimetype="application/x-pkcs7-certificates",
                     as_attachment=True, download_name=f"{cert.safe_domain}.p7b")


@bp.route("/certificates/<int:cert_id>/download/der")
@login_required
def download_der(cert_id):
    """GET — Download the signed certificate in DER (binary) format."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    x509_cert = x509.load_pem_x509_certificate(cert.signed_cert_pem.encode())
    der_bytes = x509_cert.public_bytes(serialization.Encoding.DER)
    _audit("download_der", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(BytesIO(der_bytes), mimetype="application/x-x509-ca-cert",
                     as_attachment=True, download_name=f"{cert.safe_domain}.der")