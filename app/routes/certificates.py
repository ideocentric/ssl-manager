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
from cryptography.x509.oid import NameOID
from flask import Blueprint, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import login_required

from ..crypto import (
    create_components_zip,
    create_jks,
    create_p7b,
    create_pkcs12,
    find_matching_chain,
    generate_key_and_csr,
    get_chain_intermediates,
    get_default_profile,
    get_key_info,
    identify_leaf_cert,
    keys_match,
    parse_cert_expiry,
    parse_p7b_bundle,
    parse_pem_bundle,
    parse_pkcs12,
    split_bundle_by_role,
)
from ..extensions import db
from ..models import Certificate, CertChain, CertificateAuthority, IntermediateCert, Settings
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


# ---------------------------------------------------------------------------
# Import helpers (shared by upload, P12, and keypair routes)
# ---------------------------------------------------------------------------

def _cert_cn(cert_obj):
    try:
        cn = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        cn = str(cert_obj.subject)
    return cn[:256]


def _cert_expiry_str(cert_obj):
    try:
        exp = parse_cert_expiry(cert_obj.public_bytes(serialization.Encoding.PEM).decode())
        return exp.strftime("%Y-%m-%d")
    except Exception:
        return "unknown"


def _parse_cert_file(file_obj):
    """Read an uploaded cert file. Returns (cert_pairs, invalid_count, fmt).

    cert_pairs is a list of (pem_str, x509.Certificate).
    fmt is 'p7b' or 'pem'.
    """
    data = file_obj.read()
    filename = (file_obj.filename or "").lower()
    invalid_count = 0

    if filename.endswith((".p7b", ".p7")):
        fmt = "p7b"
        pem_strs = parse_p7b_bundle(data)
    else:
        fmt = "pem"
        pem_strs = parse_pem_bundle(data.decode("utf-8", errors="replace").strip())

    cert_pairs = []
    for pem in pem_strs:
        try:
            cert_pairs.append((pem, x509.load_pem_x509_certificate(pem.encode())))
        except Exception:
            invalid_count += 1
    return cert_pairs, invalid_count, fmt


def _resolve_intermediates(domain, intermediates, current_chain_id):
    """Assign intermediates to a chain. No DB commit.

    Returns (chain_id, chain_action, chain_name, added, skipped).
    chain_action: 'none' | 'create' | 'use_existing' | 'add_to_assigned'
    """
    if not intermediates:
        return current_chain_id, "none", None, 0, 0

    serial_set = {c.serial_number for c in intermediates}
    matching = find_matching_chain(serial_set)
    if matching:
        return matching.id, "use_existing", matching.name, 0, len(intermediates)

    chain_id = current_chain_id
    if chain_id is None:
        new_chain = CertChain(name=f"{domain} (imported)")
        db.session.add(new_chain)
        db.session.flush()
        chain_id = new_chain.id
        chain_name = new_chain.name
        chain_action = "create"
    else:
        chain_obj = db.session.get(CertChain, chain_id)
        chain_name = chain_obj.name if chain_obj else f"chain {chain_id}"
        chain_action = "add_to_assigned"

    existing = IntermediateCert.query.filter_by(chain_id=chain_id).all()
    existing_serials = set()
    for ic in existing:
        try:
            existing_serials.add(
                x509.load_pem_x509_certificate(ic.pem_data.encode()).serial_number
            )
        except Exception:
            pass

    next_order = max((ic.order for ic in existing), default=-1) + 1
    added = skipped = 0

    for cert_obj in intermediates:
        if cert_obj.serial_number in existing_serials:
            skipped += 1
            continue
        pem = cert_obj.public_bytes(serialization.Encoding.PEM).decode()
        db.session.add(IntermediateCert(
            name=_cert_cn(cert_obj),
            pem_data=pem,
            order=next_order,
            chain_id=chain_id,
        ))
        existing_serials.add(cert_obj.serial_number)
        next_order += 1
        added += 1

    return chain_id, chain_action, chain_name, added, skipped


def _preview_chain_info(domain, intermediates, current_chain_id):
    """Return chain preview info dict (no DB writes)."""
    if not intermediates:
        return {"chain_action": "none", "chain_name": None,
                "existing_chain_id": None, "existing_chain_name": None}

    serial_set = {c.serial_number for c in intermediates}
    matching = find_matching_chain(serial_set)
    if matching:
        return {"chain_action": "use_existing", "chain_name": matching.name,
                "existing_chain_id": matching.id, "existing_chain_name": matching.name}

    if current_chain_id is None:
        return {"chain_action": "create", "chain_name": f"{domain} (imported)",
                "existing_chain_id": None, "existing_chain_name": None}

    chain_obj = db.session.get(CertChain, current_chain_id)
    chain_name = chain_obj.name if chain_obj else f"chain {current_chain_id}"
    return {"chain_action": "add_to_assigned", "chain_name": chain_name,
            "existing_chain_id": None, "existing_chain_name": None}


def _intermediates_preview(intermediates, chain_id):
    """Return list of intermediate preview dicts with is_duplicate flag."""
    existing_serials = set()
    if chain_id is not None:
        for ic in IntermediateCert.query.filter_by(chain_id=chain_id).all():
            try:
                existing_serials.add(
                    x509.load_pem_x509_certificate(ic.pem_data.encode()).serial_number
                )
            except Exception:
                pass
    return [
        {"cn": _cert_cn(c), "is_duplicate": c.serial_number in existing_serials}
        for c in intermediates
    ]


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
    cas = CertificateAuthority.query.order_by(CertificateAuthority.name.asc()).all()
    return render_template("cert_detail.html", cert=cert, intermediates=intermediates, chains=chains, cas=cas)


@bp.route("/certificates/<int:cert_id>/modal")
@login_required
def certificate_detail_modal(cert_id):
    """GET /certificates/<cert_id>/modal — Partial for the detail modal."""
    cert = db.get_or_404(Certificate, cert_id)
    intermediates = get_chain_intermediates(cert.chain_id)
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    cas = CertificateAuthority.query.order_by(CertificateAuthority.name.asc()).all()
    return render_template("cert_detail_modal.html", cert=cert, intermediates=intermediates, chains=chains, cas=cas)


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
    """POST /certificates/<cert_id>/upload — Upload a signed certificate (PEM, bundle, or P7B)."""
    cert = db.get_or_404(Certificate, cert_id)

    cert_pairs = []
    invalid_count = 0
    fmt = "pem"

    uploaded = request.files.get("cert_file")
    if uploaded and uploaded.filename:
        try:
            cert_pairs, invalid_count, fmt = _parse_cert_file(uploaded)
        except ValueError as e:
            flash(f"Could not read file: {e}", "error")
            return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    else:
        pem_text = request.form.get("signed_cert_pem", "").strip()
        if not pem_text:
            flash("No certificate provided.", "error")
            return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
        try:
            for pem in parse_pem_bundle(pem_text):
                try:
                    cert_pairs.append((pem, x509.load_pem_x509_certificate(pem.encode())))
                except Exception:
                    invalid_count += 1
        except ValueError as e:
            flash(f"Invalid certificate PEM: {e}", "error")
            return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))

    if not cert_pairs:
        flash("No valid certificates found in the provided input.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))

    leaves, intermediates = split_bundle_by_role([c for _, c in cert_pairs])
    leaf = identify_leaf_cert(leaves, cert.csr_pem)

    if leaf is None:
        if not leaves:
            flash("No end-entity certificate found — all certificates have CA:TRUE.", "error")
        else:
            flash("Multiple end-entity certificates found and none matched the stored CSR.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))

    # Warn on public-key mismatch vs stored CSR (don't block — CA re-key is legitimate)
    if cert.csr_pem:
        try:
            csr = x509.load_pem_x509_csr(cert.csr_pem.encode())
            csr_pub = csr.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            leaf_pub = leaf.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if csr_pub != leaf_pub:
                flash("Warning: the certificate's public key does not match the stored CSR. "
                      "Verify this is the correct certificate.", "warning")
        except Exception:
            pass

    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()

    try:
        expiry = parse_cert_expiry(leaf_pem)
    except Exception as e:
        flash(f"Invalid certificate: {e}", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))

    cert.signed_cert_pem = leaf_pem
    cert.status = "active"
    if expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)
    cert.expiry_date = expiry

    chain_id, chain_action, chain_name, added, skipped = _resolve_intermediates(
        cert.domain, intermediates, cert.chain_id
    )
    if chain_id != cert.chain_id:
        cert.chain_id = chain_id

    db.session.commit()
    _audit("certificate_signed", "certificate", cert_id, "success",
           f"domain={cert.domain!r} format={fmt}")

    if chain_action == "none" and not invalid_count:
        flash("Signed certificate uploaded successfully.", "success")
    else:
        parts = ["Signed certificate uploaded."]
        if chain_action == "use_existing":
            parts.append(f"Matched existing chain '{chain_name}'.")
        elif chain_action == "create":
            parts.append(f"Created new chain '{chain_name}' with {added} intermediate(s).")
        elif chain_action == "add_to_assigned":
            msg = f"Added {added} intermediate(s) to chain '{chain_name}'."
            if skipped:
                msg += f" {skipped} duplicate(s) skipped."
            parts.append(msg)
        if invalid_count:
            parts.append(f"{invalid_count} unparseable block(s) skipped.")
        flash(" ".join(parts), "success")

    return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))


@bp.route("/certificates/<int:cert_id>/upload/preview", methods=["POST"])
@login_required
def certificate_upload_preview(cert_id):
    """POST — Analyse a certificate file and return JSON preview (no DB writes)."""
    cert = db.get_or_404(Certificate, cert_id)

    uploaded = request.files.get("cert_file")
    if not uploaded or not uploaded.filename:
        return jsonify({"ok": False, "error": "No file provided."})

    try:
        cert_pairs, invalid_count, fmt = _parse_cert_file(uploaded)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)})

    if not cert_pairs:
        return jsonify({"ok": False, "error": "No valid certificates found in file."})

    leaves, intermediates = split_bundle_by_role([c for _, c in cert_pairs])
    leaf = identify_leaf_cert(leaves, cert.csr_pem)

    if leaf is None:
        if not leaves:
            return jsonify({"ok": False,
                            "error": "No end-entity certificate found — all certs have CA:TRUE."})
        return jsonify({"ok": False,
                        "error": "Multiple end-entity certificates found. Upload the leaf certificate only."})

    matches_csr = None
    if cert.csr_pem:
        try:
            csr = x509.load_pem_x509_csr(cert.csr_pem.encode())
            csr_pub = csr.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            leaf_pub = leaf.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            matches_csr = (csr_pub == leaf_pub)
        except Exception:
            pass

    return jsonify({
        "ok": True,
        "format": fmt,
        "leaf": {"cn": _cert_cn(leaf), "expiry": _cert_expiry_str(leaf), "matches_csr": matches_csr},
        "intermediates": _intermediates_preview(intermediates, cert.chain_id),
        "invalid_count": invalid_count,
        **_preview_chain_info(cert.domain, intermediates, cert.chain_id),
        "error": None,
    })


@bp.route("/certificates/import-p12", methods=["GET", "POST"])
@login_required
def certificate_import_p12():
    """GET/POST /certificates/import-p12 — Import a PKCS#12 file as a new certificate record."""
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    if request.method == "GET":
        return render_template("cert_import_p12.html", chains=chains)

    uploaded = request.files.get("p12_file")
    if not uploaded or not uploaded.filename:
        flash("No P12 file provided.", "error")
        return render_template("cert_import_p12.html", chains=chains)

    password = request.form.get("password", "")
    try:
        key_pem, leaf_cert_pem, ca_pems = parse_pkcs12(uploaded.read(), password)
    except ValueError:
        flash("Could not read P12 file — wrong password or invalid file.", "error")
        return render_template("cert_import_p12.html", chains=chains)

    try:
        leaf_cert = x509.load_pem_x509_certificate(leaf_cert_pem.encode())
    except Exception as e:
        flash(f"Invalid certificate in P12: {e}", "error")
        return render_template("cert_import_p12.html", chains=chains)

    ca_x509 = []
    for pem in ca_pems:
        try:
            ca_x509.append(x509.load_pem_x509_certificate(pem.encode()))
        except Exception:
            pass
    _, intermediates = split_bundle_by_role(ca_x509)

    domain = _clean(request.form.get("domain", ""), 253) or _cert_cn(leaf_cert)
    if not domain:
        flash("Could not determine domain. Please provide a domain name.", "error")
        return render_template("cert_import_p12.html", chains=chains)

    try:
        chain_id = int(request.form.get("chain_id", "")) or None
    except (ValueError, TypeError):
        chain_id = None

    try:
        expiry = parse_cert_expiry(leaf_cert_pem)
    except Exception as e:
        flash(f"Invalid certificate: {e}", "error")
        return render_template("cert_import_p12.html", chains=chains)

    key_info = get_key_info(key_pem)
    cert = Certificate(
        domain=domain,
        private_key_pem=key_pem,
        signed_cert_pem=leaf_cert_pem,
        key_size=key_info.get("bits") or 0,
        status="active",
        csr_pem=None,
    )
    if expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)
    cert.expiry_date = expiry
    db.session.add(cert)
    db.session.flush()

    new_chain_id, chain_action, chain_name, added, _ = _resolve_intermediates(
        domain, intermediates, chain_id
    )
    cert.chain_id = new_chain_id
    db.session.commit()
    _audit("p12_import", "certificate", cert.id, "success", f"domain={domain!r}")

    parts = [f"P12 certificate for {domain} imported successfully."]
    if chain_action == "use_existing":
        parts.append(f"Matched existing chain '{chain_name}'.")
    elif chain_action == "create":
        parts.append(f"Created new chain '{chain_name}' with {added} intermediate(s).")
    elif chain_action == "add_to_assigned":
        parts.append(f"Added {added} intermediate(s) to chain '{chain_name}'.")
    flash(" ".join(parts), "success")
    return redirect(url_for("certificates.certificate_detail", cert_id=cert.id))


@bp.route("/certificates/import-p12/preview", methods=["POST"])
@login_required
def certificate_import_p12_preview():
    """POST — Analyse a P12 file and return JSON preview (no DB writes)."""
    uploaded = request.files.get("p12_file")
    if not uploaded or not uploaded.filename:
        return jsonify({"ok": False, "error": "No file provided."})

    password = request.form.get("password", "")
    try:
        key_pem, leaf_cert_pem, ca_pems = parse_pkcs12(uploaded.read(), password)
    except ValueError:
        return jsonify({"ok": False, "error": "Could not read P12 file — wrong password or invalid file."})

    try:
        leaf_cert = x509.load_pem_x509_certificate(leaf_cert_pem.encode())
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid certificate in P12: {e}"})

    ca_x509 = []
    for pem in ca_pems:
        try:
            ca_x509.append(x509.load_pem_x509_certificate(pem.encode()))
        except Exception:
            pass
    _, intermediates = split_bundle_by_role(ca_x509)

    domain = _cert_cn(leaf_cert)
    try:
        chain_id = int(request.form.get("chain_id", "")) or None
    except (ValueError, TypeError):
        chain_id = None

    return jsonify({
        "ok": True,
        "format": "pkcs12",
        "private_key": get_key_info(key_pem),
        "leaf": {"cn": domain, "expiry": _cert_expiry_str(leaf_cert), "matches_key": True},
        "intermediates": _intermediates_preview(intermediates, chain_id),
        "invalid_count": 0,
        **_preview_chain_info(domain, intermediates, chain_id),
        "error": None,
    })


@bp.route("/certificates/import-keypair", methods=["GET", "POST"])
@login_required
def certificate_import_keypair():
    """GET/POST /certificates/import-keypair — Import a private key + certificate as a new record."""
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    if request.method == "GET":
        return render_template("cert_import_keypair.html", chains=chains)

    # --- Private key ---
    key_pem = ""
    key_file = request.files.get("key_file")
    if key_file and key_file.filename:
        try:
            key_pem = key_file.read().decode("utf-8", errors="replace").strip()
        except Exception as e:
            flash(f"Could not read key file: {e}", "error")
            return render_template("cert_import_keypair.html", chains=chains)
    if not key_pem:
        key_pem = request.form.get("key_pem", "").strip()
    if not key_pem:
        flash("No private key provided.", "error")
        return render_template("cert_import_keypair.html", chains=chains)

    key_password = request.form.get("key_password", "").strip() or None
    try:
        pwd = key_password.encode() if key_password else None
        key_obj = serialization.load_pem_private_key(key_pem.encode(), password=pwd)
        if key_password:
            key_pem = key_obj.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ).decode()
    except Exception as e:
        flash(f"Invalid private key: {e}", "error")
        return render_template("cert_import_keypair.html", chains=chains)

    # --- Certificate ---
    cert_pairs = []
    invalid_count = 0
    cert_file = request.files.get("cert_file")
    if cert_file and cert_file.filename:
        try:
            cert_pairs, invalid_count, _ = _parse_cert_file(cert_file)
        except ValueError as e:
            flash(f"Could not read certificate file: {e}", "error")
            return render_template("cert_import_keypair.html", chains=chains)
    else:
        pem_text = request.form.get("cert_pem", "").strip()
        if pem_text:
            try:
                for pem in parse_pem_bundle(pem_text):
                    try:
                        cert_pairs.append((pem, x509.load_pem_x509_certificate(pem.encode())))
                    except Exception:
                        invalid_count += 1
            except ValueError as e:
                flash(f"Invalid certificate PEM: {e}", "error")
                return render_template("cert_import_keypair.html", chains=chains)

    if not cert_pairs:
        flash("No valid certificates found.", "error")
        return render_template("cert_import_keypair.html", chains=chains)

    leaves, intermediates = split_bundle_by_role([c for _, c in cert_pairs])

    # Identify leaf — try CSR-style match first, then key match
    leaf = identify_leaf_cert(leaves, csr_pem=None)
    if leaf is None and len(leaves) > 1:
        for candidate in leaves:
            if keys_match(key_pem, candidate.public_bytes(serialization.Encoding.PEM).decode()):
                leaf = candidate
                break

    if leaf is None:
        if not leaves:
            flash("No end-entity certificate found — all certificates have CA:TRUE.", "error")
        else:
            flash("Multiple end-entity certificates found. Please provide a single leaf certificate.", "error")
        return render_template("cert_import_keypair.html", chains=chains)

    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()

    if not keys_match(key_pem, leaf_pem):
        flash("The private key does not match the certificate's public key. Import aborted.", "error")
        return render_template("cert_import_keypair.html", chains=chains)

    domain = _clean(request.form.get("domain", ""), 253) or _cert_cn(leaf)
    if not domain:
        flash("Could not determine domain. Please provide a domain name.", "error")
        return render_template("cert_import_keypair.html", chains=chains)

    try:
        chain_id = int(request.form.get("chain_id", "")) or None
    except (ValueError, TypeError):
        chain_id = None

    try:
        expiry = parse_cert_expiry(leaf_pem)
    except Exception as e:
        flash(f"Invalid certificate: {e}", "error")
        return render_template("cert_import_keypair.html", chains=chains)

    key_info = get_key_info(key_pem)
    cert_rec = Certificate(
        domain=domain,
        private_key_pem=key_pem,
        signed_cert_pem=leaf_pem,
        key_size=key_info.get("bits") or 0,
        status="active",
        csr_pem=None,
    )
    if expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)
    cert_rec.expiry_date = expiry
    db.session.add(cert_rec)
    db.session.flush()

    new_chain_id, chain_action, chain_name, added, _ = _resolve_intermediates(
        domain, intermediates, chain_id
    )
    cert_rec.chain_id = new_chain_id
    db.session.commit()
    _audit("keypair_import", "certificate", cert_rec.id, "success", f"domain={domain!r}")

    parts = [f"Certificate for {domain} imported successfully."]
    if chain_action == "use_existing":
        parts.append(f"Matched existing chain '{chain_name}'.")
    elif chain_action == "create":
        parts.append(f"Created new chain '{chain_name}' with {added} intermediate(s).")
    elif chain_action == "add_to_assigned":
        parts.append(f"Added {added} intermediate(s) to chain '{chain_name}'.")
    if invalid_count:
        parts.append(f"{invalid_count} unparseable block(s) skipped.")
    flash(" ".join(parts), "success")
    return redirect(url_for("certificates.certificate_detail", cert_id=cert_rec.id))


@bp.route("/certificates/import-keypair/preview", methods=["POST"])
@login_required
def certificate_import_keypair_preview():
    """POST — Analyse a keypair and return JSON preview (no DB writes)."""
    key_pem = ""
    key_file = request.files.get("key_file")
    if key_file and key_file.filename:
        try:
            key_pem = key_file.read().decode("utf-8", errors="replace").strip()
        except Exception:
            pass
    if not key_pem:
        key_pem = request.form.get("key_pem", "").strip()
    if not key_pem:
        return jsonify({"ok": False, "error": "No private key provided."})

    key_password = request.form.get("key_password", "").strip() or None
    try:
        pwd = key_password.encode() if key_password else None
        key_obj = serialization.load_pem_private_key(key_pem.encode(), password=pwd)
        if key_password:
            key_pem = key_obj.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ).decode()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid private key: {e}"})

    cert_pairs = []
    invalid_count = 0
    cert_file = request.files.get("cert_file")
    if cert_file and cert_file.filename:
        try:
            cert_pairs, invalid_count, _ = _parse_cert_file(cert_file)
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)})
    else:
        pem_text = request.form.get("cert_pem", "").strip()
        if pem_text:
            try:
                for pem in parse_pem_bundle(pem_text):
                    try:
                        cert_pairs.append((pem, x509.load_pem_x509_certificate(pem.encode())))
                    except Exception:
                        invalid_count += 1
            except ValueError as e:
                return jsonify({"ok": False, "error": str(e)})

    if not cert_pairs:
        return jsonify({"ok": False, "error": "No valid certificates found."})

    leaves, intermediates = split_bundle_by_role([c for _, c in cert_pairs])
    leaf = identify_leaf_cert(leaves, csr_pem=None)
    if leaf is None and len(leaves) > 1:
        for candidate in leaves:
            if keys_match(key_pem, candidate.public_bytes(serialization.Encoding.PEM).decode()):
                leaf = candidate
                break

    if leaf is None:
        if not leaves:
            return jsonify({"ok": False, "error": "No end-entity certificate found."})
        return jsonify({"ok": False, "error": "Multiple end-entity certificates found."})

    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    match = keys_match(key_pem, leaf_pem)

    try:
        chain_id = int(request.form.get("chain_id", "")) or None
    except (ValueError, TypeError):
        chain_id = None

    domain = _cert_cn(leaf)
    return jsonify({
        "ok": True,
        "format": "keypair",
        "private_key": get_key_info(key_pem),
        "leaf": {"cn": domain, "expiry": _cert_expiry_str(leaf), "matches_key": match},
        "intermediates": _intermediates_preview(intermediates, chain_id),
        "invalid_count": invalid_count,
        **_preview_chain_info(domain, intermediates, chain_id),
        "error": None,
    })


@bp.route("/certificates/import-csr", methods=["GET", "POST"])
@login_required
def certificate_import_csr():
    """GET/POST /certificates/import-csr — Import an external CSR into the database."""
    chains = CertChain.query.order_by(CertChain.name.asc()).all()
    if request.method == "POST":
        csr_raw = ""
        uploaded = request.files.get("csr_file")
        if uploaded and uploaded.filename:
            try:
                csr_raw = uploaded.read().decode("utf-8", errors="replace").strip()
            except Exception as e:
                flash(f"Could not read uploaded file: {e}", "error")
                return redirect(url_for("certificates.certificate_import_csr"))
        if not csr_raw:
            csr_raw = request.form.get("csr_pem", "").strip()

        if not csr_raw:
            flash("No CSR provided.", "error")
            return redirect(url_for("certificates.certificate_import_csr"))

        try:
            from cryptography import x509 as _x509
            csr_obj = _x509.load_pem_x509_csr(csr_raw.encode())
            from cryptography.x509.oid import NameOID as _NameOID
            cn_attrs = csr_obj.subject.get_attributes_for_oid(_NameOID.COMMON_NAME)
            domain = cn_attrs[0].value if cn_attrs else ""
        except Exception as e:
            flash(f"Invalid CSR PEM: {e}", "error")
            return redirect(url_for("certificates.certificate_import_csr"))

        if not domain:
            domain = _clean(request.form.get("domain", ""), 253)
        if not domain:
            flash("Could not determine domain from CSR Common Name.", "error")
            return redirect(url_for("certificates.certificate_import_csr"))

        try:
            chain_id = int(request.form.get("chain_id", "")) or None
        except (ValueError, TypeError):
            chain_id = None

        cert = Certificate(
            domain=domain,
            csr_pem=csr_raw,
            status="pending_signing",
            key_size=0,  # no private key managed here
        )
        if chain_id:
            cert.chain_id = chain_id
        db.session.add(cert)
        db.session.commit()
        _audit("csr_import", "certificate", cert.id, "success", f"domain={domain!r}")
        flash(f"CSR for {domain} imported successfully.", "success")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert.id))

    return render_template("cert_import_csr.html", chains=chains)


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
                                [ic.pem_data for ic in intermediates])
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


@bp.route("/certificates/<int:cert_id>/download/cert-pem")
@login_required
def download_cert_pem(cert_id):
    """GET — Download the signed certificate only as a PEM file."""
    cert = db.get_or_404(Certificate, cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificates.certificate_detail", cert_id=cert_id))
    _audit("download_cert_pem", "certificate", cert_id, "success", f"domain={cert.domain!r}")
    return send_file(BytesIO(cert.signed_cert_pem.encode()), mimetype="application/x-pem-file",
                     as_attachment=True, download_name=f"{cert.safe_domain}.pem")


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