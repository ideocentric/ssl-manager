# ==============================================================================
# FILE:           app/routes/chains.py
# DESCRIPTION:    Certificate chain routes: list, create, edit, delete;
#                 intermediate certificate management; reorder; bulk import.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from ..crypto import parse_pem_bundle
from ..extensions import db
from ..models import Certificate, CertChain, IntermediateCert
from ..security import _audit
from ..validators import _clean

bp = Blueprint("chains", __name__)


@bp.route("/intermediates")
@login_required
def intermediates():
    """GET /intermediates — Legacy redirect to the /chains page."""
    return redirect(url_for("chains.chains"))


@bp.route("/chains")
@login_required
def chains():
    """GET /chains — List all certificate chains with their certificate counts."""
    all_chains = CertChain.query.order_by(CertChain.created_at.asc()).all()
    chain_cert_counts = {c.id: Certificate.query.filter_by(chain_id=c.id).count() for c in all_chains}
    return render_template("chains.html", chains=all_chains, chain_cert_counts=chain_cert_counts)


@bp.route("/chains/new", methods=["GET", "POST"])
@login_required
def chain_new():
    """GET/POST /chains/new — Display and process the new-chain creation form."""
    if request.method == "POST":
        name        = _clean(request.form.get("name", ""), 256)
        description = _clean(request.form.get("description", ""), 512)
        if not name:
            flash("Chain name is required.", "error")
            return render_template("chain_form.html", chain=None)
        if CertChain.query.filter_by(name=name).first():
            flash(f"A chain named '{name}' already exists.", "error")
            return render_template("chain_form.html", chain=None)
        chain = CertChain(name=name, description=description)
        db.session.add(chain)
        db.session.commit()
        _audit("chain_created", "chain", chain.id, "success", f"name={name!r}")
        flash(f"Chain '{name}' created.", "success")
        return redirect(url_for("chains.chain_detail", chain_id=chain.id))
    return render_template("chain_form.html", chain=None)


@bp.route("/chains/<int:chain_id>")
@login_required
def chain_detail(chain_id):
    """GET /chains/<chain_id> — Show details and intermediates for a specific chain."""
    chain = db.get_or_404(CertChain, chain_id)
    intermediates = sorted(chain.intermediates, key=lambda ic: ic.order)
    cert_count = Certificate.query.filter_by(chain_id=chain_id).count()
    return render_template("chain_detail.html", chain=chain, intermediates=intermediates, cert_count=cert_count)


@bp.route("/chains/<int:chain_id>/edit")
@login_required
def chain_edit(chain_id):
    """GET /chains/<chain_id>/edit — Show the edit form for an existing chain."""
    chain = db.get_or_404(CertChain, chain_id)
    return render_template("chain_form.html", chain=chain)


@bp.route("/chains/<int:chain_id>/update", methods=["POST"])
@login_required
def chain_update(chain_id):
    """POST /chains/<chain_id>/update — Save name and description changes to a chain."""
    chain = db.get_or_404(CertChain, chain_id)
    name        = _clean(request.form.get("name", ""), 256)
    description = _clean(request.form.get("description", ""), 512)
    if not name:
        flash("Chain name is required.", "error")
        return render_template("chain_form.html", chain=chain)
    dup = CertChain.query.filter(CertChain.name == name, CertChain.id != chain_id).first()
    if dup:
        flash(f"A chain named '{name}' already exists.", "error")
        return render_template("chain_form.html", chain=chain)
    chain.name = name
    chain.description = description
    db.session.commit()
    _audit("chain_updated", "chain", chain_id, "success", f"name={name!r}")
    flash(f"Chain '{name}' updated.", "success")
    return redirect(url_for("chains.chain_detail", chain_id=chain_id))


@bp.route("/chains/<int:chain_id>/delete", methods=["POST"])
@login_required
def chain_delete(chain_id):
    """POST /chains/<chain_id>/delete — Delete a chain and unlink any assigned certificates."""
    chain = db.get_or_404(CertChain, chain_id)
    Certificate.query.filter_by(chain_id=chain_id).update({"chain_id": None})
    name = chain.name
    db.session.delete(chain)
    db.session.commit()
    _audit("chain_deleted", "chain", chain_id, "success", f"name={name!r}")
    flash(f"Chain '{name}' deleted. Assigned certificates have been unlinked.", "success")
    return redirect(url_for("chains.chains"))


@bp.route("/chains/<int:chain_id>/intermediates/new")
@login_required
def chain_intermediate_form_new(chain_id):
    """GET — Show the form to add a new intermediate certificate."""
    chain = db.get_or_404(CertChain, chain_id)
    return render_template("intermediate_form.html", cert=None, chain=chain,
                           action=url_for("chains.chain_intermediate_new", chain_id=chain_id))


@bp.route("/chains/<int:chain_id>/intermediates", methods=["POST"])
@login_required
def chain_intermediate_new(chain_id):
    """POST — Validate and save a new intermediate certificate to a chain."""
    chain = db.get_or_404(CertChain, chain_id)
    name     = _clean(request.form.get("name", ""), 256)
    pem_data = (request.form.get("pem_data", "") or "").strip()
    try:
        order = max(0, int(request.form.get("order", 0)))
    except (ValueError, TypeError):
        order = 0
    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("chains.chain_intermediate_form_new", chain_id=chain_id))
    if not pem_data:
        flash("PEM data is required.", "error")
        return redirect(url_for("chains.chain_intermediate_form_new", chain_id=chain_id))
    try:
        x509.load_pem_x509_certificate(pem_data.encode())
    except Exception as e:
        flash(f"Invalid PEM certificate data: {e}", "error")
        return redirect(url_for("chains.chain_intermediate_form_new", chain_id=chain_id))
    ic = IntermediateCert(name=name, pem_data=pem_data, order=order, chain_id=chain_id)
    db.session.add(ic)
    db.session.commit()
    _audit("intermediate_created", "intermediate", ic.id, "success", f"name={name!r} chain_id={chain_id}")
    flash(f"Certificate '{name}' added.", "success")
    return redirect(url_for("chains.chain_detail", chain_id=chain_id))


@bp.route("/chains/<int:chain_id>/intermediates/<int:ic_id>/edit")
@login_required
def chain_intermediate_edit(chain_id, ic_id):
    """GET — Show the edit form for an intermediate certificate."""
    chain = db.get_or_404(CertChain, chain_id)
    ic = db.get_or_404(IntermediateCert, ic_id)
    return render_template("intermediate_form.html", cert=ic, chain=chain,
                           action=url_for("chains.chain_intermediate_update", chain_id=chain_id, ic_id=ic_id))


@bp.route("/chains/<int:chain_id>/intermediates/<int:ic_id>/update", methods=["POST"])
@login_required
def chain_intermediate_update(chain_id, ic_id):
    """POST — Save edits to an existing intermediate certificate."""
    chain = db.get_or_404(CertChain, chain_id)
    ic = db.get_or_404(IntermediateCert, ic_id)
    name     = _clean(request.form.get("name", ""), 256)
    pem_data = (request.form.get("pem_data", "") or "").strip()
    try:
        order = max(0, int(request.form.get("order", 0)))
    except (ValueError, TypeError):
        order = 0
    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("chains.chain_intermediate_edit", chain_id=chain_id, ic_id=ic_id))
    if not pem_data:
        flash("PEM data is required.", "error")
        return redirect(url_for("chains.chain_intermediate_edit", chain_id=chain_id, ic_id=ic_id))
    try:
        x509.load_pem_x509_certificate(pem_data.encode())
    except Exception as e:
        flash(f"Invalid PEM certificate data: {e}", "error")
        return redirect(url_for("chains.chain_intermediate_edit", chain_id=chain_id, ic_id=ic_id))
    ic.name = name
    ic.pem_data = pem_data
    ic.order = order
    db.session.commit()
    _audit("intermediate_updated", "intermediate", ic_id, "success", f"name={name!r} chain_id={chain_id}")
    flash(f"Certificate '{name}' updated.", "success")
    return redirect(url_for("chains.chain_detail", chain_id=chain_id))


@bp.route("/chains/<int:chain_id>/intermediates/<int:ic_id>/delete", methods=["POST"])
@login_required
def chain_intermediate_delete(chain_id, ic_id):
    """POST — Remove an intermediate certificate from a chain."""
    ic = db.get_or_404(IntermediateCert, ic_id)
    name = ic.name
    db.session.delete(ic)
    db.session.commit()
    _audit("intermediate_deleted", "intermediate", ic_id, "success", f"name={name!r} chain_id={chain_id}")
    flash(f"Certificate '{name}' deleted.", "success")
    return redirect(url_for("chains.chain_detail", chain_id=chain_id))


@bp.route("/chains/<int:chain_id>/reorder", methods=["POST"])
@login_required
def chain_reorder(chain_id):
    """POST — Accept a JSON list of {id, order} pairs and update sort positions."""
    data = request.get_json()
    if not data or not isinstance(data, list):
        return {"error": "Invalid data"}, 400
    for item in data:
        ic = db.session.get(IntermediateCert, item.get("id"))
        if ic is not None:
            ic.order = item.get("order", 0)
    db.session.commit()
    return {"status": "ok"}


@bp.route("/chains/<int:chain_id>/import", methods=["GET", "POST"])
@login_required
def chain_import(chain_id):
    """GET/POST — Import a PEM bundle into a chain, skipping duplicates."""
    chain = db.get_or_404(CertChain, chain_id)

    if request.method == "GET":
        return render_template("chain_import.html", chain=chain)

    pem_text = ""
    uploaded = request.files.get("bundle_file")
    if uploaded and uploaded.filename:
        try:
            pem_text = uploaded.read().decode("utf-8", errors="replace")
        except Exception as e:
            flash(f"Could not read uploaded file: {e}", "error")
            return render_template("chain_import.html", chain=chain)
    else:
        pem_text = request.form.get("pem_text", "").strip()

    if not pem_text:
        flash("No PEM data provided.", "error")
        return render_template("chain_import.html", chain=chain)

    try:
        pem_blocks = parse_pem_bundle(pem_text)
    except ValueError as e:
        flash(str(e), "error")
        return render_template("chain_import.html", chain=chain)

    existing = IntermediateCert.query.filter_by(chain_id=chain_id).order_by(
        IntermediateCert.order.desc()
    ).first()
    next_order = (existing.order + 1) if existing else 0

    added = 0
    skipped = []
    for pem in pem_blocks:
        try:
            parsed = x509.load_pem_x509_certificate(pem.encode())
        except Exception as e:
            skipped.append(f"(unparseable block: {e})")
            continue

        try:
            cn = parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            cn = str(parsed.subject)

        if IntermediateCert.query.filter_by(chain_id=chain_id, pem_data=pem).first():
            skipped.append(cn)
            continue

        db.session.add(IntermediateCert(name=cn, pem_data=pem, order=next_order, chain_id=chain_id))
        next_order += 1
        added += 1

    db.session.commit()

    if added:
        _audit("chain_import", "chain", chain_id, "success", f"imported={added} skipped={len(skipped)}")
        flash(f"Imported {added} certificate(s) successfully.", "success")
    if skipped:
        flash(f"Skipped {len(skipped)} duplicate/invalid certificate(s): {', '.join(skipped)}", "warning")
    if not added and not skipped:
        flash("No certificates were imported.", "warning")

    return redirect(url_for("chains.chain_detail", chain_id=chain_id))