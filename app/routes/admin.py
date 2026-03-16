# ==============================================================================
# FILE:           app/routes/admin.py
# DESCRIPTION:    Admin routes: database integrity check and audit log viewer.
#
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
#                 Copyright (C) 2026  Matt Comeione / ideocentric
# ==============================================================================

from flask import Blueprint, render_template, request, session

from ..extensions import db
from ..models import AuditLog
from ..security import _audit, superadmin_required

bp = Blueprint("admin", __name__)


@bp.route("/admin/db-check")
@superadmin_required
def db_integrity_check():
    """GET /admin/db-check — Run SQLite integrity checks (superadmin only)."""
    from sqlalchemy import text
    results = {}
    try:
        with db.engine.connect() as conn:
            rows = conn.execute(text("PRAGMA integrity_check")).fetchall()
            results["integrity_check"] = [r[0] for r in rows]

            rows = conn.execute(text("PRAGMA quick_check")).fetchall()
            results["quick_check"] = [r[0] for r in rows]

            row = conn.execute(text("PRAGMA journal_mode")).fetchone()
            results["journal_mode"] = row[0] if row else "unknown"

            rows = conn.execute(text("PRAGMA foreign_key_check")).fetchall()
            results["foreign_key_violations"] = len(rows)
            results["foreign_key_details"] = [
                {"table": r[0], "rowid": r[1], "parent": r[2], "fkid": r[3]}
                for r in rows
            ]

            row = conn.execute(text("PRAGMA page_count")).fetchone()
            results["page_count"] = row[0] if row else 0
            row = conn.execute(text("PRAGMA page_size")).fetchone()
            results["page_size"] = row[0] if row else 0
            row = conn.execute(text("PRAGMA freelist_count")).fetchone()
            results["freelist_count"] = row[0] if row else 0

        integrity_ok = results["integrity_check"] == ["ok"]
        quick_ok     = results["quick_check"]     == ["ok"]
        fk_ok        = results["foreign_key_violations"] == 0
        overall_ok   = integrity_ok and quick_ok and fk_ok

        _audit("db_integrity_check", result="success" if overall_ok else "failure",
               detail=f"integrity={'ok' if integrity_ok else 'FAIL'} "
                      f"quick={'ok' if quick_ok else 'FAIL'} "
                      f"fk_violations={results['foreign_key_violations']}")
    except Exception as e:
        results = {"error": str(e)}
        overall_ok = False
        _audit("db_integrity_check", result="failure", detail=f"exception={e!r}")

    return render_template("db_check.html", results=results, overall_ok=overall_ok)


@bp.route("/audit")
@superadmin_required
def audit_log_view():
    """GET /audit — Paginated, searchable, sortable audit log (superadmin only)."""
    valid_per_page = {10, 20, 50, 0}  # 0 = all
    if "per_page" in request.args:
        per_page = request.args.get("per_page", type=int)
        if per_page in valid_per_page:
            session["audit_per_page"] = per_page
        else:
            per_page = session.get("audit_per_page", 20)
    else:
        per_page = session.get("audit_per_page", 20)

    sortable_columns = {
        "timestamp": AuditLog.timestamp,
        "username":  AuditLog.username,
        "action":    AuditLog.action,
        "resource":  AuditLog.resource_type,
        "result":    AuditLog.result,
    }
    if "sort" in request.args or "dir" in request.args:
        sort_col = request.args.get("sort", "timestamp")
        sort_dir = request.args.get("dir",  "desc")
        if sort_col not in sortable_columns:
            sort_col = "timestamp"
        if sort_dir not in ("asc", "desc"):
            sort_dir = "desc"
        session["audit_sort_col"] = sort_col
        session["audit_sort_dir"] = sort_dir
    else:
        sort_col = session.get("audit_sort_col", "timestamp")
        sort_dir = session.get("audit_sort_dir", "desc")
    col_expr = sortable_columns[sort_col]
    order_expr = col_expr.asc() if sort_dir == "asc" else col_expr.desc()

    q = request.args.get("q", "").strip()
    query = AuditLog.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                AuditLog.username.ilike(like),
                AuditLog.ip_address.ilike(like),
                AuditLog.action.ilike(like),
                AuditLog.resource_type.ilike(like),
                AuditLog.result.ilike(like),
                AuditLog.detail.ilike(like),
            )
        )

    page = request.args.get("page", 1, type=int)
    if per_page == 0:
        count = query.count()
        pagination = query.order_by(order_expr).paginate(
            page=1, per_page=max(count, 1), error_out=False
        )
    else:
        pagination = query.order_by(order_expr).paginate(
            page=page, per_page=per_page, error_out=False
        )
    return render_template(
        "audit.html",
        entries=pagination.items,
        pagination=pagination,
        per_page=per_page,
        sort_col=sort_col,
        sort_dir=sort_dir,
        q=q,
    )