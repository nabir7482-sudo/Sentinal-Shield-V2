"""Administrator views for temporary defensive IP blocks."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, flash, jsonify, redirect, render_template, url_for

from database.database import db
from database.models import BlockedIP
from middleware.security_middleware import audit
from routes.auth import api_login_required, csrf_protect, login_required

blueprint = Blueprint("blocked_ips", __name__)


@blueprint.get("/blocked-ips")
@login_required
def list_blocks() -> Any:
    blocks = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return render_template("blocked_ips.html", blocks=blocks)


def _unblock(ip_address: str) -> bool:
    block = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if block is None:
        return False
    block.active = False
    audit("IP block removed", ip_address)
    db.session.commit()
    return True


@blueprint.post("/blocked-ips/<string:ip_address>/unblock")
@login_required
@csrf_protect
def unblock(ip_address: str) -> Any:
    if _unblock(ip_address):
        flash(f"Block removed for {ip_address}.", "success")
    else:
        flash("Blocked IP entry was not found.", "warning")
    return redirect(url_for("blocked_ips.list_blocks"))


@blueprint.get("/api/blocked-ips")
@api_login_required
def api_blocks() -> Any:
    blocks = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify({"blocked_ips": [block.as_dict() for block in blocks]})


@blueprint.post("/api/blocked-ips/<string:ip_address>/unblock")
@api_login_required
@csrf_protect
def api_unblock(ip_address: str) -> Any:
    if not _unblock(ip_address):
        return jsonify({"error": "Blocked IP not found"}), 404
    return jsonify({"message": f"Block removed for {ip_address}"})
