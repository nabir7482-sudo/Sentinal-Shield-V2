"""Authenticated localhost-only detector demonstration page."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, abort, current_app, render_template, request

from database.database import db, settings
from detection.detector import RequestDetector
from middleware.security_middleware import client_ip, record_event
from routes.auth import csrf_protect, login_required

blueprint = Blueprint("lab", __name__)
detector = RequestDetector()


def _local_lab_only() -> None:
    if not current_app.config["LAB_MODE"] or request.remote_addr not in {"127.0.0.1", "::1", None}:
        abort(404)


@blueprint.route("/lab/test-request", methods=["GET", "POST"])
@login_required
@csrf_protect
def test_request() -> Any:
    _local_lab_only()
    result = None
    submitted = ""
    if request.method == "POST":
        submitted = request.form.get("test_value", "")[:2048]
        result = detector.analyze(submitted, sensitivity=settings()["detection_sensitivity"])
        if result.detected:
            record_event(
                result,
                ip_address=client_ip(),
                method="LAB",
                path="/lab/test-request",
                user_agent="local lab test",
                action="LOGGED",
                description=(result.reason or "Suspicious lab string.") + " Local laboratory test; no payload was executed.",
            )
            db.session.commit()
    return render_template("lab.html", result=result, submitted=submitted)
