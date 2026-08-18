"""Validated, persisted IDS configuration management."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, flash, redirect, render_template, request, url_for

from database.database import db, settings
from database.models import AppConfiguration
from middleware.security_middleware import audit
from routes.auth import csrf_protect, login_required

blueprint = Blueprint("settings", __name__)


def _integer(form_key: str, label: str, minimum: int, maximum: int) -> int:
    value = request.form.get(form_key, "")
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a whole number.") from error
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}.")
    return parsed


@blueprint.route("/settings", methods=["GET", "POST"])
@login_required
@csrf_protect
def manage() -> Any:
    if request.method == "POST":
        try:
            new_values = {
                "brute_force_threshold": str(_integer("brute_force_threshold", "Brute-force threshold", 2, 100)),
                "brute_force_window_seconds": str(_integer("brute_force_window_seconds", "Brute-force window", 10, 3600)),
                "max_requests_per_minute": str(_integer("max_requests_per_minute", "Requests per minute", 10, 10000)),
                "block_duration_minutes": str(_integer("block_duration_minutes", "Block duration", 1, 1440)),
                "auto_block_enabled": "true" if request.form.get("auto_block_enabled") else "false",
                "detection_sensitivity": request.form.get("detection_sensitivity", "standard"),
            }
            if new_values["detection_sensitivity"] not in {"conservative", "standard", "sensitive"}:
                raise ValueError("Detection sensitivity has an invalid value.")
        except ValueError as error:
            flash(str(error), "danger")
            return render_template("settings.html", values=settings())
        records = {item.key: item for item in AppConfiguration.query.all()}
        for key, value in new_values.items():
            records[key].value = value
        audit("Security configuration changed", "IDS thresholds or blocking settings updated")
        db.session.commit()
        flash("Security settings saved.", "success")
        return redirect(url_for("settings.manage"))
    return render_template("settings.html", values=settings())
