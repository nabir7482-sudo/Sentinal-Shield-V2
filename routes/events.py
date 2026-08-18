"""Security-event list, detail view, and authenticated JSON API."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, abort, jsonify, render_template, request

from database.database import db
from database.models import SecurityEvent
from routes.auth import api_login_required, login_required

blueprint = Blueprint("events", __name__)
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@blueprint.get("/events")
@login_required
def list_events() -> Any:
    query = SecurityEvent.query
    severity = request.args.get("severity", "")
    category = request.args.get("category", "")
    if severity in VALID_SEVERITIES:
        query = query.filter_by(severity=severity)
    if category:
        query = query.filter_by(category=category[:64])
    page = max(1, request.args.get("page", 1, type=int))
    pagination = query.order_by(SecurityEvent.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)
    categories = [row[0] for row in SecurityEvent.query.with_entities(SecurityEvent.category).distinct().all()]
    return render_template("events.html", pagination=pagination, categories=categories, selected_severity=severity, selected_category=category)


@blueprint.get("/events/<int:event_id>")
@login_required
def detail(event_id: int) -> Any:
    event = SecurityEvent.query.get_or_404(event_id)
    return render_template("event_detail.html", event=event)


@blueprint.get("/api/events")
@api_login_required
def api_events() -> Any:
    limit = min(max(request.args.get("limit", 100, type=int), 1), 200)
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return jsonify({"events": [event.as_dict() for event in events]})


@blueprint.get("/api/events/<int:event_id>")
@api_login_required
def api_event(event_id: int) -> Any:
    event = db.session.get(SecurityEvent, event_id)
    if event is None:
        return jsonify({"error": "Event not found"}), 404
    return jsonify(event.as_dict())
