"""Security-event list, detail view, and authenticated JSON API."""

from __future__ import annotations

from typing import Any

from flask import Blueprint, abort, jsonify, render_template, request, redirect, url_for

from ai_assistant import analyze_attack, explain_payload, whitelist_path
from database.database import db
from database.models import SecurityEvent
from routes.auth import api_login_required, csrf_protect, login_required

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


@blueprint.get("/investigate/<int:log_id>")
@login_required
def investigate(log_id: int) -> Any:
    event = SecurityEvent.query.get_or_404(log_id)
    history = SecurityEvent.query.filter_by(source_ip=event.source_ip).order_by(SecurityEvent.timestamp.desc()).limit(10).all()
    analysis = analyze_attack(event.payload_preview or event.description, event.category, event.source_ip, history)
    return render_template("investigate.html", event=event, analysis=analysis)


@blueprint.post("/events/<int:event_id>/verdict")
@login_required
@csrf_protect
def verdict(event_id: int) -> Any:
    event = SecurityEvent.query.get_or_404(event_id)
    value = request.form.get("analyst_verdict", "Pending")
    if value not in {"Pending", "True Positive", "False Positive", "Benign"}:
        abort(400)
    event.analyst_verdict = value
    if value == "False Positive":
        with whitelist_path().open("a", encoding="utf-8") as handle:
            handle.write(f"{event.source_ip}\n")
    db.session.commit()
    return redirect(request.form.get("next") or url_for("dashboard.index"))


@blueprint.get("/events/<int:event_id>/explain")
@login_required
def explain(event_id: int) -> Any:
    event = SecurityEvent.query.get_or_404(event_id)
    return jsonify({"explanation": explain_payload(event.payload_preview, event.category)})


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
