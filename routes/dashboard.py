"""Dashboard and shared statistics queries."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, jsonify, render_template, request
from sqlalchemy import func

from database.models import SecurityEvent
from ai_assistant import chat_answer
from routes.auth import api_login_required, csrf_protect, login_required
from middleware.security_middleware import is_ip_blocked

blueprint = Blueprint("dashboard", __name__)


def statistics() -> dict[str, Any]:
    """Compute dashboard values directly from stored events."""
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all()
    severity_counts = Counter(event.severity for event in events)
    category_counts = Counter(event.category for event in events)
    ip_counts = Counter(event.source_ip for event in events)
    verdict_counts = Counter(event.analyst_verdict for event in events)
    now = datetime.now(timezone.utc)
    per_day: Counter[str] = Counter()
    for event in events:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if timestamp >= now - timedelta(days=6):
            per_day[timestamp.date().isoformat()] += 1
    dates = [(now - timedelta(days=offset)).date().isoformat() for offset in range(6, -1, -1)]
    hours = [now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=offset) for offset in range(11, -1, -1)]
    return {
        "total_events": len(events),
        "critical_events": severity_counts["CRITICAL"],
        "high_events": severity_counts["HIGH"],
        "blocked_requests": sum(event.action_taken == "BLOCKED" for event in events),
        "unique_ips": len(ip_counts),
        "severity": dict(severity_counts),
        "categories": dict(category_counts),
        "top_ips": dict(ip_counts.most_common(5)),
        "top_attacker_ip": ip_counts.most_common(1)[0][0] if ip_counts else "None",
        "tp_rate": round(verdict_counts["True Positive"] / len(events) * 100, 1) if events else 0,
        "fp_rate": round(verdict_counts["False Positive"] / len(events) * 100, 1) if events else 0,
        "verdicts": dict(verdict_counts),
        "hourly": {"labels": [hour.strftime("%H:%M") for hour in hours], "values": [sum(1 for event in events if (event.timestamp.replace(tzinfo=timezone.utc) if event.timestamp.tzinfo is None else event.timestamp).replace(minute=0, second=0, microsecond=0) == hour) for hour in hours]},
        "timeline": {"labels": dates, "values": [per_day[date] for date in dates]},
        "recent": [event.as_dict() for event in events[:10]],
    }


@blueprint.get("/")
@login_required
def index() -> Any:
    return render_template("dashboard.html", stats=statistics())


@blueprint.post("/ai-chat")
@login_required
@csrf_protect
def ai_chat() -> Any:
    question = request.form.get("question", "")[:500]
    return jsonify(chat_answer(question))


@blueprint.get("/api/logs")
@api_login_required
def api_logs() -> Any:
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(200).all()
    return jsonify({"logs": [event.as_dict() for event in events], "format": "SIEM"})


@blueprint.get("/api/statistics")
@api_login_required
def api_statistics() -> Any:
    return jsonify(statistics())
