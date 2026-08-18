"""Dashboard and shared statistics queries."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, jsonify, render_template
from sqlalchemy import func

from database.models import SecurityEvent
from middleware.security_middleware import is_ip_blocked
from routes.auth import api_login_required, login_required

blueprint = Blueprint("dashboard", __name__)


def statistics() -> dict[str, Any]:
    """Compute dashboard values directly from stored events."""
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all()
    severity_counts = Counter(event.severity for event in events)
    category_counts = Counter(event.category for event in events)
    ip_counts = Counter(event.source_ip for event in events)
    now = datetime.now(timezone.utc)
    per_day: Counter[str] = Counter()
    for event in events:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if timestamp >= now - timedelta(days=6):
            per_day[timestamp.date().isoformat()] += 1
    dates = [(now - timedelta(days=offset)).date().isoformat() for offset in range(6, -1, -1)]
    return {
        "total_events": len(events),
        "critical_events": severity_counts["CRITICAL"],
        "high_events": severity_counts["HIGH"],
        "blocked_requests": sum(event.action_taken == "BLOCKED" for event in events),
        "unique_ips": len(ip_counts),
        "severity": dict(severity_counts),
        "categories": dict(category_counts),
        "top_ips": dict(ip_counts.most_common(5)),
        "timeline": {"labels": dates, "values": [per_day[date] for date in dates]},
        "recent": [event.as_dict() for event in events[:10]],
    }


@blueprint.get("/")
@login_required
def index() -> Any:
    return render_template("dashboard.html", stats=statistics())


@blueprint.get("/api/statistics")
@api_login_required
def api_statistics() -> Any:
    return jsonify(statistics())
