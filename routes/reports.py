"""Database-backed security reporting and CSV export."""

from __future__ import annotations

import csv
from io import StringIO
from typing import Any

from flask import Blueprint, Response, render_template

from database.models import SecurityEvent, utcnow
from routes.auth import login_required
from routes.dashboard import statistics

blueprint = Blueprint("reports", __name__)


@blueprint.get("/reports")
@login_required
def report_page() -> Any:
    return render_template("reports.html", stats=statistics(), report_date=utcnow().date().isoformat())


@blueprint.get("/reports/download.csv")
@login_required
def download_csv() -> Response:
    """Produce a straightforward, portable report from current event records."""
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["SentinelShield Security Report", utcnow().isoformat()])
    writer.writerow([])
    writer.writerow(["Event ID", "Time", "Source IP", "Category", "Rule", "Severity", "Confidence", "Action", "Status"])
    for event in SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all():
        writer.writerow([
            event.id, event.timestamp.isoformat(), event.source_ip, event.category,
            event.rule_id, event.severity, f"{event.confidence:.2f}", event.action_taken, event.status,
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelshield-security-report.csv"},
    )
