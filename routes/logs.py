"""Safe, bounded access-log analysis for local demonstration files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from database.database import db, settings
from detection.detector import RequestDetector
from middleware.security_middleware import audit, record_event
from routes.auth import csrf_protect, login_required

blueprint = Blueprint("logs", __name__)
detector = RequestDetector()

ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+-\s+-\s+\[[^]]+\]\s+"'
    r'(?P<method>[A-Z]+)\s+(?P<path>[^\s]+)\s+HTTP/[^\s"]+"\s+(?P<status>\d{3})'
)


def analyse_access_log(lines: list[str]) -> tuple[int, int]:
    """Analyze recognised lines and persist each resulting security event once."""
    parsed = 0
    detected = 0
    sensitivity = settings()["detection_sensitivity"]
    for line in lines:
        match = ACCESS_LOG_PATTERN.match(line.strip())
        if not match:
            continue
        parsed += 1
        path = unquote(match.group("path"))
        result = detector.analyze(path, sensitivity=sensitivity)
        if result.detected:
            record_event(
                result,
                ip_address=match.group("ip"),
                method=match.group("method"),
                path=path,
                user_agent="access-log import",
                action="LOGGED",
                description=(result.reason or "Suspicious log entry.") + " Imported from an access log.",
            )
            detected += 1
    db.session.commit()
    return parsed, detected


@blueprint.route("/logs", methods=["GET", "POST"])
@login_required
@csrf_protect
def logs() -> Any:
    if request.method == "POST":
        uploaded = request.files.get("log_file")
        if uploaded is None or not uploaded.filename:
            flash("Choose a .log or .txt access-log file first.", "warning")
            return redirect(url_for("logs.logs"))
        suffix = Path(uploaded.filename).suffix.lower()
        if suffix not in {".log", ".txt"}:
            flash("Only .log and .txt files are accepted.", "danger")
            return redirect(url_for("logs.logs"))
        contents = uploaded.read(current_app.config["MAX_CONTENT_LENGTH"] + 1)
        if len(contents) > current_app.config["MAX_CONTENT_LENGTH"]:
            flash("The uploaded log is larger than the 1 MiB safety limit.", "danger")
            return redirect(url_for("logs.logs"))
        parsed, detected = analyse_access_log(contents.decode("utf-8", errors="replace").splitlines())
        audit("Access log analysed", f"Parsed {parsed} entries; detected {detected} events")
        db.session.commit()
        flash(f"Analysed {parsed} log entries and found {detected} security events.", "success")
        return redirect(url_for("logs.logs"))
    return render_template("logs.html")


@blueprint.post("/logs/sample")
@login_required
@csrf_protect
def analyse_sample() -> Any:
    sample_path = Path(current_app.config["SAMPLE_LOG_PATH"])
    lines = sample_path.read_text(encoding="utf-8").splitlines()
    parsed, detected = analyse_access_log(lines)
    audit("Sample access log analysed", f"Parsed {parsed} entries; detected {detected} events")
    db.session.commit()
    flash(f"Sample log processed: {parsed} entries, {detected} detections.", "success")
    return redirect(url_for("logs.logs"))
