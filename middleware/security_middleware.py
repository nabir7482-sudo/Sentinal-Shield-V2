"""Request inspection, event persistence, temporary blocking, and headers."""

from __future__ import annotations

from datetime import timedelta
import logging
from functools import lru_cache
from typing import Any

import requests
from flask import Flask, abort, g, request, session

from database.database import db, setting_bool, setting_int, settings
from database.models import AuditLog, BlockedIP, SecurityEvent, utcnow
from detection.detector import DetectionResult, RequestDetector
from detection.rate_detector import RateDetector

logger = logging.getLogger("sentinelshield.security")
detector = RequestDetector()
rate_detector = RateDetector()

SENSITIVE_FIELDS = {"password", "password_confirmation", "csrf_token", "token", "secret"}


def client_ip() -> str:
    """Use the direct peer IP; proxy trust must be explicitly configured in production."""
    return (request.remote_addr or "unknown")[:45]


def audit(action: str, details: str = "") -> None:
    actor = str(session.get("admin_username", "system"))[:64]
    db.session.add(AuditLog(actor=actor, action=action[:128], details=details[:2000]))
    logger.info("Admin audit action: %s by %s", action[:128], actor)


def is_ip_blocked(ip_address: str) -> BlockedIP | None:
    block = BlockedIP.query.filter_by(ip_address=ip_address, active=True).first()
    if block and not block.is_active():
        block.active = False
        db.session.commit()
        return None
    return block


def block_ip(ip_address: str, reason: str, duration_minutes: int) -> BlockedIP:
    """Create or renew a temporary block created from a detection event only."""
    expires_at = utcnow() + timedelta(minutes=duration_minutes)
    block = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if block is None:
        block = BlockedIP(
            ip_address=ip_address,
            reason=reason[:512],
            expires_at=expires_at,
            active=True,
        )
        db.session.add(block)
    else:
        block.reason = reason[:512]
        block.blocked_at = utcnow()
        block.expires_at = expires_at
        block.active = True
    logger.warning("Temporary IP block created or renewed for %s", ip_address)
    return block


def record_event(
    result: DetectionResult,
    *,
    ip_address: str,
    method: str,
    path: str,
    user_agent: str,
    action: str,
    description: str | None = None,
    payload_preview: str = "",
) -> SecurityEvent:
    """Persist a detection result without retaining request body or secrets."""
    event = SecurityEvent(
        source_ip=ip_address[:45],
        http_method=method[:12],
        request_path=path[:1024],
        user_agent=user_agent[:512],
        category=result.category or "Suspicious HTTP Request",
        rule_id=result.matched_rule or "GENERIC-001",
        severity=result.severity or "LOW",
        confidence=result.confidence,
        description=(description or result.reason or "Suspicious activity detected.")[:4000],
        action_taken=action,
        status="OPEN",
        payload_preview=payload_preview[:500],
        country=lookup_country(ip_address),
        mitre_attack={"SQL Injection": "T1190", "Cross-Site Scripting": "T1059"}.get(result.category or "", "T1190"),
    )
    db.session.add(event)
    logger.info("Security event created: %s from %s (%s)", event.category, event.source_ip, action)
    return event


@lru_cache(maxsize=256)
def lookup_country(ip_address: str) -> str:
    if ip_address in {"127.0.0.1", "::1", "unknown"}:
        return "Local"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country", timeout=1.5)
        data = response.json()
        return str(data.get("country") or "Unknown") if data.get("status") == "success" else "Unknown"
    except (requests.RequestException, ValueError, TypeError):
        return "Unknown"


def _safe_request_text() -> str:
    """Inspect path/query/form fields while deliberately excluding secrets and files."""
    values = [request.path, request.query_string.decode("utf-8", errors="replace")]
    for key, field_values in request.values.lists():
        if key.lower() not in SENSITIVE_FIELDS:
            values.append(key)
            values.extend(str(item) for item in field_values)
    return " ".join(values)[:8192]


def _repeated_count(ip_address: str, result: DetectionResult) -> int:
    if not result.matched_rule:
        return 0
    cutoff = utcnow() - timedelta(minutes=5)
    return SecurityEvent.query.filter(
        SecurityEvent.source_ip == ip_address,
        SecurityEvent.rule_id == result.matched_rule,
        SecurityEvent.timestamp >= cutoff,
    ).count()


def register_security(app: Flask) -> None:
    """Attach defensive inspection and security-header lifecycle handlers."""

    @app.before_request
    def inspect_request() -> Any:
        if request.endpoint == "static" or request.path == "/lab/test-request":
            return None
        ip_address = client_ip()
        management_request = session.get("admin_id") and (
            request.path == "/logout"
            or request.path.startswith("/blocked-ips")
        )
        if is_ip_blocked(ip_address) and not management_request:
            logger.warning("Blocked request from %s to %s", ip_address, request.path)
            abort(403)

        rate = rate_detector.check_request(ip_address, setting_int("max_requests_per_minute"))
        if rate.exceeded:
            if rate.first_exceedance:
                rate_result = DetectionResult(
                    detected=True,
                    category="Excessive Requests",
                    severity="MEDIUM",
                    confidence=0.78,
                    reason="Request frequency exceeded the configured per-minute threshold.",
                    matched_rule="RATE-001",
                )
                record_event(
                    rate_result,
                    ip_address=ip_address,
                    method=request.method,
                    path=request.path,
                    user_agent=request.user_agent.string or "",
                    action="RATE_LIMITED",
                )
                db.session.commit()
                logger.warning("Rate limited IP %s", ip_address)
            abort(429)

        sensitivity = settings()["detection_sensitivity"]
        request_text = _safe_request_text()
        result = detector.analyze(request_text, sensitivity=sensitivity)
        if not result.detected:
            return None
        result = detector.analyze(
            request_text, _repeated_count(ip_address, result), sensitivity=sensitivity
        )
        action = "LOGGED"
        if 0.60 <= result.confidence < 0.85:
            action = "FLAGGED"
        if result.confidence >= 0.85 and setting_bool("auto_block_enabled"):
            action = "BLOCKED"
            block_ip(ip_address, result.reason or "Detected suspicious request", setting_int("block_duration_minutes"))
        event = record_event(
            result,
            ip_address=ip_address,
            method=request.method,
            path=request.path,
            user_agent=request.user_agent.string or "",
            action=action,
            payload_preview=request_text,
        )
        db.session.commit()
        g.security_event_id = event.id
        logger.warning("Detection %s (%s) from %s", result.matched_rule, result.severity, ip_address)
        if action == "BLOCKED":
            logger.warning("Temporary block applied to %s", ip_address)
            abort(403)
        return None

    @app.after_request
    def add_security_headers(response: Any) -> Any:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; "
            "font-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self'"
        )
        return response
