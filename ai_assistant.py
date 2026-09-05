"""Deterministic SOC investigator helpers for local analyst workflows."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path
import re
from typing import Any

from database.models import SecurityEvent, utcnow

MITRE = {
    "SQL Injection": ("T1190", "Exploit Public-Facing Application"),
    "Cross-Site Scripting": ("T1059", "Command and Scripting Interpreter"),
    "Path Traversal": ("T1190", "Exploit Public-Facing Application"),
    "Command Injection": ("T1059", "Command and Scripting Interpreter"),
    "Server-Side Template Injection": ("T1190", "Exploit Public-Facing Application"),
    "Brute Force": ("T1110", "Brute Force"),
    "Broken Object Level Authorization": ("T1210", "Exploitation of Remote Services"),
}
CATEGORY_ALIASES = {
    "sqli": "SQL Injection",
    "sql injection": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "cross site scripting": "Cross-Site Scripting",
    "path traversal": "Path Traversal",
    "ssti": "Server-Side Template Injection",
    "server side template injection": "Server-Side Template Injection",
    "brute force": "Brute Force",
    "bola": "Broken Object Level Authorization",
    "broken object level authorization": "Broken Object Level Authorization",
}


def _mitre(attack_type: str) -> tuple[str, str]:
    return MITRE.get(attack_type, ("T1190", "Exploit Public-Facing Application"))


def explain_payload(payload: str, attack_type: str = "") -> str:
    text = payload or "No payload preview was retained."
    lowered = text.lower()
    parts: list[str] = []
    if "'" in text or '"' in text:
        parts.append("the quote can break out of the original input context")
    if " or 1=1" in lowered or " or '1'='1" in lowered or " or \"1\"=\"1" in lowered:
        parts.append("OR 1=1 is an always-true condition")
    if "--" in text or "/*" in text or "#" in text:
        parts.append("the comment marker can hide the rest of the query")
    if "<script" in lowered or "onerror" in lowered or "javascript:" in lowered:
        parts.append("the markup or event handler attempts to execute script in a browser")
    if "../" in lowered or "..\\" in lowered:
        parts.append("dot-dot path segments attempt to move outside the intended directory")
    if not parts:
        return f"This {attack_type or 'suspicious'} payload matches a known detection pattern and needs context review."
    return "The payload appears to use " + "; ".join(parts) + "."


def analyze_attack(payload: str, attack_type: str, ip: str, history: Iterable[Any]) -> dict[str, Any]:
    history_list = list(history)
    technique, technique_name = _mitre(attack_type)
    same_type = [event for event in history_list if getattr(event, "category", "") == attack_type]
    current_event = history_list[0] if history_list else None
    severity = getattr(current_event, "severity", "HIGH")
    risk = "Critical" if severity == "CRITICAL" or len(history_list) >= 5 else "High"
    data = {
        "SQL Injection": "database records, credentials, and application data",
        "Cross-Site Scripting": "browser sessions, tokens, and user-visible data",
        "Path Traversal": "configuration files, source code, and local secrets",
        "Command Injection": "server files, process access, and environment secrets",
        "Server-Side Template Injection": "server-side secrets, rendered responses, and process access",
        "Brute Force": "user accounts, session tokens, and protected application routes",
        "Broken Object Level Authorization": "records belonging to other users or tenants",
    }.get(attack_type, "application data and internal service details")
    campaign = len(history_list) >= 2
    timestamp = getattr(current_event, "timestamp", None)
    timestamp_text = timestamp.isoformat() if timestamp else "Timestamp unavailable"
    endpoint = getattr(current_event, "request_path", "Unknown endpoint")
    method = getattr(current_event, "http_method", "Unknown method")
    user_agent = getattr(current_event, "user_agent", "Unknown user agent")
    rule_id = getattr(current_event, "rule_id", "Unknown rule")
    action = getattr(current_event, "action_taken", "Logged")
    is_local_source = ip in {"127.0.0.1", "::1", "localhost"}
    triage_reason = (
        f"The payload matches a {attack_type or 'suspicious input'} detection and must be treated as an active threat, even though the source is local ({ip})."
        if is_local_source
        else f"The payload matches a {attack_type or 'suspicious input'} detection and targets an application input or control boundary."
    )
    threat_objectives = {
        "SQL Injection": "Bypass SQLAlchemy filtering or execute unauthorized database operations.",
        "Cross-Site Scripting": "Execute attacker-controlled script in a browser context or steal session data.",
        "Path Traversal": "Read files outside the intended application directory.",
        "Command Injection": "Execute operating-system commands through an application input.",
        "Server-Side Template Injection": "Inject Jinja2 expressions to access server-side objects or secrets.",
        "Brute Force": "Automate authentication attempts until a valid credential or session is obtained.",
        "Broken Object Level Authorization": "Access or modify an object belonging to another user or tenant.",
    }
    containment = [
        f"Preserve the event and block or rate-limit source {ip}; do not exempt it because it is local.",
        f"Revoke affected sessions and review requests to {endpoint} for successful follow-on activity.",
        "Isolate the affected route or application instance if exploitation is confirmed, then rotate exposed secrets.",
    ]
    if action == "BLOCKED":
        containment[0] = f"Keep source {ip} blocked and rate-limited while validating that no alternate path reached the application."
    search_query = (
        "SecurityEvent.query.filter(SecurityEvent.source_ip == source_ip, "
        "SecurityEvent.category == category).order_by(SecurityEvent.timestamp.desc()).all()"
    )
    code_fix = {
        "SQL Injection": "Use SQLAlchemy bound parameters or ORM filters; never concatenate request values into text SQL.",
        "Cross-Site Scripting": "Render untrusted values with Jinja2 autoescaping and validate any explicitly marked safe content.",
        "Path Traversal": "Resolve paths against an approved directory and reject values that escape that directory.",
        "Command Injection": "Avoid shell execution; pass fixed argument arrays to subprocess and validate each value.",
        "Server-Side Template Injection": "Do not compile user input as a Jinja2 template; use a fixed template and data context.",
        "Brute Force": "Apply account-aware rate limits and step-up authentication to login and token endpoints.",
        "Broken Object Level Authorization": "Load objects through the authenticated owner or tenant scope before permitting access.",
    }.get(attack_type, "Validate route inputs, enforce authorization at the data-access boundary, and use parameterized queries.")
    timeline = [
        f"{timestamp_text}: {method} {endpoint} from {ip} triggered rule {rule_id}.",
        f"Detection action: {action}; stored severity: {severity}; payload review: {explain_payload(payload, attack_type)}",
        f"Correlation: {len(history_list)} recent event(s) from this source; {'campaign activity is possible.' if campaign else 'no broader campaign is established yet.'}",
    ]
    return {
        "explanation": explain_payload(payload, attack_type),
        "risk_level": risk,
        "potential_data": data,
        "campaign": campaign,
        "campaign_summary": f"{len(history_list)} events from {ip} in the recent history; this is consistent with a broader campaign." if campaign else f"Only one recent event from {ip}; no larger campaign is evident yet.",
        "mitre": {"technique": technique, "name": technique_name, "description": f"{technique_name}: adversaries may use this technique to gain access or execute commands through exposed application inputs."},
        "recommended_actions": ["Block or maintain the temporary block on the source IP.", "Patch and validate the affected input or output encoding path.", "Check application and database logs for successful follow-on activity."],
        "similar_incidents": len(same_type),
        "ip": ip,
        "monitoring": {
            "component": "Flask/Werkzeug request detection and persisted SecurityEvent record",
            "entities": {"timestamp": timestamp_text, "endpoint": endpoint, "method": method, "source_ip": ip, "user_agent": user_agent, "rule": rule_id, "action": action},
        },
        "triage": {"verdict": "True Positive", "severity": severity.title(), "reasoning": triage_reason},
        "investigation": {"threats": [attack_type or "Suspicious application input", f"OWASP-aligned application input abuse: {attack_type or 'unclassified threat'}"], "objective": threat_objectives.get(attack_type, "Probe application controls for unauthorized access or execution."), "collateral": data, "mitre": {"technique": technique, "name": technique_name}},
        "containment": containment,
        "hunting": {"query": search_query, "code_fix": code_fix},
        "reporting": {"executive_summary": f"{risk} priority {attack_type or 'security'} event from {ip} targeted {method} {endpoint}. The activity is classified as a true positive pending analyst confirmation and could expose {data}.", "timeline": timeline, "hardening": ["Centralize structured request, authentication, and SQLAlchemy audit logs with retention and alerting.", "Enforce least-privilege database credentials, secure session settings, and regression tests for this attack vector."]},
    }


def whitelist_path() -> Path:
    return Path(__file__).resolve().parent / "whitelist.txt"


def is_whitelisted(ip: str) -> bool:
    try:
        entries = {line.strip() for line in whitelist_path().read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}
    except OSError:
        entries = set()
    return ip in entries


def chat_answer(question: str) -> dict[str, Any]:
    text = question.strip()
    lowered = text.lower()
    query = SecurityEvent.query
    filters: list[str] = []
    if "last hour" in lowered:
        query = query.filter(SecurityEvent.timestamp >= utcnow() - timedelta(hours=1))
        filters.append("the last hour")
    compact_question = re.sub(r"[^a-z0-9 ]", "", lowered)
    category = next((target for alias, target in CATEGORY_ALIASES.items() if alias in compact_question), None)
    if category:
        query = query.filter_by(category=category)
        filters.append(category)
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if ip_match:
        ip = ip_match.group(0)
        query = query.filter_by(source_ip=ip)
        if "malicious" in lowered:
            count = query.count()
            return {"answer": f"{ip} has {count} matching security event(s). It is {'listed as a known false positive' if is_whitelisted(ip) else 'not on the local false-positive whitelist'}.", "count": count, "events": []}
        filters.append(ip)
    events = query.order_by(SecurityEvent.timestamp.desc()).limit(100).all()
    scope = " and ".join(filters) if filters else "all stored events"
    return {"answer": f"I found {len(events)} event(s) in {scope}.", "count": len(events), "events": [event.as_dict() for event in events]}
