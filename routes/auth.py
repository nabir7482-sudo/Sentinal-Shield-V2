"""Local administrator authentication and CSRF helpers."""

from __future__ import annotations

from functools import wraps
import hmac
import secrets
from typing import Any, Callable, TypeVar

from flask import abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from database.database import db, setting_bool, setting_int
from database.models import Admin, utcnow
from detection.detector import DetectionResult
from middleware.security_middleware import audit, block_ip, client_ip, rate_detector, record_event

F = TypeVar("F", bound=Callable[..., Any])


def csrf_token() -> str:
    """Return one per-session token for all state-changing browser actions."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return str(session["csrf_token"])


def _csrf_matches() -> bool:
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")
    return bool(submitted) and hmac.compare_digest(str(session.get("csrf_token", "")), submitted)


def csrf_protect(view: F) -> F:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_matches():
            abort(400)
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def login_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if "admin_id" not in session:
            flash("Please sign in to access SentinelShield.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def api_login_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if "admin_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def register_auth_routes(app: Any) -> None:
    from flask import Blueprint

    blueprint = Blueprint("auth", __name__)

    @blueprint.route("/login", methods=["GET", "POST"])
    @csrf_protect
    def login() -> Any:
        if "admin_id" in session:
            return redirect(url_for("dashboard.index"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            admin = Admin.query.filter_by(username=username).first()
            if admin and check_password_hash(admin.password_hash, password):
                admin.last_login_at = utcnow()
                session.clear()
                session["admin_id"] = admin.id
                session["admin_username"] = admin.username
                session.permanent = True
                csrf_token()
                rate_detector.clear_login_failures(client_ip())
                audit("Administrator signed in")
                db.session.commit()
                return redirect(url_for("dashboard.index"))

            check = rate_detector.record_login_failure(
                client_ip(), setting_int("brute_force_threshold"), setting_int("brute_force_window_seconds")
            )
            if check.first_exceedance:
                result = DetectionResult(
                    detected=True,
                    category="Brute Force",
                    severity="HIGH",
                    confidence=0.92,
                    reason="The configured number of failed authentication attempts was reached.",
                    matched_rule="BRUTE-001",
                )
                action = "LOGGED"
                if setting_bool("auto_block_enabled"):
                    action = "BLOCKED"
                    block_ip(client_ip(), result.reason or "Repeated failed logins", setting_int("block_duration_minutes"))
                record_event(
                    result,
                    ip_address=client_ip(),
                    method="POST",
                    path="/login",
                    user_agent=request.user_agent.string or "",
                    action=action,
                )
                audit("Brute-force threshold reached", f"IP {client_ip()}")
                db.session.commit()
            flash("Invalid username or password.", "danger")
        return render_template("login.html", setup_required=Admin.query.count() == 0)

    @blueprint.get("/logout")
    @login_required
    def logout() -> Any:
        audit("Administrator signed out")
        db.session.commit()
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("auth.login"))

    app.register_blueprint(blueprint)
