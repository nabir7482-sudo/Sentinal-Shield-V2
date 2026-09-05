"""SentinelShield application entry point and local admin setup commands."""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Any

import click
from flask import Flask, render_template
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash

from config import Config
from database.database import db, initialise_defaults, upgrade_event_schema
from database.models import Admin
from middleware.security_middleware import register_security
from routes.auth import csrf_token, register_auth_routes


def _configure_logging(app: Flask) -> None:
    """Write operational metadata to bounded rotating files, never request bodies."""
    log_path = app.config["LOG_PATH"]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(formatter)
    security_logger = logging.getLogger("sentinelshield")
    security_logger.setLevel(logging.INFO)
    security_logger.handlers.clear()
    security_logger.addHandler(handler)
    security_logger.propagate = False


def _bootstrap_admin_from_environment(app: Flask) -> None:
    """Optionally provision first local admin from intentionally supplied environment values."""
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")
    if username and password and Admin.query.count() == 0:
        db.session.add(Admin(username=username[:64], password_hash=generate_password_hash(password)))
        db.session.commit()
        logging.getLogger("sentinelshield").info("Initial administrator created from environment configuration")


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Build the Flask application with database, security controls, and routes."""
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=app.config["TRUSTED_PROXY_COUNT"],
        x_proto=app.config["TRUSTED_PROXY_COUNT"],
        x_host=app.config["TRUSTED_PROXY_COUNT"],
        x_port=app.config["TRUSTED_PROXY_COUNT"],
        x_prefix=app.config["TRUSTED_PROXY_COUNT"],
    )
    _configure_logging(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()
        upgrade_event_schema()
        initialise_defaults()
        _bootstrap_admin_from_environment(app)

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.context_processor
    def inject_template_values() -> dict[str, Any]:
        from flask import session

        return {"admin_username": session.get("admin_username")}

    register_security(app)
    register_auth_routes(app)

    from routes.blocked_ips import blueprint as blocked_ips_blueprint
    from routes.dashboard import blueprint as dashboard_blueprint
    from routes.events import blueprint as events_blueprint
    from routes.lab import blueprint as lab_blueprint
    from routes.logs import blueprint as logs_blueprint
    from routes.reports import blueprint as reports_blueprint
    from routes.settings import blueprint as settings_blueprint

    app.register_blueprint(dashboard_blueprint)
    app.register_blueprint(events_blueprint)
    app.register_blueprint(logs_blueprint)
    app.register_blueprint(blocked_ips_blueprint)
    app.register_blueprint(reports_blueprint)
    app.register_blueprint(settings_blueprint)
    app.register_blueprint(lab_blueprint)

    @app.errorhandler(400)
    def bad_request(_: Any) -> tuple[str, int]:
        return render_template("error.html", code=400, title="Invalid request", message="The request could not be processed safely."), 400

    @app.errorhandler(403)
    def forbidden(_: Any) -> tuple[str, int]:
        return render_template("error.html", code=403, title="Request blocked", message="SentinelShield blocked this request to protect the application."), 403

    @app.errorhandler(404)
    def not_found(_: Any) -> tuple[str, int]:
        return render_template("error.html", code=404, title="Page not found", message="The page you requested does not exist."), 404

    @app.errorhandler(429)
    def too_many_requests(_: Any) -> tuple[str, int]:
        return render_template("error.html", code=429, title="Rate limit reached", message="This request rate exceeded the configured safety limit. Please try again shortly."), 429

    @app.errorhandler(RequestEntityTooLarge)
    def upload_too_large(_: Any) -> tuple[str, int]:
        return render_template("error.html", code=413, title="Upload too large", message="Uploaded files must be no larger than 1 MiB."), 413

    @app.errorhandler(500)
    def internal_error(_: Any) -> tuple[str, int]:
        db.session.rollback()
        return render_template("error.html", code=500, title="Server error", message="An unexpected error occurred. The incident has been logged."), 500

    @app.cli.command("init-admin")
    @click.option("--username", prompt=True, help="Local administrator username")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Administrator password")
    def init_admin(username: str, password: str) -> None:
        """Create the first admin without placing credentials in source code."""
        username = username.strip()
        if not 3 <= len(username) <= 64:
            raise click.ClickException("Username must contain 3–64 characters.")
        if len(password) < 12:
            raise click.ClickException("Use a password with at least 12 characters.")
        if Admin.query.filter_by(username=username).first():
            raise click.ClickException("That administrator username already exists.")
        db.session.add(Admin(username=username, password_hash=generate_password_hash(password)))
        db.session.commit()
        click.echo("Administrator created. You can now sign in at /login.")

    logging.getLogger("sentinelshield").info("SentinelShield application started")
    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

