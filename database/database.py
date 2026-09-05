"""SQLAlchemy setup and small configuration helpers."""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

from config import DEFAULT_SETTINGS

db = SQLAlchemy()


def upgrade_event_schema() -> None:
    """Add SOC metadata columns to databases created by earlier versions."""
    if db.engine.dialect.name != "sqlite":
        return
    columns = {column["name"] for column in inspect(db.engine).get_columns("security_event")}
    additions = {
        "payload_preview": "TEXT NOT NULL DEFAULT ''",
        "country": "VARCHAR(64) NOT NULL DEFAULT 'Unknown'",
        "analyst_verdict": "VARCHAR(20) NOT NULL DEFAULT 'Pending'",
        "mitre_attack": "VARCHAR(16) NOT NULL DEFAULT 'T1190'",
    }
    for name, definition in additions.items():
        if name not in columns:
            db.session.execute(text(f'ALTER TABLE security_event ADD COLUMN {name} {definition}'))
    db.session.commit()


def initialise_defaults() -> None:
    """Create the persisted settings only when they do not exist."""
    from database.models import AppConfiguration

    existing = {item.key for item in AppConfiguration.query.all()}
    changed = False
    for key, value in DEFAULT_SETTINGS.items():
        if key not in existing:
            db.session.add(AppConfiguration(key=key, value=value))
            changed = True
    if changed:
        db.session.commit()


def settings() -> dict[str, str]:
    """Return persisted settings merged with safe defaults."""
    from database.models import AppConfiguration

    values = DEFAULT_SETTINGS.copy()
    values.update({item.key: item.value for item in AppConfiguration.query.all()})
    return values


def setting_int(key: str) -> int:
    return int(settings()[key])


def setting_bool(key: str) -> bool:
    return settings()[key].lower() == "true"
