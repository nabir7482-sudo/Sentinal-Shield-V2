"""Database models used by the defensive monitoring application."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database.database import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Admin(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityEvent(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    http_method: Mapped[str] = mapped_column(String(12), nullable=False)
    request_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(12), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    action_taken: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "http_method": self.http_method,
            "request_path": self.request_path,
            "user_agent": self.user_agent,
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "description": self.description,
            "action_taken": self.action_taken,
            "status": self.status,
        }


class BlockedIP(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        expires_at = self.expires_at
        if expires_at.tzinfo is None:  # SQLite returns naive values by default.
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return self.active and expires_at > now

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "active": self.is_active(),
        }


class AppConfiguration(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    value: Mapped[str] = mapped_column(String(128), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AuditLog(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False, default="")
