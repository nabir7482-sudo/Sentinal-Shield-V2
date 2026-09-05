"""Runtime configuration for SentinelShield."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Safe defaults for the local academic deployment."""

    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentinelshield.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # one MiB log-upload limit
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8
    LAB_MODE = os.getenv("LAB_MODE", "true").lower() == "true"
    LOG_PATH = BASE_DIR / "logs" / "sentinelshield.log"
    SAMPLE_LOG_PATH = BASE_DIR / "sample_data" / "sample_access.log"


DEFAULT_SETTINGS: dict[str, str] = {
    "brute_force_threshold": "5",
    "brute_force_window_seconds": "60",
    "max_requests_per_minute": "100",
    "auto_block_enabled": "true",
    "block_duration_minutes": "30",
    "detection_sensitivity": "standard",
}

