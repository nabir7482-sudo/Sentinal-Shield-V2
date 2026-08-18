"""Fixtures for a disposable SentinelShield application and administrator."""

from __future__ import annotations

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from database.database import db, initialise_defaults
from database.models import Admin
from middleware.security_middleware import rate_detector


@pytest.fixture()
def app():
    application = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "SECRET_KEY": "test-session-secret-not-for-production",
        "LAB_MODE": True,
    })
    with application.app_context():
        db.drop_all()
        db.create_all()
        initialise_defaults()
        db.session.add(Admin(username="testadmin", password_hash=generate_password_hash("CorrectHorseBatteryStaple")))
        db.session.commit()
        yield application
        db.session.remove()
        db.drop_all()
    rate_detector.clear_ip("127.0.0.1")


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client) -> str:
    client.get("/login")
    with client.session_transaction() as state:
        return state["csrf_token"]


@pytest.fixture()
def logged_client(client):
    token = csrf(client)
    response = client.post("/login", data={
        "username": "testadmin",
        "password": "CorrectHorseBatteryStaple",
        "csrf_token": token,
    })
    assert response.status_code == 302
    return client
