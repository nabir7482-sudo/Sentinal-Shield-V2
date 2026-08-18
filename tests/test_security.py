from database.models import AppConfiguration, BlockedIP, SecurityEvent
from middleware.security_middleware import rate_detector
from tests.conftest import csrf


def test_normal_request_creates_no_security_event(app, client):
    response = client.get("/")
    assert response.status_code == 302
    with app.app_context():
        assert SecurityEvent.query.count() == 0


def test_malicious_request_is_logged_and_blocked(app, client):
    response = client.get("/?q=training%20UNION%20SELECT%20marker")
    assert response.status_code == 403
    with app.app_context():
        event = SecurityEvent.query.one()
        assert event.category == "SQL Injection"
        assert event.action_taken == "BLOCKED"
        assert BlockedIP.query.filter_by(ip_address="127.0.0.1", active=True).count() == 1


def test_brute_force_is_recorded_and_temporary_block_created(app, client):
    rate_detector.clear_login_failures("127.0.0.1")
    token = csrf(client)
    for _ in range(5):
        response = client.post("/login", data={"username": "testadmin", "password": "wrong", "csrf_token": token})
        assert response.status_code == 200
    with app.app_context():
        event = SecurityEvent.query.filter_by(category="Brute Force").one()
        assert event.severity == "HIGH"
        assert event.action_taken == "BLOCKED"
        assert BlockedIP.query.filter_by(ip_address="127.0.0.1", active=True).one().is_active()


def test_security_headers_and_csrf_protection(logged_client):
    response = logged_client.get("/api/events")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    rejected = logged_client.post("/api/blocked-ips/192.168.1.10/unblock")
    assert rejected.status_code == 400


def test_excessive_requests_receive_rate_limit_event(app, client):
    rate_detector.clear_ip("127.0.0.1")
    with app.app_context():
        AppConfiguration.query.filter_by(key="max_requests_per_minute").one().value = "10"
        from database.database import db
        db.session.commit()
    for _ in range(10):
        assert client.get("/").status_code == 302
    response = client.get("/")
    assert response.status_code == 429
    with app.app_context():
        event = SecurityEvent.query.filter_by(rule_id="RATE-001").one()
        assert event.category == "Excessive Requests"
        assert event.action_taken == "RATE_LIMITED"
