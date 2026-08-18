from database.models import SecurityEvent
from tests.conftest import csrf


def test_admin_routes_and_json_apis(app, logged_client):
    for path in ["/", "/events", "/logs", "/blocked-ips", "/reports", "/settings", "/lab/test-request"]:
        assert logged_client.get(path).status_code == 200
    assert logged_client.get("/api/statistics").status_code == 200
    assert logged_client.get("/api/events").get_json() == {"events": []}
    assert logged_client.get("/api/events/999").status_code == 404


def test_local_lab_persists_real_detection_event(app, logged_client):
    token = csrf(logged_client)
    response = logged_client.post("/lab/test-request", data={
        "csrf_token": token, "test_value": "training UNION SELECT marker"
    })
    assert response.status_code == 200
    with app.app_context():
        event = SecurityEvent.query.one()
        assert event.category == "SQL Injection"
        assert event.action_taken == "LOGGED"


def test_sample_log_analysis_creates_events(app, logged_client):
    token = csrf(logged_client)
    response = logged_client.post("/logs/sample", data={"csrf_token": token}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Sample log processed" in response.data
    with app.app_context():
        assert SecurityEvent.query.count() == 4


def test_login_and_logout(client):
    token = csrf(client)
    response = client.post("/login", data={
        "username": "testadmin", "password": "CorrectHorseBatteryStaple", "csrf_token": token
    })
    assert response.status_code == 302
    assert client.get("/logout").status_code == 302
    assert client.get("/api/events").status_code == 401
