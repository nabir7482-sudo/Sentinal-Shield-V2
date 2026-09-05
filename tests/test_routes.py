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


def test_ai_investigation_chat_verdict_and_reports(app, logged_client):
    token = csrf(logged_client)
    response = logged_client.post("/lab/test-request", data={
        "csrf_token": token, "test_value": "' OR 1=1 --"
    })
    assert response.status_code == 200
    with app.app_context():
        event = SecurityEvent.query.one()
        event_id = event.id
    investigation = logged_client.get(f"/investigate/{event_id}")
    assert investigation.status_code == 200
    assert b"1. Monitoring &amp; log analysis" in investigation.data
    assert b"4. Containment &amp; mitigation" in investigation.data
    assert b"6. Incident reporting" in investigation.data
    chat = logged_client.post("/ai-chat", data={"csrf_token": token, "question": "show all SQLi from last hour"})
    assert chat.status_code == 200
    assert chat.get_json()["count"] == 1
    assert logged_client.get("/api/logs").get_json()["format"] == "SIEM"
    verdict = logged_client.post(f"/events/{event_id}/verdict", data={"csrf_token": token, "analyst_verdict": "True Positive"})
    assert verdict.status_code == 302
    assert logged_client.get("/generate_report").mimetype == "application/pdf"
