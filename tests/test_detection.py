from detection.detector import RequestDetector, normalize
from detection.severity import adjusted_confidence, calculate_severity


def test_normal_text_is_not_detected():
    assert RequestDetector().analyze("category=select your preferred book").detected is False


def test_sql_injection_indicator_is_high_confidence():
    result = RequestDetector().analyze("q=training UNION SELECT marker")
    assert result.detected is True
    assert result.category == "SQL Injection"
    assert result.matched_rule == "SQLI-001"
    assert result.severity == "HIGH"
    assert result.confidence >= 0.9


def test_xss_and_encoded_normalization():
    assert "<script>" in normalize("%253Cscript%253Etraining%253C/script%253E")
    result = RequestDetector().analyze("%3Cscript%3Etraining%3C/script%3E")
    assert result.category == "Cross-Site Scripting"
    assert result.severity == "HIGH"


def test_path_traversal_detection():
    result = RequestDetector().analyze("/files/..%2F..%2Ftraining.txt")
    assert result.detected and result.category == "Path Traversal"
    assert result.matched_rule == "TRAVERSAL-001"


def test_command_injection_indicator_detection_only():
    result = RequestDetector().analyze("check=;whoami")
    assert result.detected and result.category == "Command Injection"
    assert result.matched_rule == "CMD-001"


def test_deterministic_severity_and_confidence():
    assert calculate_severity([0.4], {"Suspicious HTTP Request"}) == "LOW"
    assert calculate_severity([0.7], {"Suspicious HTTP Request"}) == "MEDIUM"
    assert calculate_severity([0.92], {"SQL Injection"}) == "HIGH"
    assert calculate_severity([0.9, 0.91], {"SQL Injection", "Cross-Site Scripting"}) == "CRITICAL"
    assert adjusted_confidence([0.7, 0.9], {"A", "B"}) == 0.94
