from detection.rate_detector import RateDetector


def test_request_rate_threshold_and_first_alert():
    detector = RateDetector()
    assert detector.check_request("192.168.1.10", 2).exceeded is False
    assert detector.check_request("192.168.1.10", 2).exceeded is False
    check = detector.check_request("192.168.1.10", 2)
    assert check.exceeded is True
    assert check.first_exceedance is True
    assert detector.check_request("192.168.1.10", 2).first_exceedance is False


def test_brute_force_threshold():
    detector = RateDetector()
    for _ in range(4):
        assert detector.record_login_failure("127.0.0.1", 5, 60).exceeded is False
    check = detector.record_login_failure("127.0.0.1", 5, 60)
    assert check.exceeded is True
    assert check.first_exceedance is True
