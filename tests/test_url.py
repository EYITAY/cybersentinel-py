from cybersentinel.analyzers.url import URLAnalyzer
from cybersentinel.models import Indicator
from cybersentinel.scoring import calculate_score, get_threat_level


def test_https_url_is_low():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("https://www.google.com")

    assert result.score == 0
    assert result.threat_level == "LOW"


def test_http_url_gets_url001():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("http://www.google.com")

    assert result.score == 15
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "URL001"


def test_ip_address_gets_url002():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("https://192.168.1.10/login")

    assert result.score == 20
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "URL002"


def test_embedded_credentials_get_url003():
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "https://admin:password@example.com/login"
    )

    assert result.score == 25
    assert result.threat_level == "MEDIUM"
    assert result.indicators[0].rule_id == "URL003"


def test_percent_encoding_gets_url004():
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "https://example.com/%6c%6f%67%69%6e"
    )

    assert result.score == 10
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "URL004"


def test_multiple_indicators_are_combined():
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "http://192.168.1.10/login"
    )

    assert result.score == 35
    assert result.threat_level == "MEDIUM"
    assert len(result.indicators) == 2


def test_long_url_gets_url005():
    analyzer = URLAnalyzer()

    long_url = "https://example.com/" + ("a" * 201)

    result = analyzer.analyze(long_url)

    assert result.score == 10
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "URL005"


def test_non_standard_port_gets_url006():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("https://example.com:8080/login")

    assert result.score == 10
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "URL006"


def test_unexpected_url_scheme_gets_url007():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("ftp://example.com/login")

    assert result.score == 15
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "URL007"


def test_multiple_high_risk_indicators():
    analyzer = URLAnalyzer()

    result = analyzer.analyze(
        "http://admin:password@192.168.1.10:8080/"
    )

    assert result.score == 70
    assert result.threat_level == "HIGH"
    assert len(result.indicators) == 4


def test_normal_https_url_has_no_indicators():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("https://www.google.com")

    assert result.score == 0
    assert result.threat_level == "LOW"
    assert len(result.indicators) == 0


def test_standard_https_port_is_not_flagged():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("https://example.com:443/login")

    assert result.score == 0
    assert result.threat_level == "LOW"
    assert len(result.indicators) == 0


def test_url_under_length_threshold_is_not_flagged():
    analyzer = URLAnalyzer()

    url = "https://example.com/" + ("a" * 100)

    result = analyzer.analyze(url)

    assert result.score == 0
    assert result.threat_level == "LOW"
    assert len(result.indicators) == 0


def test_low_score_boundary():
    indicator = Indicator(
        rule_id="TEST001",
        name="Test",
        description="Test indicator",
        points=24,
    )

    score = calculate_score([indicator])

    assert score == 24
    assert get_threat_level(score) == "LOW"


def test_medium_score_boundary():
    indicator = Indicator(
        rule_id="TEST002",
        name="Test",
        description="Test indicator",
        points=25,
    )

    score = calculate_score([indicator])

    assert score == 25
    assert get_threat_level(score) == "MEDIUM"


def test_high_score_boundary():
    indicator = Indicator(
        rule_id="TEST003",
        name="Test",
        description="Test indicator",
        points=50,
    )

    score = calculate_score([indicator])

    assert score == 50
    assert get_threat_level(score) == "HIGH"


def test_critical_score_boundary():
    indicator = Indicator(
        rule_id="TEST004",
        name="Test",
        description="Test indicator",
        points=75,
    )

    score = calculate_score([indicator])

    assert score == 75
    assert get_threat_level(score) == "CRITICAL"


def test_invalid_url_returns_low_result():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("not-a-url")

    assert result.score == 0
    assert result.threat_level == "LOW"
    assert len(result.indicators) == 0
    assert "not appear to be a valid URL" in result.explanation


def test_missing_host_returns_low_result():
    analyzer = URLAnalyzer()

    result = analyzer.analyze("http://")

    assert result.score == 0
    assert result.threat_level == "LOW"
    assert len(result.indicators) == 0
    assert "not appear to be a valid URL" in result.explanation