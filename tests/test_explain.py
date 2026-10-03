from cybersentinel.models import Indicator, ThreatResult
from cybersentinel.explain import explain_indicators, format_result


def test_explain_indicators():
    indicators = [
        Indicator(
            rule_id="URL001",
            name="HTTP transport",
            description="The URL uses HTTP instead of HTTPS.",
            points=15,
        ),
        Indicator(
            rule_id="URL002",
            name="IP address host",
            description="The URL uses an IP address instead of a domain name.",
            points=20,
        ),
    ]

    explanation = explain_indicators(indicators)

    assert "HTTP instead of HTTPS" in explanation
    assert "IP address" in explanation
    assert "(+15)" in explanation
    assert "(+20)" in explanation


def test_explain_empty_indicators():
    explanation = explain_indicators([])

    assert explanation == "No security indicators were detected."


def test_format_result():
    result = ThreatResult(
        input_type="URL",
        score=35,
        threat_level="MEDIUM",
        indicators=[],
        explanation="The URL uses HTTP instead of HTTPS. (+15)",
        recommendation="Use HTTPS.",
    )

    formatted = format_result(result)

    assert "CyberSentinel Py" in formatted
    assert "Score: 35" in formatted
    assert "Threat: MEDIUM" in formatted
    assert "Why:" in formatted
    assert "Recommendation:" in formatted
    assert "Use HTTPS." in formatted