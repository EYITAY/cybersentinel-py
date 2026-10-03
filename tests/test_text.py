from cybersentinel.analyzers.text import TextAnalyzer


def test_clean_text():
    analyzer = TextAnalyzer()

    result = analyzer.analyze(
        "The team meeting is scheduled for tomorrow at 10 AM."
    )

    assert result.score == 0
    assert result.threat_level == "LOW"
    assert result.indicators == []


def test_urgent_language():
    analyzer = TextAnalyzer()

    result = analyzer.analyze(
        "URGENT: Please act immediately."
    )

    assert result.score == 10
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "TEXT001"


def test_credential_request():
    analyzer = TextAnalyzer()

    result = analyzer.analyze(
        "Please enter your password and verification code."
    )

    assert result.score == 20
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "TEXT002"


def test_suspicious_link_instruction():
    analyzer = TextAnalyzer()

    result = analyzer.analyze(
        "Click here to verify your account."
    )

    assert result.score == 15
    assert result.threat_level == "LOW"
    assert result.indicators[0].rule_id == "TEXT003"


def test_combined_text_indicators():
    analyzer = TextAnalyzer()

    result = analyzer.analyze(
        "URGENT: Click here immediately to verify your account. "
        "Enter your password and verification code."
    )

    assert result.score == 45
    assert result.threat_level == "MEDIUM"
    assert len(result.indicators) == 3