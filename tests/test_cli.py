from cybersentinel.cli import main


def test_cli_with_url(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["cybersentinel", "url", "http://example.com"],
    )

    main()

    output = capsys.readouterr().out

    assert "CyberSentinel Py" in output
    assert "Score: 15" in output
    assert "Threat: LOW" in output
    assert "HTTP instead of HTTPS" in output


def test_cli_with_text(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "cybersentinel",
            "text",
            "URGENT: Click here to verify your account.",
        ],
    )

    main()

    output = capsys.readouterr().out

    assert "CyberSentinel Py" in output
    assert "Score: 25" in output
    assert "Threat: MEDIUM" in output
    assert "urgency" in output
    assert "verify an account" in output


def test_cli_without_arguments(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["cybersentinel"],
    )

    main()

    output = capsys.readouterr().out

    assert "Usage:" in output
    assert 'cybersentinel url "<URL>"' in output
    assert 'cybersentinel text "<TEXT>"' in output


def test_cli_with_invalid_type(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["cybersentinel", "image", "example"],
    )

    main()

    output = capsys.readouterr().out

    assert "Input type must be 'url' or 'text'." in output