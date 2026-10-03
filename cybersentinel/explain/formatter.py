from cybersentinel.models import ThreatResult


def format_result(result: ThreatResult) -> str:
    """Format a ThreatResult for human-readable display."""

    return (
        "CyberSentinel Py\n"
        "----------------\n"
        f"Score: {result.score}\n"
        f"Threat: {result.threat_level}\n"
        "\n"
        "Why:\n"
        f"{result.explanation}\n"
        "\n"
        "Recommendation:\n"
        f"{result.recommendation}"
    )