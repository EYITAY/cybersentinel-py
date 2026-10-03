from cybersentinel.models import Indicator


def calculate_score(indicators: list[Indicator]) -> int:
    """Calculate a bounded security score from detected indicators."""

    score = sum(indicator.points for indicator in indicators)

    return min(score, 100)


def get_threat_level(score: int) -> str:
    """Convert a numeric score into a threat level."""

    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"