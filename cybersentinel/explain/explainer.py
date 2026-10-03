from cybersentinel.models import Indicator


def explain_indicators(indicators: list[Indicator]) -> str:
    """Turn detected indicators into a human-readable explanation."""

    if not indicators:
        return "No security indicators were detected."

    lines = []

    for indicator in indicators:
        lines.append(
            f"• {indicator.description} (+{indicator.points})"
        )

    return "\n".join(lines)