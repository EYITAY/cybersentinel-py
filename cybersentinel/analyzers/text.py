import re

from cybersentinel.models import Indicator, ThreatResult
from cybersentinel.scoring import calculate_score, get_threat_level


class TextAnalyzer:
    """Analyze text for basic security indicators."""

    def analyze(self, text: str) -> ThreatResult:
        indicators = []

        # TEXT001: Urgent language
        if re.search(r"\b(urgent|immediately|act now|within 24 hours)\b", text, re.IGNORECASE):
            indicators.append(
                Indicator(
                    rule_id="TEXT001",
                    name="Urgent language",
                    description="The text uses language intended to create urgency.",
                    points=10,
                    evidence="urgent_language_present",
                )
            )

        # TEXT002: Credential request
        if re.search(r"\b(password|passcode|login credentials|verification code)\b", text, re.IGNORECASE):
            indicators.append(
                Indicator(
                    rule_id="TEXT002",
                    name="Credential request",
                    description="The text references passwords, credentials, or verification codes.",
                    points=20,
                    evidence="credential_reference_present",
                )
            )

        # TEXT003: Suspicious link instruction
        if re.search(r"\b(click here|click the link|verify your account)\b", text, re.IGNORECASE):
            indicators.append(
                Indicator(
                    rule_id="TEXT003",
                    name="Suspicious link instruction",
                    description="The text asks the recipient to click a link or verify an account.",
                    points=15,
                    evidence="link_instruction_present",
                )
            )

        score = calculate_score(indicators)
        threat_level = get_threat_level(score)

        if indicators:
            explanation = "\n".join(
                f"• {indicator.description} (+{indicator.points})"
                for indicator in indicators
            )
        else:
            explanation = "No security indicators were detected."

        return ThreatResult(
            input_type="TEXT",
            score=score,
            threat_level=threat_level,
            indicators=indicators,
            explanation=explanation,
            recommendation=(
                "Verify unexpected requests independently before sharing "
                "credentials or clicking links."
            ),
        )