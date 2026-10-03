from urllib.parse import urlparse

from cybersentinel.models import Indicator, ThreatResult
from cybersentinel.scoring import calculate_score, get_threat_level
from cybersentinel.explain import explain_indicators

class URLAnalyzer:
    """Analyze a URL for basic security indicators."""

    def analyze(self, url: str) -> ThreatResult:
        parsed = urlparse(url)

        # Validate basic URL structure
        if not parsed.scheme or not parsed.netloc:
            return ThreatResult(
                input_type="URL",
                score=0,
                threat_level="LOW",
                indicators=[],
                explanation="The input does not appear to be a valid URL.",
                recommendation="Provide a complete URL such as https://example.com.",
            )

        indicators = []

        # URL001: HTTP instead of HTTPS
        if parsed.scheme.lower() == "http":
            indicators.append(
                Indicator(
                    rule_id="URL001",
                    name="HTTP transport",
                    description="The URL uses HTTP instead of HTTPS.",
                    points=15,
                    evidence="scheme=http",
                )
            )

        # URL002: IP address used as the host
        if parsed.hostname:
            hostname_parts = parsed.hostname.split(".")

            if len(hostname_parts) == 4 and all(
                part.isdigit() for part in hostname_parts
            ):
                indicators.append(
                    Indicator(
                        rule_id="URL002",
                        name="IP address host",
                        description="The URL uses an IP address instead of a domain name.",
                        points=20,
                        evidence=f"host={parsed.hostname}",
                    )
                )

        # URL003: Username or password embedded in the URL
        if parsed.username or parsed.password:
            indicators.append(
                Indicator(
                    rule_id="URL003",
                    name="Embedded credentials",
                    description="The URL contains a username or password before the host.",
                    points=25,
                    evidence="userinfo_present",
                )
            )

        # URL004: Percent-encoded characters
        if "%" in url:
            indicators.append(
                Indicator(
                    rule_id="URL004",
                    name="Encoded URL characters",
                    description="The URL contains percent-encoded characters.",
                    points=10,
                    evidence="percent_encoding_present",
                )
            )

        # URL005: Suspiciously long URL
        if len(url) > 200:
            indicators.append(
                Indicator(
                    rule_id="URL005",
                    name="Unusually long URL",
                    description="The URL is unusually long and may contain obfuscated or excessive data.",
                    points=10,
                    evidence=f"url_length={len(url)}",
                )
            )

        # URL006: Non-standard port
        if parsed.port is not None and parsed.port not in (80, 443):
            indicators.append(
                Indicator(
                    rule_id="URL006",
                    name="Non-standard port",
                    description="The URL uses a port other than the standard HTTP or HTTPS ports.",
                    points=10,
                    evidence=f"port={parsed.port}",
                )
            )

        # URL007: Unexpected URL scheme
        if parsed.scheme.lower() not in ("http", "https"):
            indicators.append(
                Indicator(
                    rule_id="URL007",
                    name="Unexpected URL scheme",
                    description="The URL uses a scheme other than HTTP or HTTPS.",
                    points=15,
                    evidence=f"scheme={parsed.scheme}",
                )
            )

        # Calculate score using the centralized scoring engine
        score = calculate_score(indicators)
        threat_level = get_threat_level(score)

        # Return standardized result
        return ThreatResult(
            input_type="URL",
            score=score,
            threat_level=threat_level,
            indicators=indicators,
            explanation=explain_indicators(indicators),
            recommendation="Use HTTPS and verify the destination before entering sensitive information.",
        )