from dataclasses import dataclass, field


@dataclass
class Indicator:
    """A single security signal detected by an analyzer."""

    rule_id: str
    name: str
    description: str
    points: int
    evidence: str = ""


@dataclass
class ThreatResult:
    """Standard result returned by CyberSentinel analyzers."""

    input_type: str
    score: int
    threat_level: str
    indicators: list[Indicator] = field(default_factory=list)
    explanation: str = ""
    recommendation: str = ""