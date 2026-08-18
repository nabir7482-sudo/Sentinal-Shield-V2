"""Input normalization and rule evaluation for SentinelShield."""

from __future__ import annotations

from dataclasses import dataclass
import html
import unicodedata
from urllib.parse import unquote_plus

from detection.rules import RULES, DetectionRule
from detection.severity import adjusted_confidence, calculate_severity


@dataclass(frozen=True)
class DetectionResult:
    detected: bool
    category: str | None = None
    severity: str | None = None
    confidence: float = 0.0
    reason: str | None = None
    matched_rule: str | None = None
    matched_rules: tuple[DetectionRule, ...] = ()

    def as_dict(self, source_ip: str | None = None) -> dict[str, object]:
        data: dict[str, object] = {
            "detected": self.detected,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
        }
        if source_ip:
            data["source_ip"] = source_ip
        return data


def normalize(value: str) -> str:
    """Decode common encodings a few times, bounded to prevent resource abuse."""
    text = unicodedata.normalize("NFKC", str(value))[:8192]
    for _ in range(3):
        decoded = html.unescape(unquote_plus(text))
        if decoded == text:
            break
        text = decoded
    return text.lower()


class RequestDetector:
    """Evaluate request text against transparent, static detection rules."""

    def analyze(
        self, value: str, repeat_count: int = 0, sensitivity: str = "standard"
    ) -> DetectionResult:
        normalized = normalize(value)
        matches = tuple(rule for rule in RULES if rule.pattern.search(normalized))
        if sensitivity == "conservative":
            # Low-confidence reconnaissance signatures are logged only in the
            # standard/sensitive profiles; high-confidence exploit indicators remain.
            matches = tuple(rule for rule in matches if rule.confidence >= 0.8)
        if not matches:
            return DetectionResult(detected=False)
        categories = {rule.category for rule in matches}
        confidence = adjusted_confidence([rule.confidence for rule in matches], categories)
        if sensitivity == "sensitive":
            confidence = min(0.99, round(confidence + 0.04, 2))
        severity = calculate_severity([rule.confidence for rule in matches], categories, repeat_count)
        primary = max(matches, key=lambda rule: rule.confidence)
        reason = primary.reason
        if len(matches) > 1:
            reason += f" {len(matches)} correlated rules matched."
        return DetectionResult(
            detected=True,
            category=primary.category,
            severity=severity,
            confidence=confidence,
            reason=reason,
            matched_rule=primary.rule_id,
            matched_rules=matches,
        )
