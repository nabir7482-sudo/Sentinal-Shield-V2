"""Deterministic severity decisions shared by all detection paths."""

from __future__ import annotations


def calculate_severity(confidences: list[float], categories: set[str], repeat_count: int = 0) -> str:
    """Classify by signal strength, correlation, and repetition—not chance."""
    if not confidences:
        return "LOW"
    strongest = max(confidences)
    if len(categories) >= 2 or (strongest >= 0.9 and repeat_count >= 3):
        return "CRITICAL"
    if strongest >= 0.8:
        return "HIGH"
    if strongest >= 0.6 or repeat_count >= 1:
        return "MEDIUM"
    return "LOW"


def adjusted_confidence(confidences: list[float], categories: set[str]) -> float:
    """Combine corroborating signatures while keeping the result in [0, 1]."""
    if not confidences:
        return 0.0
    confidence = max(confidences)
    if len(categories) > 1:
        confidence = min(0.99, confidence + 0.04 * (len(categories) - 1))
    return round(confidence, 2)
