"""Conservative, explainable signatures for harmless request inspection."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    confidence: float
    reason: str


def _rule(
    rule_id: str, category: str, expression: str, confidence: float, reason: str
) -> DetectionRule:
    return DetectionRule(rule_id, category, re.compile(expression, re.IGNORECASE), confidence, reason)


# Patterns intentionally require meaningful combinations. A plain word such as
# "select" is not a SQL injection alert.
RULES: tuple[DetectionRule, ...] = (
    _rule("SQLI-001", "SQL Injection", r"\bunion\s+(?:all\s+)?select\b", 0.95,
          "UNION SELECT syntax is commonly used to alter a database query."),
    _rule("SQLI-002", "SQL Injection", r"['\"]\s*(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", 0.92,
          "A quoted Boolean tautology was found in request input."),
    _rule("SQLI-003", "SQL Injection", r"(?:['\"]\s*(?:--|#)|/\*.*?\*/)", 0.83,
          "SQL comment syntax appeared in a query-like context."),
    _rule("SQLI-004", "SQL Injection", r"\binformation_schema\b", 0.90,
          "A database metadata table reference was found."),
    _rule("XSS-001", "Cross-Site Scripting", r"<\s*script\b[^>]*>", 0.96,
          "A script tag was found after decoding request input."),
    _rule("XSS-002", "Cross-Site Scripting", r"\bon[a-z]{3,24}\s*=\s*['\"]?[^\s>]+", 0.87,
          "An inline browser event handler was found in request input."),
    _rule("XSS-003", "Cross-Site Scripting", r"javascript\s*:", 0.91,
          "A javascript: URL scheme was found in request input."),
    _rule("TRAVERSAL-001", "Path Traversal", r"(?:\.\./|\.\.\\)", 0.95,
          "A parent-directory traversal sequence was found."),
    _rule("CMD-001", "Command Injection", r"(?:;|&&|\|\||\||`)\s*(?:whoami|id|uname|cat|curl|wget|ping|sh|bash)\b", 0.91,
          "A shell separator was combined with a command-like token."),
    _rule("CMD-002", "Command Injection", r"\$\(\s*(?:whoami|id|uname|cat|ping)\b", 0.88,
          "Command substitution syntax was combined with a command-like token."),
    _rule("SCAN-001", "Suspicious HTTP Request", r"/(?:\.git(?:/|$)|\.env(?:$|[/?])|phpmyadmin(?:/|$))", 0.67,
          "A sensitive administrative or configuration path was requested."),
)
