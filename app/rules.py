import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    pattern: re.Pattern[str]
    severity: str


RULES = [
    Rule("SQLI-001", "sql-injection", re.compile(
        r"(union(?:\s+all)?\s+select|or\s+1=1|drop\s+table|information_schema|sleep\s*\()",
        re.I,
    ), "high"),
    Rule("XSS-001", "xss", re.compile(
        r"(<script\b|javascript:|onerror\s*=|onload\s*=|<iframe\b)",
        re.I,
    ), "high"),
    Rule("TRAV-001", "path-traversal", re.compile(
        r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
        re.I,
    ), "high"),
    Rule("CMD-001", "command-injection", re.compile(
        r"(;\s*(?:cat|id|whoami|curl|wget)|\|\s*(?:sh|bash)|&&\s*(?:cat|id|whoami))",
        re.I,
    ), "critical"),
    Rule("SSTI-001", "template-injection", re.compile(
        r"(\{\{.*\}\}|<%.*%>)",
        re.I,
    ), "high"),
]


def inspect_text(value: str):
    findings = []
    for rule in RULES:
        if rule.pattern.search(value):
            findings.append({
                "rule_id": rule.rule_id,
                "category": rule.category,
                "severity": rule.severity,
            })
    return findings
