import json
from flask import request

from .rate_limiter import RateLimiter
from .rules import inspect_text


class WAF:
    def __init__(self, blocked_ips, rate_limit, rate_window):
        self.blocked_ips = blocked_ips
        self.rate_limiter = RateLimiter(rate_limit, rate_window)

    def inspect_request(self):
        client_ip = request.remote_addr or "unknown"

        if client_ip in self.blocked_ips:
            return {
                "blocked": True,
                "reason": "ip-reputation",
                "findings": [{
                    "rule_id": "IP-001",
                    "category": "blocked-ip",
                    "severity": "high",
                }],
            }

        if not self.rate_limiter.allowed(client_ip):
            return {
                "blocked": True,
                "reason": "rate-limit",
                "findings": [{
                    "rule_id": "RATE-001",
                    "category": "rate-limit",
                    "severity": "medium",
                }],
            }

        pieces = [
            request.full_path,
            request.query_string.decode("utf-8", errors="ignore"),
            request.headers.get("User-Agent", ""),
        ]
        if request.data:
            pieces.append(request.data.decode("utf-8", errors="ignore"))

        payload = request.get_json(silent=True)
        if payload is not None:
            pieces.append(json.dumps(payload, default=str))

        findings = []
        seen = set()
        for finding in inspect_text(" ".join(pieces)):
            if finding["rule_id"] not in seen:
                findings.append(finding)
                seen.add(finding["rule_id"])

        return {
            "blocked": bool(findings),
            "reason": "rule-match" if findings else "allowed",
            "findings": findings,
        }
