import os


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Config:
    BLOCKED_IPS = _csv(os.getenv("WAF_BLOCKED_IPS", "192.168.1.100,10.0.0.5"))
    RATE_LIMIT = int(os.getenv("WAF_RATE_LIMIT", "60"))
    RATE_WINDOW = int(os.getenv("WAF_RATE_WINDOW", "60"))
    MAX_BODY_SIZE = int(os.getenv("WAF_MAX_BODY_SIZE", "1048576"))
