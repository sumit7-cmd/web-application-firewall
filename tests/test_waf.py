import json

import pytest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app


class TestConfig:
    TESTING = True
    BLOCKED_IPS = ["192.168.1.100"]
    RATE_LIMIT = 3
    RATE_WINDOW = 60
    MAX_BODY_SIZE = 100


@pytest.fixture()
def client():
    return create_app(TestConfig).test_client()


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "healthy"


def test_blocks_ip(client):
    response = client.get("/data", environ_base={"REMOTE_ADDR": "192.168.1.100"})
    assert response.status_code == 403
    assert response.json["reason"] == "ip-reputation"


@pytest.mark.parametrize("payload", [
    "/data?id=1%20UNION%20SELECT%20username%20FROM%20users",
    "/data?q=<script>alert(1)</script>",
    "/data?file=../../etc/passwd",
])
def test_blocks_attack_patterns(client, payload):
    response = client.get(payload)
    assert response.status_code == 403
    assert response.json["reason"] == "rule-match"


def test_allows_normal_traffic(client):
    response = client.get("/data?q=hello")
    assert response.status_code == 200


def test_rate_limit(client):
    base = {"REMOTE_ADDR": "203.0.113.10"}
    assert client.get("/data", environ_base=base).status_code == 200
    assert client.get("/data", environ_base=base).status_code == 200
    assert client.get("/data", environ_base=base).status_code == 200
    assert client.get("/data", environ_base=base).status_code == 403


def test_body_limit(client):
    response = client.post(
        "/echo",
        data=json.dumps({"payload": "x" * 200}),
        content_type="application/json",
    )
    assert response.status_code == 413


def test_security_headers(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
