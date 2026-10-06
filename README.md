# 🛡️ Web Application Firewall (WAF)

A defensive, rule-based Web Application Firewall built with **Python + Flask**. It demonstrates how an application-layer security control can inspect HTTP requests, detect common malicious patterns, enforce source-IP policy and rate limiting, add security headers, and emit security events suitable for SOC-style monitoring.

## ✨ Features

- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Path traversal detection
- Command injection detection
- Server-side template injection (SSTI) detection
- Configurable IP blocklist
- Per-IP rate limiting
- Request body size protection
- Security response headers
- Security-event logging
- Automated pytest coverage
- Docker / Docker Compose
- GitHub Actions CI

## 🏗️ Architecture

Client → Flask → WAF middleware → Rule Engine / IP Policy / Rate Limiter → Allow or Block → Protected endpoint

## 📁 Project Structure

```text
web-application-firewall/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── logging_config.py
│   ├── rate_limiter.py
│   ├── routes.py
│   ├── rules.py
│   └── waf.py
├── tests/
│   └── test_waf.py
├── .github/workflows/ci.yml
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── LICENSE
├── SECURITY.md
├── requirements.txt
└── main.py
```

## 🚀 Run locally

```bash
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Open **http://127.0.0.1:5000/health**.

## 🐳 Run with Docker

```bash
docker compose up --build
```

## 🧪 Test

```bash
pytest -q
```

## 🔎 Safe demonstrations

Normal request:

```bash
curl "http://127.0.0.1:5000/data?q=hello"
```

XSS detection:

```bash
curl "http://127.0.0.1:5000/data?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

SQL injection detection:

```bash
curl "http://127.0.0.1:5000/data?id=1%20UNION%20SELECT%20username"
```

These examples are intended only for the local demo environment.

## 📊 SOC / Resume Value

The project demonstrates practical concepts relevant to a junior SOC or application-security role: HTTP request inspection, rule-based detections, source-IP blocking, alert generation, security logging, rate limiting, automated testing, and containerized deployment.

## ⚠️ Limitations

This is a learning-focused WAF, not a production replacement for mature WAF platforms. Regex-based rules can create false positives/negatives, the in-memory limiter is not shared across multiple workers, and the project does not yet provide persistent event storage or a full analyst dashboard.

## 🔮 Roadmap

Potential next steps include Redis-backed distributed rate limiting, persistent event storage, Prometheus metrics, an alert dashboard, richer OWASP-aligned detections, reverse-proxy integration with Nginx, and cloud deployment.

## 🔐 Security

See [SECURITY.md](SECURITY.md). Only use this project to protect or test systems you own or have explicit authorization to assess.

## 📄 License

MIT
