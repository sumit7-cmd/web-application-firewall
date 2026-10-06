from flask import Flask

from .config import Config
from .logging_config import configure_logging
from .waf import WAF


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    configure_logging(app)

    app.extensions["waf"] = WAF(
        blocked_ips=set(app.config["BLOCKED_IPS"]),
        rate_limit=app.config["RATE_LIMIT"],
        rate_window=app.config["RATE_WINDOW"],
    )

    from .routes import api
    app.register_blueprint(api)

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

    return app
