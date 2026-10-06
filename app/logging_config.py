import logging


class SecurityEventFilter(logging.Filter):
    def filter(self, record):
        return True


def configure_logging(app):
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    handler.addFilter(SecurityEventFilter())
    handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    ))
    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
