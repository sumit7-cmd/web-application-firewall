from flask import Blueprint, current_app, jsonify, request

api = Blueprint("api", __name__)


@api.before_request
def waf_middleware():
    waf = current_app.extensions["waf"]

    if request.content_length and request.content_length > current_app.config["MAX_BODY_SIZE"]:
        current_app.logger.warning(
            "security_event=blocked reason=body-too-large ip=%s method=%s path=%s",
            request.remote_addr, request.method, request.path,
        )
        return jsonify({"error": "Request blocked", "reason": "body-too-large"}), 413

    result = waf.inspect_request()

    if result["blocked"]:
        current_app.logger.warning(
            "security_event=blocked reason=%s ip=%s method=%s path=%s findings=%s",
            result["reason"], request.remote_addr, request.method,
            request.path, result["findings"],
        )
        return jsonify({
            "error": "Request blocked by WAF",
            "reason": result["reason"],
            "findings": result["findings"],
        }), 403


@api.get("/")
def index():
    return jsonify({
        "service": "Web Application Firewall",
        "status": "online",
        "version": "2.0.0",
    })


@api.get("/health")
def health():
    return jsonify({"status": "healthy"})


@api.get("/data")
def get_data():
    return jsonify({
        "data": "This endpoint is protected by the WAF.",
        "request_id": request.headers.get("X-Request-ID", "not-set"),
    })


@api.post("/echo")
def echo():
    return jsonify({"received": request.get_json(silent=True) or {}})
