"""Intentionally imperfect, synthetic-data learning API. Bind only to loopback."""
import os
import secrets
import time
from functools import wraps
from flask import Flask, jsonify, request, g, Response
import jwt

USERS = {"alice": "alice-lab-only", "bob": "bob-lab-only"}
OBJECTS = {101: {"id": 101, "owner": "alice", "note": "Synthetic Alice notebook"},
           202: {"id": 202, "owner": "bob", "note": "Synthetic Bob notebook"}}

def create_app():
    app = Flask(__name__)
    # New ephemeral secret on each restart; never used outside this learning lab.
    app.config.update(JWT_SECRET=secrets.token_hex(32), CORS_MODE=os.getenv("LAB_CORS_MODE", "reflect"))
    buckets = {}

    def authenticated(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            value = request.headers.get("Authorization", "")
            if not value.startswith("Bearer "):
                return jsonify(error="Authentication required"), 401
            try:
                claims = jwt.decode(value[7:], app.config["JWT_SECRET"], algorithms=["HS256"],
                    issuer="api-toolkit-local-lab", audience="api-toolkit-learners",
                    options={"require": ["exp", "iat", "sub", "iss", "aud"]})
                if claims["sub"] not in USERS:
                    raise jwt.InvalidTokenError()
                g.subject = claims["sub"]
            except jwt.PyJWTError:
                return jsonify(error="Invalid or expired token"), 401
            return fn(*args, **kwargs)
        return wrapped

    @app.get("/api/public")
    def public():
        return jsonify(message="Public synthetic learning data")

    @app.post("/api/login")
    def login():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(error="JSON object required"), 400
        user = data.get("username")
        if not isinstance(user, str) or user not in USERS or data.get("password") != USERS[user]:
            return jsonify(error="Invalid lab credentials"), 401
        now = int(time.time())
        token = jwt.encode({"sub": user, "iss": "api-toolkit-local-lab", "aud": "api-toolkit-learners",
                            "iat": now, "exp": now + 3600}, app.config["JWT_SECRET"], algorithm="HS256")
        return jsonify(token=token)

    @app.get("/api/me")
    @authenticated
    def me():
        return jsonify(sub=g.subject)

    @app.get("/api/protected")
    @authenticated
    def protected():
        return jsonify(message="Private synthetic data", user=g.subject)

    @app.get("/api/auth-missing")
    def auth_missing():
        # Intentional: documentation requires auth, but this function does not.
        return jsonify(message="Synthetic private notice exposed without login")

    @app.get("/api/objects/<int:object_id>")
    @authenticated
    def vulnerable_object(object_id):
        # Intentional BOLA: authenticates but does not compare owner with subject.
        if object_id not in OBJECTS:
            return jsonify(error="Not found"), 404
        return jsonify(OBJECTS[object_id])

    @app.get("/api/safe-objects/<int:object_id>")
    @authenticated
    def safe_object(object_id):
        obj = OBJECTS.get(object_id)
        if obj is None or obj["owner"] != g.subject:
            return jsonify(error="Not found"), 404
        return jsonify(obj)

    @app.get("/api/search")
    def search():
        return jsonify(query=request.args.get("q", ""), limit=request.args.get("limit", "5"), results=[])

    @app.get("/api/cors")
    @authenticated
    def cors():
        return jsonify(message="Synthetic CORS data", user=g.subject)

    @app.get("/api/html")
    def html():
        # Intentionally missing browser hardening headers.
        return "<!doctype html><title>Local lab</title><h1>Synthetic learning page</h1>"

    @app.get("/api/limited")
    def limited():
        # Three requests per client IP per 30s fixed window; only in-memory lab state.
        now = time.monotonic()
        key = request.remote_addr
        start, count = buckets.get(key, (now, 0))
        if now - start >= 30:
            start, count = now, 0
        count += 1
        buckets[key] = (start, count)
        if count > 3:
            response = jsonify(error="Lab request quota exceeded")
            response.status_code = 429
            response.headers["Retry-After"] = str(max(1, int(30 - (now - start))))
            return response
        return jsonify(message="Within lab quota", remaining=3-count)

    @app.get("/openapi.json")
    def openapi_spec():
        from pathlib import Path
        spec_path = Path(__file__).resolve().parent.parent / "input" / "openapi.json"
        if spec_path.is_file():
            return Response(spec_path.read_text(encoding="utf-8"), mimetype="application/json")
        return jsonify(error="OpenAPI spec not found"), 404

    @app.after_request
    def cors_headers(response):
        if request.path == "/api/cors":
            origin = request.headers.get("Origin")
            mode = app.config["CORS_MODE"]
            if mode == "reflect" and origin:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
            elif mode == "wildcard":
                response.headers["Access-Control-Allow-Origin"] = "*"
            elif mode == "strict" and origin == "http://127.0.0.1:8000":
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
            if response.headers.get("Access-Control-Allow-Origin"):
                response.headers["Vary"] = "Origin"
                response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        return response
    return app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=False)
