"""Generic-target behaviour: capability detection, statuses and a second API.

Proves the toolkit is not hard-coded to the local lab: a different authorized
API with a different authentication structure (API key header) is assessed end
to end, and tests that cannot apply are reported as skipped with a reason.
"""
import json
import threading
import time
from pathlib import Path

import pytest
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from main import parser, run
from web.app import SESSION_HEADER, create_app
from web.jobs import COMPLETED

ROOT = Path(__file__).resolve().parents[1]
API_KEY = "second-api-key-1234567890"

MODULES = ("endpoint_discovery", "openapi_analysis", "parameter_discovery", "method_analysis",
           "auth_analysis", "authorization", "jwt_analysis", "headers_analysis",
           "cors_analysis", "rate_limit")


def session_headers(app):
    return {SESSION_HEADER: app.extensions["session_token"]}


def wait_for(client, job_id, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get("/api/assessment/" + job_id).get_json()
        if body["status"] in ("completed", "failed", "cancelled"):
            return body
        time.sleep(0.2)
    raise AssertionError("assessment did not finish in time")


# --------------------------------------------------------------------- helpers

def write_endpoint_file(tmp_path, entries):
    path = tmp_path / "endpoints.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def offline_coverage(tmp_path, selected):
    """Run the engine offline (no target) and return its coverage block."""
    endpoint_file = write_endpoint_file(tmp_path, ["/things"])
    output = tmp_path / "out"
    args = parser().parse_args(["--endpoints", str(endpoint_file), "--output", str(output)])
    run(args, selected=set(selected))
    return json.loads((output / "evidence.json").read_text())["coverage"]


# ------------------------------------------------------- capability detection

def test_inapplicable_tests_are_skipped_with_reasons(tmp_path):
    coverage = offline_coverage(tmp_path, {
        "endpoint_discovery", "openapi_analysis", "authorization", "jwt_analysis", "rate_limit",
    })
    # endpoint_discovery applies (an endpoint list was supplied); the rest cannot.
    assert coverage["tests_executed"] == ["endpoint_discovery"]
    assert coverage["tests_skipped"] == ["authorization", "jwt_analysis", "openapi_analysis", "rate_limit"]
    reasons = coverage["skip_reasons"]
    assert "OpenAPI" in reasons["openapi_analysis"]
    assert "BOLA" in reasons["authorization"]
    assert "JWT" in reasons["jwt_analysis"]
    assert "rate-limit" in reasons["rate_limit"]
    # Every selected test has an explicit status, and none is falsely executed.
    statuses = {t["key"]: t["status"] for t in coverage["tests"]}
    assert statuses["endpoint_discovery"] == "passed"
    assert statuses["jwt_analysis"] == "skipped"


def test_target_only_tests_are_skipped_without_a_target(tmp_path):
    coverage = offline_coverage(tmp_path, {"headers_analysis", "method_analysis", "parameter_discovery"})
    assert coverage["tests_skipped"] == ["headers_analysis", "method_analysis"]
    assert coverage["tests_executed"] == ["parameter_discovery"]
    assert "target" in coverage["skip_reasons"]["headers_analysis"].lower()
    assert "target" in coverage["skip_reasons"]["method_analysis"].lower()


# --------------------------------------------------- a second, different API

@pytest.fixture
def second_api():
    """A small API with API-key auth and a different structure than the lab."""
    app = Flask("second-api")

    def require_key():
        return request.headers.get("X-API-Key") == API_KEY

    @app.get("/api/status")
    def status_public():
        return jsonify(status="ok", service="second-api")

    @app.get("/api/account")
    def account():
        if not require_key():
            return jsonify(error="API key required"), 401
        return jsonify(id="acct-1", owner="keyuser", tier="gold")

    @app.get("/api/health")
    def health():
        response = jsonify(healthy=True)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:" + str(server.server_port)
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def test_second_api_with_api_key_auth(tmp_path, second_api):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    client = app.test_client()
    payload = {
        "target": second_api,
        "endpoints_text": json.dumps([
            {"path": "/api/status"},
            {"path": "/api/account", "security": [{"apiKeyAuth": []}]},
        ]),
        "identities": {"primary": {"scheme": "api_key", "header": "X-API-Key", "value": API_KEY}},
        "default_identity": "primary",
        "tests": ["endpoint_discovery", "parameter_discovery", "headers_analysis",
                  "method_analysis", "auth_analysis"],
    }
    created = client.post("/api/assessment/start", json=payload, headers=session_headers(app))
    assert created.status_code == 202, created.get_json()
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED, job["error"]

    coverage = client.get(f"/api/assessment/{job_id}/coverage").get_json()["coverage"]
    # The API-key identity let the authenticated comparison run against a
    # completely different API, with no lab assumptions.
    assert "auth_analysis" in coverage["tests_executed"]
    assert "headers_analysis" in coverage["tests_executed"]
    assert coverage["requests_sent"] > 0
    # The protected endpoint denies anonymous access, so no auth finding (passed).
    statuses = {t["key"]: t["status"] for t in coverage["tests"]}
    assert statuses["auth_analysis"] == "passed"

    # No credential value may be persisted in the job directory or responses.
    bodies = b"".join(client.get(path).data for path in (
        f"/api/assessment/{job_id}",
        f"/api/assessment/{job_id}/coverage",
        f"/api/assessment/{job_id}/evidence.json"))
    assert API_KEY.encode() not in bodies
    assert not any(API_KEY in p.read_text(encoding="utf-8", errors="ignore")
                   for p in (jobs_root / job_id).iterdir() if p.is_file())
    assert not (jobs_root / job_id / "secrets").exists()


def test_api_key_identity_in_engine_config(tmp_path):
    """The engine config writer emits an api_key auth entry the engine can read."""
    from web.job_config import build_engine_args
    directory = tmp_path / "job"
    config = {
        "identities": {"primary": {"scheme": "api_key", "header": "X-API-Key", "value": API_KEY}},
        "default_identity": "primary", "bola": None,
    }
    args, _ = build_engine_args(directory, {
        "target": "http://127.0.0.1:5000", "authorized": False, "openapi_text": None,
        "endpoints_text": json.dumps(["/x"]), "identities": config["identities"],
        "default_identity": "primary", "bola": None, "jwt_token": None, "rate_limit": None,
        "limits": {"timeout": 5, "max_requests": 10, "delay": 0.2},
    })
    from main import load_config
    loaded, identities, secrets = load_config(str(directory / "config.json"))
    assert identities["primary"]["X-API-Key"] == API_KEY
    assert API_KEY in secrets


# --------------------------------------------------- Public API (No Auth)

@pytest.fixture
def public_api():
    """A completely public API requiring no credentials."""
    app = Flask("public-api")

    @app.get("/api/status")
    def status():
        return jsonify(status="ok", public=True)

    @app.get("/api/info")
    def info():
        return jsonify(service="public-service", version="1.0.0")

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:" + str(server.server_port)
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def test_public_api_assessment_without_auth(tmp_path, public_api):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    client = app.test_client()

    payload = {
        "target": public_api,
        "endpoints_text": json.dumps(["/api/status", "/api/info"]),
        "tests": ["endpoint_discovery", "parameter_discovery", "headers_analysis",
                  "method_analysis", "auth_analysis", "cors_analysis"],
    }
    created = client.post("/api/assessment/start", json=payload, headers=session_headers(app))
    assert created.status_code == 202
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED, job.get("error")

    coverage = client.get(f"/api/assessment/{job_id}/coverage").get_json()["coverage"]
    assert "headers_analysis" in coverage["tests_executed"]
    assert "method_analysis" in coverage["tests_executed"]
    # Auth and credentialed CORS checks are skipped gracefully because no identity was provided
    assert "auth_analysis" in coverage["tests_skipped"]
    assert "cors_analysis" in coverage["tests_skipped"]
    assert "No authenticated identity available" in coverage["skip_reasons"]["auth_analysis"]
    assert coverage["tests_failed"] == []

    # Evidence and report exist
    for path in (f"/api/assessment/{job_id}/evidence.json", f"/api/assessment/{job_id}/report/html"):
        res = client.get(path)
        assert res.status_code == 200


# --------------------------------------------------- Bearer-Protected API

BEARER_TOKEN = "eyTestBearerToken9876543210"

@pytest.fixture
def bearer_api():
    """An API protected with Bearer tokens, with one leaking endpoint."""
    app = Flask("bearer-api")

    @app.get("/api/profile")
    def profile():
        auth = request.headers.get("Authorization", "")
        if auth != "Bearer " + BEARER_TOKEN:
            return jsonify(error="Unauthorized"), 401
        return jsonify(user="operator", role="tester")

    @app.get("/api/unprotected-data")
    def unprotected():
        # Flawed endpoint: returns identical data even when called anonymously
        return jsonify(secret_item="flagged_publicly", status="leaked")

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:" + str(server.server_port)
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def test_bearer_token_protected_api(tmp_path, bearer_api):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    client = app.test_client()

    payload = {
        "target": bearer_api,
        "endpoints_text": json.dumps([
            {"path": "/api/profile", "security": [{"bearerAuth": []}]},
            {"path": "/api/unprotected-data", "security": [{"bearerAuth": []}]},
        ]),
        "identities": {"primary": {"scheme": "bearer", "token": BEARER_TOKEN}},
        "default_identity": "primary",
        "tests": ["endpoint_discovery", "headers_analysis", "auth_analysis"],
    }
    created = client.post("/api/assessment/start", json=payload, headers=session_headers(app))
    assert created.status_code == 202
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED

    evidence = client.get(f"/api/assessment/{job_id}/evidence.json").get_json()
    coverage = evidence["coverage"]
    assert "auth_analysis" in coverage["tests_executed"]

    # auth_analysis finds the issue on /api/unprotected-data
    statuses = {t["key"]: t["status"] for t in coverage["tests"]}
    assert statuses["auth_analysis"] == "finding"
    auth_findings = [f for f in evidence["findings"] if f["category"] == "Authentication"]
    assert len(auth_findings) == 1
    assert auth_findings[0]["endpoint"] == "/api/unprotected-data"

    # Token must be redacted everywhere
    bodies = client.get(f"/api/assessment/{job_id}/evidence.json").data
    assert BEARER_TOKEN.encode() not in bodies
    assert not (jobs_root / job_id / "secrets").exists()


# --------------------------------------------------- Basic & Custom Header APIs

BASIC_USER = "testadmin"
BASIC_PASS = "securepass123"
CUSTOM_HEADER = "X-Internal-Token"
CUSTOM_VAL = "custom-secret-token-val"

@pytest.fixture
def auth_schemes_api():
    """An API with endpoints protected by Basic auth and a custom header."""
    app = Flask("schemes-api")

    @app.get("/api/basic-secure")
    def basic_secure():
        import base64
        expected = "Basic " + base64.b64encode(f"{BASIC_USER}:{BASIC_PASS}".encode()).decode("ascii")
        if request.headers.get("Authorization") != expected:
            return jsonify(error="Basic auth required"), 401
        return jsonify(authenticated=True, user=BASIC_USER)

    @app.get("/api/custom-secure")
    def custom_secure():
        if request.headers.get(CUSTOM_HEADER) != CUSTOM_VAL:
            return jsonify(error="Custom token required"), 401
        return jsonify(authenticated=True, source="custom-header")

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:" + str(server.server_port)
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def test_basic_auth_api_end_to_end(tmp_path, auth_schemes_api):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    client = app.test_client()

    payload = {
        "target": auth_schemes_api,
        "endpoints_text": json.dumps([
            {"path": "/api/basic-secure", "security": [{"basicAuth": []}]},
        ]),
        "identities": {"primary": {"scheme": "basic", "username": BASIC_USER, "password": BASIC_PASS}},
        "default_identity": "primary",
        "tests": ["endpoint_discovery", "headers_analysis", "auth_analysis"],
    }
    created = client.post("/api/assessment/start", json=payload, headers=session_headers(app))
    assert created.status_code == 202
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED

    coverage = client.get(f"/api/assessment/{job_id}/coverage").get_json()["coverage"]
    assert "auth_analysis" in coverage["tests_executed"]
    statuses = {t["key"]: t["status"] for t in coverage["tests"]}
    assert statuses["auth_analysis"] == "passed"

    # Password is not persisted
    evidence_bytes = client.get(f"/api/assessment/{job_id}/evidence.json").data
    assert BASIC_PASS.encode() not in evidence_bytes
    assert not (jobs_root / job_id / "secrets").exists()


def test_custom_header_api_end_to_end(tmp_path, auth_schemes_api):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    client = app.test_client()

    payload = {
        "target": auth_schemes_api,
        "endpoints_text": json.dumps([
            {"path": "/api/custom-secure", "security": [{"customAuth": []}]},
        ]),
        "identities": {"primary": {"scheme": "header", "header": CUSTOM_HEADER, "value": CUSTOM_VAL}},
        "default_identity": "primary",
        "tests": ["endpoint_discovery", "headers_analysis", "auth_analysis"],
    }
    created = client.post("/api/assessment/start", json=payload, headers=session_headers(app))
    assert created.status_code == 202
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED

    coverage = client.get(f"/api/assessment/{job_id}/coverage").get_json()["coverage"]
    assert "auth_analysis" in coverage["tests_executed"]
    statuses = {t["key"]: t["status"] for t in coverage["tests"]}
    assert statuses["auth_analysis"] == "passed"

    evidence_bytes = client.get(f"/api/assessment/{job_id}/evidence.json").data
    assert CUSTOM_VAL.encode() not in evidence_bytes
    assert not (jobs_root / job_id / "secrets").exists()


# --------------------------------------------------- Non-JSON & Error Responses

@pytest.fixture
def non_json_and_error_api():
    """An API returning HTML, 204 No Content, 404, and 500 error."""
    app = Flask("error-api")

    @app.get("/api/html")
    def html_page():
        return "<!DOCTYPE html><html><body>Error page</body></html>", 200, {"Content-Type": "text/html"}

    @app.get("/api/empty")
    def empty_response():
        return "", 204

    @app.get("/api/not-found")
    def not_found():
        return "Not found", 404, {"Content-Type": "text/plain"}

    @app.get("/api/server-error")
    def server_error():
        return jsonify(error="Internal Server Error"), 500

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:" + str(server.server_port)
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def test_api_returning_non_json_and_errors(tmp_path, non_json_and_error_api):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    client = app.test_client()

    payload = {
        "target": non_json_and_error_api,
        "endpoints_text": json.dumps([
            "/api/html",
            "/api/empty",
            "/api/not-found",
            "/api/server-error",
        ]),
        "tests": ["endpoint_discovery", "headers_analysis", "method_analysis"],
    }
    created = client.post("/api/assessment/start", json=payload, headers=session_headers(app))
    assert created.status_code == 202
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    # The assessment finishes cleanly without crashing
    assert job["status"] == COMPLETED

    evidence = client.get(f"/api/assessment/{job_id}/evidence.json").get_json()
    coverage = evidence["coverage"]
    assert coverage["requests_sent"] > 0
    # Stop reason recorded gracefully on 500
    assert "Stopped after HTTP 429 or server error" in (coverage.get("stop_reason") or "")

