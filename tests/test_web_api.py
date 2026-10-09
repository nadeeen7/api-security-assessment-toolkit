"""Web API tests.

These live in tests/ on purpose: conftest.py's autouse network guard asserts that
every outgoing request goes to 127.0.0.1, so the API tests inherit the same
"no real API is ever contacted" guarantee as the engine tests.
"""
import json
import threading
import time
from pathlib import Path

import pytest

from web.app import SESSION_HEADER, create_app
from web.jobs import CANCELLED, COMPLETED, JobManager
from web.request_schema import TEST_CATALOGUE, validate_start

ROOT = Path(__file__).resolve().parents[1]


def session_headers(app, **extra):
    """Headers carrying the per-run session token the API now requires."""
    return {SESSION_HEADER: app.extensions["session_token"], **extra}


@pytest.fixture
def api(tmp_path):
    app = create_app(root=str(tmp_path / "jobs"))
    return app, app.test_client(), tmp_path / "jobs"


def start(app, client, payload, **extra):
    return client.post("/api/assessment/start", json=payload, headers=session_headers(app, **extra))


def wait_for(client, job_id, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get("/api/assessment/" + job_id).get_json()
        if body["status"] in ("completed", "failed", "cancelled"):
            return body
        time.sleep(0.2)
    raise AssertionError("assessment did not finish in time")


def test_catalogue_and_health(api):
    _, client, _ = api
    health = client.get("/api/health").get_json()
    assert health["status"] == "ok"
    assert health["loopback_only"] is True
    keys = [item["key"] for item in client.get("/api/tests").get_json()["tests"]]
    assert keys == list(health["tests_available"])
    assert len(keys) == 10
    # Every checkbox states whether it sends traffic, so the UI cannot imply otherwise.
    assert all(isinstance(item["requests"], bool) for item in TEST_CATALOGUE)


def test_mutating_requests_require_session_token_and_exact_origin(api):
    app, client, _ = api
    token = app.extensions["session_token"]
    # No token at all is rejected before validation runs.
    assert client.post("/api/assessment/start", json={}).status_code == 403
    # A wrong token is rejected.
    assert client.post("/api/assessment/start", json={},
                       headers={SESSION_HEADER: "not-the-token"}).status_code == 403
    # The configured dev origin (Vite 5173) is allowed and reaches validation.
    assert client.post("/api/assessment/start", json={},
                       headers=session_headers(app, Origin="http://localhost:5173")).status_code == 400
    # A cross-origin request that is neither same-origin nor a dev origin is rejected.
    assert client.post("/api/assessment/start", json={},
                       headers=session_headers(app, Origin="https://evil.example")).status_code == 403
    # Same scheme+host+port as the request is accepted.
    assert client.post("/api/assessment/start", json={},
                       headers=session_headers(app, Origin="http://localhost")).status_code == 400
    # Loopback host check still applies to every request.
    assert client.get("/api/health", base_url="http://attacker.test").status_code == 403


def test_session_endpoint_reveals_a_per_run_token(api):
    app, client, _ = api
    body = client.get("/api/session").get_json()
    assert body["token"] and body["header"] == SESSION_HEADER
    assert body["token"] == app.extensions["session_token"]
    assert client.get("/api/session").headers["Cache-Control"] == "no-store"
    assert "error" not in body


@pytest.mark.parametrize("payload,fragment", [
    ({}, "at least one"),
    ({"tests": ["not_a_test"], "target": "http://127.0.0.1:5000"}, "unknown assessment test"),
    ({"tests": ["headers_analysis"], "target": "https://api.example.com"}, "authorization"),
    ({"tests": ["headers_analysis"], "target": "http://api.example.com", "authorized": True}, "HTTPS"),
    ({"tests": ["headers_analysis"], "target": "http://127.0.0.1:5000/x"}, "optional port"),
    ({"tests": ["rate_limit"], "target": "http://127.0.0.1:5000"}, "path and bounded sample"),
    ({"tests": ["rate_limit"], "target": "http://127.0.0.1:5000",
      "rate_limit": {"path": "/api/limited", "count": 50}}, "between"),
    ({"tests": ["authorization"], "target": "http://127.0.0.1:5000"}, "explicit object case"),
    ({"tests": ["headers_analysis"], "identities": {"alice": "token"}}, "target"),
    ({"tests": ["headers_analysis"], "target": "http://127.0.0.1:5000/",
      "identities": {"alice": "two words"}}, "whitespace"),
    ({"tests": ["endpoint_discovery"], "openapi_text": "not-valid-json"}, "valid JSON"),
    ({"tests": ["endpoint_discovery"], "endpoints_text": "not-valid-json"}, "valid JSON"),
])
def test_start_validation_rejects_unsafe_input(api, payload, fragment):
    app, client, _ = api
    response = start(app, client, payload)
    assert response.status_code == 400
    assert fragment in response.get_json()["error"]


def test_unknown_and_malformed_job_ids_are_404(api):
    app, client, _ = api
    for job_id in ("0" * 32, "../../etc/passwd", "..%2f..%2fetc"):
        assert client.get("/api/assessment/" + job_id).status_code == 404
        assert client.post("/api/assessment/" + job_id + "/cancel",
                           headers=session_headers(app)).status_code == 404


def test_openapi_analyze_is_offline_and_returns_documentation_findings(api):
    app, client, jobs_root = api
    text = (ROOT / "input/openapi.json").read_text(encoding="utf-8")
    body = client.post("/api/openapi/analyze", json={"openapi_text": text},
                       headers=session_headers(app)).get_json()
    assert body["requests_sent"] == 0
    assert len(body["endpoints"]) == 10
    assert body["security_schemes"]["bearerAuth"]["scheme"] == "bearer"
    assert all(f["category"] == "OpenAPI" for f in body["findings"])
    assert not jobs_root.exists()  # analysis never creates a job
    bad = client.post("/api/openapi/analyze", json={"openapi_text": '{"openapi":"3.0.3"}'},
                      headers=session_headers(app))
    assert bad.status_code == 400 and "validation failed" in bad.get_json()["error"]


def test_assessment_end_to_end_through_the_api(api, lab, identities):
    app, client, jobs_root = api
    tokens = {name: headers["Authorization"][7:] for name, headers in identities.items()}
    payload = {
        "target": lab[1],
        # The documented security requirement is what makes the authenticated
        # comparison meaningful; a bare path string carries no such declaration.
        "endpoints_text": json.dumps([{"path": "/api/auth-missing",
                                       "security": [{"bearerAuth": []}]}]),
        "identities": tokens,
        "default_identity": "alice",
        "tests": ["endpoint_discovery", "parameter_discovery", "auth_analysis", "headers_analysis"],
    }
    created = start(app, client, payload)
    assert created.status_code == 202
    job_id = created.get_json()["job_id"]

    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED, job["error"]
    assert job["duration_seconds"] >= 0
    assert [event["phase"] for event in job["progress"]][:2] == ["endpoint_discovery", "endpoint"]
    summary = job["summary"]
    assert summary["endpoints_total"] == 1
    assert summary["severity_summary"]["Medium"] == 1      # missing authentication enforcement
    assert summary["severity_summary"]["Informational"] >= 1
    assert summary["requests_sent"] == 2                    # anonymous + authenticated

    findings = client.get("/api/assessment/" + job_id + "/findings").get_json()["findings"]
    assert any(f["category"] == "Authentication" and f["cwe"] == "CWE-306" for f in findings)
    assert client.get("/api/assessment/" + job_id + "/findings?severity=Medium").get_json()["total"] == 1
    assert client.get("/api/assessment/" + job_id + "/findings?severity=Critical").get_json()["total"] == 0
    assert client.get("/api/assessment/" + job_id + "/findings?category=CORS").get_json()["total"] == 0

    coverage = client.get("/api/assessment/" + job_id + "/coverage").get_json()
    # The engine records the selection sorted, so compare as sets.
    assert sorted(coverage["coverage"]["tests_selected"]) == sorted(payload["tests"])
    assert coverage["coverage"]["tests_executed"]  # accurate executed metric now exists
    assert coverage["limitations"]

    for name, mimetype in (("report/html", "text/html"), ("report/markdown", "text/markdown"),
                           ("evidence.json", "application/json")):
        response = client.get("/api/assessment/" + job_id + "/" + name)
        assert response.status_code == 200 and mimetype in response.headers["Content-Type"]
    assert client.get("/api/assessment/" + job_id + "/report/html").headers["Content-Security-Policy"]

    # No response body and no file on disk may contain a supplied token.
    bodies = b"".join(client.get(path).data for path in (
        "/api/assessment/" + job_id,
        "/api/assessment/" + job_id + "/findings",
        "/api/assessment/" + job_id + "/coverage",
        "/api/assessment/" + job_id + "/evidence.json"))
    assert all(token.encode() not in bodies for token in tokens.values())
    assert not (jobs_root / job_id / "secrets").exists()
    assert not any(token in path.read_text(encoding="utf-8", errors="ignore")
                   for token in tokens.values() for path in (jobs_root / job_id).iterdir() if path.is_file())

    history = client.get("/api/assessments").get_json()["assessments"]
    assert [entry["job_id"] for entry in history] == [job_id]
    assert history[0]["severity_summary"]["Medium"] == 1

    assert client.delete("/api/assessment/" + job_id, headers=session_headers(app)).status_code == 200
    assert client.get("/api/assessment/" + job_id).status_code == 404


def test_relative_jobs_root_still_serves_reports(tmp_path, monkeypatch, lab, identities):
    """Regression: Flask resolves relative paths against its package directory.

    The default root is relative, so report routes used to look in web/output/...
    and return 500 even though the files existed. This test runs the app from a
    different working directory with a relative root, exactly like `python -m web`.
    """
    monkeypatch.chdir(tmp_path)
    app = create_app(root="output/web")
    assert Path(app.extensions["jobs_root"]).is_absolute()
    client = app.test_client()

    payload = {
        "target": lab[1],
        "endpoints_text": json.dumps(["/api/public"]),
        "tests": ["endpoint_discovery", "headers_analysis"],
    }
    job_id = start(app, client, payload).get_json()["job_id"]
    assert wait_for(client, job_id)["status"] == COMPLETED

    for name in ("report/html", "report/markdown", "evidence.json"):
        response = client.get(f"/api/assessment/{job_id}/{name}")
        assert response.status_code == 200, f"{name} returned {response.status_code}"
        assert response.data


def test_engine_failure_is_reported_without_exception_text(api):
    """The engine hides exception strings because they can carry credentials."""
    app, client, _ = api
    payload = {"target": "http://127.0.0.1:5000", "openapi_text": '{"openapi":"9.9"}',
               "tests": ["openapi_analysis"]}
    job_id = start(app, client, payload).get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == "failed"
    assert job["error"]["type"] == "ValueError"
    assert "check the target" in job["error"]["message"].lower()
    assert "9.9" not in json.dumps(job)


def test_cancellation_stops_a_running_assessment(tmp_path):
    """A stub engine proves cancellation without touching the network."""
    first_call = threading.Event()

    def stub_engine(args, progress=None, selected=None):
        for _ in range(500):
            first_call.set()
            time.sleep(0.01)
            progress("endpoint", {"path": "/stub"})
        raise AssertionError("stub engine should have been cancelled")

    manager = JobManager(tmp_path / "jobs", engine=stub_engine)
    job_id = manager.start(validate_start(
        {"target": "http://127.0.0.1:5000", "tests": ["headers_analysis"]}))["job_id"]
    assert first_call.wait(timeout=10), "stub engine never started"
    manager.cancel(job_id)
    job = manager.wait(job_id, timeout=30)
    assert job["status"] == CANCELLED
    assert not (tmp_path / "jobs" / job_id / "secrets").exists()


def test_queued_jobs_are_serialised(tmp_path):
    """One worker: this toolkit must not be usable as a flooder."""
    order = []
    lock = threading.Lock()

    def stub_engine(args, progress=None, selected=None):
        with lock:
            order.append("start")
        time.sleep(0.05)
        with lock:
            order.append("end")

    manager = JobManager(tmp_path / "jobs", engine=stub_engine)
    payload = {"target": "http://127.0.0.1:5000", "tests": ["headers_analysis"]}
    ids = [manager.start(validate_start(payload))["job_id"] for _ in range(3)]
    for job_id in ids:
        assert manager.wait(job_id, timeout=30)["status"] == COMPLETED
    assert order == ["start", "end"] * 3


def test_openapi_sample_and_fetch(api, lab):
    app, client, _ = api
    sample = client.get("/api/openapi/sample")
    assert sample.status_code == 200
    assert "paths" in sample.get_json()["content"]

    fetched = client.post("/api/openapi/fetch", json={"url": f"{lab[1]}/openapi.json"},
                          headers=session_headers(app))
    assert fetched.status_code == 200
    assert "paths" in fetched.get_json()["content"]

