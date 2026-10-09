"""Phase E hardening tests.

Cover the per-run session token, the exact same-origin rule and the secret
cleanup ordering/visibility. The network guard in conftest.py still applies:
nothing here leaves loopback.
"""
import logging

import pytest

from web.app import SESSION_HEADER, create_app
from web.job_config import clear_secrets
from web.jobs import JobManager
from web.request_schema import validate_start


def token_headers(app, **extra):
    return {SESSION_HEADER: app.extensions["session_token"], **extra}


@pytest.fixture
def hardened(tmp_path):
    app = create_app(root=str(tmp_path / "jobs"))
    return app, app.test_client()


def test_get_routes_do_not_require_a_token(hardened):
    _, client = hardened
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/session").status_code == 200


def test_same_origin_version_of_request_is_accepted(hardened):
    app, client = hardened
    # Origin exactly equal to this request's scheme://host[:port].
    response = client.post("/api/assessment/start", json={},
                           headers=token_headers(app, Origin="http://localhost"))
    assert response.status_code == 400  # reached validation, guard passed


def test_valid_token_without_origin_is_accepted(hardened):
    # Non-browser callers may omit Origin; the token is the primary control.
    app, client = hardened
    response = client.post("/api/assessment/start", json={},
                           headers=token_headers(app))
    assert response.status_code == 400


def test_mismatched_origin_is_rejected_even_with_valid_token(hardened):
    app, client = hardened
    for origin in ("http://127.0.0.1:5055", "http://localhost:9999", "https://127.0.0.1"):
        # http://localhost is this request's origin; these are not.
        response = client.post("/api/assessment/start", json={},
                               headers=token_headers(app, Origin=origin))
        assert response.status_code == 403, origin


def test_dev_origin_allowlist_is_configurable(tmp_path):
    app = create_app(root=str(tmp_path / "jobs"), allow_origins=[])
    client = app.test_client()
    response = client.post("/api/assessment/start", json={},
                           headers=token_headers(app, Origin="http://127.0.0.1:5173"))
    assert response.status_code == 403


def test_missing_or_wrong_token_is_rejected_before_validation(hardened):
    app, client = hardened
    assert client.post("/api/assessment/start", json={}).status_code == 403
    assert client.post("/api/assessment/start", json={},
                       headers={SESSION_HEADER: "x" * 43}).status_code == 403


def test_clear_secrets_removes_files_and_reports_success(tmp_path):
    directory = tmp_path / "job"
    (directory / "secrets").mkdir(parents=True)
    (directory / "secrets" / "alice.token").write_text("sensitive", encoding="utf-8")
    assert clear_secrets(directory) is None
    assert not (directory / "secrets").exists()
    # Nothing to remove is still success, not an error.
    assert clear_secrets(directory) is None


def test_cleanup_failure_is_recorded_on_the_job(tmp_path, monkeypatch, caplog):
    def stub_engine(args, progress=None, selected=None):
        return []

    manager = JobManager(tmp_path / "jobs", engine=stub_engine)
    monkeypatch.setattr("web.jobs.clear_secrets", lambda directory: "PermissionError")
    with caplog.at_level(logging.WARNING, logger="api_toolkit"):
        job_id = manager.start(validate_start(
            {"target": "http://127.0.0.1:5000", "tests": ["headers_analysis"]}))["job_id"]
        job = manager.wait(job_id, timeout=30)
    assert job["status"] == "completed"
    assert job["cleanup_error"] == "PermissionError"
    assert any("cleanup failed" in record.getMessage().lower() for record in caplog.records)


def test_successful_job_records_no_cleanup_error(tmp_path):
    def stub_engine(args, progress=None, selected=None):
        return []

    manager = JobManager(tmp_path / "jobs", engine=stub_engine)
    job_id = manager.start(validate_start(
        {"target": "http://127.0.0.1:5000", "tests": ["headers_analysis"]}))["job_id"]
    job = manager.wait(job_id, timeout=30)
    assert job["status"] == "completed"
    assert job.get("cleanup_error") is None
