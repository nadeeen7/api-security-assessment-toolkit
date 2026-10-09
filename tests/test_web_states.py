"""Application states through the API: empty history, missing artifacts, failures."""
import json
import time
from pathlib import Path

import pytest

from web.app import SESSION_HEADER, create_app

ROOT = Path(__file__).resolve().parents[1]


def headers(app):
    return {SESSION_HEADER: app.extensions["session_token"]}


@pytest.fixture
def web(tmp_path):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    return app, app.test_client(), jobs_root


def wait_for(client, job_id, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get("/api/assessment/" + job_id).get_json()
        if body["status"] in ("completed", "failed", "cancelled"):
            return body
        time.sleep(0.2)
    raise AssertionError("assessment did not finish in time")


def test_empty_history_is_an_empty_list(web):
    _, client, _ = web
    assert client.get("/api/assessments").get_json() == {"assessments": []}


def test_missing_artifacts_report_404_not_a_crash(web, lab):
    app, client, jobs_root = web
    job_id = client.post("/api/assessment/start", json={
        "target": lab[1], "tests": ["endpoint_discovery"],
        "endpoints_text": json.dumps(["/api/public"]),
    }, headers=headers(app)).get_json()["job_id"]
    assert wait_for(client, job_id)["status"] == "completed"

    # Remove the generated artifacts, then confirm the API reports their absence.
    (jobs_root / job_id / "report.html").unlink()
    (jobs_root / job_id / "evidence.json").unlink()
    assert client.get(f"/api/assessment/{job_id}/report/html").status_code == 404
    assert client.get(f"/api/assessment/{job_id}/evidence.json").status_code == 404
    # The job itself still exists and is reported as completed.
    assert client.get(f"/api/assessment/{job_id}").get_json()["status"] == "completed"


def test_failed_assessment_is_terminal_and_reports_a_safe_error(web):
    app, client, _ = web
    payload = {"target": "http://127.0.0.1:5000", "openapi_text": '{"openapi":"9.9"}',
               "tests": ["openapi_analysis"]}
    job_id = client.post("/api/assessment/start", json=payload,
                         headers=headers(app)).get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == "failed"
    assert job["error"]["type"] and "9.9" not in json.dumps(job)


def test_invalid_job_and_finding_index_are_handled(web):
    _, client, _ = web
    missing = client.get("/api/assessment/" + "f" * 32)
    assert missing.status_code == 404
    assert "error" in missing.get_json()
