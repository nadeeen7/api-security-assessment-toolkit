"""Every assessment module exercised through the real Flask API and the lab.

These are genuine end-to-end runs: the API starts a background job, the engine
talks to the loopback lab, and the results are checked through the same JSON
endpoints the UI consumes. No module is mocked and no module is only "selected".
"""
import json
import time
from pathlib import Path

import pytest

from web.app import SESSION_HEADER, create_app
from web.jobs import COMPLETED

ROOT = Path(__file__).resolve().parents[1]
ALL_MODULES = (
    "endpoint_discovery", "openapi_analysis", "parameter_discovery", "method_analysis",
    "auth_analysis", "authorization", "jwt_analysis", "headers_analysis",
    "cors_analysis", "rate_limit",
)


def headers(app):
    return {SESSION_HEADER: app.extensions["session_token"]}


@pytest.fixture
def web(tmp_path):
    jobs_root = tmp_path / "jobs"
    app = create_app(root=str(jobs_root))
    return app, app.test_client(), jobs_root


def start(app, client, payload):
    return client.post("/api/assessment/start", json=payload, headers=headers(app))


def wait_for(client, job_id, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get("/api/assessment/" + job_id).get_json()
        if body["status"] in ("completed", "failed", "cancelled"):
            return body
        time.sleep(0.2)
    raise AssertionError("assessment did not finish in time")


def categories(client, job_id):
    return {f["category"] for f in
            client.get(f"/api/assessment/{job_id}/findings").get_json()["findings"]}


def test_offline_openapi_endpoint_and_parameter_discovery(web):
    app, client, _ = web
    payload = {
        "tests": ["endpoint_discovery", "openapi_analysis", "parameter_discovery"],
        "openapi_text": (ROOT / "input/openapi.json").read_text(encoding="utf-8"),
    }
    created = start(app, client, payload)
    assert created.status_code == 202
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED, job["error"]

    # OpenAPI analysis produced documentation findings, offline.
    assert "OpenAPI" in categories(client, job_id)
    coverage = client.get(f"/api/assessment/{job_id}/coverage").get_json()["coverage"]
    assert coverage["requests_sent"] == 0
    for module in ("endpoint_discovery", "openapi_analysis", "parameter_discovery"):
        assert module in coverage["tests_executed"], module
    assert coverage["tests_skipped"] == []

    # Endpoint discovery + parameter discovery populated the endpoint summary.
    endpoints = client.get(f"/api/assessment/{job_id}/endpoints").get_json()["endpoints"]
    assert len(endpoints) == 10
    assert any(e["parameters"] for e in endpoints)


def test_full_assessment_executes_every_module(web, lab, identities):
    app, client, jobs_root = web
    tokens = {name: value["Authorization"][7:] for name, value in identities.items()}
    payload = {
        "target": lab[1],
        "authorized": True,
        "openapi_text": (ROOT / "input/openapi.json").read_text(encoding="utf-8"),
        "identities": tokens,
        "default_identity": "alice",
        "jwt_token": tokens["alice"],
        "bola": {
            "path": "/api/objects/101", "identity_path": "/api/me",
            "owner_identity": "alice", "other_identity": "bob",
            "owner_subject": "alice", "other_subject": "bob",
            "expected_object_id": 101, "id_field": "id", "owner_field": "owner",
        },
        "rate_limit": {"path": "/api/limited", "count": 5, "delay": 0.2},
        "tests": list(ALL_MODULES),
    }
    created = start(app, client, payload)
    assert created.status_code == 202, created.get_json()
    job_id = created.get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED, job["error"]

    coverage = client.get(f"/api/assessment/{job_id}/coverage").get_json()["coverage"]
    # Every selected module actually ran at least once.
    assert sorted(coverage["tests_executed"]) == sorted(ALL_MODULES)
    assert coverage["tests_skipped"] == []
    assert coverage["requests_sent"] > 0
    assert coverage["stop_reason"]  # the lab returns 429 during the rate sample

    # Categories prove the analysis modules produced real findings.
    found = categories(client, job_id)
    for expected in ("OpenAPI", "JWT", "Authorization", "Authentication",
                     "Security headers", "CORS", "Rate limiting"):
        assert expected in found, expected
    # Risk engine: BOLA High, missing-auth Medium, documentation Informational.
    summary = job["summary"]["severity_summary"]
    assert summary["High"] >= 1 and summary["Medium"] >= 1 and summary["Informational"] >= 1

    # Evidence + report generation.
    evidence = client.get(f"/api/assessment/{job_id}/evidence.json").get_json()
    assert evidence["coverage"]["tests_executed"]
    assert (jobs_root / job_id / "report.html").is_file()
    assert (jobs_root / job_id / "report.md").is_file()
    for name in ("report/html", "report/markdown", "evidence.json"):
        assert client.get(f"/api/assessment/{job_id}/{name}").status_code == 200

    # History persistence for this job.
    history = client.get("/api/assessments").get_json()["assessments"]
    assert job_id in [entry["job_id"] for entry in history]

    # Credentials are gone from disk once the job is terminal.
    assert not (jobs_root / job_id / "secrets").exists()
    assert job.get("cleanup_error") is None


def test_zero_findings_assessment_is_reported_honestly(web, lab):
    app, client, _ = web
    # Discovery only: the engine reads the document and sends no analysis that
    # can raise a finding, so the honest result is zero findings.
    payload = {"target": lab[1], "tests": ["endpoint_discovery"],
               "endpoints_text": json.dumps(["/api/public"])}
    job_id = start(app, client, payload).get_json()["job_id"]
    job = wait_for(client, job_id)
    assert job["status"] == COMPLETED
    findings = client.get(f"/api/assessment/{job_id}/findings").get_json()
    assert findings["total"] == 0
    assert all(value == 0 for value in job["summary"]["severity_summary"].values())
    # Reports are still generated for a clean run.
    assert client.get(f"/api/assessment/{job_id}/report/html").status_code == 200


def test_persisted_history_survives_a_new_app_instance(web, lab, tmp_path):
    app, client, jobs_root = web
    job_id = start(app, client, {
        "target": lab[1], "tests": ["endpoint_discovery"],
        "endpoints_text": json.dumps(["/api/public"]),
    }).get_json()["job_id"]
    assert wait_for(client, job_id)["status"] == COMPLETED

    # A fresh app over the same root reads the on-disk history.
    fresh = create_app(root=str(jobs_root))
    listing = fresh.test_client().get("/api/assessments").get_json()["assessments"]
    assert job_id in [entry["job_id"] for entry in listing]
