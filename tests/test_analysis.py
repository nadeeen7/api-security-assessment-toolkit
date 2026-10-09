import json
from pathlib import Path
import time
import jwt
import pytest
from core.models import Endpoint, Observation
from core.risk_engine import finding
from modules import auth_analysis, authorization_analysis, jwt_analysis, headers_analysis, cors_analysis, method_detection, rate_limit

ROOT = Path(__file__).resolve().parents[1]

def test_auth_missing_and_protected(client, identities):
    for path, expected in (("/api/auth-missing", True), ("/api/protected", False)):
        endpoint = Endpoint(path, security=[{"bearerAuth":[]}])
        result = auth_analysis.analyze(endpoint, client.request("GET", path), client.request("GET", path, headers=identities["alice"]))
        assert bool(result) == expected
    assert not auth_analysis.requires_auth([{}, {"bearerAuth":[]}])

def test_bola_positive_and_negative(client, identities):
    case = json.loads((ROOT / "input/lab_config.json").read_text())["bola"]
    findings, note = authorization_analysis.analyze(client, case, identities["alice"], identities["bob"])
    assert findings[0].severity == "High"
    assert findings[0].confidence == "High"
    case["path"] = "/api/safe-objects/101"
    findings, note = authorization_analysis.analyze(client, case, identities["alice"], identities["bob"])
    assert not findings
    assert note["outcome"] == "Access denied for other user"
    with pytest.raises(ValueError):
        authorization_analysis.analyze(client, case, identities["alice"], identities["alice"])

def test_bola_wrong_expected_owner_is_inconclusive(client, identities):
    case = json.loads((ROOT / "input/lab_config.json").read_text())["bola"]
    case["expected_object_id"] = 999
    findings, note = authorization_analysis.analyze(client, case, identities["alice"], identities["bob"])
    assert not findings
    assert "Inconclusive" in note["outcome"]

def test_jwt_no_secrets_or_verification_claims():
    token = jwt.encode({"sub":"alice", "email":"private@example.test", "exp":int(time.time())-30}, "x"*32, algorithm="HS256")
    item = jwt_analysis.analyze(token)[0]
    assert item.classification == "JWT configuration finding"
    assert not item.evidence["signature_verified"]
    assert "private@example.test" not in str(item.to_dict())
    assert "Missing claim: iss" in item.evidence["issues"]
    with pytest.raises(ValueError):
        jwt_analysis.analyze("not.a.jwt")

def test_header_context():
    json_obs = Observation("GET", "/", 200, {"content-type":"application/json"})
    assert headers_analysis.analyze(json_obs)[0].evidence["missing"] == ["x-content-type-options"]
    assert "strict-transport-security" in headers_analysis.analyze(json_obs, https=True)[0].evidence["missing"]
    html = Observation("GET", "/", 200, {"content-type":"text/html"})
    assert "content-security-policy" in headers_analysis.analyze(html)[0].evidence["missing"]
    assert headers_analysis.analyze(html)[0].severity == "Informational"

def test_cors_reflect_wildcard_strict(client, identities, lab):
    app, _ = lab
    headers = {**identities["alice"], "Origin":cors_analysis.TEST_ORIGIN}
    assert cors_analysis.analyze(client.request("GET", "/api/cors", headers=headers))[0].severity == "Medium"
    app.config["CORS_MODE"] = "wildcard"
    assert cors_analysis.analyze(client.request("GET", "/api/cors", headers=headers))[0].severity == "Informational"
    app.config["CORS_MODE"] = "strict"
    assert not cors_analysis.analyze(client.request("GET", "/api/cors", headers=headers))

def test_options_does_not_claim_exploit():
    obs = Observation("OPTIONS", "/", 200, {"allow":"GET, HEAD, OPTIONS, DELETE"})
    result = method_detection.analyze(obs, {"GET"})
    assert result[0].evidence["unexpected_methods"] == ["DELETE"]
    assert result[0].severity == "Low"

def test_rate_stops_at_429(client):
    result = rate_limit.analyze(client, "/api/limited", count=5, delay=0.2)[0]
    assert result.title == "Rate limiting observed"
    assert len(result.evidence["observations"]) == 4
    assert result.evidence["observations"][-1]["headers"]["retry-after"]
    assert client.count == 4
    assert client.request("GET", "/api/public").status is None


def test_no_429_not_vulnerability(client):
    result = rate_limit.analyze(client, "/api/public", count=2, delay=0.2)[0]
    assert result.severity == "Informational"
    assert result.confidence == "Low"
    with pytest.raises(ValueError):
        rate_limit.analyze(client, "/api/public", count=11)


def test_rate_limit_404_path_is_labeled_not_found(client):
    """A path that 404s on every probe must NOT produce a rate-limit or inconclusive finding."""
    result = rate_limit.analyze(client, "/api/does-not-exist", count=3, delay=0.2)[0]
    assert result.title == "Rate limit path not found (HTTP 404)", (
        "A 404-only probe must be labeled as endpoint-not-found, not inconclusive"
    )
    assert result.evidence["endpoint_not_found"] is True
    assert result.severity == "Informational"
    # All observations must be 404
    statuses = [o["status"] for o in result.evidence["observations"]]
    assert all(s == 404 for s in statuses), f"Expected all 404, got: {statuses}"


def test_rate_limit_correct_path_triggers_429(client):
    """The correct lab rate-limit path /api/limited must actually return 429 within 5 probes."""
    result = rate_limit.analyze(client, "/api/limited", count=5, delay=0.2)[0]
    assert result.title == "Rate limiting observed"
    assert result.evidence["endpoint_not_found"] is False


def test_finding_model_and_risk():
    f = finding("docs", "Title", "OpenAPI", "/", "GET", "Description", {}, "Review")
    assert f.to_dict()["severity"] == "Informational"
    assert f.severity_reason


def test_report_status_column_rendering(tmp_path):
    """Regression: actual_status=None shows 'Not observed'; integer shows 'HTTP N'."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from reports.report_generator import generate, md

    def _make_report(actual_status):
        return {
            "target": "http://127.0.0.1:5000",
            "date": "2026-01-01T00:00:00+00:00",
            "scope": "test",
            "methodology": "test",
            "findings": [],
            "coverage": {"tests": [], "requests_sent": 0},
            "metadata": {},
            "limitations": [],
            "endpoints": [{
                "path": "/api/test",
                "resolved_path": None,
                "method": "GET",
                "authentication": "Anonymous allowed by documentation",
                "parameters": [],
                "response_statuses": ["200"],
                "request_schema_present": False,
                "response_schema_present": False,
                "actual_status": actual_status,
                "authenticated": "No",
                "check_status": "skipped" if actual_status is None else "passed",
                "check_reason": "Not tested" if actual_status is None else "OK",
            }],
        }

    out_none = tmp_path / "none"
    generate(_make_report(None), str(out_none))
    md_none = (out_none / "report.md").read_text(encoding="utf-8")
    html_none = (out_none / "report.html").read_text(encoding="utf-8")
    assert "Not observed" in md_none, "Markdown must show 'Not observed' when actual_status is None"
    assert "Not observed" in html_none, "HTML must show 'Not observed' when actual_status is None"
    assert "HTTP None" not in md_none
    assert "HTTP None" not in html_none

    out_200 = tmp_path / "ok"
    generate(_make_report(200), str(out_200))
    md_200 = (out_200 / "report.md").read_text(encoding="utf-8")
    html_200 = (out_200 / "report.html").read_text(encoding="utf-8")
    assert "HTTP 200" in md_200, "Markdown must show 'HTTP 200' for status 200"
    assert "HTTP 200" in html_200, "HTML must show 'HTTP 200' for status 200"
