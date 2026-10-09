"""Tests for VAmPI improvements: safe path parameter resolution, endpoint status recording,
documentation observation separation, robust BOLA checks, and bounded rate limiting.
"""
import json
from pathlib import Path
import pytest
from core.path_resolver import extract_parameter_example, resolve_path_template
from core.models import Endpoint, Observation
from modules.openapi_analysis import analyze
from modules import authorization_analysis, rate_limit, auth_analysis
from main import parser, run

ROOT = Path(__file__).resolve().parents[1]


# -------------------------------------------------- 1. Path parameter resolution

def test_extract_parameter_example_sources():
    # Top-level example
    assert extract_parameter_example({"name": "id", "in": "path", "example": 101}) == "101"
    # Top-level default
    assert extract_parameter_example({"name": "id", "in": "path", "default": "item_1"}) == "item_1"
    # Schema example
    assert extract_parameter_example({"name": "id", "in": "path", "schema": {"type": "integer", "example": 42}}) == "42"
    # Schema default
    assert extract_parameter_example({"name": "id", "in": "path", "schema": {"type": "string", "default": "main"}}) == "main"
    # OpenAPI 3 named examples
    assert extract_parameter_example({"name": "id", "in": "path", "examples": {"sample": {"value": "alice"}}}) == "alice"


def test_extract_parameter_example_rejects_unsafe():
    # Path traversal
    assert extract_parameter_example({"name": "id", "in": "path", "example": "../etc/passwd"}) is None
    # Slashing / path injection
    assert extract_parameter_example({"name": "id", "in": "path", "example": "foo/bar"}) is None
    # Query / fragment injection
    assert extract_parameter_example({"name": "id", "in": "path", "example": "item?admin=1"}) is None
    assert extract_parameter_example({"name": "id", "in": "path", "example": "item#sec"}) is None
    # Whitespace or empty
    assert extract_parameter_example({"name": "id", "in": "path", "example": ""}) is None
    assert extract_parameter_example({"name": "id", "in": "path", "example": "   "}) is None
    # Complex non-primitives
    assert extract_parameter_example({"name": "id", "in": "path", "example": {"sub": 1}}) is None


def test_resolve_path_template():
    params = [
        {"name": "object_id", "in": "path", "schema": {"type": "integer", "example": 101}},
        {"name": "filter", "in": "query", "schema": {"type": "string"}},
    ]
    resolved, unresolved = resolve_path_template("/api/objects/{object_id}", params)
    assert resolved == "/api/objects/101"
    assert unresolved == []

    # Multiple parameters
    multi_params = [
        {"name": "user_id", "in": "path", "example": "user_1"},
        {"name": "post_id", "in": "path", "example": "post_99"},
    ]
    resolved, unresolved = resolve_path_template("/api/users/{user_id}/posts/{post_id}", multi_params)
    assert resolved == "/api/users/user_1/posts/post_99"
    assert unresolved == []


def test_resolve_path_template_unresolved_never_invents_id():
    # No example provided in spec
    params = [
        {"name": "object_id", "in": "path", "schema": {"type": "integer"}},
    ]
    resolved, unresolved = resolve_path_template("/api/objects/{object_id}", params)
    assert resolved is None
    assert unresolved == ["object_id"]


# -------------------------------------------------- 2. Endpoint actual status and auth recording

def test_endpoint_summary_records_actual_status_and_auth(lab, identities, tmp_path):
    output = tmp_path / "out"
    args = parser().parse_args([
        "--target", lab[1],
        "--openapi", str(ROOT / "input/openapi.json"),
        "--output", str(output),
    ])
    run(args, selected={"endpoint_discovery", "openapi_analysis", "headers_analysis"})
    evidence = json.loads((output / "evidence.json").read_text())

    endpoints = evidence["endpoints"]
    assert len(endpoints) >= 10
    for e in endpoints:
        assert "actual_status" in e
        assert "authenticated" in e
        assert "check_status" in e
        assert "check_reason" in e
        # Live GET endpoints that succeeded should show 200 OK
        if e["path"] in ("/api/public", "/api/html"):
            assert e["actual_status"] == 200
            assert e["check_status"] in ("passed", "finding")
            assert e["authenticated"] == "No"
        # Non-GET endpoints should show skipped
        if e["method"] == "POST":
            assert e["actual_status"] is None
            assert e["check_status"] == "skipped"
            assert "Non-GET" in e["check_reason"]


# -------------------------------------------------- 3. Documentation findings vs vulnerabilities

def test_openapi_anonymous_findings_are_observations_not_vulnerabilities():
    endpoints, findings, _ = analyze(ROOT / "input/openapi.json")
    doc_findings = [f for f in findings if f.category == "OpenAPI"]
    assert len(doc_findings) > 0
    for f in doc_findings:
        assert f.severity == "Informational"
        assert f.confidence == "Low"
        assert f.classification == "Documentation observation"
        assert "not establish deployed server behavior or a confirmed vulnerability" in f.description
        assert f.evidence.get("documented_only") is True
        assert f.evidence.get("verified_at_runtime") is False


# -------------------------------------------------- 4. BOLA access comparison & non-destructive checks

def test_bola_identity_mismatch_is_inconclusive(client, identities):
    case = json.loads((ROOT / "input/lab_config.json").read_text())["bola"]
    case["owner_subject"] = "non_existent_subject"
    findings, note = authorization_analysis.analyze(client, case, identities["alice"], identities["bob"])
    assert not findings
    assert "Inconclusive: identity verification failed" in note["outcome"]


def test_bola_access_denied_is_not_vulnerable(client, identities):
    case = json.loads((ROOT / "input/lab_config.json").read_text())["bola"]
    case["path"] = "/api/safe-objects/101"
    findings, note = authorization_analysis.analyze(client, case, identities["alice"], identities["bob"])
    assert not findings
    assert note["outcome"] == "Access denied for other user"


def test_bola_requires_distinct_tokens(client, identities):
    case = json.loads((ROOT / "input/lab_config.json").read_text())["bola"]
    with pytest.raises(ValueError, match="BOLA requires distinct credentials"):
        authorization_analysis.analyze(client, case, identities["alice"], identities["alice"])


# -------------------------------------------------- 5. Rate limit bounded sample and immediate halt

def test_rate_limit_stops_immediately_on_429(client):
    result = rate_limit.analyze(client, "/api/limited", count=5, delay=0.2)[0]
    assert result.title == "Rate limiting observed"
    # Lab responds with 429 after 3 requests; engine halts immediately
    assert len(result.evidence["observations"]) == 4
    assert result.evidence["observations"][-1]["status"] == 429
    assert result.classification == "Observation"


def test_rate_limit_request_bounds(client):
    with pytest.raises(ValueError, match="Rate test count must be 1..10"):
        rate_limit.analyze(client, "/api/public", count=0)
    with pytest.raises(ValueError, match="Rate test count must be 1..10"):
        rate_limit.analyze(client, "/api/public", count=11)
    with pytest.raises(ValueError, match="delay 0.2..10 seconds"):
        rate_limit.analyze(client, "/api/public", count=3, delay=0.05)
