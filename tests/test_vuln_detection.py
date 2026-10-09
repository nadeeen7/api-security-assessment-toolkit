"""Tests for the new vulnerability detection capabilities:

1. auth_bypass — anonymous HTTP 200 on a documented-protected endpoint
2. auth (body-equality) — still fires when anonymous and authenticated bodies match
3. BOLA via inline login_endpoint — no pre-written token files needed
4. login_via_endpoint helper
5. Integration: full assessment run flags the intentional vulnerabilities

All tests use the local lab server; no external requests are made (conftest
block_external_network fixture enforces 127.0.0.1 only).
"""
import json
from pathlib import Path
import pytest
from core.models import Endpoint, Observation
from modules import auth_analysis
from modules.authorization_analysis import login_via_endpoint
from main import parser, run

ROOT = Path(__file__).resolve().parents[1]


# ------------ 1. Auth bypass (anonymous 200) ----------------------------------

class TestAuthBypassFinding:
    """auth_analysis.analyze() should flag anonymous 200 on protected endpoints."""

    def test_anonymous_200_on_protected_endpoint(self, client):
        """Lab auth-missing: documented as protected, no enforcement."""
        endpoint = Endpoint("/api/auth-missing", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/auth-missing")
        assert anon.status == 200
        result = auth_analysis.analyze(endpoint, anon, None)
        assert len(result) >= 1
        bypass = next((f for f in result if f.title.startswith("Documented-protected")), None)
        assert bypass is not None
        assert bypass.severity == "Medium"
        assert bypass.evidence["anonymous_status"] == 200
        assert bypass.evidence["verified_at_runtime"] is True
        assert bypass.evidence["comparison_available"] is False
        assert "Potential issue" in bypass.classification
        assert bypass.cwe == "CWE-306"

    def test_anonymous_200_with_auth_comparison(self, client):
        """With auth available and differing responses, comparison evidence is attached."""
        endpoint = Endpoint("/api/auth-missing", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/auth-missing")
        authenticated = Observation("GET", "/api/auth-missing", 200, data={"user": "alice", "private": True})
        result = auth_analysis.analyze(endpoint, anon, authenticated)
        bypass = next((f for f in result if "Documented-protected" in f.title), None)
        assert bypass is not None
        assert bypass.evidence["comparison_available"] is True

    def test_no_false_positive_on_public_endpoint(self, client):
        """Public endpoint must not trigger auth_bypass."""
        endpoint = Endpoint("/api/public", security=[])
        anon = client.request("GET", "/api/public")
        assert auth_analysis.analyze(endpoint, anon, None) == []

    def test_no_false_positive_when_401_returned(self, client):
        """Correctly enforced endpoint returning 401 must not be flagged."""
        endpoint = Endpoint("/api/protected", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/protected")
        assert anon.status == 401
        assert auth_analysis.analyze(endpoint, anon, None) == []

    def test_no_false_positive_security_none(self, client):
        """security=None must not trigger auth_bypass."""
        endpoint = Endpoint("/api/public", security=None)
        anon = client.request("GET", "/api/public")
        assert auth_analysis.analyze(endpoint, anon, None) == []


# ------------ 2. Body-equality finding still fires ----------------------------

class TestBodyEqualityFinding:

    def test_body_equality_fires_when_bodies_match(self, client, identities):
        """auth-missing returns same body to anon and authenticated callers."""
        endpoint = Endpoint("/api/auth-missing", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/auth-missing")
        authenticated = client.request("GET", "/api/auth-missing", headers=identities["alice"])
        result = auth_analysis.analyze(endpoint, anon, authenticated)
        eq_f = next((f for f in result if "identical JSON" in f.description), None)
        assert eq_f is not None
        assert eq_f.evidence["json_equal"] is True

    def test_body_equality_does_not_fire_when_bodies_differ(self, client, identities):
        """Endpoint that 401s anon: no body-equality finding."""
        endpoint = Endpoint("/api/protected", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/protected")
        auth = client.request("GET", "/api/protected", headers=identities["alice"])
        result = auth_analysis.analyze(endpoint, anon, auth)
        assert not any("identical JSON" in f.description for f in result)


# ------------ 3. login_via_endpoint helper ------------------------------------

class TestLoginViaEndpoint:

    def test_returns_bearer_header(self, client):
        secrets = []
        h = login_via_endpoint(client, "/api/login", "alice", "alice-lab-only", secrets)
        assert h is not None
        assert h["Authorization"].startswith("Bearer ")
        assert len(secrets) == 1

    def test_wrong_password_returns_none(self, client):
        assert login_via_endpoint(client, "/api/login", "alice", "wrong", []) is None

    def test_unknown_user_returns_none(self, client):
        assert login_via_endpoint(client, "/api/login", "nobody", "x", []) is None

    def test_two_users_get_distinct_tokens(self, client):
        alice = login_via_endpoint(client, "/api/login", "alice", "alice-lab-only", [])
        bob = login_via_endpoint(client, "/api/login", "bob", "bob-lab-only", [])
        assert alice is not None and bob is not None
        assert alice != bob


# ------------ 4. BOLA via inline login ----------------------------------------

class TestBolaViaInlineLogin:

    def test_bola_detected_via_login_endpoint(self, client):
        from modules import authorization_analysis as aa
        secrets = []
        alice_h = login_via_endpoint(client, "/api/login", "alice", "alice-lab-only", secrets)
        bob_h = login_via_endpoint(client, "/api/login", "bob", "bob-lab-only", secrets)
        case = {
            "path": "/api/objects/101",
            "identity_path": "/api/me",
            "owner_subject": "alice",
            "other_subject": "bob",
            "expected_object_id": 101,
            "id_field": "id",
            "owner_field": "owner",
        }
        findings, note = aa.analyze(client, case, alice_h, bob_h)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "High"
        assert "BOLA" in f.title
        assert note["outcome"] == "Potential BOLA"

    def test_safe_endpoint_not_flagged(self, client):
        from modules import authorization_analysis as aa
        secrets = []
        alice_h = login_via_endpoint(client, "/api/login", "alice", "alice-lab-only", secrets)
        bob_h = login_via_endpoint(client, "/api/login", "bob", "bob-lab-only", secrets)
        case = {
            "path": "/api/safe-objects/101",
            "identity_path": "/api/me",
            "owner_subject": "alice",
            "other_subject": "bob",
            "expected_object_id": 101,
            "id_field": "id",
            "owner_field": "owner",
        }
        findings, note = aa.analyze(client, case, alice_h, bob_h)
        assert findings == []
        assert note["outcome"] == "Access denied for other user"


# ------------ 5. Full integration run ----------------------------------------

class TestIntegrationRun:

    def test_auth_bypass_in_assessment_findings(self, lab, tmp_path):
        _, url = lab
        out = tmp_path / "out"
        args = parser().parse_args([
            "--target", url,
            "--openapi", str(ROOT / "input/openapi.json"),
            "--output", str(out),
        ])
        run(args, selected={"endpoint_discovery", "openapi_analysis", "auth_analysis"})
        evidence = json.loads((out / "evidence.json").read_text())
        bypass_findings = [
            f for f in evidence["findings"] if "Documented-protected" in f["title"]
        ]
        assert len(bypass_findings) >= 1, (
            f"Expected auth_bypass finding; got titles: {[f['title'] for f in evidence['findings']]}"
        )
        bypass = bypass_findings[0]
        assert bypass["endpoint"] == "/api/auth-missing"
        assert bypass["severity"] == "Medium"
        assert bypass["evidence"]["verified_at_runtime"] is True

    def test_bola_login_config_produces_finding(self, lab, tmp_path):
        _, url = lab
        out = tmp_path / "out"
        config_file = ROOT / "input/lab_bola_login_config.json"
        assert config_file.exists()
        args = parser().parse_args([
            "--target", url,
            "--config", str(config_file),
            "--bola",
            "--output", str(out),
        ])
        run(args, selected={"endpoint_discovery", "authorization"})
        evidence = json.loads((out / "evidence.json").read_text())
        bola_findings = [f for f in evidence["findings"] if "BOLA" in f["title"]]
        assert len(bola_findings) >= 1, (
            f"Expected BOLA finding; got: {[f['title'] for f in evidence['findings']]}"
        )
        assert bola_findings[0]["severity"] == "High"
        raw = (out / "evidence.json").read_text()
        assert "alice-lab-only" not in raw
        assert "bob-lab-only" not in raw

    def test_protected_endpoints_show_401_no_bypass(self, lab, tmp_path):
        _, url = lab
        out = tmp_path / "out"
        args = parser().parse_args([
            "--target", url,
            "--openapi", str(ROOT / "input/openapi.json"),
            "--output", str(out),
        ])
        run(args, selected={"endpoint_discovery", "openapi_analysis", "auth_analysis"})
        evidence = json.loads((out / "evidence.json").read_text())
        protected_ep = next(
            (e for e in evidence["endpoints"] if e["path"] == "/api/protected"), None
        )
        assert protected_ep is not None
        assert protected_ep["actual_status"] == 401
        # No false-positive bypass finding for /api/protected
        false_positives = [
            f for f in evidence["findings"]
            if "Documented-protected" in f["title"] and f["endpoint"] == "/api/protected"
        ]
        assert false_positives == []
