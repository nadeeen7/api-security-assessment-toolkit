"""Comprehensive audit and quality regression tests covering:
1. OpenAPI/Swagger parsing (Swagger 2.0, OpenAPI 3.0.x, OpenAPI 3.1.x, YAML, root/operation security).
2. SSRF prevention and safe bounded Fetch Spec.
3. Authentication enforcement analysis and deduplication.
4. VAmPI and generic API compatibility.
5. Secrets redaction and safety controls.
"""
import json
from pathlib import Path
import pytest
from core.models import Endpoint, Observation
from core.http_client import validate_path
from modules import openapi_analysis, auth_analysis
from web.request_schema import (
    fetch_openapi_document, parse_openapi_text, is_blocked_destination,
    _validate_openapi_spec, validate_start
)
from main import scrub

ROOT = Path(__file__).resolve().parents[1]


# ==============================================================================
# Phase 2 — Generic OpenAPI / Swagger Integration Tests
# ==============================================================================

class TestOpenApiParsing:
    def test_openapi_3_0_json_parsed_correctly(self, tmp_path):
        spec = {
            "openapi": "3.0.3",
            "info": {"title": "Test 3.0 API", "version": "1.0.0"},
            "paths": {
                "/items": {
                    "get": {
                        "summary": "List items",
                        "responses": {"200": {"description": "OK"}},
                        "security": [{"bearerAuth": []}]
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"}
                }
            }
        }
        spec_path = tmp_path / "openapi3.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        endpoints, findings, meta = openapi_analysis.analyze(str(spec_path))
        assert len(endpoints) == 1
        assert endpoints[0].path == "/items"
        assert endpoints[0].method == "GET"
        assert endpoints[0].security == [{"bearerAuth": []}]
        assert meta["version"] == "3.0.3"
        assert "bearerAuth" in meta["security_schemes"]

    def test_swagger_2_0_with_basepath(self, tmp_path):
        spec = {
            "swagger": "2.0",
            "info": {"title": "Swagger 2 API", "version": "1.0"},
            "basePath": "/v1",
            "paths": {
                "/users": {
                    "get": {
                        "responses": {"200": {"description": "OK"}},
                        "security": []
                    }
                }
            },
            "securityDefinitions": {
                "api_key": {"type": "apiKey", "name": "X-API-Key", "in": "header"}
            }
        }
        spec_path = tmp_path / "swagger2.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        endpoints, findings, meta = openapi_analysis.analyze(str(spec_path))
        assert len(endpoints) == 1
        assert endpoints[0].path == "/v1/users"
        assert endpoints[0].method == "GET"
        assert meta["version"] == "2.0"
        assert "api_key" in meta["security_schemes"]

    def test_openapi_yaml_parsing(self, tmp_path):
        yaml_content = """
openapi: "3.0.1"
info:
  title: "YAML Sample API"
  version: "1.0.0"
paths:
  /data:
    get:
      responses:
        "200":
          description: "Success"
      security: []
"""
        yaml_path = tmp_path / "spec.yaml"
        yaml_path.write_text(yaml_content, encoding="utf-8")
        endpoints, findings, meta = openapi_analysis.analyze(str(yaml_path))
        assert len(endpoints) == 1
        assert endpoints[0].path == "/data"
        assert meta["version"] == "3.0.1"

    def test_root_security_inheritance_and_override(self, tmp_path):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Security Inheritance API", "version": "1.0.0"},
            "security": [{"rootAuth": []}],
            "paths": {
                "/inherited": {
                    "get": {
                        "responses": {"200": {"description": "OK"}}
                    }
                },
                "/public-override": {
                    "get": {
                        "responses": {"200": {"description": "OK"}},
                        "security": []
                    }
                }
            }
        }
        spec_path = tmp_path / "sec.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        endpoints, findings, _ = openapi_analysis.analyze(str(spec_path))
        by_path = {e.path: e for e in endpoints}
        # /inherited inherits rootAuth
        assert by_path["/inherited"].security == [{"rootAuth": []}]
        assert auth_analysis.requires_auth(by_path["/inherited"].security) is True
        # /public-override overrides with empty security
        assert by_path["/public-override"].security == []
        assert auth_analysis.requires_auth(by_path["/public-override"].security) is False

    def test_unsupported_version_rejected(self, tmp_path):
        spec = {
            "openapi": "1.2.0",
            "info": {"title": "Old API", "version": "1.0.0"},
            "paths": {}
        }
        spec_path = tmp_path / "old.json"
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        with pytest.raises(ValueError, match="Supported versions"):
            openapi_analysis.analyze(str(spec_path))

    def test_oversized_spec_rejected(self, tmp_path):
        huge_path = tmp_path / "huge.json"
        huge_path.write_bytes(b"x" * 2_000_001)
        with pytest.raises(ValueError, match="exceeds 2 MB"):
            openapi_analysis.analyze(str(huge_path))


# ==============================================================================
# Phase 2 — SSRF Prevention & Fetch Spec Safety
# ==============================================================================

class TestSsrfAndFetchSafety:
    def test_cloud_metadata_ip_blocked(self):
        blocked, reason = is_blocked_destination("169.254.169.254")
        assert blocked is True
        assert "metadata" in reason.lower() or "link-local" in reason.lower()

    def test_cloud_metadata_hostname_blocked(self):
        blocked, reason = is_blocked_destination("metadata.google.internal")
        assert blocked is True
        assert "metadata" in reason.lower()

    def test_private_rfc1918_ips_blocked(self):
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.100"):
            blocked, reason = is_blocked_destination(ip)
            assert blocked is True
            assert "private" in reason.lower()

    def test_loopback_allowed_for_lab(self):
        for host in ("127.0.0.1", "localhost"):
            blocked, _ = is_blocked_destination(host)
            assert blocked is False

    def test_fetch_spec_blocks_ssrf_attempt(self):
        with pytest.raises(ValueError, match="prohibited"):
            fetch_openapi_document("http://169.254.169.254/latest/meta-data", authorized=True)

    def test_fetch_spec_blocks_non_loopback_http(self):
        with pytest.raises(ValueError, match="requires HTTPS"):
            fetch_openapi_document("http://api.example.com/openapi.json", authorized=True)

    def test_fetch_spec_blocks_non_loopback_without_auth(self):
        with pytest.raises(ValueError, match="requires explicit authorization"):
            fetch_openapi_document("https://api.example.com/openapi.json", authorized=False)


# ==============================================================================
# Phase 3 & 4 — Authentication Enforcement & Deduplication Tests
# ==============================================================================

class TestAuthEnforcementAndDeduplication:
    def test_anonymous_200_flags_potential_issue(self, client):
        """Anonymous 200 on protected endpoint reports auth_bypass when no credentials available."""
        ep = Endpoint("/api/auth-missing", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/auth-missing")
        assert anon.status == 200
        findings = auth_analysis.analyze(ep, anon, None)
        assert len(findings) == 1
        f = findings[0]
        assert f.title == "Documented-protected endpoint accessible without authentication"
        assert f.severity == "Medium"
        assert f.classification == "Potential issue"
        assert f.cwe == "CWE-306"

    def test_body_equality_supersedes_unauthenticated_200_no_duplicate(self, client, identities):
        """When bodies match, only the definitive body-equality finding is returned."""
        ep = Endpoint("/api/auth-missing", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/auth-missing")
        auth = client.request("GET", "/api/auth-missing", headers=identities["alice"])
        findings = auth_analysis.analyze(ep, anon, auth)
        # Exactly 1 finding; not 2
        assert len(findings) == 1
        assert findings[0].title == "Possible missing authentication enforcement"
        assert findings[0].evidence["json_equal"] is True

    def test_protected_endpoint_401_no_finding(self, client):
        """Properly protected endpoint returning 401 anonymously produces no finding."""
        ep = Endpoint("/api/protected", security=[{"bearerAuth": []}])
        anon = client.request("GET", "/api/protected")
        assert anon.status == 401
        assert auth_analysis.analyze(ep, anon, None) == []

    def test_public_endpoint_no_finding(self, client):
        """Genuinely public endpoint producing 200 produces no finding."""
        ep = Endpoint("/api/public", security=[])
        anon = client.request("GET", "/api/public")
        assert anon.status == 200
        assert auth_analysis.analyze(ep, anon, None) == []


# ==============================================================================
# Phase 9 — Secrets Redaction
# ==============================================================================

class TestSecretsRedaction:
    def test_scrub_redacts_tokens(self):
        secret = "secret-token-12345"
        data = {
            "header": f"Bearer {secret}",
            "nested": [{"val": secret}, "public-data"]
        }
        clean = scrub(data, [secret])
        assert secret not in str(clean)
        assert clean["header"] == "Bearer [REDACTED]"
        assert clean["nested"][0]["val"] == "[REDACTED]"
        assert clean["nested"][1] == "public-data"

    def test_scrub_ignores_empty_strings(self):
        data = "hello world"
        clean = scrub(data, ["", None])
        assert clean == "hello world"
