import json
from pathlib import Path
import pytest
from modules.openapi_analysis import analyze
from modules.endpoint_discovery import discover
from modules.parameter_discovery import extract
from core.models import Endpoint

ROOT = Path(__file__).resolve().parents[1]

def test_openapi_discovery_security_and_schemas():
    endpoints, findings, metadata = analyze(ROOT / "input/openapi.json")
    assert len(endpoints) == 10
    assert metadata["security_schemes"]["bearerAuth"]["scheme"] == "bearer"
    obj = next(e for e in endpoints if e.path == "/api/objects/{object_id}")
    assert obj.responses["200"]["content"]["application/json"]["schema"]["properties"]["owner"]
    assert obj.security == [{"bearerAuth": []}]
    assert all(f.severity == "Informational" for f in findings)

def test_swagger2_and_operation_override(tmp_path):
    spec = {"swagger":"2.0", "info":{"title":"Test", "version":"1"}, "basePath":"/v1",
      "securityDefinitions":{"key":{"type":"apiKey", "in":"header", "name":"X-Key"}},
      "security":[{"key":[]}], "paths":{"/items":{"get":{"security":[], "responses":{"200":{"description":"OK"}}}}}}
    path = tmp_path / "swagger.json"
    path.write_text(json.dumps(spec))
    endpoints, _, _ = analyze(path)
    assert endpoints[0].path == "/v1/items"
    assert endpoints[0].security == []

def test_reject_external_refs_before_validation(tmp_path):
    path = tmp_path / "external.json"
    path.write_text('{"openapi":"3.0.3", "$ref":"https://example.com/spec"}')
    with pytest.raises(ValueError, match="document-local"):
        analyze(path)

def test_invalid_spec_and_empty_list(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text('{"openapi":"3.0.3"}')
    with pytest.raises(ValueError, match="validation failed"):
        analyze(path)
    path.write_text('[]')
    assert discover(endpoint_file=path)[0] == []

def test_parameter_names_not_values():
    endpoint = Endpoint("/objects/{id}?api_key=secret", request_schema={"type":"object", "properties":{"name":{"type":"string"}, "nested":{"type":"object", "properties":{"age":{"type":"integer"}}}}})
    result = extract(endpoint)
    assert {p["name"] for p in result} >= {"id", "api_key", "name", "nested.age"}
    assert "secret" not in str(result)
