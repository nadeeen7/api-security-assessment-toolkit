import pytest
import requests
from core.http_client import HTTPClient, validate_path

def test_json_status_post_and_identity_isolation(client, identities):
    assert client.request("GET", "/api/public").data["message"]
    assert client.request("GET", "/api/me", headers=identities["alice"]).data["sub"] == "alice"
    assert client.request("GET", "/api/me").status == 401
    assert client.request("GET", "/api/me", headers=identities["bob"]).data["sub"] == "bob"
    assert client.request("POST", "/api/login", json={"username":"alice", "password":"alice-lab-only"}).status == 200

@pytest.mark.parametrize("path", ["https://example.com/", "//example.com/", "/../x", "/%2e%2e/x", "/x#fragment", "/%5cevil", "/x%0d%0aHost:x"])
def test_path_scope(path):
    with pytest.raises(ValueError):
        validate_path(path)

def test_nonlocal_guard():
    with pytest.raises(ValueError):
        HTTPClient("https://example.com")
    with pytest.raises(ValueError):
        HTTPClient("http://example.com", authorized=True)

def test_disallowed_methods_and_budget(lab):
    client = HTTPClient(lab[1], max_requests=1)
    with pytest.raises(ValueError):
        client.request("DELETE", "/api/public")
    with pytest.raises(ValueError):
        client.request("POST", "/api/login")
    assert client.request("GET", "/api/public").status == 200
    assert client.request("GET", "/api/public").error == "Request budget reached"
    assert client.count == 1
    client.close()

def test_timeout_stops_and_does_not_leak(client, monkeypatch):
    def fail(*a, **kw):
        raise requests.Timeout("secret password content")
    monkeypatch.setattr(client.session, "request", fail)
    obs = client.request("GET", "/api/public?secret=123")
    assert obs.error == "Timeout"
    assert "secret" not in str(obs.evidence())
    assert client.request("GET", "/api/public").status is None
    assert client.count == 1

def test_redirect_not_followed(lab):
    from flask import redirect
    app, target = lab
    app.add_url_rule("/redirect", view_func=lambda: redirect("https://example.com/"))
    client = HTTPClient(target)
    assert client.request("GET", "/redirect").status == 302
    assert client.count == 1
    client.close()

def test_oversize_body_and_error_stop(lab):
    app, target = lab
    app.add_url_rule("/large", endpoint="large", view_func=lambda: ("x"*300000, 200, {"Content-Type":"application/json"}))
    app.add_url_rule("/error", endpoint="error", view_func=lambda: ("Synthetic error", 503))
    client = HTTPClient(target)
    assert client.request("GET", "/large").truncated
    assert client.request("GET", "/error").status == 503
    assert client.request("GET", "/api/public").status is None
    client.close()
