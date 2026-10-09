"""Flask serves the built React SPA safely from a single origin.

These tests use a tiny synthetic build directory so they are deterministic and
never depend on the hashed asset names Vite produces. One test also checks the
real default `webui/dist` path, which exists after `npm --prefix webui run build`.

They inherit conftest.py's autouse loopback guard: nothing here contacts a real
API. The route under test either serves a local file or returns JSON.
"""
from pathlib import Path

import pytest

from web.app import DEFAULT_FRONTEND_DIR, SESSION_HEADER, create_app

SHELL_MARKER = b"SPA-SHELL-MARKER"
ASSET_MARKER = b"SPA-ASSET-MARKER"

DEEP_LINKS = [
    "/",
    "/history",
    "/assessment/631f16a08a3641b984c4f05a4e9e1ee7",
    "/assessment/631f16a08a3641b984c4f05a4e9e1ee7/results",
    "/assessment/631f16a08a3641b984c4f05a4e9e1ee7/findings",
    "/assessment/631f16a08a3641b984c4f05a4e9e1ee7/findings/3",
    "/assessment/631f16a08a3641b984c4f05a4e9e1ee7/reports",
]


def build_fake_dist(directory):
    (directory / "assets").mkdir(parents=True)
    (directory / "index.html").write_text(
        "<!doctype html><html><body><div id=\"root\">SPA-SHELL-MARKER</div></body></html>",
        encoding="utf-8",
    )
    (directory / "assets" / "app.js").write_text(
        "console.log('SPA-ASSET-MARKER');\n", encoding="utf-8"
    )
    (directory / "assets" / "app.css").write_text(".x{color:red}\n", encoding="utf-8")
    return directory


@pytest.fixture
def ui(tmp_path):
    dist = build_fake_dist(tmp_path / "dist")
    app = create_app(root=str(tmp_path / "jobs"), frontend=str(dist))
    return app, app.test_client(), dist


@pytest.mark.parametrize("path", DEEP_LINKS)
def test_spa_shell_is_served_for_app_routes(ui, path):
    """Deep links and the root all return the React index, never a Flask 404."""
    _, client, _ = ui
    response = client.get(path)
    assert response.status_code == 200, path
    assert response.mimetype == "text/html"
    assert SHELL_MARKER in response.data


def test_built_assets_are_served_with_correct_content_types(ui):
    _, client, _ = ui
    script = client.get("/assets/app.js")
    stylesheet = client.get("/assets/app.css")
    assert script.status_code == 200
    assert "javascript" in script.headers["Content-Type"]
    assert ASSET_MARKER in script.data
    assert stylesheet.status_code == 200
    assert "css" in stylesheet.headers["Content-Type"]


def test_unknown_asset_with_extension_is_a_404_not_the_shell(ui):
    _, client, _ = ui
    response = client.get("/assets/does-not-exist.js")
    assert response.status_code == 404
    assert SHELL_MARKER not in response.data


def test_unknown_api_route_stays_json_404(ui):
    """The SPA fallback must never hide an API error behind index.html."""
    _, client, _ = ui
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.mimetype == "application/json"
    assert response.get_json().get("error")
    assert SHELL_MARKER not in response.data
    # The bare /api path is not an application route either.
    assert client.get("/api").status_code == 404


def test_unknown_api_route_is_json_for_mutating_methods(ui):
    app, client, _ = ui
    headers = {SESSION_HEADER: app.extensions["session_token"]}
    response = client.post("/api/does-not-exist", json={}, headers=headers)
    assert response.status_code in (404, 405)
    assert response.mimetype == "application/json"
    assert SHELL_MARKER not in response.data


def test_spa_shell_carries_a_restrictive_csp(ui):
    _, client, _ = ui
    csp = client.get("/").headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src" not in csp  # default-src 'none' already blocks objects


def test_spa_assets_are_not_served_csp_as_html(ui):
    # A JS asset must keep its script content type and not gain the HTML CSP.
    _, client, _ = ui
    response = client.get("/assets/app.js")
    assert "javascript" in response.headers["Content-Type"]
    assert "Content-Security-Policy" not in response.headers


def test_existing_api_routes_still_work_with_spa_enabled(ui):
    _, client, _ = ui
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.get_json()["status"] == "ok"


@pytest.mark.parametrize("path", [
    "/../web/app.py",
    "/..%2f..%2fweb%2fapp.py",
    "/assets/../../web/app.py",
    "/assets/%2e%2e/%2e%2e/web/app.py",
    "/%2e%2e/web/app.py",
    "/..\\..\\web\\app.py",
    "/../../../../etc/passwd",
])
def test_path_traversal_is_rejected(ui, path):
    _, client, _ = ui
    response = client.get(path)
    assert response.status_code == 404, path
    # Neither the SPA shell nor any source file may leak.
    assert SHELL_MARKER not in response.data
    assert b"create_app" not in response.data
    assert b"root:x:" not in response.data


def test_files_outside_the_build_directory_are_never_served(tmp_path):
    dist = build_fake_dist(tmp_path / "dist")
    outside = tmp_path / "secret.txt"
    outside.write_text("TOP-SECRET-OUTSIDE-DIST", encoding="utf-8")
    app = create_app(root=str(tmp_path / "jobs"), frontend=str(dist))
    client = app.test_client()
    for path in ("/secret.txt", "/../secret.txt", "/assets/../secret.txt"):
        response = client.get(path)
        assert b"TOP-SECRET-OUTSIDE-DIST" not in response.data


def test_missing_build_returns_actionable_503(tmp_path):
    app = create_app(root=str(tmp_path / "jobs"), frontend=str(tmp_path / "does-not-exist"))
    client = app.test_client()
    for path in ("/", "/history", "/assessment/" + "0" * 32 + "/results"):
        response = client.get(path)
        assert response.status_code == 503, path
        assert response.mimetype == "application/json"
        assert "not been built" in response.get_json()["error"]


def test_spa_still_honours_the_loopback_guard(ui):
    _, client, _ = ui
    assert client.get("/", base_url="http://attacker.test").status_code == 403


def test_default_frontend_is_absolute_and_points_at_webui_dist():
    assert DEFAULT_FRONTEND_DIR.is_absolute()
    assert DEFAULT_FRONTEND_DIR.name == "dist"
    assert DEFAULT_FRONTEND_DIR.parent.name == "webui"
    app = create_app(root="output/web")
    assert Path(app.extensions["frontend_root"]) == DEFAULT_FRONTEND_DIR
    # The real production build must actually be served from the default path.
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b'<div id="root">' in response.data
