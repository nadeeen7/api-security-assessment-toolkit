"""Flask REST API for the assessment engine.

Two rules shape this file:
  1. It never performs assessments itself, it only drives main.run().
  2. It never returns exception text from the engine, only its own safe messages.
"""
import json
import secrets
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_file
import requests
from werkzeug.exceptions import HTTPException

from main import ASSESSMENT_TESTS
from modules.openapi_analysis import analyze as analyze_openapi
from web import store
from web.jobs import JobManager
from web.request_schema import (
    CATALOGUE_BY_KEY, TEST_CATALOGUE, validate_start, _is_loopback, fetch_openapi_document,
)

# A local tool is reachable by any page the user happens to have open, so
# state-changing routes require BOTH an exact same-origin call AND a per-run
# session token. A cross-origin page can neither read the token (same-origin
# policy blocks reading our responses) nor forge the exact Origin header.
ALLOWED_HOSTNAMES = {"127.0.0.1", "localhost", "::1"}
SESSION_HEADER = "X-Session-Token"
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Development-only: the Vite dev server is a separate loopback origin (5173)
# that proxies /api to Flask. These exact origins are accepted for state-changing
# calls so `npm run dev` keeps working; the session token is still required.
DEFAULT_DEV_ORIGINS = (
    "http://127.0.0.1:5173",
    "http://localhost:5173",
)

OPENAPI_REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
                      "base-uri 'none'; form-action 'none'")

# The SPA bundle is fully self-hosted (no inline scripts, no remote origins).
# style-src allows 'unsafe-inline' only because the progress bar sets a width
# style attribute; scripts remain strictly 'self'.
SPA_CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
           "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

MAX_SPEC_BYTES = 2_000_000

FINDING_FILTERS = ("severity", "category", "endpoint", "confidence")

# The built React SPA lives in webui/dist. Resolve it from this file so the
# path is absolute regardless of the working directory `python -m web` starts in.
WEB_PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_FRONTEND_DIR = (WEB_PACKAGE_DIR.parent / "webui" / "dist").resolve()
SPA_SHELL = "index.html"


def _hostname(value):
    try:
        return (urlsplit("//" + value).hostname or "").lower()
    except ValueError:
        return ""


def _origin_allowed(req, origin, dev_origins):
    """True when `origin` is exactly this request's origin or an allowed dev origin."""
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    same_as_request = (parsed.scheme.lower() == req.scheme.lower()
                       and parsed.netloc.lower() == req.host.lower())
    return same_as_request or origin.rstrip("/").lower() in dev_origins


def _safe_reports(directory):
    """Return which report artifacts actually exist for a finished job."""
    available = {}
    for name in ("report.html", "report.md", "evidence.json"):
        available[name] = (Path(directory) / name).is_file()
    return available


def create_app(root="output/web", manager=None, frontend=None, allow_origins=None):
    # static_folder=None removes Flask's default /static route: the only files
    # this app ever serves are the built SPA assets under webui/dist.
    app = Flask(__name__, static_folder=None)
    app.config["JSON_SORT_KEYS"] = False
    # One unguessable token per app instance (per server run). It is readable
    # only from this origin and is required on every state-changing request.
    session_token = secrets.token_urlsafe(32)
    app.extensions["session_token"] = session_token
    dev_origins = {value.rstrip("/").lower() for value in
                   (DEFAULT_DEV_ORIGINS if allow_origins is None else allow_origins)}
    # Resolve the job root once, absolutely. Flask's send_file() resolves a
    # relative path against the package directory rather than the working
    # directory, so a relative root made the report routes look in web/output/...
    # and fail with a 500 even though the files existed.
    root = Path(root).expanduser().resolve()
    jobs = manager if manager is not None else JobManager(root)
    app.extensions["jobs"] = jobs
    app.extensions["jobs_root"] = str(root)  # already absolute
    frontend_root = Path(frontend if frontend is not None else DEFAULT_FRONTEND_DIR)
    frontend_root = frontend_root.expanduser().resolve()
    app.extensions["frontend_root"] = str(frontend_root)

    # ------------------------------------------------------------------ guards

    @app.before_request
    def guard_local_only():
        if _hostname(request.host) not in ALLOWED_HOSTNAMES:
            return jsonify(error="This API only accepts requests addressed to loopback."), 403
        if request.method in MUTATING_METHODS:
            # Exact origin check: scheme + host + port must match this request's
            # own origin, or be one of the explicitly allowed dev origins.
            origin = request.headers.get("Origin")
            if origin and not _origin_allowed(request, origin, dev_origins):
                return jsonify(error="Cross-origin requests are not accepted."), 403
            supplied = request.headers.get(SESSION_HEADER, "")
            if not supplied or not secrets.compare_digest(supplied, session_token):
                return jsonify(error="Missing or invalid session token."), 403
        return None

    @app.errorhandler(HTTPException)
    def json_errors(exception):
        return jsonify(error=exception.description, status=exception.code), exception.code

    @app.errorhandler(404)
    def spa_not_found(exception):
        # Unknown browser routes fall through to the React shell so deep links and
        # refreshes work. API paths and non-GET methods keep their JSON error, so
        # the SPA can never mask an API 404 or a missing asset.
        if request.method in ("GET", "HEAD") and not _is_api_path(request.path):
            return _spa_response(app, request.path)
        return jsonify(error=exception.description, status=404), 404

    # ------------------------------------------------------------------- meta

    @app.get("/api/session")
    def session():
        """Hand the per-run token to the same-origin SPA.

        A cross-origin page cannot read this JSON (the browser blocks reading
        our responses without CORS), so the token cannot be harvested from
        another site the user happens to have open.
        """
        response = jsonify(token=session_token, header=SESSION_HEADER)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", loopback_only=True, python=sys.version.split()[0],
                       tests_available=list(ASSESSMENT_TESTS),
                       max_requests_per_run=200, minimum_request_delay_seconds=0.2,
                       warning="Only test systems you own or have explicit authorization to assess.")

    @app.get("/api/tests")
    def tests():
        return jsonify(tests=list(TEST_CATALOGUE))

    @app.post("/api/openapi/analyze")
    def openapi_analyze():
        """Validate a supplied document offline. Sends no requests anywhere."""
        payload = request.get_json(silent=True)
        text = payload.get("openapi_text") if isinstance(payload, dict) else None
        if not isinstance(text, str) or not text:
            return jsonify(error="openapi_text is required."), 400
        if len(text) > MAX_SPEC_BYTES:
            return jsonify(error="openapi_text is too large."), 400
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        try:
            handle.write(text)
            handle.close()
            endpoints, findings, metadata = analyze_openapi(handle.name)
        except ValueError as exception:
            # Engine messages here name the failure class, never document contents.
            return jsonify(error=str(exception)), 400
        finally:
            Path(handle.name).unlink(missing_ok=True)
        return jsonify(
            document=metadata.get("version"),
            security_schemes=metadata.get("security_schemes", {}),
            limitations=metadata.get("limitations"),
            endpoints=[{"path": e.path, "method": e.method, "security": e.security,
                        "parameters": e.parameters, "responses": sorted(e.responses),
                        "request_schema_present": bool(e.request_schema)} for e in endpoints],
            findings=[f.to_dict() for f in findings],
            requests_sent=0,
        )

    @app.get("/api/openapi/sample")
    def openapi_sample():
        """Return the built-in sample/lab OpenAPI spec for quick testing."""
        sample_path = Path(__file__).resolve().parent.parent / "input" / "openapi.json"
        if sample_path.is_file():
            return jsonify(content=sample_path.read_text(encoding="utf-8"))
        return jsonify(error="Sample spec not found."), 404

    @app.post("/api/openapi/fetch")
    def openapi_fetch():
        """Fetch an OpenAPI document from a URL safely."""
        payload = request.get_json(silent=True) or {}
        url = payload.get("url")
        authorized = bool(payload.get("authorized", False))
        try:
            res = fetch_openapi_document(url, authorized=authorized)
            return jsonify(
                content=res["content"],
                title=res["title"],
                paths_count=res["paths_count"],
                version=res["version"],
            )
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    # -------------------------------------------------------------- assessments

    @app.post("/api/assessment/start")
    def start_assessment():
        try:
            config = validate_start(request.get_json(silent=True))
        except ValueError as exception:
            return jsonify(error=str(exception)), 400
        try:
            job = jobs.start(config)
        except RuntimeError as exception:
            return jsonify(error=str(exception)), 429
        return jsonify(job_id=job["job_id"], status=job["status"],
                       progress_url="/api/assessment/" + job["job_id"]), 202

    @app.get("/api/assessments")
    def list_assessments():
        return jsonify(assessments=jobs.history())

    @app.get("/api/assessment/<job_id>")
    def assessment_status(job_id):
        try:
            job = jobs.status(job_id)
        except ValueError:
            return jsonify(error="Unknown assessment id."), 404
        directory = Path(app.extensions["jobs_root"]) / job_id
        job["reports"] = _safe_reports(directory) if job["status"] == "completed" else {}
        return jsonify(job)

    @app.get("/api/assessment/<job_id>/findings")
    def assessment_findings(job_id):
        report = _finished_report(app, job_id)
        if isinstance(report, tuple):
            return report
        findings = report.get("findings") or []
        for key in FINDING_FILTERS:
            wanted = request.args.get(key)
            if wanted:
                values = {item.strip().lower() for item in wanted.split(",") if item.strip()}
                findings = [f for f in findings if str(f.get(key, "")).lower() in values]
        return jsonify(total=len(findings), filters={k: request.args.get(k) for k in FINDING_FILTERS if request.args.get(k)},
                       findings=findings)

    @app.get("/api/assessment/<job_id>/endpoints")
    def assessment_endpoints(job_id):
        report = _finished_report(app, job_id)
        if isinstance(report, tuple):
            return report
        return jsonify(endpoints=report.get("endpoints") or [],
                       metadata=report.get("metadata") or {})

    @app.get("/api/assessment/<job_id>/coverage")
    def assessment_coverage(job_id):
        report = _finished_report(app, job_id)
        if isinstance(report, tuple):
            return report
        return jsonify(coverage=report.get("coverage") or {},
                       limitations=report.get("limitations") or [],
                       severity_summary=report.get("severity_summary") or {})

    @app.get("/api/assessment/<job_id>/report/html")
    def report_html(job_id):
        return _report_file(app, job_id, "report.html", "text/html", OPENAPI_REPORT_CSP)

    @app.get("/api/assessment/<job_id>/report/markdown")
    def report_markdown(job_id):
        return _report_file(app, job_id, "report.md", "text/markdown", None)

    @app.get("/api/assessment/<job_id>/evidence.json")
    def report_evidence(job_id):
        return _report_file(app, job_id, "evidence.json", "application/json", None)

    @app.post("/api/assessment/<job_id>/cancel")
    def cancel_assessment(job_id):
        try:
            return jsonify(jobs.cancel(job_id))
        except ValueError:
            return jsonify(error="Unknown assessment id."), 404

    @app.delete("/api/assessment/<job_id>")
    def delete_assessment(job_id):
        try:
            jobs.delete(job_id)
        except ValueError as exception:
            return jsonify(error=str(exception)), 409
        return jsonify(deleted=job_id)

    # ------------------------------------------------- single-origin SPA serving
    #
    # In the packaged run Flask serves the built React app and the JSON API from
    # one origin, so the browser has no cross-origin surface at all. Only files
    # that resolve inside webui/dist are ever sent (see the 404 handler above).

    @app.get("/")
    def spa_root():
        return _spa_index(app)

    return app


def _frontend_root(app):
    return Path(app.extensions["frontend_root"])


def _index_file(app):
    return _frontend_root(app) / SPA_SHELL


def _missing_build(app):
    """A clear, actionable response instead of the JSON 404 from the error handler."""
    return jsonify(
        error="The web interface has not been built.",
        detail="Run `npm --prefix webui ci` then `npm --prefix webui run build`, "
               "then restart `python -m web`.",
        expected=str(_index_file(app)),
    ), 503


def _has_traversal(path):
    """Reject any path that tries to climb out of the build directory."""
    normalized = path.replace("\\", "/")
    if "\x00" in normalized:
        return True
    return any(segment == ".." for segment in normalized.split("/"))


def _is_api_path(path):
    return path == "/api" or path.startswith("/api/")


def _spa_index(app):
    index = _index_file(app)
    if not index.is_file():
        return _missing_build(app)
    response = send_file(index, mimetype="text/html")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = SPA_CSP
    return response


def _spa_response(app, url_path):
    """Serve a real built asset, else the SPA shell for client-side routing."""
    relative = url_path.lstrip("/")
    if not _index_file(app).is_file():
        return _missing_build(app)
    if _has_traversal(relative):
        return jsonify(error="Not found.", status=404), 404
    frontend_root = _frontend_root(app)
    candidate = (frontend_root / relative).resolve()
    if relative and candidate.is_file() and candidate.is_relative_to(frontend_root):
        response = send_file(candidate)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    # A missing path that names a file (has an extension) is a genuine asset
    # miss. Only extension-less app routes fall back to index.html for deep links.
    if Path(relative).suffix:
        return jsonify(error="Not found.", status=404), 404
    return _spa_index(app)


def _finished_report(app, job_id):
    """Return the engine's report dict, or a Flask response tuple on failure."""
    try:
        job = app.extensions["jobs"].status(job_id)
    except ValueError:
        return jsonify(error="Unknown assessment id."), 404
    if job["status"] != "completed":
        return jsonify(error="The assessment has not finished successfully.", status=job["status"]), 409
    directory = Path(app.extensions["jobs_root"]) / job_id
    report = store.read_json(directory / "evidence.json")
    if not isinstance(report, dict):
        return jsonify(error="The report for this assessment is unavailable."), 404
    return report


def _report_file(app, job_id, name, mimetype, csp):
    try:
        job = app.extensions["jobs"].status(job_id)
    except ValueError:
        return jsonify(error="Unknown assessment id."), 404
    if job["status"] != "completed":
        return jsonify(error="The assessment has not finished successfully.", status=job["status"]), 409
    path = Path(app.extensions["jobs_root"]) / job_id / name
    if not path.is_file():
        return jsonify(error="That report is unavailable for this assessment."), 404
    response = send_file(path, mimetype=mimetype, as_attachment=request.args.get("download") == "1",
                         download_name=name)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if csp:
        response.headers["Content-Security-Policy"] = csp
    return response

