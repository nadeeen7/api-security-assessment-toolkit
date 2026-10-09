"""CLI coordinator: parse inputs, run bounded checks, write reports."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from core.http_client import HTTPClient, validate_path
from core.models import Endpoint
from core.logger import get_logger
from modules.endpoint_discovery import discover
from modules import auth_analysis, authorization_analysis, cors_analysis, headers_analysis
from modules import jwt_analysis, method_detection, parameter_discovery, rate_limit
from modules.authorization_analysis import login_via_endpoint as _login_via_endpoint
from reports.report_generator import generate

WARNING = "Only test systems you own or have explicit authorization to assess."

# One key per selectable assessment phase; one key per user-facing checkbox.
# Selection only ever GATES work and never triggers it: BOLA still requires --bola
# and rate testing still requires --rate-limit-path. Passing no selection (the CLI)
# runs every phase its arguments imply, which is the original behaviour.
ASSESSMENT_TESTS = ("endpoint_discovery", "openapi_analysis", "parameter_discovery",
                    "method_analysis", "auth_analysis", "authorization", "jwt_analysis",
                    "headers_analysis", "cors_analysis", "rate_limit")

def emit(progress, phase, **detail):
    """Report a phase boundary to an optional callback. The CLI passes none."""
    if progress is not None:
        progress(phase, detail)

def parser():
    p = argparse.ArgumentParser(description="Controlled API assessment; local lab first.")
    p.add_argument("--target", help="Origin only, e.g. http://127.0.0.1:5000")
    p.add_argument("--authorized", action="store_true", help="Confirm explicit permission for a non-loopback HTTPS target")
    p.add_argument("--openapi", help="Local Swagger 2/OpenAPI 3 JSON file")
    p.add_argument("--endpoints", help="Local JSON list of endpoint paths or objects")
    p.add_argument("--config", help="Local JSON identity/BOLA config; token paths relative to config")
    p.add_argument("--output", default="output/latest")
    p.add_argument("--timeout", type=float, default=5)
    p.add_argument("--max-requests", type=int, default=100)
    p.add_argument("--delay", type=float, default=0.2)
    p.add_argument("--jwt-file", help="Locally inspect one JWT without server verification")
    p.add_argument("--bola", action="store_true", help="Run the single explicitly configured two-user case")
    p.add_argument("--rate-limit-path", help="Opt in to a small GET-only rate sample on this exact path")
    p.add_argument("--rate-limit-count", type=int, default=5)
    p.add_argument("--rate-limit-delay", type=float, default=0.5)
    p.add_argument("--check-environment", action="store_true")
    return p


def read_token(path):
    if Path(path).stat().st_size > 16000:
        raise ValueError("Token file is too large")
    token = Path(path).read_text(encoding="utf-8").strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError("Token must be a single non-empty value")
    return token


def _valid_header_name(name):
    return isinstance(name, str) and 1 <= len(name) <= 64 and all(c.isalnum() or c in "-_" for c in name)


def _read_identity(base, item, secrets):
    """Turn one configured identity into request headers, scheme-agnostic.

    Backward compatible: {"token_file": ...} is a Bearer token. The richer
    {"auth": {"type": ...}} form supports Bearer, API key, Basic and a custom
    header so the toolkit can adapt to different real APIs.
    """
    auth = item.get("auth") if isinstance(item, dict) else None
    if auth is None:
        token = read_token(base / item["token_file"])
        secrets.append(token)
        return {"Authorization": "Bearer " + token}
    kind = auth.get("type", "bearer")
    if kind == "bearer":
        token = read_token(base / auth["token_file"])
        secrets.append(token)
        return {"Authorization": "Bearer " + token}
    if kind in ("api_key", "header"):
        header = auth.get("header")
        if not _valid_header_name(header):
            raise ValueError("Identity header name is not a simple HTTP header name")
        value = read_token(base / auth["value_file"])
        secrets.append(value)
        return {header: value}
    if kind == "basic":
        username = read_token(base / auth["username_file"])
        password = read_token(base / auth["password_file"])
        secrets.append(password)
        import base64
        encoded = base64.b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
        return {"Authorization": "Basic " + encoded}
    raise ValueError("Unsupported identity authentication type")


def load_config(filename):
    if not filename:
        return {}, {}, []
    path = Path(filename)
    if path.stat().st_size > 100_000:
        raise ValueError("Configuration is too large")
    # utf-8-sig handles both UTF-8 with and without a BOM (e.g. PowerShell Out-File).
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    identities, secrets = {}, []
    for name, item in config.get("identities", {}).items():
        identities[name] = _read_identity(path.parent, item, secrets)
    return config, identities, secrets


def _applicability(args, endpoints, auth_available, bola):
    """Return a plain-language reason for each selected test that cannot run.

    A test absent from this map is applicable and will be attempted; a test in
    the map is reported as skipped with its reason, never as executed.
    """
    reasons = {}
    if not args.openapi:
        reasons["openapi_analysis"] = "No OpenAPI/Swagger document was supplied"
    if not endpoints:
        reasons["parameter_discovery"] = "No endpoints available to inspect"
    if not args.target:
        reasons["method_analysis"] = "No target supplied; OPTIONS cannot be observed"
        reasons["headers_analysis"] = "No target supplied; no responses to inspect"
        reasons["auth_analysis"] = "No target supplied"
        reasons["cors_analysis"] = "No target supplied"
    else:
        if not auth_available:
            reasons["cors_analysis"] = "No authenticated identity available for the credentialed CORS check"
            if not any(auth_analysis.requires_auth(ep.security) for ep in endpoints):
                reasons["auth_analysis"] = "No authenticated identity available"
    if not (args.bola and bola):
        reasons["authorization"] = "No BOLA case configured (two identities, object path and identity path)"
    if not args.jwt_file:
        reasons["jwt_analysis"] = "No JWT supplied to inspect"
    if not args.rate_limit_path:
        reasons["rate_limit"] = "No rate-limit path supplied for a bounded sample"
    # Note: authorization via login_endpoint requires a loopback target; checked at runtime.
    return reasons


def run_module(records, key, func):
    """Run one selected module, isolating its failure and recording its status."""
    record = records[key]
    if record["status"] == "skipped":
        return []
    try:
        produced = func() or []
    except Exception as exception:  # isolate: one module cannot abort the run
        record["status"] = "failed"
        record["reason"] = "Module error: " + type(exception).__name__
        return []
    record["findings"] += len(produced)
    record["status"] = "finding" if record["findings"] else "passed"
    return produced

def scrub(value, secrets):
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {scrub(k, secrets): scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secrets) for v in value]
    return value

def run(args, progress=None, selected=None):
    """Run one controlled assessment and write the reports.

    `progress` and `selected` are optional and additive. The CLI calls run(args)
    and keeps its original behaviour byte-for-byte; the web API passes both.
    """
    if sys.version_info < (3, 11):
        raise ValueError("Python 3.11 or newer is required")
    if selected is None:
        selected = set(ASSESSMENT_TESTS)
    else:
        selected = set(selected)
        if selected - set(ASSESSMENT_TESTS):
            raise ValueError("Unknown assessment test selection")
    if args.check_environment:
        from importlib.metadata import version
        print("Python:", sys.version.split()[0])
        print("Executable:", sys.executable)
        print("Virtual environment:", sys.prefix != sys.base_prefix)
        for package in ("requests", "PyJWT", "openapi-spec-validator", "Flask", "Jinja2", "pytest"):
            print(package + ":", version(package))
        print("Environment check passed. No API requests sent.")
        return []
    if not any((args.target, args.openapi, args.endpoints, args.jwt_file)):
        raise ValueError("Choose --target, --openapi, --endpoints, --jwt-file, or --check-environment")
    if (args.bola or args.rate_limit_path or args.config) and not args.target:
        raise ValueError("Active test configuration requires --target")
    if not 1 <= args.rate_limit_count <= 10 or not 0.2 <= args.rate_limit_delay <= 10:
        raise ValueError("Rate settings: count 1..10, delay 0.2..10")
    if args.rate_limit_path:
        validate_path(args.rate_limit_path)
    endpoints, findings, metadata = discover(args.openapi, args.endpoints)
    if args.openapi:
        emit(progress, "openapi_analysis", document=str(metadata.get("version", "unknown")),
             security_schemes=sorted(metadata.get("security_schemes", {})))
    if "openapi_analysis" not in selected:
        findings = [f for f in findings if f.category != "OpenAPI"]
    emit(progress, "endpoint_discovery", endpoints=len(endpoints))
    if not endpoints and args.target:
        endpoints = [Endpoint("/api/public")]
    if len(endpoints) > 100:
        raise ValueError("At most 100 documented endpoints are accepted per run")
    config, identities, secrets = load_config(args.config)
    auth_name = config.get("default_identity")
    if auth_name and auth_name not in identities:
        raise ValueError("Unknown default_identity")
    auth = identities.get(auth_name)
    bola = config.get("bola")
    # BOLA may use either pre-written token files (identities map) or an inline
    # login_endpoint + owner_credentials/other_credentials in the BOLA config block.
    # The inline-login path is only wired after a live client is created (loopback only).
    _bola_uses_login = bool(
        args.bola and bola
        and bola.get("login_endpoint")
        and bola.get("owner_credentials")
        and bola.get("other_credentials")
    )
    if args.bola:
        if not bola or not {"path", "identity_path", "owner_subject", "other_subject",
                             "expected_object_id", "id_field", "owner_field"} <= bola.keys():
            raise ValueError("--bola requires a complete explicit BOLA case")
        if not _bola_uses_login:
            # Token-file path: identities must already be loaded
            if bola.get("owner_identity") not in identities or bola.get("other_identity") not in identities:
                raise ValueError("BOLA identities must be configured (or use login_endpoint + credentials)")
            if identities.get(bola["owner_identity"]) == identities.get(bola["other_identity"]):
                raise ValueError("BOLA requires two distinct users and tokens")
        validate_path(bola["path"])
        validate_path(bola["identity_path"])
        if bola["owner_subject"] == bola["other_subject"]:
            raise ValueError("BOLA requires two distinct subjects")

    # --------------------------------------------------- capability detection
    # Decide applicability BEFORE running, with a plain-language reason. A
    # selected test that cannot apply is reported as skipped, never executed.
    records = {key: {"key": key, "status": "skipped", "reason": "", "findings": 0} for key in selected}
    reasons = _applicability(args, endpoints, bool(auth), bola)
    for key, reason in reasons.items():
        if key in records:
            records[key]["reason"] = reason
    for record in records.values():
        if not record["reason"]:
            record["status"] = "pending"  # applicable; filled in when it runs
    if "endpoint_discovery" in records and records["endpoint_discovery"]["status"] == "pending":
        records["endpoint_discovery"]["status"] = "passed"
    openapi_findings = [f for f in findings if f.category == "OpenAPI"]
    if "openapi_analysis" in records and records["openapi_analysis"]["status"] == "pending":
        records["openapi_analysis"]["findings"] = len(openapi_findings)
        records["openapi_analysis"]["status"] = "finding" if openapi_findings else "passed"

    coverage = {"requests_sent": 0, "observations": [], "skipped": [], "bola": "Not requested",
                "rate_test": "Not requested", "tests_selected": sorted(selected)}
    client = None

    if args.jwt_file and "jwt_analysis" in selected:
        token = read_token(args.jwt_file)
        secrets.append(token)
        findings.extend(run_module(records, "jwt_analysis", lambda: jwt_analysis.analyze(token)))
        emit(progress, "jwt_analysis", inspected=1)
    if args.target:
        # allow_post is needed only for the inline BOLA login path on loopback.
        _need_post = _bola_uses_login if args.bola else False
        client = HTTPClient(args.target, args.timeout, args.max_requests, args.delay,
                            args.authorized, allow_post=_need_post)
        try:
            # Run explicitly configured comparisons before broad documentation checks.
            if args.bola and "authorization" in selected and records["authorization"]["status"] == "pending":
                emit(progress, "authorization", case=bola["path"])
                try:
                    # Resolve credentials: inline login wins over token-file identities.
                    if _bola_uses_login:
                        lep = bola["login_endpoint"]
                        validate_path(lep)
                        oc = bola["owner_credentials"]
                        tc = bola["other_credentials"]
                        if not isinstance(oc, dict) or not isinstance(tc, dict):
                            raise ValueError("owner_credentials and other_credentials must be objects")
                        owner_headers = _login_via_endpoint(
                            client, lep, oc["username"], oc["password"], secrets)
                        other_headers = _login_via_endpoint(
                            client, lep, tc["username"], tc["password"], secrets)
                        if not owner_headers or not other_headers:
                            raise ValueError("Inline BOLA login failed; check credentials and login_endpoint")
                        if owner_headers == other_headers:
                            raise ValueError("BOLA requires distinct credentials; login returned identical tokens")
                    else:
                        owner_headers = identities[bola["owner_identity"]]
                        other_headers = identities[bola["other_identity"]]
                    result, note = authorization_analysis.analyze(
                        client, bola, owner_headers, other_headers)
                    records["authorization"]["findings"] += len(result)
                    records["authorization"]["status"] = "finding" if result else "passed"
                except Exception as exception:
                    result, note = [], {"outcome": "Module failed"}
                    records["authorization"]["status"] = "failed"
                    records["authorization"]["reason"] = "Module error: " + type(exception).__name__
                findings.extend(result)
                coverage["bola"] = note
            endpoint_outcomes = {}
            expected = {}
            for e in endpoints:
                expected.setdefault(e.path.split("?")[0], set()).add(e.method)
                if e.resolved_path:
                    expected.setdefault(e.resolved_path.split("?")[0], set()).add(e.method)
            want_auth = "auth_analysis" in selected
            want_headers = "headers_analysis" in selected
            want_methods = "method_analysis" in selected
            want_cors = "cors_analysis" in selected
            for position, endpoint in enumerate(endpoints, 1):
                safe_path = endpoint.path.split("?")[0]
                if endpoint.method != "GET":
                    endpoint_outcomes[endpoint.path] = {
                        "status": "skipped",
                        "reason": f"Non-GET method ({endpoint.method}); active discovery limited to safe GET/OPTIONS",
                        "actual_status": None,
                        "authenticated": "Skipped",
                    }
                    coverage["skipped"].append({"path": safe_path, "method": endpoint.method, "reason": "Non-GET or unresolved template; no active request"})
                    continue
                if ("{" in endpoint.path or "}" in endpoint.path) and not endpoint.resolved_path:
                    unres_msg = f"Unresolved path template (missing example for: {', '.join(endpoint.unresolved_parameters) or 'parameter'})"
                    endpoint_outcomes[endpoint.path] = {
                        "status": "skipped",
                        "reason": unres_msg,
                        "actual_status": None,
                        "authenticated": "Skipped",
                    }
                    coverage["skipped"].append({"path": safe_path, "method": endpoint.method, "reason": "Non-GET or unresolved template; no active request"})
                    continue
                if client.stopped or client.count >= client.max_requests:
                    stop_msg = client.stopped or "Budget exhausted"
                    endpoint_outcomes[endpoint.path] = {
                        "status": "skipped",
                        "reason": stop_msg,
                        "actual_status": None,
                        "authenticated": "Skipped",
                    }
                    coverage["skipped"].append({"path": safe_path, "reason": stop_msg})
                    continue

                active_path = endpoint.resolved_path or endpoint.path
                emit(progress, "endpoint", path=active_path, method=endpoint.method,
                     index=position, total=len(endpoints), requests_sent=client.count)
                prev_findings = len(findings)
                anon = client.request("GET", active_path)
                coverage["observations"].append(anon.evidence())
                if want_headers:
                    findings.extend(run_module(records, "headers_analysis",
                        lambda: headers_analysis.analyze(anon, args.target.startswith("https://"))))
                authenticated = None
                if auth and (want_auth or want_cors):
                    authenticated = client.request("GET", active_path, headers=auth)
                    coverage["observations"].append(authenticated.evidence())
                if want_auth:
                    findings.extend(run_module(records, "auth_analysis",
                        lambda: auth_analysis.analyze(endpoint, anon, authenticated)))
                if want_methods:
                    options = client.request("OPTIONS", active_path)
                    coverage["observations"].append(options.evidence())
                    lookup_key = active_path.split("?")[0]
                    findings.extend(run_module(records, "method_analysis",
                        lambda: method_detection.analyze(options, expected.get(lookup_key) or expected.get(safe_path) or set())))
                if want_cors and records["cors_analysis"]["status"] != "skipped":
                    cors_headers = {**(auth or {}), "Origin": cors_analysis.TEST_ORIGIN}
                    cors = client.request("GET", active_path, headers=cors_headers)
                    preflight = client.request("OPTIONS", active_path, headers={"Origin": cors_analysis.TEST_ORIGIN,
                        "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
                    coverage["observations"] += [cors.evidence(), preflight.evidence()]
                    findings.extend(run_module(records, "cors_analysis", lambda: cors_analysis.analyze(cors)))

                new_ep_findings = findings[prev_findings:]
                is_auth = "Yes" if authenticated is not None else "No"
                act_status = authenticated.status if authenticated is not None else anon.status

                if anon.error or (authenticated and authenticated.error):
                    ep_st = "failed"
                    ep_rs = f"Request error: {anon.error or authenticated.error}"
                elif new_ep_findings:
                    ep_st = "finding"
                    ep_rs = f"Finding: {'; '.join(dict.fromkeys(f.title for f in new_ep_findings))}"
                else:
                    ep_st = "passed"
                    if authenticated is not None:
                        if anon.status in (401, 403) and authenticated.status == 200:
                            ep_rs = f"Access control verified: anonymous HTTP {anon.status}, authenticated HTTP {authenticated.status}"
                        else:
                            ep_rs = f"Checks completed: anonymous HTTP {anon.status}, authenticated HTTP {authenticated.status}"
                    else:
                        ep_rs = f"Checks completed: anonymous HTTP {anon.status}"

                endpoint_outcomes[endpoint.path] = {
                    "status": ep_st,
                    "reason": ep_rs,
                    "actual_status": act_status,
                    "authenticated": is_auth,
                }
            if args.rate_limit_path and "rate_limit" in selected and records["rate_limit"]["status"] == "pending":
                emit(progress, "rate_limit", path=args.rate_limit_path, count=args.rate_limit_count)
                findings.extend(run_module(records, "rate_limit",
                    lambda: rate_limit.analyze(client, args.rate_limit_path, args.rate_limit_count, args.rate_limit_delay, auth)))
                coverage["rate_test"] = "Requested; see finding evidence and stop conditions"
            coverage["requests_sent"] = client.count
            coverage["stop_reason"] = client.stopped
        finally:
            client.close()
    else:
        endpoint_outcomes = {}
    summaries = []
    for e in endpoints:
        res = endpoint_outcomes.get(e.path, {
            "status": "skipped",
            "reason": "Offline analysis only (no target configured)" if not args.target else "Not tested",
            "actual_status": None,
            "authenticated": "No",
        })
        summaries.append({
            "path": urlsplit(e.path).path,
            "resolved_path": urlsplit(e.resolved_path).path if e.resolved_path else None,
            "method": e.method,
            "authentication": "Unknown" if e.security is None else "Required by documentation" if auth_analysis.requires_auth(e.security) else "Anonymous allowed by documentation",
            "parameters": parameter_discovery.extract(e) if "parameter_discovery" in selected else [],
            "response_statuses": sorted(e.responses),
            "request_schema_present": bool(e.request_schema),
            "response_schema_present": any("schema" in r or bool(r.get("content")) for r in e.responses.values()),
            "actual_status": res.get("actual_status"),
            "authenticated": res.get("authenticated", "No"),
            "check_status": res.get("status", "skipped"),
            "check_reason": res.get("reason", "—"),
        })
    if "parameter_discovery" in records and records["parameter_discovery"]["status"] == "pending":
        records["parameter_discovery"]["status"] = "passed"
    # A selected module that was applicable but never got to run is honestly
    # skipped, with the reason, rather than silently counted as executed.
    for record in records.values():
        if record["status"] == "pending":
            record["status"] = "skipped"
            record["reason"] = "Not executed: no endpoint request was sent (stop condition, budget or no concurrent work)"
    coverage["tests"] = [records[key] for key in sorted(selected)]
    coverage["tests_executed"] = sorted(key for key in selected if records[key]["status"] in ("passed", "finding"))
    coverage["tests_skipped"] = sorted(key for key in selected if records[key]["status"] == "skipped")
    coverage["tests_failed"] = sorted(key for key in selected if records[key]["status"] == "failed")
    coverage["skip_reasons"] = {key: records[key]["reason"] for key in sorted(selected)
                                if records[key]["status"] == "skipped" and records[key]["reason"]}
    report = {"target": args.target or "Offline supplied files only", "date": datetime.now(timezone.utc).isoformat(),
        "scope": "One configured authorized origin. Endpoints come only from the supplied OpenAPI document or endpoint list; the engine never crawls or guesses paths. Tests that cannot apply to this target are skipped with a reason.",
        "methodology": "Documentation review and safe endpoint discovery; serial GET/OPTIONS observations; optional authenticated comparisons, one BOLA case, offline JWT inspection and a bounded rate sample. Each selected test records executed/passed/finding/skipped/failed.",
        "endpoints": summaries, "findings": [f.to_dict() for f in findings], "metadata": metadata, "coverage": coverage,
        "limitations": ["Automated candidates require manual validation and business-policy context. No finding does not establish safety.",
            "Documentation is not proof of deployment. OpenAPI 3 server URLs/base paths/variables are not followed; supply explicit paths where needed.",
            "Active discovery is limited to supplied concrete GET endpoints. Non-GET and unresolved path templates are skipped; no injection attacks.",
            "JWT claims are unverified; CORS headers alone do not demonstrate browser exploitation.",
            "No raw bodies or credentials are persisted. Evidence is deliberately minimized; retain manual evidence privately if required.",
            "TLS verification stays enabled, redirects/proxies are disabled, responses are capped at 256 KiB; truncation/timeouts reduce coverage.",
            "Requests timeout is an inactivity limit, not a strict whole-run deadline. Read loop also limits elapsed response processing.",
            "Single-threaded, at most 200 requests per run, minimum 0.2 seconds apart. No retries after 429, 5xx or transport errors."]}
    emit(progress, "report", findings=len(findings), requests_sent=coverage["requests_sent"])
    return generate(scrub(report, secrets), args.output)

def main(argv=None):
    print(WARNING)
    args = parser().parse_args(argv)
    try:
        paths = run(args)
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        # Do not print malformed config/token contents or arbitrary exception strings.
        get_logger().error("Assessment could not complete (%s). Check target, input format, token files and documented limits.", type(exc).__name__)
        return 2
    for path in paths:
        print("Saved:", path)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
