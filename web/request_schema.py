"""Validate one assessment request.

These are the web layer's own early checks so the user gets a clear message
instead of an opaque failure. They NEVER relax the engine's rules: the engine
re-validates everything (loopback/HTTPS/authorized, path scope, budgets) and
remains the authority.
"""
import ipaddress
import json
import re
import socket
from urllib.parse import urlsplit

import requests
import yaml

from main import ASSESSMENT_TESTS

MAX_TOKEN = 16000          # matches read_token() in main.py
MAX_SPEC_BYTES = 2_000_000  # matches openapi_analysis.analyze()
MAX_ENDPOINT_BYTES = 200_000  # matches endpoint_discovery.discover()
MAX_IDENTITIES = 5

NAME_PATTERN = re.compile(r"\A[A-Za-z0-9_.-]{1,32}\Z")
HEADER_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")
IDENTITY_SCHEMES = ("bearer", "api_key", "basic", "header")

# One entry per user-facing checkbox. `requests` says whether the phase sends
# traffic to the target, which the UI should state plainly.
TEST_CATALOGUE = (
    {"key": "endpoint_discovery", "label": "Endpoint Discovery", "requests": False,
     "description": "Reads the supplied OpenAPI document or endpoint list. Never crawls or guesses paths."},
    {"key": "openapi_analysis", "label": "OpenAPI Analysis", "requests": False,
     "description": "Validates a local Swagger 2 / OpenAPI 3.0-3.1 JSON document and reports operations that allow anonymous access."},
    {"key": "parameter_discovery", "label": "Parameter Discovery", "requests": False,
     "description": "Extracts parameter names and types. Never injects or guesses values."},
    {"key": "method_analysis", "label": "HTTP Method Analysis", "requests": True,
     "description": "Reads the OPTIONS Allow header. Destructive methods are never executed to confirm."},
    {"key": "auth_analysis", "label": "Authentication Analysis", "requests": True,
     "description": "Compares anonymous and authenticated responses on documented protected endpoints."},
    {"key": "authorization", "label": "Authorization / BOLA", "requests": True,
     "description": "One explicit object compared with two distinct verified users. No object-ID enumeration."},
    {"key": "jwt_analysis", "label": "JWT Analysis", "requests": False,
     "description": "Offline metadata review of one token. Signature verification is never claimed."},
    {"key": "headers_analysis", "label": "Security Headers", "requests": True,
     "description": "Checks context-relevant response headers on observed responses."},
    {"key": "cors_analysis", "label": "CORS", "requests": True,
     "description": "Sends one synthetic untrusted Origin. Header observations are not browser proof."},
    {"key": "rate_limit", "label": "Rate Limiting", "requests": True,
     "description": "Small bounded sample (max 10 requests, at least 0.2s apart). Stops at the first 429, 5xx or error."},
)

CATALOGUE_BY_KEY = {item["key"]: item for item in TEST_CATALOGUE}
assert set(CATALOGUE_BY_KEY) == set(ASSESSMENT_TESTS), "catalogue and engine selection must agree"


def _is_loopback(hostname):
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return hostname.lower() in {"localhost", "localhost.localdomain"}


def is_blocked_destination(hostname):
    """Check if destination is cloud metadata, private network, or blocked address."""
    h_lower = hostname.lower()
    if h_lower in {"metadata.google.internal", "metadata", "instance-data", "169.254.169.254"}:
        return True, "Access to cloud metadata endpoints is prohibited."
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return False, ""
        if ip.is_link_local:
            return True, "Access to link-local/cloud metadata addresses is prohibited."
        if ip.is_private:
            return True, "Access to private internal network addresses is prohibited."
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True, "Access to reserved or multicast addresses is prohibited."
        return False, ""
    except ValueError:
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_loopback and (ip.is_link_local or ip.is_private or ip.is_reserved):
                    return True, f"Destination {hostname} resolves to prohibited internal address."
        except (socket.gaierror, OSError):
            pass
        return False, ""


def _require_text(value, name, limit):
    if not isinstance(value, str) or not value:
        raise ValueError(name + " must be a non-empty string")
    if len(value) > limit:
        raise ValueError(name + " is too large")
    return value


def _validate_token(value, name):
    token = _require_text(value, name, MAX_TOKEN)
    if any(character.isspace() for character in token):
        raise ValueError(name + " must be a single value without whitespace")
    return token


def _validate_number(value, name, low, high, cast=float):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(name + " must be a number")
    number = cast(value)
    if not (low <= number <= high):
        raise ValueError(name + " must be between " + str(low) + " and " + str(high))
    return number


def _validate_target(payload):
    target = payload.get("target")
    if target in (None, ""):
        return None, False
    target = _require_text(target, "target", 2000)
    parsed = urlsplit(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an http:// or https:// origin")
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("target must be the scheme, host and optional port only; put paths in the endpoint list")
    authorized = bool(payload.get("authorized", False))
    if not _is_loopback(parsed.hostname):
        if not authorized:
            raise ValueError("non-loopback targets require explicit authorization confirmation")
        if parsed.scheme != "https":
            raise ValueError("non-loopback targets require HTTPS")
    return target.rstrip("/"), authorized


def _validate_tests(payload):
    tests = payload.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ValueError("select at least one assessment test")
    if any(not isinstance(item, str) for item in tests):
        raise ValueError("assessment test keys must be strings")
    selected = list(dict.fromkeys(tests))  # de-duplicate, keep order
    unknown = [key for key in selected if key not in ASSESSMENT_TESTS]
    if unknown:
        raise ValueError("unknown assessment test key")
    return selected


def _validate_identity(name, value):
    """Accept a bare token string (Bearer) or an explicit auth object."""
    if isinstance(value, str):
        return {"scheme": "bearer", "token": _validate_token(value, "identity token for " + name)}
    if not isinstance(value, dict):
        raise ValueError("identity for " + name + " must be a token string or an auth object")
    scheme = value.get("scheme", "bearer")
    if scheme not in IDENTITY_SCHEMES:
        raise ValueError("unsupported identity scheme for " + name)
    if scheme == "bearer":
        return {"scheme": "bearer", "token": _validate_token(value.get("token"), "identity token for " + name)}
    if scheme in ("api_key", "header"):
        header = value.get("header")
        if not isinstance(header, str) or not HEADER_PATTERN.match(header):
            raise ValueError("identity header name for " + name + " is invalid")
        return {"scheme": scheme, "header": header,
                "value": _validate_token(value.get("value"), "identity value for " + name)}
    # Basic: username and password are both treated as secrets (no whitespace).
    return {"scheme": "basic",
            "username": _validate_token(value.get("username"), "identity username for " + name),
            "password": _validate_token(value.get("password"), "identity password for " + name)}


def _validate_identities(payload):
    identities = payload.get("identities") or {}
    if not isinstance(identities, dict):
        raise ValueError("identities must be an object of name to token or auth object")
    if len(identities) > MAX_IDENTITIES:
        raise ValueError("at most " + str(MAX_IDENTITIES) + " identities are supported")
    cleaned = {}
    for name, value in identities.items():
        if not isinstance(name, str) or not NAME_PATTERN.match(name):
            raise ValueError("identity names are limited to letters, digits, dot, dash and underscore")
        cleaned[name] = _validate_identity(name, value)
    return cleaned


def _validate_bola(payload, identities, tests):
    bola = payload.get("bola")
    if "authorization" not in tests:
        return None
    if not isinstance(bola, dict):
        raise ValueError("Authorization / BOLA needs an explicit object case")
    required = ("path", "identity_path", "owner_identity", "other_identity",
                "owner_subject", "other_subject", "expected_object_id", "id_field", "owner_field")
    missing = [key for key in required if key not in bola]
    if missing:
        raise ValueError("BOLA case is missing: " + ", ".join(sorted(missing)))
    if bola["owner_identity"] not in identities or bola["other_identity"] not in identities:
        raise ValueError("BOLA owner and other identity must both be configured identities")
    if bola["owner_identity"] == bola["other_identity"]:
        raise ValueError("BOLA requires two distinct identities")
    if bola["owner_subject"] == bola["other_subject"]:
        raise ValueError("BOLA requires two distinct subjects")
    for key in ("path", "identity_path"):
        if not isinstance(bola[key], str) or not bola[key].startswith("/"):
            raise ValueError(key + " must be an absolute path on the target")
    for key in ("id_field", "owner_field"):
        if not isinstance(bola[key], str) or not NAME_PATTERN.match(bola[key]):
            raise ValueError(key + " must be a simple field name")
    if isinstance(bola["expected_object_id"], bool) or not isinstance(bola["expected_object_id"], (int, str)):
        raise ValueError("expected_object_id must be an integer or string")
    return {
        "path": bola["path"],
        "identity_path": bola["identity_path"],
        "owner_identity": bola["owner_identity"],
        "other_identity": bola["other_identity"],
        "owner_subject": bola["owner_subject"],
        "other_subject": bola["other_subject"],
        "expected_object_id": bola["expected_object_id"],
        "id_field": bola["id_field"],
        "owner_field": bola["owner_field"],
    }


def _validate_rate_limit(payload, tests):
    if "rate_limit" not in tests:
        return None
    settings = payload.get("rate_limit")
    if not settings or not isinstance(settings, dict) or not settings.get("path"):
        raise ValueError("rate_limit test requires a path and bounded sample (rate_limit.path must be set)")
    path = settings.get("path")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ValueError("rate limit path must be an absolute path on the target")
    return {
        "path": path,
        "count": _validate_number(settings.get("count", 5), "rate limit count", 1, 10, int),
        "delay": _validate_number(settings.get("delay", 0.5), "rate limit delay", 0.2, 10, float),
    }


def _validate_limits(payload):
    limits = payload.get("limits") or {}
    if not isinstance(limits, dict):
        raise ValueError("limits must be an object")
    return {
        "timeout": _validate_number(limits.get("timeout", 5), "timeout", 0.1, 30, float),
        "max_requests": _validate_number(limits.get("max_requests", 100), "max_requests", 1, 200, int),
        "delay": _validate_number(limits.get("delay", 0.2), "delay", 0.2, 10, float),
    }


def parse_openapi_text(text, check_version=False):
    """Safely parse JSON or YAML OpenAPI text and validate structure."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("OpenAPI specification cannot be empty.")
    if len(text.encode("utf-8")) > MAX_SPEC_BYTES:
        raise ValueError("OpenAPI specification exceeds 2 MB limit.")
    doc = None
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        try:
            doc = yaml.safe_load(text)
        except Exception:
            raise ValueError("OpenAPI specification must be valid JSON") from None
    if not isinstance(doc, dict):
        raise ValueError("OpenAPI specification must be a valid JSON object (or YAML object)")
    version = str(doc.get("openapi", doc.get("swagger", "")))
    if check_version and not (version == "2.0" or version.startswith(("3.0.", "3.1."))):
        raise ValueError(f"Unsupported specification version: '{version or 'unknown'}'. Supported versions: Swagger 2.0, OpenAPI 3.0.x and 3.1.x.")
    normalized_json = json.dumps(doc, indent=2)
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    title = str(info.get("title", ""))
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    paths_count = len(paths)
    return {
        "content": normalized_json,
        "doc": doc,
        "title": title,
        "paths_count": paths_count,
        "version": version,
    }


def fetch_openapi_document(url, authorized=False):
    """Fetch an OpenAPI document from a URL safely with SSRF protections and size limits."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL is required.")
    url = url.strip()
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be an http:// or https:// address.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL are not allowed.")
    blocked, reason = is_blocked_destination(parsed.hostname)
    if blocked:
        raise ValueError(reason)
    is_local = _is_loopback(parsed.hostname)
    if not is_local:
        if not authorized:
            raise ValueError("Fetching from non-loopback URL requires explicit authorization confirmation.")
        if parsed.scheme != "https":
            raise ValueError("Fetching from non-loopback URL requires HTTPS.")
    session = requests.Session()
    session.trust_env = False
    try:
        resp = session.get(url, timeout=(5, 5), allow_redirects=False,
                           headers={"User-Agent": "API-Security-Toolkit/1.0 (authorized assessment)"},
                           stream=True)
        if resp.status_code != 200:
            raise ValueError(f"Remote server returned HTTP {resp.status_code}.")
        content_length = resp.headers.get("Content-Length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_SPEC_BYTES:
            raise ValueError("OpenAPI specification exceeds 2 MB limit.")
        chunks = bytearray()
        for chunk in resp.iter_content(chunk_size=8192):
            chunks.extend(chunk)
            if len(chunks) > MAX_SPEC_BYTES:
                raise ValueError("OpenAPI specification exceeds 2 MB limit.")
        raw_text = chunks.decode("utf-8", errors="replace")
        return parse_openapi_text(raw_text)
    except requests.RequestException as exc:
        raise ValueError(f"Could not reach OpenAPI URL: {type(exc).__name__}") from None
    finally:
        session.close()


def _validate_openapi_spec(text, target=None, authorized=False):
    text = _require_text(text, "openapi_text", MAX_SPEC_BYTES)
    trimmed = text.strip()
    if trimmed.startswith(("http://", "https://")):
        result = fetch_openapi_document(trimmed, authorized=authorized)
        return result["content"]
    result = parse_openapi_text(text)
    return result["content"]


def _validate_endpoints_spec(text):
    text = _require_text(text, "endpoints_text", MAX_ENDPOINT_BYTES)
    try:
        items = json.loads(text)
        if not isinstance(items, list):
            raise ValueError("endpoint list must be a JSON array")
    except json.JSONDecodeError as err:
        raise ValueError(f"endpoint list must be valid JSON: {err}")
    return text


def validate_start(payload):
    """Return a normalised request or raise ValueError with a safe message."""
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")

    target, authorized = _validate_target(payload)
    tests = _validate_tests(payload)
    identities = _validate_identities(payload)

    openapi_text = payload.get("openapi_text")
    if openapi_text is not None:
        openapi_text = _validate_openapi_spec(openapi_text, target, authorized)
    endpoints_text = payload.get("endpoints_text")
    if endpoints_text is not None:
        endpoints_text = _validate_endpoints_spec(endpoints_text)
    if target is None and openapi_text is None and endpoints_text is None:
        raise ValueError("provide a target, an OpenAPI document or an endpoint list")

    jwt_token = payload.get("jwt_token")
    if jwt_token is not None:
        jwt_token = _validate_token(jwt_token, "jwt_token")

    default_identity = payload.get("default_identity")
    if default_identity is not None and default_identity not in identities:
        raise ValueError("default_identity must be a configured identity")

    if identities and target is None:
        raise ValueError("identities need a target")

    bola = _validate_bola(payload, identities, tests)
    if bola is not None and target is None:
        raise ValueError("Authorization / BOLA needs a target")

    rate_limit = _validate_rate_limit(payload, tests)
    if rate_limit is not None and target is None:
        raise ValueError("Rate Limiting needs a target")

    for key in ("auth_analysis", "headers_analysis", "method_analysis", "cors_analysis"):
        if key in tests and target is None:
            raise ValueError("active checks need a target")

    return {
        "target": target,
        "authorized": authorized,
        "tests": tests,
        "openapi_text": openapi_text,
        "endpoints_text": endpoints_text,
        "identities": identities,
        "default_identity": default_identity or (next(iter(identities), None)),
        "bola": bola,
        "jwt_token": jwt_token,
        "rate_limit": rate_limit,
        "limits": _validate_limits(payload),
    }
