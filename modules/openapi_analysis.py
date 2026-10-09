"""Local JSON OpenAPI/Swagger reader. External $refs are deliberately disabled."""
import json
from pathlib import Path
from openapi_spec_validator import validate
from core.models import Endpoint
from core.http_client import validate_path
from core.path_resolver import resolve_path_template
from core.risk_engine import finding

METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}

def walk(value, depth=0):
    if depth > 60:
        raise ValueError("Document nesting exceeds 60 levels.")
    if isinstance(value, dict):
        if any(k in value for k in ("$id", "$dynamicRef", "$recursiveRef")):
            raise ValueError("Schema resource rebasing/dynamic references are unsupported in this local-only reader.")
        ref = value.get("$ref")
        if ref is not None and (not isinstance(ref, str) or not ref.startswith("#/")):
            raise ValueError("Only document-local #/ references are supported; no network/file resolution.")
        for child in value.values():
            walk(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            walk(child, depth + 1)

def resolve(value, doc, seen=(), depth=0, budget=None):
    if budget is None:
        budget = [20000]
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("Reference expansion exceeds the safe node budget")
    if depth > 20:
        return {"description": "Resolution depth limited"}
    if isinstance(value, dict):
        if "$ref" in value:
            ref = value["$ref"]
            if ref in seen:
                return {"description": "Recursive schema omitted", "$ref": ref}
            current = doc
            try:
                for part in ref[2:].split("/"):
                    current = current[part.replace("~1", "/").replace("~0", "~")]
            except (KeyError, TypeError):
                raise ValueError("Unresolved local reference") from None
            return resolve(current, doc, seen + (ref,), depth + 1, budget)
        return {k: resolve(v, doc, seen, depth + 1, budget) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, doc, seen, depth + 1, budget) for v in value]
    return value

def analyze(path):
    if Path(path).stat().st_size > 2_000_000:
        raise ValueError("OpenAPI file exceeds 2 MB.")
    raw = Path(path).read_bytes()
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        try:
            import yaml
            doc = yaml.safe_load(raw)
        except Exception as y_err:
            raise ValueError(f"OpenAPI file is neither valid JSON nor valid YAML: {y_err}") from None
    if not isinstance(doc, dict):
        raise ValueError("OpenAPI document must be an object.")
    walk(doc)
    version = str(doc.get("openapi", doc.get("swagger", "")))
    if not (version == "2.0" or version.startswith(("3.0.", "3.1."))):
        raise ValueError("Supported versions: Swagger 2.0, OpenAPI 3.0.x and 3.1.x.")
    try:
        validate(doc)
    except Exception as exc:
        raise ValueError("OpenAPI validation failed (" + type(exc).__name__ + "). Check the local document.") from None
    endpoints, findings = [], []
    base = doc.get("basePath", "").rstrip("/") if version == "2.0" else ""
    for path_name, item in doc.get("paths", {}).items():
        item = resolve(item, doc)
        path_name = validate_path(base + path_name)
        for method, operation in item.items():
            if method not in METHODS:
                continue
            security = operation.get("security", doc.get("security", []))
            merged = {(p["name"], p["in"]): p for p in item.get("parameters", [])}
            merged.update({(p["name"], p["in"]): p for p in operation.get("parameters", [])})
            parameters = list(merged.values())
            schema = operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
            if version == "2.0":
                schema = next((p.get("schema", {}) for p in parameters if p.get("in") == "body"), {})
            resolved_path, unresolved = resolve_path_template(path_name, parameters)
            endpoints.append(Endpoint(
                path_name, method.upper(), parameters, security, schema, operation.get("responses", {}),
                resolved_path=resolved_path, unresolved_parameters=unresolved
            ))
            if not security or {} in security:
                findings.append(finding(
                    "docs", "Operation permits anonymous access in documentation", "OpenAPI",
                    path_name, method.upper(),
                    "Documentation review observation: the specification declares this operation permits anonymous access. This is a static documentation observation and does not establish deployed server behavior or a confirmed vulnerability.",
                    {"anonymous_allowed": True, "documented_only": True, "verified_at_runtime": False},
                    "Confirm intended access with the API owner; verify deployed authentication enforcement.",
                    confidence="Low", classification="Documentation observation"
                ))
    components = doc.get("components") if isinstance(doc.get("components"), dict) else {}
    schemes = components.get("securitySchemes", doc.get("securityDefinitions", {}))
    if not isinstance(schemes, dict):
        schemes = {}
    metadata = {"version": version, "security_schemes": {k: {key: value for key, value in v.items()
                if key in ("type", "scheme", "in", "name", "bearerFormat")} for k, v in schemes.items() if isinstance(v, dict)},
                "server_urls_used": False,
                "limitations": "OpenAPI 3 server base paths/variables and non-JSON request media types are not expanded. Use explicit endpoint lists. External refs are rejected."}
    return endpoints, findings, metadata
