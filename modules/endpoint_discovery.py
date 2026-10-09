"""Discovery means reading supplied documentation/lists, not brute force."""
import json
from pathlib import Path
from core.models import Endpoint
from core.http_client import validate_path
from core.path_resolver import resolve_path_template
from modules.openapi_analysis import analyze

def discover(openapi=None, endpoint_file=None):
    endpoints, findings, metadata = [], [], {}
    if openapi:
        endpoints, findings, metadata = analyze(openapi)
    if endpoint_file:
        path = Path(endpoint_file)
        if path.stat().st_size > 200_000:
            raise ValueError("Endpoint list is too large.")
        items = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(items, list) or len(items) > 100:
            raise ValueError("Endpoint list must contain at most 100 entries.")
        for item in items:
            if isinstance(item, str):
                item = {"path": item}
            method = item.get("method", "GET").upper()
            if method not in {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE"}:
                raise ValueError("Unsupported documented method")
            p_val = validate_path(item["path"])
            params = item.get("parameters", [])
            resolved_p, unres = resolve_path_template(p_val, params)
            endpoints.append(Endpoint(p_val, method, parameters=params, security=item.get("security"),
                                      resolved_path=resolved_p, unresolved_parameters=unres))
    unique = {(e.path, e.method): e for e in endpoints}
    return list(unique.values()), findings, metadata
