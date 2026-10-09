"""Extract names and types only. Never inject values or guess parameters."""
import re
from urllib.parse import urlsplit, parse_qsl

def schema_parameters(schema, prefix="", depth=0):
    if not isinstance(schema, dict) or depth > 12:
        return []
    result = []
    required = schema.get("required", [])
    for name, value in schema.get("properties", {}).items():
        key = prefix + name
        result.append({"name": key, "in": "body", "type": value.get("type", "unknown"),
                       "required": name in required})
        result.extend(schema_parameters(value, key + ".", depth + 1))
    if isinstance(schema.get("items"), dict):
        result.extend(schema_parameters(schema["items"], prefix + "[].", depth + 1))
    for variant in ("allOf", "anyOf", "oneOf"):
        for item in schema.get(variant, []):
            result.extend(schema_parameters(item, prefix, depth + 1))
    return result

def extract(endpoint):
    result = [{"name": p.get("name", "?"), "in": p.get("in", "?"),
               "type": p.get("schema", p).get("type", "unknown"),
               "required": p.get("required", False)} for p in endpoint.parameters]
    for name in re.findall(r"{([^}]+)}", endpoint.path):
        if not any(p["name"] == name and p["in"] == "path" for p in result):
            result.append({"name": name, "in": "path", "required": True})
    for name, _ in parse_qsl(urlsplit(endpoint.path).query, keep_blank_values=True):
        result.append({"name": name, "in": "query"})
    result.extend(schema_parameters(endpoint.request_schema))
    return result
