"""Safe OpenAPI path-parameter resolution using documented examples only.

Never invents or guesses object IDs. If an OpenAPI path template has documented
examples/defaults for all path parameters, it can be tested dynamically.
Otherwise, the template remains unresolved and is safely skipped with an
explicit reason.
"""
import re
from urllib.parse import quote

PATH_PARAM_PATTERN = re.compile(r"\{([A-Za-z0-9_.-]+)\}")


def extract_parameter_example(param_def: dict) -> str | None:
    """Extract a safe example or default value from an OpenAPI parameter definition."""
    if not isinstance(param_def, dict):
        return None

    val = None
    # 1. Top-level example or default
    if "example" in param_def and param_def["example"] is not None:
        val = param_def["example"]
    elif "default" in param_def and param_def["default"] is not None:
        val = param_def["default"]
    # 2. Schema-level example or default
    elif "schema" in param_def and isinstance(param_def["schema"], dict):
        schema = param_def["schema"]
        if "example" in schema and schema["example"] is not None:
            val = schema["example"]
        elif "default" in schema and schema["default"] is not None:
            val = schema["default"]
    # 3. Named examples object (OpenAPI 3.x)
    elif "examples" in param_def and isinstance(param_def["examples"], dict):
        for ex in param_def["examples"].values():
            if isinstance(ex, dict) and "value" in ex and ex["value"] is not None:
                val = ex["value"]
                break

    if val is None or isinstance(val, (dict, list)):
        return None

    val_str = str(val).strip()
    # Reject empty or values with directory traversal, query, fragment or whitespace
    if not val_str or any(c in val_str for c in ("/", "\\", "?", "#", "\r", "\n", "\0")):
        return None

    return quote(val_str, safe="-_.~")


def resolve_path_template(path: str, parameters: list[dict]) -> tuple[str | None, list[str]]:
    """Resolve OpenAPI path parameters safely using documented examples only.

    Returns (resolved_path, unresolved_parameters).
    - If path has no {param} templates: returns (path, []).
    - If all path parameters have documented examples: returns (resolved_path, []).
    - If any path parameter lacks a documented example: returns (None, unresolved_parameters).

    Never invents object IDs.
    """
    matches = PATH_PARAM_PATTERN.findall(path)
    if not matches:
        return path, []

    path_params = {}
    for p in parameters:
        if isinstance(p, dict) and p.get("in") == "path" and "name" in p:
            path_params[p["name"]] = p

    resolved = path
    unresolved = []
    for param_name in matches:
        param_def = path_params.get(param_name)
        example_val = extract_parameter_example(param_def) if param_def else None
        if example_val is not None:
            resolved = resolved.replace("{" + param_name + "}", example_val)
        else:
            unresolved.append(param_name)

    if unresolved:
        return None, unresolved

    return resolved, []
