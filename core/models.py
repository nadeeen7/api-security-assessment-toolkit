"""Shared data objects: observations are separate from security findings."""
from dataclasses import dataclass, field, asdict
from typing import Any

@dataclass
class Endpoint:
    path: str
    method: str = "GET"
    parameters: list[dict] = field(default_factory=list)
    security: Any = None  # None = unknown; [] = explicitly public
    request_schema: dict = field(default_factory=dict)
    responses: dict = field(default_factory=dict)
    resolved_path: str | None = None
    unresolved_parameters: list[str] = field(default_factory=list)

@dataclass
class Finding:
    title: str
    category: str
    severity: str
    endpoint: str
    method: str
    description: str
    evidence: dict
    recommendation: str
    confidence: str = "Low"
    cwe: str | None = None
    owasp_api: str | None = None
    classification: str = "Observation"
    severity_reason: str = ""

    def to_dict(self):
        return asdict(self)

@dataclass
class Observation:
    method: str
    endpoint: str
    status: int | None
    headers: dict = field(default_factory=dict)
    data: Any = None  # Memory only: never serialize raw response bodies.
    error: str | None = None
    truncated: bool = False
    elapsed_ms: int = 0

    def evidence(self):
        # No cookies, authorization headers, query values, or raw response body.
        allowed = {"content-type", "allow", "access-control-allow-origin",
                   "access-control-allow-credentials", "access-control-allow-methods",
                   "access-control-allow-headers", "retry-after",
                   "strict-transport-security", "content-security-policy",
                   "x-content-type-options", "x-frame-options", "referrer-policy"}
        return {"method": self.method, "endpoint": self.endpoint,
                "status": self.status,
                "headers": {k: v[:500] for k, v in self.headers.items() if k in allowed},
                "error": self.error, "truncated": self.truncated,
                "elapsed_ms": self.elapsed_ms}
