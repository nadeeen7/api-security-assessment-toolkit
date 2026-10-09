"""Header guidance changes with TLS and response content type."""
from core.risk_engine import finding

def analyze(obs, https=False):
    if obs.status is None:
        return []
    relevant = {"x-content-type-options"}
    if https:
        relevant.add("strict-transport-security")
    if "text/html" in obs.headers.get("content-type", "").lower():
        relevant |= {"content-security-policy", "referrer-policy"}
        if "frame-ancestors" not in obs.headers.get("content-security-policy", "").lower():
            relevant.add("x-frame-options")
    missing = sorted(relevant - {k for k, v in obs.headers.items() if v.strip()})
    if not missing:
        return []
    return [finding("headers", "Context-relevant security headers absent", "Security headers", obs.endpoint, obs.method,
        "Missing headers are hardening observations, not proof of an exploitable API flaw. CSP and framing headers are mainly relevant to browser-rendered HTML; HSTS only to HTTPS.",
        {**obs.evidence(), "missing": missing}, "Review response type and browser use; add appropriate headers.", "High", classification="Hardening observation")]
