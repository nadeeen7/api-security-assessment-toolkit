"""OPTIONS advertises capability; never execute DELETE/PUT/TRACE to test it."""
from core.risk_engine import finding

def analyze(observation, expected):
    if observation.status is None or not 200 <= observation.status < 300:
        return []
    allowed = {m.strip().upper() for m in observation.headers.get("allow", "").split(",") if m.strip()}
    extra = allowed - set(expected) - {"HEAD", "OPTIONS"}
    if not extra:
        return []
    return [finding("methods", "Unexpected methods advertised", "HTTP methods", observation.endpoint, "OPTIONS",
        "Allow lists methods outside supplied documentation; actual access is unverified.",
        {**observation.evidence(), "unexpected_methods": sorted(extra)},
        "Review intended methods and enforce authorization. Do not execute destructive methods to confirm.", "Medium")]
