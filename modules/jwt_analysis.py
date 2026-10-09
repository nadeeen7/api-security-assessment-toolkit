"""Inspect JWT metadata locally. Never forge tokens or claim signature verification."""
import math
import time
import jwt
from core.risk_engine import finding

def analyze(token):
    if len(token) > 16000:
        raise ValueError("JWT exceeds analysis size limit.")
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False,
            "verify_aud": False, "verify_iss": False, "verify_iat": False,
            "verify_nbf": False, "verify_sub": False, "verify_jti": False})
    except jwt.PyJWTError:
        raise ValueError("Malformed JWT; token content has not been logged.") from None
    issues = []
    if header.get("alg") not in {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}:
        issues.append("Missing, unsigned or unrecognized algorithm label")
    for key in ("exp", "iss", "sub", "iat"):
        if key not in payload:
            issues.append("Missing claim: " + key)
    for key in ("exp", "iat", "nbf"):
        if key in payload and (isinstance(payload[key], bool) or not isinstance(payload[key], (int, float)) or not math.isfinite(payload[key])):
            issues.append("Non-numeric or non-finite time claim: " + key)
    now = time.time()
    exp, iat = payload.get("exp"), payload.get("iat")
    if isinstance(exp, (int, float)) and exp <= now:
        issues.append("Token appears expired")
    if isinstance(iat, (int, float)) and iat > now + 60:
        issues.append("Issued-at appears in the future")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)) and exp > iat + 86400:
        issues.append("Lifetime exceeds one day; review application policy")
    for key in ("iss", "sub"):
        if key in payload and (not isinstance(payload[key], str) or not payload[key].strip()):
            issues.append("Empty or non-string claim: " + key)
    def sensitive(value, depth=0):
        if depth > 20:
            return False
        if isinstance(value, dict):
            return any(any(word in k.lower() for word in ("password", "secret", "email", "phone", "address", "api_key", "credit", "token")) or sensitive(v, depth + 1) for k, v in value.items())
        return isinstance(value, list) and any(sensitive(v, depth + 1) for v in value)
    if sensitive(payload):
        issues.append("Potential sensitive-data field names in payload")
    evidence = {"signature_verified": False, "algorithm": str(header.get("alg", "missing"))[:30],
        "standard_claims_present": [k for k in ("exp", "iss", "sub", "iat", "nbf", "aud") if k in payload], "issues": issues}
    return [finding("jwt" if issues else "docs", "JWT configuration review", "JWT", "local token", "N/A",
        "Decoded claims are untrusted. This is a JWT configuration finding, not a confirmed vulnerability. No server acceptance or signature validation was tested.",
        evidence, "Validate signatures with a fixed algorithm allowlist and expected issuer/audience on the server; enforce required claims and minimize payload data.",
        "Low", classification="JWT configuration finding")]
