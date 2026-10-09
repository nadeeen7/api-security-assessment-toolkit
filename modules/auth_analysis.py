"""Compare anonymous and configured authenticated responses conservatively.

Two independent checks are performed when an endpoint is documented as requiring
authentication (requires_auth() is True):

1. Unauthenticated HTTP 200 – anonymous GET returned 200 on a protected endpoint.
   Confidence: Low.  Could be auth via session/IP; manual confirmation required.

2. Body-equality bypass – anonymous and authenticated 200 responses returned
   identical non-empty JSON.  Confidence: Medium; stronger signal.

Neither check is claimed as a confirmed vulnerability.
"""
from core.risk_engine import finding


def requires_auth(security):
    if not security:
        return False
    if isinstance(security, (list, tuple, set)):
        return {} not in security
    return True


def analyze(endpoint, anonymous, authenticated):
    """Return findings for an endpoint documented as requiring authentication."""
    if not requires_auth(endpoint.security):
        return []

    findings = []

    # --- Check 2: Body-equality bypass (stronger signal) ---------------------
    # When anonymous and authenticated 200 responses return identical non-empty
    # JSON, this is the definitive signal of missing authentication enforcement.
    # It supersedes Check 1 to avoid duplicate CWE-306 findings on the same endpoint.
    if (
        authenticated is not None
        and anonymous.status == authenticated.status == 200
        and not anonymous.truncated
        and not authenticated.truncated
        and anonymous.data is not None
        and anonymous.data == authenticated.data
    ):
        findings.append(finding(
            "auth",
            "Possible missing authentication enforcement",
            "Authentication",
            anonymous.endpoint,
            endpoint.method,
            (
                "A documented protected endpoint returned identical JSON with and without "
                "credentials. A valid identity and intended privacy need manual confirmation."
            ),
            {
                "anonymous": anonymous.evidence(),
                "authenticated": authenticated.evidence(),
                "json_equal": True,
            },
            "Validate the configured identity and require authentication for private resources.",
            "Medium",
            cwe="CWE-306",
            owasp_api="API2:2023 Broken Authentication",
        ))
        return findings

    # --- Check 1: Anonymous HTTP 200 on a documented-protected endpoint ------
    # Fires when body-equality did not fire (e.g. no auth identity available, or
    # responses differed), but an anonymous GET still succeeded with HTTP 200.
    if anonymous.status == 200 and not anonymous.error:
        auth_ev = authenticated.evidence() if authenticated is not None else None
        findings.append(finding(
            "auth_bypass",
            "Documented-protected endpoint accessible without authentication",
            "Authentication",
            anonymous.endpoint,
            endpoint.method,
            (
                "The OpenAPI specification declares this endpoint requires authentication, "
                "yet an anonymous GET request returned HTTP 200. "
                "This may indicate missing authentication enforcement. "
                "Manual confirmation is required: the endpoint may rely on session cookies, "
                "IP restrictions, or other controls not visible in the response code."
            ),
            {
                "anonymous": anonymous.evidence(),
                "authenticated": auth_ev,
                "anonymous_status": anonymous.status,
                "comparison_available": auth_ev is not None,
                "documented_security": endpoint.security,
                "verified_at_runtime": True,
            },
            "Verify that server-side authentication is enforced for every request path.",
            "Medium",
            cwe="CWE-306",
            owasp_api="API2:2023 Broken Authentication",
            classification="Potential issue",
        ))

    return findings
