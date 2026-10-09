"""One synthetic untrusted origin. Header observations are not browser proof."""
from core.risk_engine import finding
TEST_ORIGIN = "https://untrusted.example"

def analyze(obs):
    if obs.status is None:
        return []
    origin = obs.headers.get("access-control-allow-origin", "")
    credentials = obs.headers.get("access-control-allow-credentials", "") == "true"
    if origin == TEST_ORIGIN and credentials:
        return [finding("cors_credentials", "Untrusted origin allowed with credentials", "CORS", obs.endpoint, obs.method,
            "This response permits the test origin with credentials. Exploitation also requires browser-sent credentials and sensitive readable data; bearer tokens are not automatically sent cross-origin.",
            obs.evidence(), "Use an exact trusted-origin allowlist and validate actual browser credential behavior.", "Medium", cwe="CWE-942", owasp_api="API8:2023 Security Misconfiguration")]
    if origin == "*":
        text = "Browsers reject wildcard ACAO with credentialed requests; this combination is not a credentialed data leak by itself." if credentials else "Wildcard access can be appropriate for public non-credentialed resources."
        return [finding("cors", "Wildcard CORS policy observed", "CORS", obs.endpoint, obs.method,
                        text, obs.evidence(), "Confirm that cross-origin readable data is intended to be public.", "High", classification="Configuration observation")]
    return []
