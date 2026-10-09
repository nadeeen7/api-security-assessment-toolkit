"""Conservative rules, not CVSS scores or proof of exploitability."""
from core.models import Finding

RULES = {
    "bola": ("High", "Controlled users received the same configured private object."),
    "auth": ("Medium", "Anonymous access matched an authenticated response on a documented protected endpoint; intended access still needs validation."),
    "auth_bypass": ("Medium", "An anonymous request returned HTTP 200 on an endpoint documented as requiring authentication; server-side enforcement requires manual verification."),
    "jwt": ("Low", "Unverified token metadata alone cannot prove server acceptance or compromise."),
    "cors_credentials": ("Medium", "An untrusted origin was allowed with credentials; browser and sensitive-data checks remain necessary."),
    "headers": ("Informational", "Header relevance depends on HTTPS and browser-rendered content."),
    "methods": ("Low", "Advertised methods do not prove they are executable or unauthorized."),
    "docs": ("Informational", "Documentation is not evidence of deployed behavior."),
    "rate": ("Informational", "A small sample cannot establish the absence of rate limiting."),
    "cors": ("Informational", "CORS policy must be interpreted in browser and data-access context."),
}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")

def finding(rule, title, category, endpoint, method, description, evidence,
            recommendation, confidence="Low", classification="Potential issue", **kw):
    severity, reason = RULES[rule]
    return Finding(title, category, severity, endpoint, method, description,
                   evidence, recommendation, confidence, severity_reason=reason,
                   classification=classification, **kw)
