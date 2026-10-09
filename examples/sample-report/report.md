# API Security Assessment

Target: http://127\.0\.0\.1:35945

Assessment date: 2026\-10\-07T07:19:38\.635768\+00:00

## Scope
SYNTHETIC LOCAL\-LAB EXAMPLE — generated during verification\. Supplied paths on one configured origin; explicit two\-user object and rate checks only when requested\. No crawling or guessing\.

## Methodology
Documentation review; serial GET/OPTIONS observations; optional authenticated comparisons, one BOLA case, offline JWT inspection and a bounded rate sample\.

## Severity summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 0 |
| Informational | 13 |

## Endpoint summary

| Method | Endpoint | Authentication | Parameters |
|---|---|---|---|
| GET | /api/public | Anonymous allowed by documentation | \[\] |
| GET | /api/me | Required by documentation | \[\] |
| GET | /api/protected | Required by documentation | \[\] |
| GET | /api/auth\-missing | Required by documentation | \[\] |
| GET | /api/cors | Required by documentation | \[\] |
| GET | /api/html | Anonymous allowed by documentation | \[\] |
| GET | /api/search | Anonymous allowed by documentation | \[\{&\#x27;name&\#x27;: &\#x27;q&\#x27;, &\#x27;in&\#x27;: &\#x27;query&\#x27;, &\#x27;type&\#x27;: &\#x27;string&\#x27;, &\#x27;required&\#x27;: False\}, \{&\#x27;name&\#x27;: &\#x27;limit&\#x27;, &\#x27;in&\#x27;: &\#x27;query&\#x27;, &\#x27;type&\#x27;: &\#x27;integer&\#x27;, &\#x27;required&\#x27;: False\}\] |
| GET | /api/objects/\{object\_id\} | Required by documentation | \[\{&\#x27;name&\#x27;: &\#x27;object\_id&\#x27;, &\#x27;in&\#x27;: &\#x27;path&\#x27;, &\#x27;type&\#x27;: &\#x27;integer&\#x27;, &\#x27;required&\#x27;: True\}\] |
| GET | /api/safe\-objects/\{object\_id\} | Required by documentation | \[\{&\#x27;name&\#x27;: &\#x27;object\_id&\#x27;, &\#x27;in&\#x27;: &\#x27;path&\#x27;, &\#x27;type&\#x27;: &\#x27;integer&\#x27;, &\#x27;required&\#x27;: True\}\] |
| POST | /api/login | Anonymous allowed by documentation | \[\{&\#x27;name&\#x27;: &\#x27;username&\#x27;, &\#x27;in&\#x27;: &\#x27;body&\#x27;, &\#x27;type&\#x27;: &\#x27;string&\#x27;, &\#x27;required&\#x27;: True\}, \{&\#x27;name&\#x27;: &\#x27;password&\#x27;, &\#x27;in&\#x27;: &\#x27;body&\#x27;, &\#x27;type&\#x27;: &\#x27;string&\#x27;, &\#x27;required&\#x27;: True\}\] |

## Findings

### 1. Operation permits anonymous access in documentation

Severity: Informational | Confidence: Low

Classification: Documentation finding

Category: OpenAPI

Endpoint: GET /api/public

This may be intentional for a public operation\.

Severity rationale: Documentation is not evidence of deployed behavior\.

Evidence: \{&quot;anonymous\_allowed&quot;: true\}

Recommendation: Confirm intended access with the API owner\.

References: Not assigned; Not assigned

### 2. Operation permits anonymous access in documentation

Severity: Informational | Confidence: Low

Classification: Documentation finding

Category: OpenAPI

Endpoint: GET /api/html

This may be intentional for a public operation\.

Severity rationale: Documentation is not evidence of deployed behavior\.

Evidence: \{&quot;anonymous\_allowed&quot;: true\}

Recommendation: Confirm intended access with the API owner\.

References: Not assigned; Not assigned

### 3. Operation permits anonymous access in documentation

Severity: Informational | Confidence: Low

Classification: Documentation finding

Category: OpenAPI

Endpoint: GET /api/search

This may be intentional for a public operation\.

Severity rationale: Documentation is not evidence of deployed behavior\.

Evidence: \{&quot;anonymous\_allowed&quot;: true\}

Recommendation: Confirm intended access with the API owner\.

References: Not assigned; Not assigned

### 4. Operation permits anonymous access in documentation

Severity: Informational | Confidence: Low

Classification: Documentation finding

Category: OpenAPI

Endpoint: POST /api/login

This may be intentional for a public operation\.

Severity rationale: Documentation is not evidence of deployed behavior\.

Evidence: \{&quot;anonymous\_allowed&quot;: true\}

Recommendation: Confirm intended access with the API owner\.

References: Not assigned; Not assigned

### 5. JWT configuration review

Severity: Informational | Confidence: Low

Classification: JWT configuration finding

Category: JWT

Endpoint: N/A local token

Decoded claims are untrusted\. This is a JWT configuration finding, not a confirmed vulnerability\. No server acceptance or signature validation was tested\.

Severity rationale: Documentation is not evidence of deployed behavior\.

Evidence: \{&quot;signature\_verified&quot;: false, &quot;algorithm&quot;: &quot;HS256&quot;, &quot;standard\_claims\_present&quot;: \[&quot;exp&quot;, &quot;iss&quot;, &quot;sub&quot;, &quot;iat&quot;, &quot;aud&quot;\], &quot;issues&quot;: \[\]\}

Recommendation: Validate signatures with a fixed algorithm allowlist and expected issuer/audience on the server; enforce required claims and minimize payload data\.

References: Not assigned; Not assigned

### 6. Potential cross\-user object access \(BOLA\)

Severity: High | Confidence: High

Classification: Potential issue

Category: Authorization

Endpoint: GET /api/objects/101

Two verified test users received the configured owner&\#x27;s object\. Confirm that sharing is prohibited by policy\.

Severity rationale: Controlled users received the same configured private object\.

Evidence: \{&quot;observations&quot;: \[\{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/objects/101&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/objects/101&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}\], &quot;identities\_verified&quot;: true, &quot;object\_and\_owner\_match&quot;: true\}

Recommendation: Check the object&\#x27;s owner or access policy on every request before returning it\.

References: CWE\-639; API1:2023 Broken Object Level Authorization

### 7. Context\-relevant security headers absent

Severity: Informational | Confidence: High

Classification: Hardening observation

Category: Security headers

Endpoint: GET /api/public

Missing headers are hardening observations, not proof of an exploitable API flaw\. CSP and framing headers are mainly relevant to browser\-rendered HTML; HSTS only to HTTPS\.

Severity rationale: Header relevance depends on HTTPS and browser\-rendered content\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/public&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2, &quot;missing&quot;: \[&quot;x\-content\-type\-options&quot;\]\}

Recommendation: Review response type and browser use; add appropriate headers\.

References: Not assigned; Not assigned

### 8. Context\-relevant security headers absent

Severity: Informational | Confidence: High

Classification: Hardening observation

Category: Security headers

Endpoint: GET /api/me

Missing headers are hardening observations, not proof of an exploitable API flaw\. CSP and framing headers are mainly relevant to browser\-rendered HTML; HSTS only to HTTPS\.

Severity rationale: Header relevance depends on HTTPS and browser\-rendered content\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 401, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2, &quot;missing&quot;: \[&quot;x\-content\-type\-options&quot;\]\}

Recommendation: Review response type and browser use; add appropriate headers\.

References: Not assigned; Not assigned

### 9. Context\-relevant security headers absent

Severity: Informational | Confidence: High

Classification: Hardening observation

Category: Security headers

Endpoint: GET /api/protected

Missing headers are hardening observations, not proof of an exploitable API flaw\. CSP and framing headers are mainly relevant to browser\-rendered HTML; HSTS only to HTTPS\.

Severity rationale: Header relevance depends on HTTPS and browser\-rendered content\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/protected&quot;, &quot;status&quot;: 401, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2, &quot;missing&quot;: \[&quot;x\-content\-type\-options&quot;\]\}

Recommendation: Review response type and browser use; add appropriate headers\.

References: Not assigned; Not assigned

### 10. Context\-relevant security headers absent

Severity: Informational | Confidence: High

Classification: Hardening observation

Category: Security headers

Endpoint: GET /api/auth\-missing

Missing headers are hardening observations, not proof of an exploitable API flaw\. CSP and framing headers are mainly relevant to browser\-rendered HTML; HSTS only to HTTPS\.

Severity rationale: Header relevance depends on HTTPS and browser\-rendered content\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2, &quot;missing&quot;: \[&quot;x\-content\-type\-options&quot;\]\}

Recommendation: Review response type and browser use; add appropriate headers\.

References: Not assigned; Not assigned

### 11. Possible missing authentication enforcement

Severity: Medium | Confidence: Medium

Classification: Potential issue

Category: Authentication

Endpoint: GET /api/auth\-missing

A documented protected endpoint returned identical JSON with and without credentials\. A valid identity and intended privacy need manual confirmation\.

Severity rationale: Anonymous access matched an authenticated response on a documented protected endpoint; intended access still needs validation\.

Evidence: \{&quot;anonymous&quot;: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, &quot;authenticated&quot;: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, &quot;json\_equal&quot;: true\}

Recommendation: Validate the configured identity and require authentication for private resources\.

References: CWE\-306; API2:2023 Broken Authentication

### 12. Context\-relevant security headers absent

Severity: Informational | Confidence: High

Classification: Hardening observation

Category: Security headers

Endpoint: GET /api/cors

Missing headers are hardening observations, not proof of an exploitable API flaw\. CSP and framing headers are mainly relevant to browser\-rendered HTML; HSTS only to HTTPS\.

Severity rationale: Header relevance depends on HTTPS and browser\-rendered content\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/cors&quot;, &quot;status&quot;: 401, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2, &quot;missing&quot;: \[&quot;x\-content\-type\-options&quot;\]\}

Recommendation: Review response type and browser use; add appropriate headers\.

References: Not assigned; Not assigned

### 13. Untrusted origin allowed with credentials

Severity: Medium | Confidence: Medium

Classification: Potential issue

Category: CORS

Endpoint: GET /api/cors

This response permits the test origin with credentials\. Exploitation also requires browser\-sent credentials and sensitive readable data; bearer tokens are not automatically sent cross\-origin\.

Severity rationale: An untrusted origin was allowed with credentials; browser and sensitive\-data checks remain necessary\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/cors&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;, &quot;access\-control\-allow\-origin&quot;: &quot;https://untrusted\.example&quot;, &quot;access\-control\-allow\-credentials&quot;: &quot;true&quot;, &quot;access\-control\-allow\-methods&quot;: &quot;GET, OPTIONS&quot;, &quot;access\-control\-allow\-headers&quot;: &quot;Authorization, Content\-Type&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}

Recommendation: Use an exact trusted\-origin allowlist and validate actual browser credential behavior\.

References: CWE\-942; API8:2023 Security Misconfiguration

### 14. Context\-relevant security headers absent

Severity: Informational | Confidence: High

Classification: Hardening observation

Category: Security headers

Endpoint: GET /api/html

Missing headers are hardening observations, not proof of an exploitable API flaw\. CSP and framing headers are mainly relevant to browser\-rendered HTML; HSTS only to HTTPS\.

Severity rationale: Header relevance depends on HTTPS and browser\-rendered content\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/html&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2, &quot;missing&quot;: \[&quot;content\-security\-policy&quot;, &quot;referrer\-policy&quot;, &quot;x\-content\-type\-options&quot;, &quot;x\-frame\-options&quot;\]\}

Recommendation: Review response type and browser use; add appropriate headers\.

References: Not assigned; Not assigned

### 15. Context\-relevant security headers absent

Severity: Informational | Confidence: High

Classification: Hardening observation

Category: Security headers

Endpoint: GET /api/search

Missing headers are hardening observations, not proof of an exploitable API flaw\. CSP and framing headers are mainly relevant to browser\-rendered HTML; HSTS only to HTTPS\.

Severity rationale: Header relevance depends on HTTPS and browser\-rendered content\.

Evidence: \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/search&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2, &quot;missing&quot;: \[&quot;x\-content\-type\-options&quot;\]\}

Recommendation: Review response type and browser use; add appropriate headers\.

References: Not assigned; Not assigned

### 16. Rate limiting observed

Severity: Informational | Confidence: High

Classification: Observation

Category: Rate limiting

Endpoint: GET /api/limited

This sample does not establish a global threshold or absence of protection\. No further requests are sent after a stop condition\.

Severity rationale: A small sample cannot establish the absence of rate limiting\.

Evidence: \{&quot;requested\_count&quot;: 5, &quot;observations&quot;: \[\{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/limited&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/limited&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/limited&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 1\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/limited&quot;, &quot;status&quot;: 429, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;, &quot;retry\-after&quot;: &quot;28&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}\]\}

Recommendation: Compare with the documented quota, identity/IP bucket and time window\.

References: Not assigned; Not assigned

## Coverage

\{&quot;requests\_sent&quot;: 43, &quot;observations&quot;: \[\{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/public&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/public&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/public&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/public&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/public&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 401, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/protected&quot;, &quot;status&quot;: 401, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/protected&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/protected&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/protected&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/protected&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/auth\-missing&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/cors&quot;, &quot;status&quot;: 401, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/cors&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/cors&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/cors&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;, &quot;access\-control\-allow\-origin&quot;: &quot;https://untrusted\.example&quot;, &quot;access\-control\-allow\-credentials&quot;: &quot;true&quot;, &quot;access\-control\-allow\-methods&quot;: &quot;GET, OPTIONS&quot;, &quot;access\-control\-allow\-headers&quot;: &quot;Authorization, Content\-Type&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/cors&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;, &quot;access\-control\-allow\-origin&quot;: &quot;https://untrusted\.example&quot;, &quot;access\-control\-allow\-credentials&quot;: &quot;true&quot;, &quot;access\-control\-allow\-methods&quot;: &quot;GET, OPTIONS&quot;, &quot;access\-control\-allow\-headers&quot;: &quot;Authorization, Content\-Type&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/html&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/html&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/html&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/html&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/html&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/search&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/search&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/search&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/search&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;OPTIONS&quot;, &quot;endpoint&quot;: &quot;/api/search&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;text/html; charset=utf\-8&quot;, &quot;allow&quot;: &quot;HEAD, OPTIONS, GET&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}\], &quot;skipped&quot;: \[\{&quot;path&quot;: &quot;/api/objects/\{object\_id\}&quot;, &quot;method&quot;: &quot;GET&quot;, &quot;reason&quot;: &quot;Non\-GET or unresolved template; no active request&quot;\}, \{&quot;path&quot;: &quot;/api/safe\-objects/\{object\_id\}&quot;, &quot;method&quot;: &quot;GET&quot;, &quot;reason&quot;: &quot;Non\-GET or unresolved template; no active request&quot;\}, \{&quot;path&quot;: &quot;/api/login&quot;, &quot;method&quot;: &quot;POST&quot;, &quot;reason&quot;: &quot;Non\-GET or unresolved template; no active request&quot;\}\], &quot;bola&quot;: \{&quot;outcome&quot;: &quot;Potential BOLA&quot;, &quot;observations&quot;: \[\{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/me&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/objects/101&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}, \{&quot;method&quot;: &quot;GET&quot;, &quot;endpoint&quot;: &quot;/api/objects/101&quot;, &quot;status&quot;: 200, &quot;headers&quot;: \{&quot;content\-type&quot;: &quot;application/json&quot;\}, &quot;error&quot;: null, &quot;truncated&quot;: false, &quot;elapsed\_ms&quot;: 2\}\]\}, &quot;rate\_test&quot;: &quot;Requested; see finding evidence and stop conditions&quot;, &quot;stop\_reason&quot;: &quot;Stopped after HTTP 429 or server error&quot;\}

## Metadata

\{&quot;version&quot;: &quot;3\.0\.3&quot;, &quot;security\_schemes&quot;: \{&quot;bearerAuth&quot;: \{&quot;type&quot;: &quot;http&quot;, &quot;scheme&quot;: &quot;bearer&quot;, &quot;bearerFormat&quot;: &quot;JWT&quot;\}\}, &quot;server\_urls\_used&quot;: false, &quot;limitations&quot;: &quot;OpenAPI 3 server base paths/variables and non\-JSON request media types are not expanded\. Use explicit endpoint lists\. External refs are rejected\.&quot;\}

## Limitations

\[&quot;Automated candidates require manual validation and business\-policy context\. No finding does not establish safety\.&quot;, &quot;Documentation is not proof of deployment\. OpenAPI 3 server URLs/base paths/variables are not followed; supply explicit paths where needed\.&quot;, &quot;Active discovery is limited to supplied concrete GET endpoints\. Non\-GET and unresolved path templates are skipped; no injection attacks\.&quot;, &quot;JWT claims are unverified; CORS headers alone do not demonstrate browser exploitation\.&quot;, &quot;No raw bodies or credentials are persisted\. Evidence is deliberately minimized; retain manual evidence privately if required\.&quot;, &quot;TLS verification stays enabled, redirects/proxies are disabled, responses are capped at 256 KiB; truncation/timeouts reduce coverage\.&quot;, &quot;Requests timeout is an inactivity limit, not a strict whole\-run deadline\. Read loop also limits elapsed response processing\.&quot;, &quot;Single\-threaded, at most 200 requests per run, minimum 0\.2 seconds apart\. No retries after 429, 5xx or transport errors\.&quot;\]
