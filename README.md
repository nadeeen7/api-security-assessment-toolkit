# API Security Assessment Toolkit

A modular Python and React security assessment project designed for **APIs you own or have explicit authorization to assess**. The toolkit executes controlled, non-destructive security checks and produces comprehensive dark-themed HTML reports, Markdown summaries, and sanitized, minimized JSON evidence.

> **Responsible Use Notice:** Only test systems you own or have explicit authorization to assess. This toolkit is designed for learning, defense, and authorized pre-audit validation—not unauthorized attacks or destructive exploitation.

---

## 1. Project Overview

The **API Security Assessment Toolkit** is an authorized assessment and learning framework that bridges the gap between manual testing (e.g., Burp Suite) and automated vulnerability checks. It evaluates REST/HTTP APIs against common security misconfigurations and access control flaws (including OWASP API Security Top 10 risks).

### Core Goals
- **Safe & Non-Destructive:** Uses small, strictly paced request budgets (default: 100 requests, hard maximum: 200). Never performs fuzzy exploitation, mass injection, or destructive state manipulation.
- **Evidence-Based Reporting:** Clearly distinguishes confirmed dynamic findings, potential issues, and documentation-based observations.
- **Privacy & Secret Redaction:** Never saves raw response bodies, bearer tokens, passwords, cookies, or sensitive query strings in reports, logs, or history.
- **Dual Execution Interfaces:** Run assessments seamlessly via the **Command Line Interface (CLI)** or the modern single-origin **Web Application (React + Flask)**.

---

## 2. Features

All features listed below are actively implemented, tested, and verified in the source code:

| Feature / Assessment Module | Description | Implementation Status |
| :--- | :--- | :--- |
| **OpenAPI Specification Analysis** | Validates OpenAPI 3.0.x / 3.1.x and Swagger 2.0 specs. Extracts endpoints, security requirements, and schema models offline without sending network traffic. | ✅ Fully Implemented (`modules/openapi_analysis.py`) |
| **Endpoint & Parameter Discovery** | Identifies query, path, and request body schema parameters. Discovers active GET endpoints while safely resolving documented path parameter examples. | ✅ Fully Implemented (`modules/endpoint_discovery.py`, `modules/parameter_discovery.py`) |
| **Authentication Analysis** | Identifies documented-protected endpoints that respond with HTTP 200 to anonymous requests (`auth_bypass`), and detects endpoints lacking auth enforcement. | ✅ Fully Implemented (`modules/auth_analysis.py`) |
| **BOLA / IDOR Testing** | Verifies Broken Object Level Authorization (API1:2023) by comparing object retrieval between two distinct authenticated caller identities (e.g., Alice vs. Bob). | ✅ Fully Implemented (`modules/authorization_analysis.py`) |
| **CORS Misconfiguration Analysis** | Probes CORS policies using synthetic untrusted origins (`https://untrusted.example`). Flags reflected origins with credential allowances (`Access-Control-Allow-Credentials: true`). | ✅ Fully Implemented (`modules/cors_analysis.py`) |
| **Security Headers Hardening** | Context-aware inspection of essential hardening headers: HSTS (`Strict-Transport-Security` on HTTPS), CSP, framing (`X-Frame-Options`), and `X-Content-Type-Options`. | ✅ Fully Implemented (`modules/headers_analysis.py`) |
| **HTTP Method Review** | Sends safe OPTIONS requests to examine advertised methods via the `Allow` header without executing state-modifying verbs (no DELETE, PUT, or PATCH). | ✅ Fully Implemented (`modules/method_detection.py`) |
| **Rate-Limit Testing** | Evaluates quota enforcement with a bounded sample (up to 10 requests) with strict pacing. Immediately halts upon observing HTTP 429, 5xx, or transport errors. Accurately flags 404 paths. | ✅ Fully Implemented (`modules/rate_limit.py`) |
| **Offline JWT Metadata Review** | Inspects token header algorithms (e.g., detects insecure `none`) and standard claims (expiry, subject, issuer) without claiming signature verification. | ✅ Fully Implemented (`modules/jwt_analysis.py`) |
| **Multi-Format Dark Theme Reporting** | Generates an interactive dark-themed standalone HTML report (`report.html`), Markdown summary (`report.md`), and raw minimized machine evidence (`evidence.json`). | ✅ Fully Implemented (`reports/report_generator.py`) |

---

## 3. Technology Stack

### Backend
- **Python 3.11+** (tested on Python 3.12 and 3.13)
- **Flask 3.1.x:** Single-origin API and local asset serving (`web/app.py`)
- **Requests 2.32+ / urllib3:** Controlled loopback/HTTPS communication with request budget tracking
- **PyJWT 2.10+:** Local lab authentication and offline JWT structure inspection
- **openapi-spec-validator 0.7+ / jsonschema:** Schema resolution and OpenAPI conformance validation
- **Jinja2 3.1+:** Secure HTML report compilation
- **pytest 8.3+:** Automated unit, integration, and security assertion test suite (155 tests)

### Frontend
- **React 19.3.x:** Declarative dashboard architecture
- **Vite 8.3.x:** Fast client-side bundler and development server
- **Tailwind CSS 4.3.x:** High-performance styling with dark-mode aesthetic
- **React Router 7.18.x:** Client-side SPA routing with deep-link support

---

## 4. Project Structure

```text
api-security-toolkit/
├── core/                         # Core execution engine
│   ├── http_client.py            # Budget-limited HTTP client (pacing, timeout, stop conditions)
│   ├── models.py                 # Dataclasses: Endpoint, Finding, Observation
│   ├── risk_engine.py            # Conservative severity rules and rationale mapping
│   ├── path_resolver.py          # Safe parameter replacement using OpenAPI example data
│   └── logger.py                 # Sanitized logging (no credentials or bodies)
├── modules/                      # 10 modular security analysis plugins
│   ├── openapi_analysis.py       # OpenAPI specification parser and offline checks
│   ├── endpoint_discovery.py     # Discovers and filters testable endpoints
│   ├── parameter_discovery.py    # Discovers parameters and schemas
│   ├── auth_analysis.py          # Authentication bypass and enforcement verification
│   ├── authorization_analysis.py # BOLA / IDOR cross-account comparison
│   ├── rate_limit.py             # Controlled rate-limit probing and 404/429 handling
│   ├── cors_analysis.py          # CORS credential reflection checks
│   ├── headers_analysis.py       # Context-dependent security headers checks
│   ├── method_detection.py       # OPTIONS method discovery
│   └── jwt_analysis.py           # Offline JWT header and claims analysis
├── reports/                      # Report generator and templates
│   ├── report_generator.py       # Compiles evidence.json, report.html, report.md
│   └── templates/report.html     # Dark-themed responsive HTML report template
├── web/                          # Web application backend (Flask)
│   ├── app.py                    # REST API routes and single-origin static file serving
│   ├── jobs.py                   # Sequential assessment queue and background worker
│   ├── job_config.py             # Validates web payload and builds engine arguments
│   ├── request_schema.py         # Request schema validation and SSRF origin checks
│   └── store.py                  # Job filesystem storage and newest-first index
├── webui/                        # React frontend SPA
│   ├── src/                      # Components, hooks, pages (Assessment, Progress, Results, Reports)
│   ├── dist/                     # Compiled production bundle served directly by Flask
│   ├── package.json              # Frontend dependencies and build scripts
│   └── vite.config.js            # Vite configuration with /api proxy to Flask (:5055)
├── lab/                          # Local synthetic learning API
│   └── app.py                    # Intentionally imperfect vulnerable Flask API (:5000)
├── input/                        # Test configurations and sample OpenAPI specs
│   ├── openapi.json              # Local learning API specification (10 endpoints)
│   ├── endpoints.json            # Explicit endpoint test list
│   ├── lab_config.json           # Two-identity BOLA test configuration (Alice & Bob)
│   └── lab_safe_config.json      # Correctly authorized object configuration for verification
├── scripts/                      # Helper scripts
│   ├── create_lab_tokens.py      # Generates valid JWT tokens for Alice and Bob
│   └── browser_verify.cjs        # Headless Playwright integration test suite
├── tests/                        # 155 automated unit and integration tests
├── output/                       # Assessment outputs and historical evidence (gitignored)
├── docs/                         # Additional guides
│   ├── PHASE_GUIDE.md            # Detailed phase breakdown and study notes
│   ├── BURP_VALIDATION.md        # Manual verification techniques with Burp Suite
│   └── SOURCES.md                # OWASP and CWE reference links
├── main.py                       # CLI entry point and assessment orchestrator
├── requirements.txt              # Production dependency requirements
└── requirements-tested.txt       # Tested dependency lock versions
```

---

## 5. Installation and Setup

### Prerequisites
- **Python 3.11+** installed and available in your PATH (`python --version` or `py -3 --version`)
- **Node.js 18+** & **npm** (required to build or run the web interface)

### Step 1: Clone or Extract the Project
Open a command prompt in your projects folder:
```bat
cd /d "%USERPROFILE%\Projects\api-security-toolkit"
```

### Step 2: Set Up Python Virtual Environment
```bat
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
```

### Step 3: Set Up and Build Frontend
```bat
cd webui
npm install
npm run build
cd ..
```
*Note: The production frontend bundle is compiled directly into `webui/dist` and is automatically served by Flask on port `5055`.*

---

## 6. How to Run

### 1. Start the Local Training Lab
In your first terminal, start the local synthetic vulnerable API:
```bat
.venv\Scripts\activate.bat
python -c "from lab.app import create_app; create_app().run(port=5000)"
```
*Expected: Lab server running on `http://127.0.0.1:5000`.*

### 2. Generate Lab Credentials (Alice & Bob)
In a second terminal, generate fresh test JWT tokens for Alice and Bob:
```bat
.venv\Scripts\activate.bat
python scripts\create_lab_tokens.py
```
*Expected: Saves `.local/alice.token` and `.local/bob.token` (valid for 1 hour).*

### 3. Start the Web Toolkit (Single-Origin)
In the second terminal, launch the web toolkit backend:
```bat
python -m web
```
*Expected: Serving Flask app on `http://127.0.0.1:5055`.*

Now open **http://127.0.0.1:5055/** in your web browser. The web interface and backend API run seamlessly from the same origin.

### 4. Optional: Run Frontend in Development Mode (Vite)
If actively developing the React UI, you can run the Vite dev server with Hot Module Reloading:
```bat
cd webui
npm run dev
```
Open **http://127.0.0.1:5173/**. Vite automatically proxies `/api` calls to Flask on port `5055`.

### 5. Run the Test Suite
```bat
python -m pytest -q
```
*Expected: 155 passed tests.*

---

## 7. How to Perform an Assessment

### Option A: Using the Web Dashboard (Recommended)

1. Open **http://127.0.0.1:5055/**.
2. **Card 1 (Target API):** Enter the authorized target URL (e.g., `http://127.0.0.1:5000`). Check the authorization confirmation checkbox.
3. **Card 2 (API Specification):** Paste your OpenAPI specification (or click **Load Sample Spec** to load `input/openapi.json`).
4. **Card 3 (Authentication):** Select **Bearer Token** and paste your primary token (e.g., contents of `.local/alice.token`).
5. **Card 4 (Security Tests):** Keep the default **Recommended tests** selection.
6. **Advanced Options (Optional):**
   - **BOLA Configuration:** Enter Object Path `/api/objects/101`, Identity Path `/api/me`, Secondary Token (Bob), Expected ID `101`, ID Field `id`, Owner Field `owner`.
   - **Rate Limiting:** Set Path to `/api/limited`, Request Count `5`, Delay `0.2`s.
7. Click **Start assessment**.
8. Follow real-time progress on the **Progress** page. Once completed, review categorized findings on **Results** and export the dark-themed **HTML Report** from **Reports**.

### Option B: Using the CLI

Run a comprehensive automated assessment against the local lab:
```bat
python main.py --target http://127.0.0.1:5000 ^
  --openapi input\openapi.json ^
  --config input\lab_config.json ^
  --bola ^
  --jwt-file .local\alice.token ^
  --rate-limit-path /api/limited ^
  --rate-limit-delay 0.2 ^
  --output output\my-assessment
```

Open the newly generated report:
```bat
start "" "output\my-assessment\report.html"
```

---

## 8. Local Lab and Test Users

The included training lab (`lab/app.py`) is an intentionally imperfect synthetic REST service designed for learning and testing.

### Test Accounts
- **Alice:** Username `alice`, Password `alice-lab-only`. Owns Object `101`.
- **Bob:** Username `bob`, Password `bob-lab-only`. Owns Object `202`.

### Endpoints in the Local Lab
- `GET /api/public`: Publicly accessible synthetic information.
- `POST /api/login`: Authenticates demo users and returns an ephemeral JWT.
- `GET /api/me`: Returns the authenticated subject (`{"sub": "alice"}`).
- `GET /api/protected`: Authenticated endpoint (requires valid Bearer token).
- `GET /api/auth-missing`: Intentionally misconfigured—documented as requiring auth, but responds with HTTP 200 anonymously.
- `GET /api/objects/<id>`: Intentionally vulnerable to BOLA—authenticates the caller but does not verify whether caller is the owner of the requested object.
- `GET /api/safe-objects/<id>`: Properly protected object retrieval—verifies ownership before returning data.
- `GET /api/cors`: Reflected CORS test endpoint with credential support.
- `GET /api/html`: Endpoint returning HTML without defensive browser headers.
- `GET /api/limited`: Rate-limited endpoint (quota: 3 requests per 30-second window per IP; returns HTTP 429 on subsequent requests).

### Generating Tokens
Always generate fresh tokens using the helper script:
```bat
python scripts\create_lab_tokens.py
```
Tokens are saved to `.local/alice.token` and `.local/bob.token`. Tokens expire after 1 hour and regenerate when the lab is restarted.

> **Caution:** Never publish, share, or commit token files to version control. The `.local` directory is excluded in `.gitignore`.

---

## 9. Security Checks and Limitations

### Classification Model
Findings generated by the toolkit are strictly categorized:
1. **Confirmed Dynamic Finding:** A reproducible dynamic condition verified through live HTTP responses (e.g., cross-account access in BOLA, HTTP 200 on an unauthenticated request to a protected endpoint).
2. **Potential Issue:** A condition requiring business-context confirmation (e.g., untrusted origin allowed with credentials).
3. **Observation / Hardening Recommendation:** Informational observations derived from documentation or missing optional headers (e.g., missing framing headers on an API endpoint, or documented anonymous access).

### Unsupported Checks & Boundaries

| Category | Policy / Status | Rationale |
| :--- | :--- | :--- |
| **SQL / NoSQL Injection** | ❌ Unsupported | The toolkit does not fuzz databases or inject exploit payloads. |
| **Mass Assignment** | ❌ Unsupported | The toolkit discovers schemas but does not send modifying parameter payloads. |
| **SSRF / Path Traversal** | ❌ Unsupported | No fuzzing for directory traversal or server-side request redirection. |
| **Automated ID Enumeration** | ❌ Unsupported | BOLA testing strictly compares two configured IDs; it never brute-forces or guesses object IDs. |
| **State-Modifying Verbs** | ❌ Read-Only Only | Only safe GET and OPTIONS requests are actively dispatched. POST is restricted solely to the local login helper. |

> **Important Limitation:** A clean assessment report with zero findings does **not** prove an API is secure or free of vulnerabilities. It only indicates that the specific implemented checks did not detect issues within the defined parameters.

---

## 10. Testing and Verification

The test suite covers the entire toolkit, including CLI parsing, HTTP client controls, module logic, risk calculation, web APIs, session security, and report formatting.

### Verification Commands
```bat
:: Run Python unit & integration test suite
python -m pytest -q

:: Verify frontend build
npm --prefix webui run build
```

### Verified Test Results
- **Pytest Suite:** **155 passed** (0 failed).
- **Frontend Build:** Built cleanly with Vite into `webui/dist` (0 errors).

---

## 11. Security and Responsible Use

- **Explicit Authorization:** Only run this toolkit against loopback targets or external APIs for which you have explicit written authorization.
- **Strict Network Controls:**
  - Single-origin loopback binding by default (`127.0.0.1:5055`).
  - Redirect following is explicitly disabled (`allow_redirects=False`) to prevent open-redirect SSRF.
  - TLS certificate verification remains strictly enforced for all HTTPS targets.
- **CSRF & Web Hardening:**
  - All state-changing web API endpoints (`POST /api/assessment/start`, etc.) require an exact origin check and a per-run unguessable session token (`X-Session-Token`).
  - Restrictive Content-Security-Policy (CSP) headers applied across all served web pages and generated HTML reports.
- **Secret Redaction:**
  - Token headers (`Authorization`), cookies, and request bodies are excluded from serialization.
  - Evidence payloads store only minimized status codes, elapsed response times, and an allowlist of security-relevant headers.

---

## 12. Current Project Status

- **Engine & Modules:** All 10 security modules are fully implemented, tested, and active.
- **Reporting:** Reports feature a dark theme, color-coded status badges, and precise status tracking (`HTTP <code status>` vs. `Not observed`).
- **Web Interface:** Full feature parity with the CLI, including live progress tracking, interactive findings filtering, and report downloads.
- **Lab Integration:** Verified against the local vulnerable lab with verified BOLA, rate-limiting (HTTP 429), CORS, and authentication tests.
- **Quality Assurance:** 155 automated tests passing with zero regressions.
