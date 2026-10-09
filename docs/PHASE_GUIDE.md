# Beginner guide — all 19 phases

The final instruction requested all phases together. They are delivered together, but this guide preserves a learning checkpoint for each one. Work through them in order. Commands assume CMD, the project directory as current directory, and an activated `.venv`, unless stated otherwise. Files mentioned below are already created; review them with `notepad path\to\file.py`. You do not need to overwrite them.

## Vocabulary before the code

- **API:** a defined way for programs to request data or actions from another program.
- **Endpoint:** a particular API path such as `/api/me`.
- **HTTP method:** the requested action. GET usually reads; POST submits. A poorly designed GET can still have side effects, so only list approved endpoints.
- **Header:** request or response metadata, for example content type or an authorization token.
- **JSON:** structured text with objects, lists, names and values.
- **Authentication:** “Who are you?”
- **Authorization:** “What are you allowed to do?”
- **BOLA/IDOR:** a missing object-access check that can let one user read another user's object.
- **JWT:** a token often representing an authenticated session. Its payload is readable; a signature detects tampering when properly verified. A signature is not encryption.
- **CORS:** browser rules controlling which origins can read cross-origin responses. An origin is scheme + host + port. CORS is not server-side authentication or a firewall.
- **Rate limit:** a rule restricting requests within a time window.
- **Finding:** a structured security observation needing interpretation.
- **Evidence:** recorded facts supporting an observation.
- **Severity:** potential impact/priority; **confidence:** how strongly the available evidence supports the statement. They are different.
- **False positive:** an apparent issue that is not actually a vulnerability in context.
- **OpenAPI/Swagger:** a machine-readable description of API operations, input and access requirements.
- **Schema:** a description of the expected shape/types of data.
- **CLI:** command-line interface, the options you type in a terminal.
- **CWE:** a standardized weakness label; **OWASP API category:** a broad grouping of API security risks. Neither proves a vulnerability.

## Phase 1 — Project setup

**What and why:** Create an isolated Python project so dependency installation and imports are predictable. We use Requests for HTTP, PyJWT for tokens, openapi-spec-validator for document validation, Flask for the lab, Jinja2 for escaped report templates and pytest for tests. Python already includes JSON, logging, argument parsing, dataclasses and paths; do not install separate packages for these.

**Files:** `main.py`, `requirements.txt`, package folders, `README.md`, `.gitignore`. Since all phases are now included, `main.py` already has the full CLI; its environment-check mode is the basic no-network starting point.

**Manual work:** Extract the project to `%USERPROFILE%\Projects\api-security-toolkit`. Use the extraction command in README if you have not already done this. Check your Python version first.

```bat
cd /d "%USERPROFILE%\Projects\api-security-toolkit"
py -3 --version
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
python main.py --check-environment
```

**Important code:** `parser()` defines named options; `main()` handles expected errors and the exit status. `if __name__ == "__main__"` means “run this function when this file is executed, not merely imported.” `sys.version_info` checks Python; `sys.prefix != sys.base_prefix` identifies a virtual environment. `importlib.metadata.version()` shows installed package versions.

**Test/expected:** A Python version >=3.11, executable inside `.venv`, `Virtual environment: True`, each installed dependency and `Environment check passed. No API requests sent.` If any fails, fix setup before starting the lab.

## Phase 2 — Safe local demo API

**What and why:** A local service with known behavior gives you a safe target and known positive/negative results. Flask maps paths to Python functions. No real users or business data are included.

**Understand the examples before running:**

| Path | Intended lesson |
|---|---|
| `/api/public` | Public access is intentional, not a missing-auth vulnerability |
| `/api/login` (POST) | Two known demo accounts receive signed JWTs; no guessing |
| `/api/me` | Validates the token and returns the authenticated subject |
| `/api/protected` | Correct authentication check |
| `/api/auth-missing` | Documented private but decorator omitted: demonstrates missing authentication |
| `/api/objects/101` | Requires login but fails to check owner: Bob can read Alice's synthetic notebook |
| `/api/safe-objects/101` | Correct ownership check: Bob receives 404 |
| `/api/cors` | Configurable reflected, wildcard or strict CORS; reflect+credentials is suspicious, not browser exploit proof |
| `/api/html` | HTML without relevant browser hardening headers |
| `/api/search?q=demo&limit=5` | Benign query parameters, no injection testing |
| `/api/limited` | Three requests per IP per 30-second fixed window, then 429 |

**Files:** `lab/app.py`, `scripts/create_lab_tokens.py`, example input files.

**Important code:** `create_app()` creates an independent Flask app for each test. `@app.get` and `@app.post` associate methods/paths with functions. `authenticated` is a decorator: a wrapper that checks a signed token before the endpoint runs. It fixes the accepted algorithm to HS256 and requires expected issuer/audience/time claims. `g.subject` stores the identity for just that request. The vulnerable object function omits the owner comparison; `safe_object` includes it. Rate state is a small in-memory dictionary, reset on restart. `after_request` adds demonstration CORS headers. This limiter is educational, not a distributed production limiter.

**Manual commands, terminal 1:**

```bat
python -m lab.app
```

**Terminal 2:**

```bat
cd /d "%USERPROFILE%\Projects\api-security-toolkit"
.venv\Scripts\activate.bat
python scripts\create_lab_tokens.py
curl.exe http://127.0.0.1:5000/api/public
curl.exe -i http://127.0.0.1:5000/api/protected
```

**Expected:** Server at loopback port 5000; two token files under `.local`; public JSON; protected response `401`. The helper submits exactly Alice and Bob's known passwords and prints no tokens. A fresh random signing secret is generated per server restart.

**CORS mode change:** Stop the first terminal with Ctrl+C, then:

```bat
set LAB_CORS_MODE=strict
python -m lab.app
```

After restarting, regenerate tokens in terminal 2. Use `set LAB_CORS_MODE=reflect` to restore the vulnerable demonstration. Do not bind to `0.0.0.0` or enable Flask debug mode.

## Phase 3 — HTTP client

**What and why:** Centralize network behavior so every module shares the same scope and stop rules. A timeout prevents indefinite socket inactivity; a request budget bounds total attempts.

**File:** `core/http_client.py`.

**Important code:** `validate_path()` rejects external URLs, traversal segments, backslashes and control characters. `HTTPClient.__init__()` validates an origin-only target and numeric limits. `Session.trust_env=False` avoids inherited proxies and credentials. `request()` enforces methods, increments a shared budget, spaces request starts, disables redirects, keeps TLS verification on, reads a bounded response, and normalizes header names. `Observation` returns status/JSON/error separately. `finally` clears cookies so one identity does not contaminate another. `close()` releases connections.

**Manual/test:** Review the file and run the real local integration tests:

```bat
notepad core\http_client.py
python -m pytest tests\test_http_client.py
```

**Expected:** All pass, including timeout handling, external-path rejection, redirect non-following, response size cap and stopping on server errors. The CLI uses GET/OPTIONS only. Explicit POST support is for the known local login helper; destructive methods are not implemented.

## Phase 4 — Endpoint discovery

**What and why:** Read approved paths and methods so assessments have a clear scope. “Discovery” here is inventory extraction, not probing thousands of guessed URLs.

**File:** `modules/endpoint_discovery.py`; inputs `input/openapi.json`, `input/endpoints.json`.

**Important code:** `discover()` reads a specification and/or JSON list, validates paths and deduplicates by `(path, method)`. Explicit list entries replace identical documented pairs; set their `security` field if needed. Missing security metadata in a list means unknown, not public.

**Manual:** Read the example list. A string means GET. An object can contain `path`, `method`, `security`. Never put secrets into query strings; although values are omitted from reports, your API/access logs might record them.

```bat
notepad input\endpoints.json
python main.py --openapi input\openapi.json --output output\phase04
start "" "output\phase04\report.html"
```

**Expected:** Ten documented operations, with method, path, authentication interpretation and parameter names; zero API requests. Path placeholders such as `{object_id}` stay placeholders. The explicitly configured BOLA case is how we test one concrete ID safely.

## Phase 5 — OpenAPI analysis

**What and why:** Inspect the API contract before comparing deployed behavior. Incorrect/missing documentation can explain apparent findings.

**File:** `modules/openapi_analysis.py`.

**Important code:** `walk()` rejects external references and schema rebasing; `validate()` from openapi-spec-validator checks specification structure; `resolve()` expands local references with recursion/depth/node limits. Operation-level security overrides the global setting. An empty security list, or an empty requirement alternative, permits anonymous use in the contract. Path-level and operation parameters merge by name/location. Swagger 2 `basePath`, body schema and security definitions are supported; OAS3 JSON request content and response definitions are extracted. Server URLs are never used as scan destinations.

**Manual/test:**

```bat
python -m pytest tests\test_documentation.py
python main.py --openapi input\openapi.json --output output\phase05
```

**Expected:** Valid sample parsed, Swagger 2 test passes, external refs rejected before remote retrieval, invalid document fails safely. Public documentation produces informational notes, not confirmed vulnerabilities. YAML, OAS 3.2, dynamic refs, arbitrary `$id` scopes and OAS3 server/base-path expansion are out of scope. Recursive schemas may be summarized at the limit. Live payloads are not validated against response schemas.

## Phase 6 — HTTP method analysis

**What and why:** Find discrepancies between documented and advertised methods. OPTIONS can return an `Allow` header without executing the advertised methods.

**File:** `modules/method_detection.py`.

**Important code:** `analyze()` compares `Allow` against expected methods, allowing normal HEAD/OPTIONS additions. Only successful OPTIONS responses are interpreted. It never sends DELETE, PUT, PATCH or TRACE. A missing `Allow` header gives no finding, not proof that no other method exists.

```bat
python -m pytest tests\test_analysis.py -k options
python main.py --target http://127.0.0.1:5000 --openapi input\openapi.json --output output\phase06
```

**Expected:** Test confirms an unexpected advertised DELETE gets a Low candidate. Ordinary Flask GET/HEAD/OPTIONS behavior is not flagged. Review coverage evidence for raw advertised method names.

## Phase 7 — Authentication analysis

**What and why:** Compare “no identity supplied” with one configured identity for endpoints documented as private.

**File:** `modules/auth_analysis.py`.

**Important code:** `requires_auth()` understands optional anonymous security alternatives. `analyze()` reports a candidate only if both requests return HTTP 200 with identical complete JSON and documentation requires authentication. Matching bodies alone still do not prove sensitive access: cache behavior, ignored credentials, public data and documentation errors need review.

**Manual:** Start lab and create tokens (Phase 2). Inspect `input/lab_config.json`; it contains file paths, not token contents.

```bat
python main.py --target http://127.0.0.1:5000 --openapi input\openapi.json --config input\lab_config.json --output output\phase07
python -m pytest tests\test_analysis.py -k auth_missing
```

**Expected:** `/api/auth-missing` yields a Medium potential issue; `/api/protected` denies anonymous access and does not. A successful identity is not inferred just from having a token. BOLA separately verifies identities with `/api/me`. Cookie, API-key and OAuth login flows are not implemented.

## Phase 8 — Authorization / BOLA

**What and why:** A valid login must not grant access to every user's record. We compare one object explicitly known to belong to Alice with a request by Bob.

**File:** `modules/authorization_analysis.py`; `input/lab_config.json`, `input/lab_safe_config.json`.

**Important code:** `analyze()` first confirms two different credentials return their expected subjects from `identity_path`. It then makes exactly two object requests. The configured object-ID field and owner field must match the expected values in both successful complete JSON responses. No ID ranges, guessing, brute force or account creation exists. This minimal comparator supports top-level fields; nested/custom response formats need an explicit adapter, not loose body similarity.

```bat
python main.py --target http://127.0.0.1:5000 --config input\lab_config.json --bola --output output\phase08-vulnerable
python main.py --target http://127.0.0.1:5000 --config input\lab_safe_config.json --bola --output output\phase08-safe
python -m pytest tests\test_analysis.py -k bola
```

**Expected:** Vulnerable case: High potential cross-user access with High confidence in the observation. Safe case: no BOLA finding; coverage says `Access denied for other user`. A failed identity or unmatched object produces “Inconclusive,” not “safe.” Confirm the business rule forbids sharing before labeling a real-system finding confirmed.

## Phase 9 — JWT analysis

**What and why:** Inspect token configuration offline without trying to bypass authentication.

**File:** `modules/jwt_analysis.py`.

**Important code:** `get_unverified_header()` and `jwt.decode(... verify_signature=False)` only read metadata here. They are never used by the lab to accept logins. The lab uses actual verified decoding. We inspect algorithm label, exp/iat/nbf times, issuer/subject presence/type and potentially sensitive field names, including nested structures. Field values and the complete token are omitted from evidence. Signature, expected issuer/audience matching, key strength and actual server acceptance are not verified by the analyzer.

```bat
python main.py --jwt-file .local\alice.token --output output\phase09
python -m pytest tests\test_analysis.py -k jwt
```

**Expected:** Report explicitly says `JWT configuration finding` and `signature_verified: false`. Healthy demo metadata is informational; suspicious metadata is Low. Decoded claims remain untrusted. No token forgery, signature cracking, bypass or malicious token submission is implemented.

## Phase 10 — Security headers

**What and why:** Check browser/transport hardening where relevant. Missing a header does not automatically make an API vulnerable.

**File:** `modules/headers_analysis.py`.

**Important code:** All received responses are considered for `X-Content-Type-Options`. HSTS is only relevant to HTTPS. CSP and Referrer-Policy checks are added for HTML, and X-Frame-Options is suggested when CSP lacks `frame-ancestors`. This version checks missing/empty headers, not full policy correctness. JSON API responses do not automatically need HTML framing policies.

```bat
python main.py --target http://127.0.0.1:5000 --openapi input\openapi.json --output output\phase10
python -m pytest tests\test_analysis.py -k header_context
```

**Expected:** Informational hardening notes. HTTP loopback is not penalized for missing HSTS. `/api/html` has more relevant missing headers than a JSON response.

## Phase 11 — CORS

**What and why:** Identify cross-origin policy requiring a browser-based follow-up. Browsers enforce CORS; command-line clients do not.

**File:** `modules/cors_analysis.py`; orchestration in `main.py` sends actual GET and OPTIONS preflight.

**Important code:** A single fixed origin `https://untrusted.example` is supplied. No network request is sent to that domain. Exact reflection plus `Access-Control-Allow-Credentials: true` produces Medium pending browser validation. Wildcard origin produces Informational; wildcard plus credentials is rejected by browsers for credentialed reads and is not automatically a leak. Preflight evidence includes allowed methods/headers, but this version does not fully evaluate browser policy or cache behavior.

```bat
python main.py --target http://127.0.0.1:5000 --openapi input\openapi.json --config input\lab_config.json --output output\phase11
python -m pytest tests\test_analysis.py -k cors
```

**Expected:** Default reflected `/api/cors` is suspicious; strict mode with the test origin produces no CORS finding. The lab uses an explicit bearer token, which a malicious website does not automatically possess. Do not call it confirmed cross-origin account compromise.

## Phase 12 — Rate limiting

**What and why:** Observe whether a very small request sample encounters throttling. This is not load testing.

**File:** `modules/rate_limit.py`.

**Important code:** `analyze()` accepts at most 10 requests, defaults to 5 with a 0.5-second delay, runs serially and obeys the client's shared budget. Stops on 429, transport failure, server error, authentication denial or redirect. `Retry-After` is recorded when present; the tool does not automatically resume. Client-wide stop after 429 prevents other checks from continuing, which is why the orchestrator runs the rate sample last.

**Manual:** Wait 30 seconds since any previous rate test, or restart lab and regenerate tokens. Do not add `/api/limited` to general endpoint discovery for this demonstration; those extra observations would consume its quota first.

```bat
python main.py --target http://127.0.0.1:5000 --rate-limit-path /api/limited --rate-limit-count 5 --rate-limit-delay 0.5 --output output\phase12
python -m pytest tests\test_analysis.py -k rate
```

**Expected:** Fresh bucket: three 200 responses then one 429, no fifth request; Retry-After recorded. “No 429” remains Informational because the quota may be larger, keyed differently or applied elsewhere. The threshold is a lab demonstration, not a recommended real API quota.

## Phase 13 — Parameter discovery

**What and why:** Inventory approved inputs without injecting payloads or guessing hidden parameter names.

**File:** `modules/parameter_discovery.py`.

**Important code:** `extract()` combines OpenAPI parameter names/types, `{path}` names, query names and JSON request schema properties. `schema_parameters()` traverses nested object/array and composition schemas with a depth limit. Query values are intentionally discarded. Schema property extraction is a bounded inventory; union/conditional required semantics are not a complete JSON Schema evaluator.

```bat
python main.py --openapi input\openapi.json --endpoints input\endpoints.json --output output\phase13
python -m pytest tests\test_documentation.py -k parameter
```

**Expected:** `q`, `limit`, `object_id`, login `username` and `password` field names can appear. Actual passwords or query values do not. No injection requests are sent.

## Phase 14 — Finding model and evidence

**What and why:** Every module should describe results using the same fields, making reports comparable and easier to interpret.

**File:** `core/models.py`.

**Important code:** `@dataclass` defines named data containers. `Endpoint` holds documentation, `Observation` holds one HTTP result, and `Finding` holds title/category/severity/endpoint/method/description/evidence/recommendation/confidence/CWE/OWASP plus classification and severity rationale. `field(default_factory=list)` creates a new list for each object, avoiding accidentally shared data. `to_dict()` prepares only findings for reports. `Observation.evidence()` is the privacy boundary: it does not serialize `data`, the raw in-memory response JSON. Only selected headers, path without query, status, error class, truncation and timing are recorded.

```bat
notepad core\models.py
python -m pytest tests\test_analysis.py -k finding_model
python -m pytest tests\test_reports_cli.py -k local_end_to_end
```

**Expected:** Consistent fields and no demo token or notebook body in reports. The user's sample wildcard-CORS High finding is deliberately not used as a severity rule; wildcard alone does not establish that risk.

## Phase 15 — Risk engine

**What and why:** Separate severity judgment from detection code and include a reason for each assignment. These are transparent project rules, not CVSS scores.

**File:** `core/risk_engine.py`.

| Severity | Meaning here | Example/rule |
|---|---|---|
| Critical | Exceptional broad compromise demonstrated | No implemented check automatically awards Critical |
| High | Strong evidence of private cross-user data exposure | Explicit two-user/object match, pending sharing-policy confirmation |
| Medium | Plausible access-policy issue requiring more context | Anonymous/authenticated private-response match; reflected credentialed CORS |
| Low | Limited configuration concern or advertised capability | JWT metadata issues; unexpected methods in Allow |
| Informational | Observation/hardening/context only | Missing headers, public docs, wildcard CORS, bounded rate results |

**Important code:** `RULES` maps a rule name to `(severity, rationale)`. `finding()` creates the object consistently; `SEVERITIES` fixes reporting order. Confidence describes the strength of observed evidence and must not be mistaken for confirmed impact. Do not raise severity just to make a report look serious.

```bat
notepad core\risk_engine.py
python -m pytest tests\test_analysis.py -k finding_model
```

**Expected:** Documentation finding is Informational with a nonempty rationale. Use manual validation and actual impact to decide the final risk on real authorized systems.

## Phase 16 — Reports

**What and why:** Produce readable deliverables and structured minimized evidence, including incomplete coverage and limitations.

**Files:** `reports/report_generator.py`, `reports/templates/report.html`.

**Important code:** `generate()` counts actual findings instead of hardcoding example counts. Jinja2 autoescaping treats input as text instead of executable HTML. The template has no external fonts/scripts/assets. `md()` escapes Markdown/HTML characters. `scrub()` in main removes configured token strings from the full report before output. Evidence JSON allows inspection of observations; no raw response body is exported. Output directories are created if needed; using an existing directory replaces those three filenames.

```bat
python main.py --openapi input\openapi.json --output output\phase16
start "" "output\phase16\report.html"
notepad output\phase16\report.md
python -m pytest tests\test_reports_cli.py -k "escaping or offline"
```

**Expected:** Target, UTC timestamp, scope, methodology, endpoint summary, findings/evidence/recommendations, severity counts, coverage, metadata and limitations. HTML works offline. Empty findings explicitly do not establish security. A prepared sample report is included under `examples/sample-report` and is identified as a synthetic local-lab example.

## Phase 17 — CLI

**What and why:** Let the user select inputs, scope, limits and output without editing Python.

**File:** `main.py`.

**Important code:** `load_config()` reads bearer tokens from files relative to the config location; `run()` validates inputs before requests, discovers endpoints, runs requested checks and reports coverage. `main()` prints the authorization warning, handles expected failures and returns 0 on success or 2 on configuration/processing failure. Error messages deliberately omit potentially secret-rich exception details. Offline mode is selected when no target is provided. `--bola` and `--rate-limit-path` are opt-in. A target origin is scheme+host+port, not a full endpoint URL.

```bat
python main.py --help
python main.py --target http://127.0.0.1:5000 --openapi input\openapi.json --config input\lab_config.json --bola --jwt-file .local\alice.token --timeout 5 --max-requests 100 --rate-limit-path /api/limited --rate-limit-count 5 --output output\complete
```

**Expected:** Warning, three saved-file paths, real assessment contents. Non-loopback HTTPS targets additionally need `--authorized`, supplied approved paths and valid target-specific credentials. The flag cannot establish that legal permission exists; that must already be true.

## Phase 18 — Tests

**What and why:** Check correct detection and false-positive controls before trusting reports.

**Files:** `pytest.ini`, `tests/conftest.py`, four `test_*.py` files.

**Important code:** pytest fixtures create a fresh local Flask app/server on an unused loopback port and close it after each test. A network guard rejects Requests destinations other than `127.0.0.1`. Real local HTTP tests cover token/user isolation, redirects, large bodies, budgets, rate limits and BOLA. Focused tests cover parsers, schema extraction, risk, HTML/Markdown escaping and JWT evidence. The CLI end-to-end test generates reports from the demo API and asserts expected High/Medium candidates and secret omission.

```bat
python -m pytest
```

**Expected:** All included tests pass. Run from the project root. Test count and observed versions are recorded in `PROJECT_PROGRESS.md`. Tests do not require your manually running port-5000 lab because they start independent loopback servers. No real third-party targets are assessed. We verified on Linux/Python 3.12; run this on Windows to complete platform validation.

## Phase 19 — Burp manual validation

**What and why:** Automated findings are hypotheses. Burp Repeater lets you inspect and repeat individual approved requests to confirm behavior, credentials and business context.

**File:** `docs/BURP_VALIDATION.md`.

**Manual:** Follow that guide using Burp's built-in browser and the loopback lab. It includes capture, Send to Repeater, the exact inspection, confirming evidence and false-positive evidence for each selected finding.

```bat
notepad docs\BURP_VALIDATION.md
```

**Expected:** You can explain the difference between (a) the tool's observation, (b) the actual request/response, and (c) the final security conclusion. Burp is not installed by pip, imported by code, or needed to run tests/reports. Manual GUI validation has not been performed on your machine.

## Checkpoint

Read `PROJECT_PROGRESS.md`. The project has been built; your next task is the Windows environment check. Do not upload real tokens, passwords or unredacted reports when asking for help. Send command output or a screenshot of the error with secrets removed.
