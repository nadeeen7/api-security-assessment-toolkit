> Current implementation record (2026-10-08): see PROJECT_PROGRESS.md. The dated baseline and phase-status sections below are historical. Phase C Step 2 pages have now been implemented; Phase D integration and Phase E hardening are separate remaining work.

# PROJECT_WEB_APP_PLAN

Turning the existing API Security Assessment Toolkit into a browser-based platform.

Status: **planning document only. No code has been written or changed for the web application yet.**
Baseline captured: 2026-10-07. Verified on this machine before writing this document.

---

## 0. Ground rules this plan obeys

1. The existing security engine is the product. It is **reused**, not rewritten.
2. `python main.py ...` must keep working exactly as it does today, including all 32 tests.
3. No second scanner. The web layer is a front end *onto the same engine*.
4. Safety posture is not weakened to make the UI more convenient.
5. No credential brute forcing, password attacks, flooding, destructive testing or exploit automation. Rate testing stays small, bounded and user-configurable.

---

## 1. Verified baseline

Everything in this section was inspected and, where stated, executed on 2026-10-07.

| Item | Value |
|---|---|
| Python environment | `.venv` = **Python 3.13.14** (not 3.14 — see §1.4) |
| Tests | Engine **32 passed**; full suite **50 passed**, exit 0 (was 32 before Phase B) |
| Dependencies | Flask 3.1.3, Jinja2 3.1.6, Werkzeug 3.1.9, requests 2.34.2, PyJWT 2.15.1, openapi-spec-validator 0.8.5 |
| Python source | ~1,220 lines across `main.py`, `core/`, `modules/`, `reports/`, `lab/`, `scripts/`, `tests/` |
| Modules | 10 assessment modules |
| Node toolchain | node v24.14.0, npm 11.9.0 (available for the Vite frontend) |
| Reports produced | `report.html`, `report.md`, `evidence.json` |
| Verified first run | High 1, Medium 2, Informational 13, 43 requests, stops at HTTP 429 |

### 1.1 Current request/data flow

```
main.py  (argparse CLI: parser() → run(args))
   │
   ├─ modules.endpoint_discovery.discover(openapi, endpoints)
   │        └─ modules.openapi_analysis.analyze(path)     ← offline, no requests
   │
   ├─ load_config()  →  identities{Authorization headers}, secrets[]
   │
   ├─ core.http_client.HTTPClient(target, timeout, max_requests, delay, authorized)
   │
   ├─ per endpoint (GET only, concrete paths only):
   │     GET anon  → modules.headers_analysis.analyze()
   │     GET auth  → modules.auth_analysis.analyze()
   │     OPTIONS   → modules.method_detection.analyze()
   │     GET+Origin → modules.cors_analysis.analyze()
   │
   ├─ [optional] modules.authorization_analysis.analyze()   one BOLA case, two users
   ├─ [optional] modules.jwt_analysis.analyze()             offline, unverified
   ├─ [optional] modules.rate_limit.analyze()               bounded sample
   │
   ├─ build `report` dict
   └─ reports.report_generator.generate(scrub(report, secrets), output)
            └─ writes report.html, report.md, evidence.json  (returns 3 Paths)
```

### 1.2 Module inventory (all reusable as-is)

| Module | Entry point | Returns | Notes |
|---|---|---|---|
| `endpoint_discovery` | `discover(openapi, endpoint_file)` | `(endpoints, findings, metadata)` | Reads supplied docs/lists. Never brute forces. |
| `openapi_analysis` | `analyze(path)` | `(endpoints, findings, metadata)` | Swagger 2.0 / OAS 3.0.x / 3.1.x **JSON**. Local `$ref` only, 2 MB cap, 60-level nesting cap. |
| `parameter_discovery` | `extract(endpoint)` | `list[dict]` | Names/types only. Never injects or guesses values. |
| `method_detection` | `analyze(observation, expected)` | `list[Finding]` | OPTIONS `Allow` only. Never executes PUT/DELETE/TRACE. |
| `auth_analysis` | `analyze(endpoint, anon, authed)` | `list[Finding]` | Needs a documented-protected endpoint + an identity. |
| `authorization_analysis` | `analyze(client, case, owner_h, other_h)` | `(findings, note)` | One explicit object, two distinct users. No ID enumeration. |
| `jwt_analysis` | `analyze(token)` | `list[Finding]` | Offline, signature unverified by design. |
| `headers_analysis` | `analyze(obs, https)` | `list[Finding]` | Context-aware (TLS, HTML response type). |
| `cors_analysis` | `analyze(obs)` | `list[Finding]` | One synthetic untrusted origin. |
| `rate_limit` | `analyze(client, path, count, delay, headers)` | `list[Finding]` | count 1..10, delay 0.2..10 s, stops on 429/5xx/error. |

### 1.3 Core: the three objects that matter

- **`Endpoint`** — `path, method, parameters[], security, request_schema, responses`
- **`Finding`** — `title, category, severity, endpoint, method, description, evidence{}, recommendation, confidence, cwe, owasp_api, classification, severity_reason`
- **`Observation`** — `method, endpoint, status, headers{}, data, error, truncated, elapsed_ms`.
  `Observation.evidence()` is already the privacy filter: a header allowlist, **no cookies, no `Authorization`, no query values, no response bodies**.

`core/risk_engine.py` owns severity. `RULES` has 9 rule keys (`bola`, `auth`, `jwt`, `cors_credentials`, `headers`, `methods`, `docs`, `rate`, `cors`) and severity is decided **by the rule, not by the caller**. No `Critical` rule exists.

### 1.4 Environment hazard (must be documented, not fixed by the web app)

`py -3` on this machine selects Python 3.14, whose `rpds` extension is blocked by a Windows application-control policy, so `openapi-spec-validator` cannot import. The venv must be created with `py -3.13`. This is an environment policy, not a code defect.

### 1.5 Safety invariants already enforced by the engine (do not weaken)

- Loopback targets only, **unless** `--authorized` is given **and** the scheme is HTTPS.
- `validate_path()` rejects absolute URLs, `//`, backslashes, fragments, dot-segments and control characters.
- Single origin. No redirects. No proxies or `.netrc` (`trust_env = False`). TLS verification stays on.
- Budget 1..200 requests, minimum 0.2 s between request starts, no retries.
- Hard stop on HTTP 429, any 5xx, or a transport error.
- Response bodies capped at 256 KiB; JSON kept in memory for comparison only, never serialized.
- Cookies cleared between requests so identity A, identity B and anonymous stay independent.
- `Host` overrides and cookie/proxy credentials are rejected outright.
- Only `GET`/`HEAD`/`OPTIONS` are executable; `POST` is opt-in in code and used solely for the two lab logins.

---

## 2. Gap analysis — what a web app needs that does not exist yet

| Need | Today | Verdict |
|---|---|---|
| Programmatic entry point | `run(args)` is already importable with no side effects | ✅ reuse |
| Machine-readable results | `evidence.json` contains the full report dict | ✅ reuse |
| HTTP API | none | ⬜ build |
| Background job / non-blocking run | `run()` is synchronous and blocking | ⬜ build |
| Progress reporting | **delivered in Phase B** as an optional `progress` callback | ✅ done |
| Test selection from UI | **delivered in Phase B** as an optional `selected` set that gates each module | ✅ done |
| Assessment duration | **delivered in Phase B**, measured by the job runner (no engine change) | ✅ done |
| Per-job isolation | `output/<name>` is overwritten if reused | ⬜ use one directory per job |
| History of past runs | none | ⬜ build (small index file) |
| Cancellation | none | ⬜ cooperative flag in the job runner |
| Browser UI | none (static HTML report only) | ⬜ build |

### 2.1 Two honest caveats to design around

1. **`run()` currently decides which modules execute.** Endpoint discovery, headers, authentication, methods and CORS always run inside the endpoint loop; BOLA, JWT and rate limiting run only when their flags are set. So "select which tests to run" cannot be honoured by the UI alone without either post-filtering findings (misleading — it would still send the requests) or adding a selection parameter to the engine. This plan proposes the selection parameter.
2. **`parameter_discovery` is not a request phase.** It is computed at report time into `endpoints[].parameters`. The UI checkbox for it therefore maps to *showing/analysing extracted parameters*, not to network activity. The UI must not imply otherwise.

---

## 3. Reuse / modify / new

### 3.1 Reused unchanged (no edits at all)

`core/http_client.py`, `core/models.py`, `core/risk_engine.py`, `core/logger.py`, all ten files in `modules/`, `reports/report_generator.py`, `reports/templates/report.html`, `lab/app.py`, `scripts/create_lab_tokens.py`, all existing tests, `pytest.ini`.

### 3.2 Modified (one file, additive and backward compatible) — DELIVERED

`main.py` gained three additions and nothing else:

1. `ASSESSMENT_TESTS` — a 10-key tuple, one key per user-facing checkbox, shared by the CLI and the API catalogue.
2. `emit(progress, phase, **detail)` — calls the callback only when one was supplied.
3. `run(args, progress=None, selected=None)` — two optional keyword arguments.

```python
def run(args, progress=None, selected=None):
    if selected is None:
        selected = set(ASSESSMENT_TESTS)   # CLI behaviour: run everything the args imply
```

- `main()` is **not** changed and still calls `run(args)`.
- Selection only ever **gates** work, it never triggers it: BOLA still needs `--bola`, rate testing still needs `--rate-limit-path`. Unchecking a box therefore removes the requests, not just the findings.
- `--check-environment` still returns before any of this runs.

Verified backward compatibility (same command as the documented first run):

| Check | Before | After |
|---|---|---|
| `severity_summary` | 0/1/2/0/13 | **identical** |
| Requests sent | 43 | **43** |
| Stop reason | HTTP 429 | **identical** |
| Endpoint summaries | 10 | **identical** |
| Finding titles, in order | 16 | **identical** |
| New JSON keys | — | `coverage.tests_selected` only |
| Tests | 32 passed | **32 passed** (engine only) |

Measured effect of selection: a two-endpoint run sends **8 requests** with every test enabled and **2 requests** when only Security Headers is selected.

Everything else the web layer needs already exists.

### 3.3 New (web layer only)

```
web/                      Flask REST API
  app.py                  app factory, routes, origin/session guard
  jobs.py                 job registry, single-worker queue, progress, cancellation
  request_schema.py       input validation and normalisation for the API
  job_config.py           builds the engine Namespace + config JSON + private token files
  store.py                job index on disk (history)
tests/test_web_api.py     API tests. They live in tests/ so they inherit conftest.py's
                          autouse loopback-only network guard automatically.
webui/                    React + Vite + Tailwind front end
  src/pages/…             assessment, progress, results, findings, reports, history
  src/components/…        Sidebar, SeverityCard, ProgressList, FindingsTable, FindingDrawer…
frontend build output     webui/dist, served by Flask in the packaged run
```

No new Python package is required: Flask, Jinja2 and Werkzeug are already dependencies. The frontend adds only Node dev-dependencies.

---

## 4. Proposed web architecture

```
            ┌──────────────────────────────────────────────┐
            │  React SPA (Vite + Tailwind, dark theme)     │
            │  assessment · progress · results · findings  │
            │  finding detail · reports · history          │
            └───────────────┬──────────────────────────────┘
                            │  JSON over HTTP (same origin)
                            ▼
            ┌──────────────────────────────────────────────┐
            │  Flask REST API  (web/app.py)                │
            │  validation · origin guard · job control     │
            └───────────────┬──────────────────────────────┘
                            │  one call: run(args, progress, selected)
                            ▼
            ┌──────────────────────────────────────────────┐
            │  Job runner (web/jobs.py)                    │
            │  background thread · single worker · cancel  │
            └───────────────┬──────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────┐
            │  EXISTING ENGINE  main.run(args)             │
            │  endpoint_discovery → 10 security modules     │
            │  → risk_engine → report_generator            │
            └───────────────┬──────────────────────────────┘
                            ▼
            output/web/<job_id>/  report.html · report.md · evidence.json · job.json
```

### 4.1 Process model

- One Flask app bound to `127.0.0.1` only.
- Development: Vite dev server on `5173` proxies `/api` → Flask on `5055`.
- Packaged: `webui/dist` is built and served by Flask, so a single process and a single origin serve everything. One command to start.
- The job runner serialises assessments with a queue and **one active worker**, so the UI (and the user) cannot accidentally point two runs at the same target at once.

### 4.2 Job lifecycle and progress

```
POST /api/assessment/start → job.json written (status=queued) → 202 {job_id}
  queued → running → completed | failed | cancelled
```

Progress phases reported by the engine callback:

```
1 OpenAPI analysis      (offline, no requests)
2 Endpoint discovery    (offline; reports how many endpoints were found)
3 Endpoint checks       (per endpoint: current endpoint + i/n, requests sent)
4 Authorization / BOLA  (optional)
5 JWT analysis          (optional, offline)
6 Rate limiting         (optional)
7 Report generation
```

The UI shows each phase as `✓ complete`, `● running`, `○ pending`, exactly as requested, driven by the `progress` callback plus `coverage.requests_sent`. Assessment duration is measured by the job runner (`time.monotonic()` start/finish) because the engine does not record it.

### 4.3 Per-job storage

```
output/web/index.json                 lightweight list for the history page
output/web/<job_id>/job.json          status, selection, target, timestamps, error
output/web/<job_id>/config.json       engine identity config (references token files by name)
output/web/<job_id>/secrets/*.token   user-supplied tokens, 0600 best effort, deleted on completion
output/web/<job_id>/evidence.json     full report dict — the API's source of truth
output/web/<job_id>/report.html       generated report
output/web/<job_id>/report.md         generated report
```

`evidence.json` is the contract between engine and API: the API never re-implements analysis, it serves what the engine already produced.

### 4.4 Secret handling

- A pasted token is written once to `output/web/<job_id>/secrets/`, never echoed back, never logged, never stored in `job.json`, and removed when the job finishes.
- The engine already scrubs token values out of the report via `scrub(report, secrets)`; the API adds no new exposure.
- Tokens are length-checked (16 000 chars, matching the engine) and rejected if they contain whitespace.
- The browser keeps tokens in component state only — no `localStorage`, no cookies.

---

## 5. REST API contract

Existing conventions are respected: `snake_case` JSON keys matching the engine's own field names, no renames, so the SPA and the CLI reports use identical vocabulary.

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/health` | liveness + engine version + whether loopback-only mode is active |
| `GET` | `/api/tests` | the test catalogue (key, label, description, offline?, requires identity?) powering the checkboxes |
| `POST` | `/api/openapi/analyze` | validate an uploaded spec **offline** (no requests), return endpoints, parameters, security schemes and documentation findings |
| `POST` | `/api/assessment/start` | create a job; returns `202 {job_id, status_url}` |
| `GET` | `/api/assessment/<job_id>` | status + progress + severity summary + duration |
| `GET` | `/api/assessment/<job_id>/findings` | findings array (filters applied server-side: severity, category, endpoint, confidence) |
| `GET` | `/api/assessment/<job_id>/endpoints` | endpoint summary rows |
| `GET` | `/api/assessment/<job_id>/coverage` | coverage, observations, skipped, stop reason, limitations |
| `GET` | `/api/assessment/<job_id>/report/html` | generated HTML (served `inline` with the template's own CSP, or as an attachment) |
| `GET` | `/api/assessment/<job_id>/report/markdown` | generated Markdown |
| `GET` | `/api/assessment/<job_id>/evidence.json` | the raw engine report for download |
| `POST` | `/api/assessment/<job_id>/cancel` | cooperative cancellation between requests |
| `GET` | `/api/assessments` | history, newest first |
| `DELETE` | `/api/assessment/<job_id>` | remove one job's directory |

`POST /api/assessment/start` request body (proposed):

```json
{
  "target": "http://127.0.0.1:5000",
  "authorized": true,
  "openapi_text": "{ … }",
  "endpoints_text": "[\"/api/public\"]",
  "identities": { "primary": "eyJ…", "secondary": "eyJ…" },
  "bola": { "path": "/api/objects/101", "identity_path": "/api/me",
            "expected_object_id": 101, "id_field": "id", "owner_field": "owner" },
  "jwt_token": "eyJ…",
  "tests": ["endpoint_discovery", "headers", "cors", "auth", "methods"],
  "rate_limit": { "path": "/api/limited", "count": 5, "delay": 0.5 },
  "limits": { "timeout": 5, "max_requests": 100, "delay": 0.2 }
}
```

Validation mirrors the engine's own rules and **never loosens them**: non-loopback targets require `authorized: true` *and* HTTPS; unknown test keys are rejected; `count` must be 1..10 and `delay` 0.2..10; `max_requests` 1..200.

The job config builder constructs the engine arguments with `parser().parse_args([...])`, so every default stays identical to the CLI's and the web layer inherits the CLI's validation for free.

---

## 6. Frontend plan

### 6.1 Routes and pages

| Route | Page | Contents |
|---|---|---|
| `/` | Assessment | title, description, authorization warning + acknowledgement, target URL, OpenAPI upload/paste, optional token inputs, test checkboxes, Start Assessment |
| `/assessment/:id` | Progress | progress bar, phase list with ✓/●/○, current endpoint, requests sent, cancel |
| `/assessment/:id/results` | Results dashboard | severity cards (Critical/High/Medium/Low/Informational), total endpoints, total tests run, duration, target, timestamp, endpoint table |
| `/assessment/:id/findings` | Findings | filterable table: Severity · Finding · Endpoint · Method · Confidence · Status |
| `/assessment/:id/findings/:index` | Finding detail | side panel: title, severity, category, endpoint, method, description, evidence, recommendation, confidence, CWE, OWASP |
| `/assessment/:id/reports` | Reports | Generate/open HTML, Generate/download Markdown, download evidence.json |
| `/history` | History | previous assessments with target, date, counts |

### 6.2 Field mapping (no engine concepts leak into the UI)

- Findings table **Status** column ← `classification` (`Potential issue`, `Observation`, `Documentation finding`, `Hardening observation`, `Configuration observation`, `JWT configuration finding`).
- **Severity** ← `severity` (rule-driven; no Critical rule exists, so Critical will read 0 and the UI must say why rather than look broken).
- **Confidence** ← `confidence`.
- Evidence panel ← `evidence` (rendered as pretty-printed JSON; it is already minimised by the engine).
- Every finding detail panel shows the engine's caveats: `severity_reason` and the report's `limitations[]`.

### 6.3 Visual design

Dark cybersecurity theme with a sidebar, cards, tables and a detail drawer. Reuse the existing report palette so the SPA and the generated HTML report look like one product: navy `#152842`, teal accent `#96d9d3`, severity colours `#90271e`/`#ffe3df` (High), `#734e00`/`#fff0ce` (Medium), `#154b70`/`#e0f1ff` (Low). Minimal animation — transitions only on hover, drawer and progress fill. Responsive: sidebar collapses, tables scroll horizontally.

### 6.4 Data fetching

Plain `fetch` plus a small `useJobPolling(jobId)` hook polling `GET /api/assessment/<id>` every ~1 s while the job is `queued`/`running`, stopping on a terminal state. Simple, reliable, no extra runtime dependency. State lives in component state; no global store is needed at this size.

---

## 7. Safety model for the web app

The web layer must not become a weaker path to the engine.

1. **Authorization gate.** A required acknowledgement checkbox plus a plain-language warning before Start is enabled. Its value maps to the engine's `--authorized`. Loopback targets work without it, exactly as the CLI does.
2. **Transport rule.** Non-loopback targets require both the acknowledgement and HTTPS — inherited unchanged from `HTTPClient`.
3. **Not implemented, by design:** credential brute forcing, password or token guessing, request flooding, destructive methods, exploit automation, unauthorized scanning. Rate testing is a bounded, configurable sample (≤10 requests, ≥0.2 s apart) that stops at the first 429/5xx/error.
4. **Single worker.** One assessment at a time, so the tool cannot be used to flood a target through a queue of jobs.
5. **Local-only service.** Flask binds `127.0.0.1`. Because a local tool is reachable by any page the user visits, the API additionally requires a same-origin check on state-changing routes and a per-run session token, and the SPA ships a restrictive CSP. This prevents a random website from driving the user's toolkit against a third party.
6. **No secrets at rest beyond the job's lifetime**, no tokens in logs, no `localStorage`.
7. **Honest reporting preserved.** The UI must keep the "potential"/"observation" language and the `limitations[]` block visible; it must not upgrade an informational observation into an alarm to look impressive.

---

## 8. Phased build plan (each phase ends with a confirmation stop)

| Phase | Deliverable | Verification |
|---|---|---|
| **A** | `PROJECT_WEB_APP_PLAN.md` | Engine baseline re-confirmed: 32 passed |
| **B — Backend API (DELIVERED)** | `main.py` additive change + `web/` package: `app.py`, `jobs.py`, `request_schema.py`, `job_config.py`, `store.py`, `__main__.py`, plus `tests/test_web_api.py` | **50 passed** (32 engine + 18 API); CLI output identical; live end-to-end run reproduced High 1 / Medium 2 / Informational 13 through the API |
| **C — Frontend** | `webui/` Vite + React + Tailwind, all pages, built against the real API | `npm run build` clean; pages render against a live job |
| **D — Integration** | Flask serves `webui/dist`; single-command start; end-to-end run through the browser | Full click-through on the local lab: start → progress → results → findings → reports |
| **E — Hardening & docs** | README/PROJECT_PROGRESS updates, limitations, run instructions | Full suite + manual browser pass |

The CLI is re-verified at the end of every phase, not just once.

---

## 9. Verification plan

- **Regression:** `python -m pytest` must report 32 passed after every phase.
- **CLI contract:** re-run the documented first assessment against the local lab and confirm the same High 1 / Medium 2 / Informational 13 shape.
- **Web tests:** same local-only guarantee as `tests/conftest.py` — a `requests.Session.send` guard asserting `127.0.0.1`, plus an ephemeral-port lab fixture (port 0), so no test can reach a real API.
- **Browser checks per phase:** load the SPA, run an assessment against `http://127.0.0.1:5000`, confirm the progress list advances and terminates, confirm the results counts match `evidence.json`, open one finding, open the HTML and Markdown reports.
- **Secret checks:** grep the job directory, `job.json` and the API responses for the pasted token; assert absence. The engine's own tests already assert tokens never reach report files.

---

## 10. Risks and open decisions

| # | Risk / decision | Recommendation |
|---|---|---|
| 1 | Progress hooks require touching `main.run` | Additive optional kwargs only; `main()` and CLI untouched. Decision needed. |
| 2 | Test selection requires touching `run`'s module loop | Same additive change (`selected`). Alternative is post-filtering findings, which is dishonest because requests would still be sent. |
| 3 | Long assessments block a request thread | Background thread + polling (chosen) rather than long-polling or websockets. |
| 4 | History persistence | `output/web/index.json` + per-job directories; survives restarts, needs no database, matches the existing file-based design. |
| 5 | Serving generated HTML | Serve inline inside a sandboxed `iframe`, or as a download. Do not inject report HTML directly into the SPA DOM. |
| 6 | OpenAPI 3 `servers`/base paths are not followed | Surface this as a UI note; users of `/v1`-style deployments must supply explicit endpoint lists. Inherited limitation, not fixable in the web layer. |
| 7 | Python 3.14 environment block | Document `py -3.13`; do not work around it in code. |
| 8 | Two processes in development (Vite + Flask) | Provide a single documented command sequence; the packaged run is one process. |

---

## 11. Exact commands for this phase

Nothing to build yet. To re-verify the untouched baseline:

```bat
cd /d "%USERPROFILE%\OneDrive\Documents\api-security-toolkit\api-security-toolkit"
.venv\Scripts\activate.bat
python -m pytest
python main.py --check-environment
```

Expected: `32 passed`, `Virtual environment: True`. The `.venv` here is Python 3.13.14; create any new environment with `py -3.13 -m venv .venv`.

---

## 12. Phase status

- **Phase A (planning): done.** Engine baseline 32 passed.
- **Phase B (backend API): done.** Engine change approved and implemented; `web/` package and 18 API tests added; 50 passed; live run through the API matches the CLI. See §13 for the verified API surface.
- **Phase C (frontend): not started.** `webui/` (Vite + React + Tailwind) is next, pending confirmation.

## 13. Phase B delivery record

New files: `web/__init__.py`, `web/app.py`, `web/jobs.py`, `web/request_schema.py`, `web/job_config.py`, `web/store.py`, `web/__main__.py`, `tests/test_web_api.py`.
Modified: `main.py` only (see §3.2). No module, core, report or lab file was touched.

Verified behaviour:

- Start → poll → completed in ~9.5 s against the local lab; phases `endpoint_discovery, endpoint, authorization, jwt_analysis, rate_limit, report` all observed.
- API results identical to the CLI: 10 endpoints, 16 findings, 43 requests, stop at 429, `Potential BOLA`.
- Filters work: `?severity=High` → 1, `?category=Authentication` → 1, `?confidence=High` → 9, `?severity=Critical` → 0.
- `report/html` served as `text/html` with CSP and `nosniff`; `report/markdown` as `text/markdown`; `evidence.json` parses.
- Supplied tokens appear in **no** API response and in **no** file on disk; the `secrets/` directory is removed when the job ends.
- Host is restricted to loopback; state-changing routes need the same-origin header and reject a foreign `Origin`.
- A failing engine returns only a safe message and the exception class name — never the exception text, which can carry a URL with credentials.
- Jobs are serialised through a single worker; cancellation stops a running assessment at the next phase boundary.

Not yet done in Phase B: the SPA itself, and a browser check of anything. There is no user interface until Phase C.

### 13.1 Known limitation introduced in Phase B

A cancelled or failed job leaves whatever the engine had already produced. A job that fails before `generate()` writes no `evidence.json`, so its `report/*` routes return 409 and `summary` stays `null`.
