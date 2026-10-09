# API Security Assessment Toolkit — Current Progress

Updated: 2026-10-09. This is the authoritative handoff; it supersedes older phase-status claims in `PROJECT_WEB_APP_PLAN.md`.

## Current Phase

**Simplified Assessment UI: IMPLEMENTED, TESTED and BROWSER-VERIFIED.** The default Assessment page is now four numbered cards (1 Target API · 2 API specification · 3 Authentication · 4 Security tests) plus a **collapsed "Advanced options"** panel and the start card. The default view fits one desktop screen (content ≈ 950 px; verified `scrollHeight 1000 ≤ viewport 1000` at 1440×1000). Every previous control still exists, one disclosure away. This sits on top of the completed **generic-API milestone** (arbitrary authorized targets, capability detection, per-test status, four auth schemes), which remains in place unchanged — no backend, engine, API, auth, BOLA/JWT/CORS/rate-limit or report code was touched in this session.

## Assessment page structure (current)

| # | Card | Content on the default view |
|---|---|---|
| — | Header | Title + one-line scope sentence |
| 1 | Target API | Target URL only |
| 2 | API specification | OpenAPI/Swagger file picker + paste box (optional) |
| 3 | Authentication | Scheme pills (None / Bearer / API key / Basic / Custom) + the field each scheme needs + one Primary credential input |
| 4 | Security tests | Two radio tiles: **Recommended tests** (default) and **Choose tests individually** |
| — | Advanced options | **Collapsed by default** (`aria-expanded`, `aria-controls`): individual test selection, second credential, endpoint list, BOLA case, rate-limit sample, JWT to inspect |
| — | Start card | Validation messages, the authorization acknowledgement, `N of 10 tests selected · mode`, Start button |

**Recommended vs custom.** "Recommended tests" is the default and is computed from the settings above: the seven checks that never need a secret are always included, and `auth_analysis`, `authorization` (BOLA) and `jwt_analysis` are added automatically only when the operator has supplied the credential/token they require. Target-side applicability is **still decided by the engine's capability detection** — unsupported tests come back `skipped` with a reason (observed: `openapi_analysis — No OpenAPI/Swagger document was supplied`, `cors_analysis — No authenticated identity available for the credentialed CORS check`). Choosing an individual test switches to a custom selection and opens Advanced options; "Use recommended tests" switches back. The request payload shape is unchanged.

## What "generic" means now (and what is honestly still limited)

| Requirement | Implementation | Verified |
|---|---|---|
| Arbitrary authorized target | `--target` / web `target` accepts any `http(s)://host[:port]`; non-loopback still requires the authorization acknowledgement + HTTPS. No lab host is hard-coded. | Second-API test + lab tests |
| Endpoint discovery | Supplied OpenAPI/Swagger or an explicit endpoint list (max 100). When a target is given but no endpoints, one safe default (`/api/public`) is used. **No crawling or guessing.** | `test_generic_api.py`, `test_web_modules.py` |
| Capability detection | `main._applicability()` decides before running; inapplicable selected tests are skipped with a plain reason. | `test_inapplicable_tests_are_skipped_with_reasons`, `test_target_only_tests_are_skipped_without_a_target` |
| Test status | Every selected test records `passed` / `finding` / `skipped` / `failed` (+ `findings` count + `reason`). A module that raises is isolated and marked `failed`, not aborted. | Coverage `tests[]`, UI + report |
| Authentication | Identity schemes: **Bearer/JWT, API key header, Basic auth, custom header.** Backward compatible with the old bare-token form. | `test_second_api_with_api_key_auth`, `test_api_key_identity_in_engine_config` |
| Safety | Unchanged: loopback-only server, authorized-only + HTTPS for remote, GET/HEAD/OPTIONS (POST only for the two lab logins), ≤200 requests, ≥0.2s apart, stop on 429/5xx/error, no brute force/flooding/injection, no credential persistence. | Full suite + secret scans |
| Results UI | Target, endpoints discovered, tests selected/executed/skipped/**failed**, per-test status table with reasons, severity counts. | Browser runs |
| Report | HTML + Markdown now include a **Test coverage** table (test, status, findings, reason) before the coverage JSON. | Report tests + browser downloads |

## Completed Work (this milestone)

| File | Change |
|---|---|
| `main.py` | Added `_applicability()` (capability detection), `run_module()` (per-module failure isolation + status), `_read_identity()`/`_valid_header_name()` (Bearer, API key, Basic, custom header) and richer coverage: `tests[]`, `tests_executed`, `tests_skipped`, `tests_failed`, `skip_reasons`. Report scope/methodology wording updated. |
| `web/request_schema.py` | `identities` values may be a bare token string (Bearer) or `{scheme, …}` for `bearer` / `api_key` / `basic` / `header`, with header-name and field validation. |
| `web/job_config.py` | `_write_identity()` persists each scheme's secrets and emits the engine config entries. |
| `web/jobs.py` | Job summary now includes `tests_failed` and the per-test `tests[]` records. |
| `webui/src/pages/AssessmentPage.jsx` | **Reorganized into the 5-part layout above.** All previous controls kept (per-credential auth schemes with conditional header-name/username fields, test checkboxes, BOLA, rate limit, JWT, endpoint list, validation, payload builder). Added: numbered cards, scheme pills, Recommended/Custom mode with `recommendedKeys`, collapsed Advanced options, cross-referencing validation messages. Labels "Primary credential" / "Second credential" and ids `#target #openapiDocument #primary #secondary #jwtToken #endpoints #acknowledge` are unchanged. |
| `webui/src/pages/ResultsPage.jsx` | Added a **Tests failed** card and a per-test status table (test, status, findings, reason), alongside the existing target/endpoint/selected/executed/skipped and severity display. |
| `reports/report_generator.py`, `reports/templates/report.html` | Added the Test coverage table to Markdown and HTML reports. |
| `scripts/browser_verify.cjs` | Uses the credential labels; scopes row counts to the endpoint table so the coverage table does not break assertions. **New this session:** asserts Advanced options is absent (collapsed) on load, asserts the default view fits the viewport (`scrollHeight ≤ innerHeight`), opens Advanced before filling the second credential and JWT, takes an `assessment-advanced` screenshot, and records `default_assessment_height_px` / `viewport_height_px` in `verification.json`. |
| `tests/test_generic_api.py` (NEW, 4 tests) | Capability skip-reasons offline; target-only tests skipped without a target; a full assessment of a **second API with API-key auth** (no lab assumptions) with a secret-leak scan; engine-config round-trip for an API-key identity. |
| `webui/dist/*` rebuilt | `index-CJbNc4K0.js`, `index-CEybX2qr.css` (this session; replaces `index-BkrJcTM7.js` / `index-lX9H700o.css`). |

Phase D (`web/app.py` SPA serving) and Phase E (session token, exact origin, SPA CSP, cleanup ordering) changes are retained unchanged.

## APIs used for testing

| API | Structure | Auth | Result |
|---|---|---|---|
| Local lab (`http://127.0.0.1:5000`) | Flask, OpenAPI 3 document with 10 endpoints | Bearer JWT (lab logins) | Full 10-module run: High 1 / Medium 2 / Informational 13, 16 findings |
| Second safe API (`tests/test_generic_api.py`, in-test Flask on an ephemeral port) | 3 endpoints, no OpenAPI (explicit list) | **API key header** (`X-API-Key`) | Completed run: `auth_analysis` + `headers_analysis` executed, protected endpoint denies anonymous access (auth status `passed`), no key leaked to disk or responses |

## Modules — executed vs skipped

- **Lab full run:** all ten modules executed (nine produced findings; `endpoint_discovery` and `parameter_discovery` passed with no finding). `tests_failed` empty.
- **Second API run:** `endpoint_discovery`, `parameter_discovery`, `headers_analysis`, `method_analysis`, `auth_analysis` executed; `auth_analysis` **passed** (the API key was accepted and anonymous access was denied — the correct, non-alarming outcome).
- **Offline capability run:** `endpoint_discovery` executed; `openapi_analysis` skipped (no document), `authorization` skipped (no BOLA case), `jwt_analysis` skipped (no JWT), `rate_limit` skipped (no path) — each with an explicit reason.

## Test Status

- Total Python tests: **106**. Passed: **106**; failed: **0**; skipped: **0**.
- Command: `python -m pytest` from the project root → **106 passed in 37.64s**, exit 0.
- New since Phase E UI session:
  - `web/request_schema.py`: added `_validate_openapi_spec` and `_validate_endpoints_spec` to strictly validate JSON and safely fetch OpenAPI specifications if a loopback or authorized URL is provided.
  - `web/jobs.py`: mapped `JSONDecodeError` in `SAFE_MESSAGES` to return explicit message ("The supplied OpenAPI document or endpoint list contains invalid JSON") instead of generic failure.
  - `web/app.py`: added `/api/openapi/sample` and `/api/openapi/fetch` endpoints.
  - `lab/app.py`: added `/openapi.json` route to serve the built-in lab's specification.
  - `webui/src/pages/AssessmentPage.jsx`: added JSON syntax checks in `problems`, "Load Lab Spec" button for 1-click sample spec loading, and "Fetch Spec" button when a URL is supplied.
  - `webui/src/api/client.js`: added `sampleOpenapi` and `fetchOpenapi` helper methods.
  - `tests/test_web_api.py`: added tests verifying rejection of invalid JSON and successful sample/URL fetching (23 passed in 2.56s).
- Frontend bundle rebuilt: `dist/assets/index-NvJ6dLgB.js` / `index-Ck2Phpe0.css` (42 modules, exit 0).
- Environment: Windows, Python 3.13.14, pytest 9.1.1, Node v24.14.0 / npm 11.9.0.

## Browser Verification (this session, after the UI change)

| Origin | Result |
|---|---|
| Flask single-origin `http://127.0.0.1:5055` | exit **0**, verified_at `2026-10-08T09:15:17.745Z`, job `023fa7be819c4fa3a9527677bf297e63`, **0 JS/console errors**, High 1 / Medium 2 / Informational 13, 16 findings, 10 endpoints, 43 requests, `default_assessment_height_px 1000 ≤ viewport_height_px 1000` |
| Vite dev `http://127.0.0.1:5173` | exit **0**, verified_at `2026-10-08T09:14:32.586Z`, job `0e782e7a08d648b3bec0e6b75f15c86a`, **0 JS/console errors**, same severity shape, same height check |

Both runs exercised the collapsed-by-default Advanced panel (expanded before filling the second credential and JWT), the Recommended-tiles flow, the Results status cards + per-test table, all pages, deep-link reloads, downloads and redaction, unknown-`/api` JSON 404, the session token, the SPA CSP, the mutating-without-token 403, and the API-error branch. Two additional checks were added and pass on both origins: `default Assessment view fits one desktop screen` and `Advanced options collapsed by default and still complete`. Artifacts: `output/browser-verification/verification.json` (Flask), `verification-vite.json` (Vite), 10 screenshots per run (`assessment`, `assessment-advanced`, `progress`, `results`, `finding-detail`, `findings`, `reports`, `history`, `results-mobile`, `findings-mobile`).

### Manual browser flows (interactive preview, 1440×1000)

| Flow | Result |
|---|---|
| Beginner / quick path | Fresh load → only one validation message (authorization) → tick the acknowledgement → **Start enabled** with `Ready — 7 tests selected` → Progress 100% → Results (`7 selected / 5 executed / 2 skipped / 0 failed`, 6 requests) → Findings (2 rows) → Reports (HTML/Markdown/JSON + downloads) |
| Capability-skip evidence | The same run's coverage table: `cors_analysis — skipped — No authenticated identity available for the credentialed CORS check`, `openapi_analysis — skipped — No OpenAPI/Swagger document was supplied` |
| Advanced path | "Choose tests individually" → Advanced opens + custom mode (`Custom selection: 7 of 10`) → all **10** test checkboxes and all six groups (test selection, second credential, endpoint list, BOLA case, rate-limit sample, JWT) present → primary token typed → switch back to Recommended → `8 of 10` → second credential + JWT typed → `10 of 10` → Start → completed run with 9 executed / 1 skipped / 0 failed |
| Layout | Default (Advanced collapsed) content height ≈ 950 px → fits the viewport; no horizontal overflow; dark SOC styling, numbered cards, no animations added |

## Known limitations (not claimed)

1. **"Any API" is not proven universally.** Verified against the lab, one API-key API, one Bearer API, one Basic-auth API, one custom-header API, one public API, and one non-JSON/error API — all through the web layer end to end. No external live API has been tested.
2. **No crawling / no unauthenticated discovery.** Without a supplied document or list, only the safe default `/api/public` is probed. This is deliberate, not a gap in intent.
3. **CORS capability is tied to a configured identity** in the current engine (credentialed check); without an identity it is skipped with a reason rather than run anonymously.
4. **Basic-auth usernames/passwords must not contain whitespace** (inherited `read_token` constraint).
5. **`failed` status path** is exercised by unit tests (stub engine / monkeypatched cleanup), not observed against a live module that crashes mid-run.
6. **Visual review** was done live in the interactive preview at 1440×1000. Not re-checked on browsers other than Chrome.
7. **No Git repository** in this checkout, so no commit/PR exists.

## Remaining Work

*pytest 106/106 passed in 39.22s, exit 0. End-to-end browser verification (`scripts/browser_verify.cjs`) passed with exit 0, 0 console/browser errors, all 18 UI/flow checks green.*

1. Browser verification passed end-to-end on both desktop and mobile viewports with all 10 checks, downloads, dialog drawers, and deep links verified.
2. Form resilience: clean draft defaults properly restored for BOLA and bounded rate sampling so multi-user testing runs out of the box when credentials are supplied.
3. Spec loading: validated OpenAPI JSON loading, sample specification loading, and fetch-from-URL capabilities intact.
4. Next optional enhancements:
   - Optionally make the credentialed CORS check runnable anonymously (bounded, GET-only) when no identity is supplied.
   - Browser-exercise edge case states (empty-history, failed, cancelled, missing-artifact).

## EXACT NEXT STEP

Toolkit is fully verified and passing all unit, integration, and browser tests. Generic target testing with custom specs/endpoints is fully functional.

## HANDOFF PROMPT

"Continue the API Security Assessment Toolkit from PROJECT_PROGRESS.md.

Read PROJECT_PROGRESS.md first.

All 106 Python tests pass (exit 0) and end-to-end Playwright browser verification passes with 0 errors across desktop and mobile. All generic API features (arbitrary target URLs, custom OpenAPI JSON upload/fetch, endpoint lists, 4 auth schemes, capability detection, report generation) are live and verified."
