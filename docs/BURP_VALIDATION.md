# Burp Suite — controlled manual validation

Use only the included lab or a separately authorized API. **Repeater** is Burp's tool for manually editing and resending a single request. It is not needed by the Python application.

## Capture one local request

1. Start the local Flask API with `python -m lab.app` in CMD. Leave it running.
2. Open Burp Suite Community or Professional and create a temporary local project if prompted.
3. Under **Proxy**, choose **Open browser**. The built-in browser is preconfigured to use Burp. Labels may vary slightly by version.
4. Set **Intercept is off** while learning so requests do not appear to hang.
5. In that browser visit `http://127.0.0.1:5000/api/public`.
6. Open **Proxy → HTTP history**. Find that exact host/path, right-click the request and select **Send to Repeater**. Switch to Repeater and press **Send** once.
7. Inspect the request method/path, Host header and response status/body. The target must remain `127.0.0.1:5000`.

For authenticated browser requests, while on the same local API origin open browser developer tools → Console. Type this yourself after reading it; do not disable browser protections to paste unknown code. These snippets log in only to the local demonstration accounts:

```javascript
window.labAlice = await fetch('/api/login', {
  method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username: 'alice', password: 'alice-lab-only'})
}).then(r => r.json());
await fetch('/api/me', {headers: {Authorization: 'Bearer ' + window.labAlice.token}});
```

The login response and following authenticated request appear in Burp history. Tokens in history are credentials: keep this project private. You may copy the Authorization header from a captured request into another local Repeater request. Regenerate tokens after a lab restart or after an hour. Console state is temporary; closing/reloading the browser can remove it.

To capture Bob's identity separately:

```javascript
window.labBob = await fetch('/api/login', {
  method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username: 'bob', password: 'bob-lab-only'})
}).then(r => r.json());
await fetch('/api/me', {headers: {Authorization: 'Bearer ' + window.labBob.token}});
```

No automated password attempts, Intruder jobs or mass enumeration are needed.

## Finding 1 — Possible missing authentication

1. **Tool detected:** `/api/auth-missing` is documented as private but returns identical JSON anonymously and with Alice's token.
2. **Capture:** Visit `/api/auth-missing` in the built-in browser. Capture an authenticated version using:
   ```javascript
   await fetch('/api/auth-missing', {headers: {Authorization: 'Bearer ' + window.labAlice.token}});
   ```
3. **Repeater:** Send both captured requests to separate Repeater tabs. Ensure the anonymous tab has no Authorization or Cookie header.
4. **Inspect:** Confirm Alice's token first returns `sub: alice` from `/api/me`. Compare statuses and JSON in both tabs. A 200 alone is not proof; some apps return error JSON with 200.
5. **Confirm:** Known-private synthetic notice is returned without credentials while the intended policy requires login. In this lab the missing decorator intentionally demonstrates it.
6. **False positive:** Endpoint is intentionally public, documentation is stale, returned body is merely public/error data, or an unnoticed session cookie supplied identity. The safe `/api/protected` should return 401 anonymously.

## Finding 2 — Cross-user object access (BOLA)

1. **Tool detected:** Both verified identities can retrieve configured Alice object 101 with matching ID/owner fields.
2. **Capture:** In the built-in browser console:
   ```javascript
   await fetch('/api/objects/101', {headers: {Authorization: 'Bearer ' + window.labAlice.token}});
   await fetch('/api/objects/101', {headers: {Authorization: 'Bearer ' + window.labBob.token}});
   ```
3. **Repeater:** Send the two requests into clearly named Alice/Bob tabs. Preserve `/api/objects/101`; do not enumerate IDs. Verify each token with `/api/me` first.
4. **Inspect:** The response must have `id: 101`, `owner: alice` and the synthetic object content. Confirm Bob is not Alice and has no sharing permission.
5. **Confirm:** Bob receives the same private Alice record despite a policy that forbids it. Save a redacted pair of requests and responses, verified identity responses and the ownership rule.
6. **False positive:** Object is public/shared; Bob has an authorized privileged role; same token was used twice; a response contains an error rather than the object; or ID/owner fields do not match. The control `/api/safe-objects/101` returns 404 for Bob and 200 for Alice. A 404 denial can intentionally conceal object existence.

## Finding 3 — Reflected credentialed CORS

1. **Tool detected:** `/api/cors` reflects `https://untrusted.example` with `Access-Control-Allow-Credentials: true`.
2. **Capture:** Use a captured Alice-authenticated local request; send it to Repeater and change its path to `/api/cors`.
3. **Repeater:** Add `Origin: https://untrusted.example`. Send once. In a second tab send OPTIONS with Origin, `Access-Control-Request-Method: GET`, and `Access-Control-Request-Headers: authorization`, without an Authorization token.
4. **Inspect:** ACAO should match the origin exactly, ACAC should equal lowercase `true`, and preflight method/header permissions must permit the intended browser request. Check actual response content and authentication mechanism. Preflight success alone is insufficient.
5. **Confirm:** These requests confirm the permissive **header configuration**. A real data-exposure vulnerability additionally requires sensitive data readable by a malicious browser origin with credentials it can actually send. For cookie sessions, cookie SameSite/Secure behavior, third-party cookie restrictions and the full browser flow matter. Repeater does not enforce CORS.
6. **False positive/limit:** Public data, a legitimately trusted origin, no browser-available credentials, rejected preflight or browser restrictions can prevent exploitation. The demo's bearer token is explicitly supplied; an attacker website does not automatically know it. `ACAO: *` plus credentials is not valid for credentialed browser reads. Do not label this lab result confirmed account compromise.

Change `LAB_CORS_MODE` to `strict`, restart and regenerate tokens to check the control. Untrusted-origin permission should disappear.

## Finding 4 — Missing security headers

1. **Tool detected:** Context-relevant headers are absent, especially on `/api/html`.
2. **Capture:** Visit `/api/html` in Burp's browser and find it in HTTP history.
3. **Repeater:** Send that GET to Repeater. Do the same for `/api/public` (JSON).
4. **Inspect:** Status, Content-Type, CSP, X-Content-Type-Options, Referrer-Policy and framing policy. Only evaluate HSTS on HTTPS; the local lab is HTTP.
5. **Confirm:** This confirms a missing header only. Establish a relevant browser threat and content context before assigning higher risk. CSP `frame-ancestors` can cover framing protections without X-Frame-Options.
6. **False positive/limit:** JSON responses do not need every HTML policy; a proxy may add headers in deployment; framing protection may already be present in CSP. No HSTS on HTTP loopback is expected. Absence of these headers alone does not prove an API exploit.

## Finding 5 — Rate-limit observation

1. **Tool detected:** A tiny GET sample received 429 and possibly Retry-After, or completed without observing 429.
2. **Capture:** Wait at least 30 seconds to start a fresh lab quota. Visit `/api/limited` once; that captured visit already counts as request 1.
3. **Repeater:** Send the captured request to Repeater. Send it at most three more times, one second apart, stopping immediately on 429 or errors. Do not use automatic repetition.
4. **Inspect:** Expect two more successes, then the fourth total request gets 429. Read Retry-After; do not keep clicking Send.
5. **Confirm:** The response confirms a limiter is operating for the current IP/window. It does not prove every endpoint or identity is protected.
6. **False positive/limit:** Lack of 429 in a small sample does not mean no limiter. A different IP/key/window, previous requests consuming quota or upstream behavior can change results. The lab limiter is deliberately simple and in-memory.

## Finding 6 — Unexpected advertised HTTP methods

1. **Tool detected:** OPTIONS advertised a method not in supplied documentation. The default lab may have no such finding; a test fixture covers detection.
2. **Capture:** Capture a GET for the exact approved endpoint.
3. **Repeater:** Change only the request method to OPTIONS; remove an irrelevant body/content length. Send once.
4. **Inspect:** The Allow header versus approved OpenAPI methods. HEAD/OPTIONS can be normal additions.
5. **Confirm:** You can confirm a documentation/capability discrepancy. Actual unauthorized destructive access is not established.
6. **False positive/limit:** The method is legitimate, the contract is incomplete, or a server advertises methods that are separately authorized. Do not send destructive requests to prove it.

## Finding 7 — JWT configuration finding

1. **Tool detected:** Missing/odd claims, an expired timestamp, unusual algorithm label or sensitive-looking field names in a locally decoded JWT.
2. **Capture:** Use `/api/login` and the resulting `/api/me` request in HTTP history. Keep the token private.
3. **Repeater:** Send the **unchanged, legitimate token** to `/api/me` to confirm the current session works. No token editing/forgery/bypass is needed.
4. **Inspect:** Compare report metadata with the application token policy. Do not paste real tokens into online decoders. Server verification uses a fixed algorithm/issuer/audience and time checks in the lab.
5. **Confirm:** Claim presence/absence is observable. Sensitive payload data is visible to token holders because signing is not encryption. A server validation weakness needs separate authorized evidence; the toolkit has not tested that.
6. **False positive/limit:** A long token lifetime may be deliberate; issuer/subject policy differs by use; expired tokens saved locally are normal; a named field may not contain real sensitive data. Unverified payload content does not establish authenticity or server acceptance.

## Evidence checklist for manual notes

Record date/time, exact approved scope, method/path, response status, relevant redacted headers and the minimum synthetic/private-data excerpt necessary to prove the authorized test. Label the user roles without exposing tokens. Explain the intended rule, observed behavior, control result and remaining uncertainty. Keep unredacted Burp history local and restricted. Do not attach entire token-bearing history to a public issue or report.

This guide has been written against official PortSwigger Repeater documentation. GUI exercises remain for you to perform locally; they were not automated or claimed as completed.
