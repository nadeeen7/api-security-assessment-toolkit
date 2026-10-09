/**
 * Thin client for the local Flask API.
 *
 * The API requires a per-run session token on every state-changing request.
 * That token is fetched once from `/api/session`, which a cross-origin page
 * cannot read, so the token acts as a CSRF guard. If the API restarts, its token
 * changes and a 403 triggers one transparent re-fetch and retry.
 */

let session = null; // { token, header }
let sessionPromise = null;

async function loadSession() {
  if (session) return session;
  if (!sessionPromise) {
    sessionPromise = (async () => {
      const response = await fetch("/api/session", {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error("Could not establish a session with the local API.");
      }
      const payload = await response.json();
      if (!payload || !payload.token || !payload.header) {
        throw new Error("The local API did not return a session token.");
      }
      session = payload;
      return payload;
    })().catch((error) => {
      sessionPromise = null; // let the next call try again
      throw error;
    });
  }
  return sessionPromise;
}

function offlineError() {
  const error = new Error(
    "Could not reach the local assessment API. Is `python -m web` still running on 127.0.0.1:5055?",
  );
  error.offline = true;
  return error;
}

async function request(path, { method = "GET", body, retried = false } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const active = await loadSession();
    headers[active.header] = active.token;
  }

  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw offlineError();
  }

  // A server restart rotates the token; refresh once and retry the mutation.
  if (response.status === 403 && method !== "GET" && !retried) {
    session = null;
    sessionPromise = null;
    return request(path, { method, body, retried: true });
  }

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const error = new Error(
      (payload && payload.error) || `Request failed with status ${response.status}.`,
    );
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

export const api = {
  health: () => request("/api/health"),
  session: () => loadSession(),
  tests: () => request("/api/tests"),
  history: () => request("/api/assessments"),
  startAssessment: (payload) => request("/api/assessment/start", { method: "POST", body: payload }),
  job: (jobId) => request(`/api/assessment/${jobId}`),
  findings: (jobId) => request(`/api/assessment/${jobId}/findings`),
  endpoints: (jobId) => request(`/api/assessment/${jobId}/endpoints`),
  coverage: (jobId) => request(`/api/assessment/${jobId}/coverage`),
  analyzeOpenapi: (openapiText) =>
    request("/api/openapi/analyze", { method: "POST", body: { openapi_text: openapiText } }),
  sampleOpenapi: () => request("/api/openapi/sample"),
  fetchOpenapi: (url, authorized = false) =>
    request("/api/openapi/fetch", { method: "POST", body: { url, authorized } }),
  cancel: (jobId) => request(`/api/assessment/${jobId}/cancel`, { method: "POST" }),

  // Report artifacts are plain links, not fetches.
  reportUrl: (jobId, kind, download = false) =>
    `/api/assessment/${jobId}/report/${kind}${download ? "?download=1" : ""}`,
  evidenceUrl: (jobId, download = false) =>
    `/api/assessment/${jobId}/evidence.json${download ? "?download=1" : ""}`,
};
