/**
 * The engine emits real phase boundaries from main.run(). Progress in this UI is
 * derived from those events only — nothing here is simulated or time-based.
 */

/** Order in which main.run() actually emits phases. */
export const PHASE_ORDER = [
  "openapi_analysis",
  "endpoint_discovery",
  "jwt_analysis",
  "authorization",
  "endpoint",
  "rate_limit",
  "report",
];

/**
 * Which engine phase each selectable test belongs to.
 * The four in-loop checks share the "endpoint" phase, and parameter extraction
 * happens during report generation, so those tests complete together.
 */
export const TEST_PHASE = {
  openapi_analysis: "openapi_analysis",
  endpoint_discovery: "endpoint_discovery",
  jwt_analysis: "jwt_analysis",
  authorization: "authorization",
  method_analysis: "endpoint",
  auth_analysis: "endpoint",
  headers_analysis: "endpoint",
  cors_analysis: "endpoint",
  rate_limit: "rate_limit",
  parameter_discovery: "report",
};

export function statesForTests(tests, job) {
  const observed = new Set((job?.progress || []).map((event) => event.phase));
  const currentPhase = job?.current_phase;
  const currentIndex = PHASE_ORDER.indexOf(currentPhase);
  const finished = job?.status === "completed";
  const failed = job?.status === "failed" || job?.status === "cancelled";

  return tests.map((key) => {
    const phase = TEST_PHASE[key] || "report";
    const index = PHASE_ORDER.indexOf(phase);
    let state = "pending";

    if (finished) {
      state = "done";
    } else if (phase === currentPhase) {
      state = "running";
    } else if (observed.has(phase)) {
      // Single-shot phases announce themselves once, so seeing the event means done.
      state = "done";
    } else if (!failed && currentIndex >= 0 && index < currentIndex) {
      state = "done";
    }
    return { key, state };
  });
}

/** The most recent per-endpoint event, used to show partial progress inside the loop. */
export function lastEndpointEvent(job) {
  const events = (job?.progress || []).filter((event) => event.phase === "endpoint");
  return events.length ? events[events.length - 1] : null;
}

export function progressPercent(tests, job) {
  if (!tests.length) return 0;
  if (job?.status === "completed") return 100;

  const states = statesForTests(tests, job);
  const done = states.filter((item) => item.state === "done").length;
  let percent = (done / tests.length) * 100;

  // Inside the endpoint loop, credit the endpoints already covered.
  if (job?.current_phase === "endpoint") {
    const event = lastEndpointEvent(job);
    const detail = event?.detail || {};
    if (detail.index && detail.total) {
      percent += (detail.index / detail.total) * (100 / tests.length);
    }
  }
  return Math.max(0, Math.min(99, Math.round(percent)));
}

export const PHASE_LABELS = {
  openapi_analysis: "OpenAPI analysis",
  endpoint_discovery: "Endpoint discovery",
  jwt_analysis: "JWT analysis",
  authorization: "Authorization / BOLA",
  endpoint: "Endpoint checks",
  rate_limit: "Rate limiting",
  report: "Parameter extraction & report",
};
