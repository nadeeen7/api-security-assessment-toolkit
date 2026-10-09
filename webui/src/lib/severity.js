/**
 * Severity vocabulary comes straight from the engine's risk_engine.RULES.
 * Class names are written as complete literals so Tailwind's scanner finds them.
 */
export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

export const SEVERITY_TONE = {
  Critical: { badge: "bg-critical/15 text-critical border-critical/40", dot: "bg-critical", text: "text-critical" },
  High: { badge: "bg-high/15 text-high border-high/40", dot: "bg-high", text: "text-high" },
  Medium: { badge: "bg-medium/15 text-medium border-medium/40", dot: "bg-medium", text: "text-medium" },
  Low: { badge: "bg-low/15 text-low border-low/40", dot: "bg-low", text: "text-low" },
  Informational: { badge: "bg-info/15 text-info border-info/40", dot: "bg-info", text: "text-info" },
};

export const SEVERITY_NOTE = {
  Critical:
    "The engine implements no Critical rule. A zero here is not proof of safety.",
  High: "High is a prioritisation label; the report still says “potential” until policy is confirmed.",
  Medium: "Needs manual confirmation of intended access before it is a confirmed issue.",
  Low: "Low-confidence metadata, not proof of exploitability.",
  Informational: "Hardening or documentation observation. Not a vulnerability by itself.",
};

export function severityTone(severity) {
  return SEVERITY_TONE[severity] || SEVERITY_TONE.Informational;
}

/** How many findings exist at each severity, defaulting missing ones to 0. */
export function summariseSeverities(findings = []) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((name) => [name, 0]));
  for (const finding of findings) {
    const key = finding.severity in counts ? finding.severity : "Informational";
    counts[key] += 1;
  }
  return counts;
}
