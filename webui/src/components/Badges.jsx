import { severityTone } from "../lib/severity";
import { statusTone } from "../lib/format";

const BASE =
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold whitespace-nowrap";

export function SeverityBadge({ severity }) {
  const tone = severityTone(severity);
  return (
    <span className={`${BASE} ${tone.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${tone.dot}`} aria-hidden="true" />
      {severity || "Unknown"}
    </span>
  );
}

export function StatusBadge({ status }) {
  return (
    <span className={`${BASE} ${statusTone(status)}`}>
      {status === "running" && (
        <span className="h-1.5 w-1.5 rounded-full bg-current status-dot-running" aria-hidden="true" />
      )}
      {status}
    </span>
  );
}

export function ClassificationBadge({ label }) {
  return (
    <span className={`${BASE} bg-raised text-info border-line`}>
      {label || "Observation"}
    </span>
  );
}

export function ConfidenceBadge({ confidence }) {
  const tone =
    confidence === "High"
      ? "bg-ok/10 text-ok border-ok/30"
      : confidence === "Medium"
        ? "bg-medium/10 text-medium border-medium/30"
        : "bg-info/10 text-info border-info/30";
  return (
    <span className={`${BASE} ${tone}`}>
      {confidence || "Low"} confidence
    </span>
  );
}
