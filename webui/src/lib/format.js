export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const value = Number(seconds);
  if (!Number.isFinite(value)) return "—";
  if (value < 60) return `${value.toFixed(value < 10 ? 2 : 1)}s`;
  const minutes = Math.floor(value / 60);
  return `${minutes}m ${Math.round(value - minutes * 60)}s`;
}

export function formatDateTime(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

export function formatJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function statusTone(status) {
  switch (status) {
    case "completed":
      return "bg-ok/15 text-ok border-ok/40";
    case "running":
      return "bg-accent/15 text-accent border-accent/40";
    case "queued":
      return "bg-info/15 text-info border-info/40";
    case "failed":
      return "bg-critical/15 text-critical border-critical/40";
    case "cancelled":
      return "bg-medium/15 text-medium border-medium/40";
    default:
      return "bg-info/15 text-info border-info/40";
  }
}
