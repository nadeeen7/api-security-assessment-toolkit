import { Link, NavLink } from "react-router-dom";
import { StatusBadge } from "./Badges";
import { formatDateTime, formatDuration } from "../lib/format";

export function ReportGate({ report, children }) {
  const { job, data, error, retry } = report;

  if (error) {
    return (
      <section className="card p-6" role="alert">
        <div className="empty-state">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-critical/40">
            <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
          </svg>
          <div>
            <h1 className="text-lg font-bold text-white">Assessment unavailable</h1>
            <p className="text-sm text-critical mt-1">{error.message}</p>
          </div>
          <div className="flex gap-3">
            <button className="btn btn-ghost" onClick={retry}>Retry</button>
            <Link className="btn btn-ghost" to="/history">History</Link>
          </div>
        </div>
      </section>
    );
  }

  if (!job) {
    return (
      <div className="card p-8">
        <div className="empty-state">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-accent animate-spin">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          <p className="text-sm text-info" role="status">Loading assessment…</p>
        </div>
      </div>
    );
  }

  if (job.status !== "completed") {
    return (
      <section className="card p-6">
        <div className="empty-state">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-medium/40">
            <circle cx="12" cy="12" r="10" /><path d="M12 8v4l4 2" />
          </svg>
          <div>
            <h1 className="text-lg font-bold text-white">Results not yet available</h1>
            <p className="text-sm text-info mt-1">
              Assessment status: <StatusBadge status={job.status} />
            </p>
            <p className="text-sm text-info mt-1">
              Reports are available only after successful completion.
            </p>
            {job.error && (
              <p className="text-sm text-critical mt-2">{job.error.message}</p>
            )}
          </div>
          <Link className="btn btn-ghost" to={`/assessment/${job.job_id}`}>
            View progress
          </Link>
        </div>
      </section>
    );
  }

  if (!data) {
    return (
      <div className="card p-8">
        <div className="empty-state">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-accent animate-spin">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          <p className="text-sm text-info" role="status">Loading report…</p>
        </div>
      </div>
    );
  }

  return children;
}

const NAV_TABS = [
  { path: "",         label: "Progress" },
  { path: "/results", label: "Results" },
  { path: "/findings", label: "Findings" },
  { path: "/reports",  label: "Reports" },
];

export function ReportHeader({ job, title }) {
  const base = `/assessment/${job.job_id}`;
  return (
    <header className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.15em] text-accent-strong mb-1">
            Assessment / {job.job_id.slice(0, 8)}…
          </p>
          <h1 className="text-2xl font-bold text-white">{title}</h1>
          <p className="mt-1 text-sm text-info break-all">
            {job.target || "Offline analysis"}
            {job.finished_at && ` · ${formatDateTime(job.summary?.date || job.finished_at)}`}
            {job.duration_seconds != null && ` · ${formatDuration(job.duration_seconds)}`}
          </p>
        </div>
        <StatusBadge status={job.status} />
      </div>

      {/* Subnav tabs */}
      <nav aria-label="Assessment sections" className="flex flex-wrap gap-1">
        {NAV_TABS.map(({ path, label }) => (
          <NavLink
            key={label}
            to={base + path}
            end={!path}
            className={({ isActive }) =>
              [
                "px-3.5 py-1.5 rounded-lg text-sm font-medium transition-all border",
                isActive
                  ? "bg-accent-dim border-accent-strong/40 text-accent"
                  : "border-transparent text-info hover:text-slate-200 hover:bg-surface/60",
              ].join(" ")
            }
          >
            {label}
          </NavLink>
        ))}
      </nav>
    </header>
  );
}

export function Limitations({ items = [] }) {
  if (!items.length) return null;
  return (
    <section className="card p-5">
      <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-3">
        Assessment limitations
      </h2>
      <ul className="space-y-2">
        {items.map((item, index) => (
          <li key={index} className="flex items-start gap-2.5 text-sm text-info">
            <span className="mt-1.5 h-1.5 w-1.5 rounded-full bg-info/40 flex-shrink-0" aria-hidden="true" />
            {item}
          </li>
        ))}
      </ul>
    </section>
  );
}
