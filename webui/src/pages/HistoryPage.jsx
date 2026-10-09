import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { StatusBadge } from "../components/Badges";
import { formatDateTime, formatDuration } from "../lib/format";
import { SEVERITY_ORDER, severityTone } from "../lib/severity";

function SeverityMiniBar({ summary }) {
  if (!summary) return <span className="text-xs text-slate-500">—</span>;
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {SEVERITY_ORDER.filter((s) => (summary[s] ?? 0) > 0).map((s) => (
        <span
          key={s}
          className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-semibold ${
            s === "High" ? "border-high/30 bg-high/10 text-high"
            : s === "Medium" ? "border-medium/30 bg-medium/10 text-medium"
            : s === "Low" ? "border-low/30 bg-low/10 text-low"
            : s === "Critical" ? "border-critical/30 bg-critical/10 text-critical"
            : "border-info/30 bg-info/10 text-info"
          }`}
        >
          {s === "Informational" ? "Info" : s}: {summary[s]}
        </span>
      ))}
      {SEVERITY_ORDER.every((s) => !(summary[s] ?? 0)) && (
        <span className="text-xs text-ok">No findings</span>
      )}
    </div>
  );
}

export default function HistoryPage() {
  const [state, setState] = useState({});
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    let timer;
    const load = async () => {
      try {
        const data = await api.history();
        if (!active) return;
        setState({ data: data.assessments });
        if (data.assessments.some((j) => ["queued", "running"].includes(j.status))) {
          timer = setTimeout(load, 1500);
        }
      } catch (error) {
        if (active) setState({ error });
      }
    };
    setState({});
    load();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [attempt]);

  return (
    <div className="space-y-5">
      {/* ── Header ── */}
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.15em] text-accent-strong mb-1">
            Assessment Toolkit
          </p>
          <h1 className="text-2xl font-bold text-white">Assessment history</h1>
          <p className="mt-1 text-sm text-info">
            Previous assessments, newest first.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link className="btn btn-primary text-sm" to="/">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M12 5v14M5 12h14" />
            </svg>
            New assessment
          </Link>
          <button
            className="btn btn-ghost text-sm"
            onClick={() => setAttempt((v) => v + 1)}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
              <path d="M3 3v5h5" />
            </svg>
            Refresh
          </button>
        </div>
      </header>

      {/* ── Content ── */}
      {state.error ? (
        <section className="card p-6" role="alert">
          <div className="flex items-start gap-3">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-critical mt-0.5 flex-shrink-0">
              <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
            </svg>
            <div>
              <p className="text-sm font-semibold text-critical">Failed to load history</p>
              <p className="text-sm text-info mt-1">{state.error.message}</p>
            </div>
          </div>
        </section>
      ) : !state.data ? (
        <div className="card p-8">
          <div className="empty-state">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-accent animate-spin">
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            <p className="text-sm text-info">Loading history…</p>
          </div>
        </div>
      ) : !state.data.length ? (
        <section className="card p-8">
          <div className="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-line">
              <path d="M12 8v4l3 3m6-3a9 9 0 1 1-18 0 9 9 0 0 1 18 0z" />
            </svg>
            <div>
              <p className="text-lg font-bold text-white">No assessments yet</p>
              <p className="text-sm text-info mt-1">
                No security assessments have been completed.
              </p>
            </div>
            <Link className="btn btn-primary" to="/">
              Start your first assessment
            </Link>
          </div>
        </section>
      ) : (
        <section className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="data-table table-as-cards">
              <thead>
                <tr>
                  {["Target", "Date", "Status", "Duration", "Endpoints", "Findings", "Actions"].map((h) => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {state.data.map((j) => (
                  <tr key={j.job_id}>
                    <td data-label="Target">
                      <p className="font-medium text-slate-200 break-all max-w-xs">
                        {j.target || "Offline analysis"}
                      </p>
                      <p className="mt-1 font-mono text-xs text-slate-500">{j.job_id}</p>
                    </td>
                    <td data-label="Date" className="whitespace-nowrap">
                      <p className="text-sm text-slate-300">{formatDateTime(j.created_at)}</p>
                    </td>
                    <td data-label="Status">
                      <StatusBadge status={j.status} />
                    </td>
                    <td data-label="Duration" className="whitespace-nowrap text-slate-300">
                      {formatDuration(j.duration_seconds)}
                    </td>
                    <td data-label="Endpoints" className="text-slate-300">
                      {j.endpoints_total ?? "—"}
                    </td>
                    <td data-label="Findings">
                      {j.severity_summary ? (
                        <SeverityMiniBar summary={j.severity_summary} />
                      ) : j.findings_total !== undefined && j.findings_total !== null ? (
                        <span className="text-slate-300">{j.findings_total}</span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td data-label="Actions">
                      <Link
                        className="btn btn-ghost py-1.5 px-3 text-xs"
                        to={`/assessment/${j.job_id}${j.status === "completed" ? "/results" : ""}`}
                      >
                        {j.status === "completed" ? "View results" : "View progress"}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
