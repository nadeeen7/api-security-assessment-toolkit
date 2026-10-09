import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useJobPolling } from "../hooks/useJobPolling";
import { labelsFrom, useTestCatalogue } from "../hooks/useTestCatalogue";
import { PHASE_LABELS, lastEndpointEvent, progressPercent, statesForTests } from "../lib/progress";
import { SEVERITY_ORDER, severityTone } from "../lib/severity";
import { formatDuration } from "../lib/format";
import { StatusBadge } from "../components/Badges";

const MARKERS = {
  done:    { icon: "✓", cls: "text-ok" },
  running: { icon: "●", cls: "text-accent status-dot-running" },
  pending: { icon: "○", cls: "text-slate-600" },
};

function LiveStat({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2 border-b border-line-soft last:border-0">
      <dt className="text-sm text-info">{label}</dt>
      <dd className="text-sm font-semibold text-slate-200">{value}</dd>
    </div>
  );
}

export default function ProgressPage() {
  const { jobId } = useParams();
  const { job, error, refresh } = useJobPolling(jobId);
  const { tests: catalogue } = useTestCatalogue();
  const testLabels = useMemo(() => labelsFrom(catalogue), [catalogue]);
  const [cancelling, setCancelling] = useState(false);
  const [actionError, setActionError] = useState(null);

  const tests        = job?.tests_selected || [];
  const states       = useMemo(() => statesForTests(tests, job), [tests, job]);
  const percent      = progressPercent(tests, job);
  const endpointEvent = lastEndpointEvent(job);
  const finished     = job?.status === "completed";
  const active       = job?.status === "queued" || job?.status === "running";

  async function cancel() {
    setCancelling(true);
    setActionError(null);
    try {
      await api.cancel(jobId);
      await refresh();
    } catch (exception) {
      setActionError(exception.message);
    } finally {
      setCancelling(false);
    }
  }

  if (error && !job) {
    return (
      <div className="card p-6">
        <div className="empty-state">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-critical/40">
            <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
          </svg>
          <div>
            <h1 className="text-lg font-bold text-white">Assessment unavailable</h1>
            <p className="text-sm text-critical mt-1">{error.message}</p>
          </div>
          <Link className="btn btn-ghost" to="/">
            Start a new assessment
          </Link>
        </div>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="card p-8">
        <div className="empty-state">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-accent animate-spin">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
          <p className="text-sm text-info">Loading assessment…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* ── Header ── */}
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.15em] text-accent-strong mb-1">
            Assessment in progress
          </p>
          <h1 className="text-xl font-bold text-white truncate">
            {job.target || "Offline analysis"}
          </h1>
          <p className="mt-1 font-mono text-xs text-info">{job.job_id}</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={job.status} />
          {active && (
            <button
              type="button"
              className="btn btn-danger"
              onClick={cancel}
              disabled={cancelling}
            >
              {cancelling ? "Cancelling…" : "Cancel"}
            </button>
          )}
        </div>
      </header>

      {actionError && (
        <p className="text-sm text-critical">{actionError}</p>
      )}

      {/* ── Error card ── */}
      {job.error && (
        <section className="card border-critical/30 bg-critical/5 p-5">
          <div className="flex items-start gap-3">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-critical mt-0.5 flex-shrink-0">
              <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
            </svg>
            <div>
              <h2 className="text-sm font-bold text-critical">Assessment could not be completed</h2>
              <p className="mt-1 text-sm text-info">{job.error.message}</p>
              <details className="mt-2">
                <summary className="text-xs text-slate-500 cursor-pointer">Technical details</summary>
                <p className="mt-1 font-mono text-xs text-slate-500">{job.error.type}</p>
              </details>
            </div>
          </div>
        </section>
      )}

      {/* ── Progress bar ── */}
      <section className="card p-5">
        <div className="mb-4 flex items-end justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-white">
              {finished
                ? "Assessment complete"
                : job.current_phase
                ? `Running: ${PHASE_LABELS[job.current_phase] || job.current_phase}`
                : "Waiting to start…"}
            </p>
            {endpointEvent?.detail?.path && (
              <p className="mt-1 font-mono text-xs text-info">
                {endpointEvent.detail.method}{" "}
                <span className="text-slate-300">{endpointEvent.detail.path}</span>
                {endpointEvent.detail.index && endpointEvent.detail.total
                  ? ` — endpoint ${endpointEvent.detail.index} of ${endpointEvent.detail.total}`
                  : ""}
              </p>
            )}
          </div>
          <span className="text-2xl font-bold text-white tabular-nums">{percent}%</span>
        </div>
        <div
          className="progress-track"
          role="progressbar"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Assessment progress"
        >
          <div className="progress-fill" style={{ width: `${percent}%` }} />
        </div>
      </section>

      {/* ── Tests + Live stats ── */}
      <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
        {/* Selected tests */}
        <section className="card p-5">
          <h2 className="mb-4 text-sm font-bold text-white uppercase tracking-wider">Selected tests</h2>
          <ul className="space-y-1">
            {states.map(({ key, state }) => (
              <li key={key} className="flex items-center justify-between gap-3 py-1">
                <span className="flex items-center gap-3">
                  <span
                    className={`w-4 text-center text-sm ${MARKERS[state].cls}`}
                    aria-hidden="true"
                  >
                    {MARKERS[state].icon}
                  </span>
                  <span className={`text-sm ${state === "pending" ? "text-slate-500" : "text-slate-200"}`}>
                    {testLabels[key] || PHASE_LABELS[key] || key}
                  </span>
                </span>
                <span className={`text-xs ${
                  state === "done" ? "text-ok" : state === "running" ? "text-accent" : "text-slate-600"
                }`}>
                  {state}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-4 border-t border-line pt-3 text-xs text-slate-500 leading-relaxed">
            In-loop checks share one phase — methods, auth, headers and CORS advance together while endpoints are visited.
          </p>
        </section>

        {/* Live detail */}
        <section className="card p-5">
          <h2 className="mb-4 text-sm font-bold text-white uppercase tracking-wider">Live detail</h2>
          <dl>
            <LiveStat
              label="Requests sent"
              value={job.summary?.requests_sent ?? endpointEvent?.detail?.requests_sent ?? 0}
            />
            <LiveStat label="Duration" value={formatDuration(job.duration_seconds)} />
            <LiveStat label="Started"  value={job.started_at ? job.started_at.slice(11, 19) : "—"} />
            <LiveStat label="Progress events" value={job.progress?.length ?? 0} />
          </dl>
          {job.summary?.stop_reason && (
            <p className="mt-4 border-t border-line pt-3 text-xs text-medium leading-relaxed">
              {job.summary.stop_reason}
            </p>
          )}
        </section>
      </div>

      {/* ── Completion summary ── */}
      {finished && job.summary && (
        <section className="card p-5">
          <h2 className="mb-4 text-sm font-bold text-white uppercase tracking-wider">Assessment complete</h2>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5 mb-4">
            {SEVERITY_ORDER.map((name) => (
              <div
                key={name}
                className="rounded-xl border border-line bg-surface/30 p-3 text-center"
              >
                <p className={`text-xs font-bold uppercase tracking-wider mb-1 ${severityTone(name).text}`}>
                  {name === "Informational" ? "Info" : name}
                </p>
                <p className={`text-2xl font-bold ${severityTone(name).text}`}>
                  {job.summary.severity_summary?.[name] ?? 0}
                </p>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-500 mb-4">
            Critical is always zero — the engine implements no Critical rule.
          </p>
          <div className="flex flex-wrap gap-3">
            <Link className="btn btn-primary" to={`/assessment/${jobId}/results`} aria-label="Results dashboard">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                <rect x="3" y="3" width="18" height="18" rx="2" /><path d="M9 9h6M9 12h6M9 15h4" />
              </svg>
              View results
            </Link>
            <Link className="btn btn-ghost" to={`/assessment/${jobId}/findings`}>
              Findings
            </Link>
            <a
              className="btn btn-ghost"
              href={api.reportUrl(jobId, "html")}
              target="_blank"
              rel="noreferrer"
            >
              Open HTML report
            </a>
          </div>
        </section>
      )}
    </div>
  );
}
