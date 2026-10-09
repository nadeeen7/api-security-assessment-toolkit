import { useParams } from "react-router-dom";
import { useAssessmentReport } from "../hooks/useAssessmentReport";
import {
  ReportGate,
  ReportHeader,
  Limitations,
} from "../components/ReportLayout";
import { SEVERITY_ORDER, severityTone } from "../lib/severity";
import { formatJson } from "../lib/format";
import { SeverityBadge } from "../components/Badges";

// Severity card class mapping
const SEVERITY_CARD_CLASS = {
  Critical: "severity-card severity-card-critical",
  High:     "severity-card severity-card-high",
  Medium:   "severity-card severity-card-medium",
  Low:      "severity-card severity-card-low",
  Informational: "severity-card severity-card-info",
};

function MetricCard({ label, value, accent }) {
  return (
    <div className="card p-4">
      <p className="text-xs font-semibold uppercase tracking-wider text-info mb-2">{label}</p>
      <p className={`text-2xl font-bold ${accent || "text-white"}`}>{value}</p>
    </div>
  );
}

function TestStatusBadge({ status }) {
  const map = {
    passed:  { cls: "bg-ok/10 text-ok border-ok/30", label: "Completed" },
    finding: { cls: "bg-high/10 text-high border-high/30", label: "Finding" },
    skipped: { cls: "bg-info/10 text-info border-info/30", label: "Skipped" },
    failed:  { cls: "bg-critical/10 text-critical border-critical/30", label: "Failed" },
  };
  const item = map[status] || { cls: "bg-raised text-info border-line", label: status };
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${item.cls}`}>
      {item.label}
    </span>
  );
}

export default function ResultsPage() {
  const { jobId } = useParams();
  const report = useAssessmentReport(jobId);
  const { job, data } = report;
  const coverage = data?.coverage || {};

  return (
    <ReportGate report={report}>
      {data && (
        <div className="space-y-6">
          <ReportHeader job={job} title="Assessment Results" />

          {/* ── Severity summary ── */}
          <section aria-label="Severity summary" className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            {SEVERITY_ORDER.map((name) => (
              <div key={name} className={SEVERITY_CARD_CLASS[name] || SEVERITY_CARD_CLASS.Informational}>
                <h2 className={`text-xs font-bold uppercase tracking-wider mb-2 ${severityTone(name).text}`}>
                  {name}
                </h2>
                <p className={`text-3xl font-bold ${severityTone(name).text}`}>
                  {data.severity_summary[name] ?? 0}
                </p>
              </div>
            ))}
          </section>

          {/* ── Assessment metrics ── */}
          <section>
            <p className="text-xs font-semibold uppercase tracking-wider text-info mb-3">Assessment Coverage</p>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
              {[
                ["Endpoints", data.endpoints.length, null],
                [
                  "Tests selected",
                  coverage.tests_selected?.length ?? job.tests_selected.length,
                  null,
                ],
                [
                  "Executed",
                  coverage.tests_executed?.length ?? "—",
                  "text-ok",
                ],
                [
                  "Skipped",
                  coverage.tests_skipped?.length ?? "—",
                  "text-medium",
                ],
                [
                  "Failed",
                  coverage.tests_failed?.length ?? "—",
                  (coverage.tests_failed?.length ?? 0) > 0 ? "text-critical" : null,
                ],
                ["Requests sent", coverage.requests_sent ?? "—", null],
              ].map(([label, value, accent]) => (
                <MetricCard key={label} label={label} value={value} accent={accent} />
              ))}
            </div>
          </section>

          {/* ── Test coverage table ── */}
          {coverage.tests?.length ? (
            <section className="card overflow-hidden">
              <div className="px-5 py-4 border-b border-line">
                <h2 className="font-semibold text-white">Test Coverage</h2>
                <p className="mt-1 text-xs text-info">
                  "Executed" means the module ran its checks. "Skipped" means it was selected but had no applicable input.
                </p>
              </div>
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      {["Test", "Status", "Findings", "Reason / note"].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {coverage.tests.map((t) => (
                      <tr key={t.key}>
                        <td className="font-mono text-xs text-slate-300">{t.key}</td>
                        <td><TestStatusBadge status={t.status} /></td>
                        <td className="text-slate-300">{t.findings ?? 0}</td>
                        <td className="text-info text-xs max-w-xs">{t.reason || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          {/* ── Coverage notes ── */}
          {(coverage.stop_reason || coverage.tests_executed || coverage.tests_skipped) && (
            <section className="card p-5">
              <h2 className="font-semibold text-white mb-3">Coverage detail</h2>
              {coverage.tests_executed?.length ? (
                <p className="mt-2 text-sm text-ok break-words">
                  Executed: {coverage.tests_executed.join(", ")}
                </p>
              ) : null}
              {coverage.tests_skipped?.length ? (
                <p className="mt-2 text-sm text-medium break-words">
                  Skipped: {coverage.tests_skipped.join(", ")}
                </p>
              ) : null}
              {coverage.stop_reason && (
                <p className="mt-3 text-sm text-medium">
                  Stop reason: {coverage.stop_reason}
                </p>
              )}
              {coverage.bola && (
                <p className="mt-2 text-sm text-info">
                  BOLA:{" "}
                  {typeof coverage.bola === "object" && coverage.bola !== null
                    ? coverage.bola.outcome || "See finding evidence"
                    : coverage.bola || "Not recorded"}
                </p>
              )}
              {coverage.rate_test && (
                <p className="mt-2 text-sm text-info">
                  Rate test:{" "}
                  {typeof coverage.rate_test === "object"
                    ? formatJson(coverage.rate_test)
                    : coverage.rate_test}
                </p>
              )}
              {coverage.skipped?.length > 0 && (
                <div className="mt-3">
                  <h3 className="text-sm font-semibold text-white mb-1">Skipped endpoints</h3>
                  <pre className="code-block mt-2">{formatJson(coverage.skipped)}</pre>
                </div>
              )}
            </section>
          )}

          {/* ── Endpoint summary ── */}
          <section className="card overflow-hidden">
            <div className="px-5 py-4 border-b border-line">
              <h2 className="font-semibold text-white">Endpoint summary</h2>
            </div>
            {data.endpoints.length ? (
              <div className="overflow-x-auto">
                <table className="data-table table-as-cards">
                  <thead>
                    <tr>
                      {["Method", "Path", "Actual Status", "Authentication", "Result / Note", "Parameters", "Documented Responses"].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {data.endpoints.map((e, i) => (
                      <tr key={i}>
                        <td data-label="Method">
                          <span className="font-mono text-xs font-bold text-accent-strong">{e.method}</span>
                        </td>
                        <td data-label="Path" className="font-mono text-xs break-all">
                          <div>{e.path}</div>
                          {e.resolved_path && e.resolved_path !== e.path && (
                            <div className="mt-1">
                              <span className="inline-flex items-center rounded bg-accent/15 px-1.5 py-0.5 text-[10px] text-accent-strong font-mono">
                                Example: {e.resolved_path}
                              </span>
                            </div>
                          )}
                        </td>
                        <td data-label="Actual Status">
                          {e.actual_status !== null && e.actual_status !== undefined ? (
                            <span className={`font-mono text-xs font-bold ${
                              e.actual_status >= 200 && e.actual_status < 300 ? "text-ok"
                              : e.actual_status >= 400 && e.actual_status < 500 ? "text-medium"
                              : e.actual_status >= 500 ? "text-critical" : "text-info"
                            }`}>
                              HTTP {e.actual_status}
                            </span>
                          ) : (
                            <span className="text-slate-500 text-xs">Skipped</span>
                          )}
                          {e.authenticated && e.authenticated !== "Skipped" && (
                            <span className="block text-[10px] text-info mt-0.5">
                              Auth: {e.authenticated}
                            </span>
                          )}
                        </td>
                        <td data-label="Auth">{e.authentication || "—"}</td>
                        <td data-label="Result / Note" className="text-xs max-w-xs text-info">
                          {e.check_status && (
                            <span className={`inline-block mr-1 font-semibold ${
                              e.check_status === "passed" ? "text-ok"
                              : e.check_status === "finding" ? "text-high"
                              : e.check_status === "failed" ? "text-critical" : "text-info"
                            }`}>
                              [{e.check_status.toUpperCase()}]
                            </span>
                          )}
                          <span className="text-slate-300">{e.check_reason || "—"}</span>
                        </td>
                        <td data-label="Params">
                          <pre className="text-xs whitespace-pre-wrap max-w-xs">
                            {formatJson(e.parameters)}
                          </pre>
                        </td>
                        <td data-label="Responses">
                          {e.response_statuses?.join(", ") || "Not documented"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state text-info">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-line">
                  <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
                </svg>
                <p className="text-sm">No endpoints were recorded for this assessment.</p>
              </div>
            )}
          </section>

          {/* ── HTTP observations (collapsed) ── */}
          <details className="card overflow-hidden">
            <summary className="cursor-pointer px-5 py-4 text-sm font-semibold text-white hover:bg-surface/30 transition-colors">
              HTTP observations ({coverage.observations?.length || 0})
            </summary>
            <div className="border-t border-line px-5 py-4">
              <pre className="code-block max-h-96">
                {formatJson(coverage.observations || [])}
              </pre>
            </div>
          </details>

          <Limitations items={data.limitations} />
        </div>
      )}
    </ReportGate>
  );
}
