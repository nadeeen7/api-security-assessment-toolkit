import { useEffect, useRef, useState } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { useAssessmentReport } from "../hooks/useAssessmentReport";
import {
  ReportGate,
  ReportHeader,
  Limitations,
} from "../components/ReportLayout";
import {
  SeverityBadge,
  ConfidenceBadge,
  ClassificationBadge,
} from "../components/Badges";
import { formatJson } from "../lib/format";

// ─── Finding detail drawer ────────────────────────────────────────────────────

function DetailRow({ label, value }) {
  if (!value) return null;
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs font-semibold uppercase tracking-wider text-info">{label}</dt>
      <dd className="text-sm text-slate-200 break-all">{value}</dd>
    </div>
  );
}

function Section({ title, value }) {
  if (!value) return null;
  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wider text-info mb-2">{title}</h3>
      <p className="text-sm leading-relaxed text-slate-300 whitespace-pre-wrap">{value}</p>
    </section>
  );
}

function FindingDrawer({ finding, limitations, onClose }) {
  const dialog = useRef(null);
  useEffect(() => {
    const element = dialog.current;
    const previous = document.activeElement;
    element.showModal();
    return () => {
      element.close();
      previous?.focus();
    };
  }, []);

  return (
    <dialog
      ref={dialog}
      aria-labelledby="finding-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      className="finding-dialog"
    >
      <div className="h-full flex flex-col">
        {/* Drawer header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-line bg-raised/40 sticky top-0">
          <p className="text-xs font-semibold uppercase tracking-wider text-info">Finding detail</p>
          <button
            autoFocus
            aria-label="Close finding"
            className="btn btn-ghost py-1.5 px-3 text-xs"
            onClick={onClose}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
            Close
          </button>
        </div>

        {/* Drawer body */}
        <div className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          <div>
            <h2 id="finding-title" className="text-xl font-bold text-white mb-3 leading-tight">
              {finding.title}
            </h2>
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity={finding.severity} />
              <ConfidenceBadge confidence={finding.confidence} />
              <ClassificationBadge label={finding.classification} />
            </div>
          </div>

          {/* Key metadata */}
          <div className="rounded-xl border border-line bg-surface/30 p-4">
            <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <DetailRow label="Endpoint" value={finding.endpoint} />
              <DetailRow label="Method"   value={finding.method} />
              <DetailRow label="Category" value={finding.category} />
              <DetailRow label="CWE"      value={finding.cwe} />
              <DetailRow label="OWASP API" value={finding.owasp_api} />
            </dl>
          </div>

          {/* Narrative sections */}
          <Section title="Description"        value={finding.description} />
          <Section title="Why it matters"     value={finding.severity_reason} />
          <Section title="Recommendation"     value={finding.recommendation} />

          {/* Evidence */}
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-info mb-2">
              Evidence (minimized)
            </h3>
            <pre className="code-block max-h-80">
              {formatJson(finding.evidence)}
            </pre>
          </section>

          <Limitations items={limitations} />
        </div>
      </div>
    </dialog>
  );
}

// ─── Findings page ────────────────────────────────────────────────────────────

const FILTER_FIELDS = ["severity", "category", "endpoint", "confidence"];

export default function FindingsPage() {
  const { jobId, index } = useParams();
  const report = useAssessmentReport(jobId);
  const { job, data } = report;
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const navigate = useNavigate();

  // Preserve the original engine array index when filtering so deep links never
  // point at a different finding after changing a filter.
  const rows = (data?.findings || []).map((finding, index) => ({ finding, index }));

  const visible = rows.filter(({ finding }) => {
    const matchesFilters = FILTER_FIELDS.every(
      (key) => !params.get(key) || finding[key] === params.get(key)
    );
    const matchesSearch =
      !search ||
      finding.title?.toLowerCase().includes(search.toLowerCase()) ||
      finding.endpoint?.toLowerCase().includes(search.toLowerCase()) ||
      finding.category?.toLowerCase().includes(search.toLowerCase());
    return matchesFilters && matchesSearch;
  });

  const selected =
    index !== undefined && /^\d+$/.test(index)
      ? data?.findings[Number(index)]
      : null;

  const base   = `/assessment/${jobId}/findings`;
  const suffix = params.toString() ? `?${params}` : "";
  const close  = () => navigate(base + suffix);

  return (
    <ReportGate report={report}>
      {data && (
        <div className="space-y-5">
          <ReportHeader job={job} title="Findings" />

          {/* ── Filters ── */}
          <section className="card p-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
              {/* Search */}
              <div className="lg:col-span-2 relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-info pointer-events-none">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
                  </svg>
                </span>
                <input
                  type="text"
                  className="field-input pl-9 text-sm"
                  placeholder="Search findings…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>

              {/* Dropdown filters */}
              {FILTER_FIELDS.map((key) => (
                <div key={key}>
                  <select
                    aria-label={key}
                    className="field-input text-sm capitalize"
                    value={params.get(key) || ""}
                    onChange={(event) => {
                      const next = new URLSearchParams(params);
                      event.target.value ? next.set(key, event.target.value) : next.delete(key);
                      setParams(next);
                    }}
                  >
                    <option value="">All {key}s</option>
                    {[...new Set(rows.map(({ finding }) => finding[key]).filter(Boolean))]
                      .sort()
                      .map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                  </select>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between mt-3 pt-3 border-t border-line-soft">
              <p className="text-xs text-info">
                Showing{" "}
                <span className="text-white font-semibold">{visible.length}</span>{" "}
                of{" "}
                <span className="text-white font-semibold">{rows.length}</span>{" "}
                findings
              </p>
              {(params.toString() || search) && (
                <button
                  className="btn btn-ghost py-1 px-3 text-xs"
                  aria-label="Clear filters"
                  onClick={() => {
                    setParams({});
                    setSearch("");
                  }}
                >
                  Clear filters
                </button>
              )}
            </div>
          </section>

          {/* ── Findings table ── */}
          <section className="card overflow-hidden">
            {visible.length ? (
              <div className="overflow-x-auto">
                <table className="data-table table-as-cards">
                  <thead>
                    <tr>
                      {["Severity", "Finding", "Endpoint", "Method", "Confidence", "Status"].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map(({ finding: f, index: i }) => (
                      <tr key={i}>
                        <td data-label="Severity">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td data-label="Finding" className="max-w-xs">
                          <Link
                            className="text-accent hover:text-accent-strong transition-colors font-medium hover:underline"
                            to={`${base}/${i}${suffix}`}
                          >
                            {f.title}
                          </Link>
                        </td>
                        <td data-label="Endpoint" className="font-mono text-xs break-all max-w-[12rem]">
                          {f.endpoint || "—"}
                        </td>
                        <td data-label="Method">
                          {f.method ? (
                            <span className="font-mono text-xs font-bold text-accent-strong">{f.method}</span>
                          ) : "—"}
                        </td>
                        <td data-label="Confidence">
                          <ConfidenceBadge confidence={f.confidence} />
                        </td>
                        <td data-label="Status">
                          <ClassificationBadge label={f.classification} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-line">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <div>
                  <p className="text-base font-semibold text-white">
                    {rows.length ? "No findings match these filters." : "No findings detected"}
                  </p>
                  <p className="text-sm text-info mt-1">
                    {rows.length
                      ? "Try adjusting the filters or search query."
                      : "No security findings were recorded for this assessment. This does not establish safety."}
                  </p>
                </div>
                {rows.length > 0 && (
                  <button
                    className="btn btn-ghost text-sm"
                    onClick={() => { setParams({}); setSearch(""); }}
                  >
                    Reset filters
                  </button>
                )}
              </div>
            )}
          </section>

          {index !== undefined && !selected && (
            <section role="alert" className="card p-5">
              <p className="text-sm text-medium">
                Finding not found.{" "}
                <Link className="text-accent underline" to={base + suffix}>
                  Return to findings
                </Link>
              </p>
            </section>
          )}

          {selected && (
            <FindingDrawer
              key={`${jobId}-${index}`}
              finding={selected}
              limitations={data.limitations}
              onClose={close}
            />
          )}

          <Limitations items={data.limitations} />
        </div>
      )}
    </ReportGate>
  );
}
