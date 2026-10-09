import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { useAssessmentReport } from "../hooks/useAssessmentReport";
import {
  ReportGate,
  ReportHeader,
  Limitations,
} from "../components/ReportLayout";
import { formatDateTime } from "../lib/format";

const REPORT_ICONS = {
  "report.html": (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-accent-strong">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8" />
    </svg>
  ),
  "report.md": (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-low">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
      <path d="m9 15 2-2 2 2" /><path d="M11 13v5" />
    </svg>
  ),
  "evidence.json": (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="text-medium">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
      <path d="M10 12a2 2 0 1 0 0 4 2 2 0 0 0 0-4z" />
      <path d="M16 12a2 2 0 1 0 0 4 2 2 0 0 0 0-4z" />
      <path d="M12 14h2" />
    </svg>
  ),
};

export default function ReportsPage() {
  const { jobId } = useParams();
  const report = useAssessmentReport(jobId);
  const { job, data } = report;

  const artifacts = [
    {
      name: "HTML report",
      file: "report.html",
      text: "Fully formatted security report with findings, evidence, and recommendations.",
      url:  api.reportUrl(jobId, "html", true),
      open: api.reportUrl(jobId, "html"),
    },
    {
      name: "Markdown report",
      file: "report.md",
      text: "Plain-text report for documentation, review, and version control.",
      url:  api.reportUrl(jobId, "markdown", true),
    },
    {
      name: "JSON evidence",
      file: "evidence.json",
      text: "Structured assessment data with minimized HTTP evidence for programmatic use.",
      url:  api.evidenceUrl(jobId, true),
    },
  ];

  return (
    <ReportGate report={report}>
      {data && (
        <div className="space-y-5">
          <ReportHeader job={job} title="Reports" />

          <p className="text-sm text-info">
            These artifacts were generated when the assessment completed.
            Opening or downloading them does not run another assessment.
          </p>

          <div className="grid gap-4 lg:grid-cols-3">
            {artifacts.map((a) => (
              <section
                key={a.file}
                className={[
                  "card p-5 flex flex-col gap-4",
                  !job.reports?.[a.file] && "opacity-60",
                ].filter(Boolean).join(" ")}
              >
                {/* Icon + name */}
                <div className="flex items-start gap-3">
                  <span className="mt-0.5 flex-shrink-0">
                    {REPORT_ICONS[a.file] || REPORT_ICONS["report.html"]}
                  </span>
                  <div className="min-w-0">
                    <h2 className="text-base font-bold text-white">{a.name}</h2>
                    <p className="text-xs font-mono text-info mt-0.5">{a.file}</p>
                  </div>
                </div>

                <p className="text-sm text-info leading-relaxed">{a.text}</p>

                {/* Generated timestamp */}
                {job.reports?.[a.file] && job.finished_at && (
                  <p className="text-xs text-slate-500">
                    Generated {formatDateTime(job.finished_at)}
                  </p>
                )}

                {/* Actions */}
                <div className="mt-auto">
                  {job.reports?.[a.file] ? (
                    <div className="flex flex-wrap gap-2">
                      {a.open && (
                        <a
                          className="btn btn-primary text-sm"
                          target="_blank"
                          rel="noreferrer"
                          href={a.open}
                          aria-label="Open HTML"
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                            <polyline points="15 3 21 3 21 9" />
                            <line x1="10" y1="14" x2="21" y2="3" />
                          </svg>
                          Open HTML
                        </a>
                      )}
                      <a
                        className="btn btn-ghost text-sm"
                        href={a.url}
                        download={a.file}
                        aria-label={`Download ${a.file}`}
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                          <polyline points="7 10 12 15 17 10" />
                          <line x1="12" y1="15" x2="12" y2="3" />
                        </svg>
                        Download {a.file}
                      </a>
                    </div>
                  ) : (
                    <p role="status" className="text-sm text-medium flex items-center gap-2">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="flex-shrink-0">
                        <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
                      </svg>
                      Artifact unavailable
                    </p>
                  )}
                </div>
              </section>
            ))}
          </div>

          <Limitations items={data.limitations} />
        </div>
      )}
    </ReportGate>
  );
}
