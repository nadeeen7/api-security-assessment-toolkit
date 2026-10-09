import { Link, useParams } from "react-router-dom";

/**
 * These routes exist so navigation never 404s, but they are deliberately not
 * faked. They will be built in the next step of Phase C.
 */
export default function PlaceholderPage({ title, description }) {
  const { jobId } = useParams();
  return (
    <div className="card p-6">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-accent">Not built yet</p>
      <h1 className="mt-1 text-2xl font-semibold text-white">{title}</h1>
      <p className="mt-2 max-w-2xl text-sm leading-relaxed text-info">{description}</p>
      <p className="mt-3 text-xs text-slate-500">
        This is the next step of Phase C. Nothing here shows invented data.
      </p>
      <div className="mt-5 flex flex-wrap gap-3">
        {jobId ? (
          <Link className="btn btn-ghost" to={`/assessment/${jobId}`}>
            Back to progress
          </Link>
        ) : null}
        <Link className="btn btn-ghost" to="/">
          New assessment
        </Link>
      </div>
    </div>
  );
}
