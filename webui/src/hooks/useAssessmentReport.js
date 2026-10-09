import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useJobPolling } from "./useJobPolling";

// Only read report resources after successful completion. Ignore late responses
// when navigating between jobs; never display another assessment's data.
export function useAssessmentReport(jobId) {
  const { job: polledJob, error: jobError } = useJobPolling(jobId);
  const job = polledJob?.job_id === jobId ? polledJob : null;
  const [state, setState] = useState({});
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    setState({});
    if (job?.status === "completed") {
      Promise.all([
        api.endpoints(jobId),
        api.findings(jobId),
        api.coverage(jobId),
      ])
        .then(([endpoints, findings, coverage]) => {
          if (active)
            setState({
              jobId,
              data: { ...endpoints, ...findings, ...coverage },
            });
        })
        .catch((error) => {
          if (active) setState({ jobId, error });
        });
    }
    return () => {
      active = false;
    };
  }, [jobId, job?.status, attempt]);
  return {
    job,
    data: state.jobId === jobId ? state.data : null,
    error: jobError || (state.jobId === jobId ? state.error : null),
    retry: () => setAttempt((value) => value + 1),
  };
}
