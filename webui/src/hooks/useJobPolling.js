import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";

const TERMINAL = ["completed", "failed", "cancelled"];

/**
 * Poll one assessment until it reaches a terminal state.
 * Polling stops on completion instead of hammering the API forever, and backs
 * off if the API is briefly unavailable.
 */
export function useJobPolling(jobId, intervalMs = 1000) {
  const [job, setJob] = useState(null);
  const [error, setError] = useState(null);
  const timer = useRef(null);

  const refresh = useCallback(async () => {
    if (!jobId) return;
    try {
      const next = await api.job(jobId);
      setJob(next);
      setError(null);
    } catch (exception) {
      setError(exception);
    }
  }, [jobId]);

  useEffect(() => {
    if (!jobId) return undefined;
    let cancelled = false;
    let delay = intervalMs;

    const tick = async () => {
      try {
        const next = await api.job(jobId);
        if (cancelled) return;
        setJob(next);
        setError(null);
        delay = intervalMs;
        if (!TERMINAL.includes(next.status)) {
          timer.current = setTimeout(tick, delay);
        }
      } catch (exception) {
        if (cancelled) return;
        setError(exception);
        delay = Math.min(delay * 2, 5000);
        timer.current = setTimeout(tick, delay);
      }
    };

    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer.current);
    };
  }, [jobId, intervalMs]);

  return { job, error, refresh };
}
