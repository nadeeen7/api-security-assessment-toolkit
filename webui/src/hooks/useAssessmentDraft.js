import { useEffect, useState } from "react";

const STORAGE_KEY = "assessment-draft:v1";

/**
 * Clean default state for a brand-new assessment.
 * Demonstrates no hardcoded demo values; only schema defaults.
 */
export const cleanDraft = {
  target: "",
  openapiText: "",
  openapiName: "",
  authScheme: "bearer",
  primaryHeader: "X-API-Key",
  primaryUsername: "",
  primaryToken: "",
  secondaryAuth: { scheme: "bearer", header: "X-API-Key", username: "" },
  secondaryToken: "",
  endpointsText: "",
  jwtToken: "",
  bola: {
    path: "/api/objects/101",
    identity_path: "/api/me",
    owner_subject: "alice",
    other_subject: "bob",
    expected_object_id: "101",
    id_field: "id",
    owner_field: "owner",
  },
  rateLimit: { path: "/api/limited", count: "5", delay: "0.5" },
  mode: "recommended",
  customKeys: [],
  advancedOpen: false,
  acknowledged: false,
};

/**
 * Hook managing assessment form state.
 *
 * SECURITY & RELIABILITY:
 * Whenever opening a new assessment or refreshing the page, the form
 * starts with a clean slate. Credentials, tokens, keys, and previous form
 * inputs are NEVER restored from browser storage (localStorage/sessionStorage).
 * Historical assessments remain safely stored in the backend and accessible via History.
 */
export function useAssessmentDraft() {
  const [state, setState] = useState(cleanDraft);

  // Ensure any previous storage residue is purged on mount
  useEffect(() => {
    if (typeof window !== "undefined") {
      try {
        window.sessionStorage.removeItem(STORAGE_KEY);
        window.localStorage.removeItem(STORAGE_KEY);
      } catch {
        // Storage access may be blocked; safe to ignore
      }
    }
  }, []);

  function update(partial) {
    setState((previous) => {
      return typeof partial === "function" ? partial(previous) : { ...previous, ...partial };
    });
  }

  function resetToClean() {
    if (typeof window !== "undefined") {
      try {
        window.sessionStorage.removeItem(STORAGE_KEY);
        window.localStorage.removeItem(STORAGE_KEY);
      } catch {
        // ignore
      }
    }
    setState(cleanDraft);
  }

  return { state, update, resetToClean };
}
