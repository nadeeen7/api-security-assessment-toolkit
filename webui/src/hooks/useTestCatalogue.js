import { useEffect, useState } from "react";
import { api } from "../api/client";

// The catalogue is static for the lifetime of the API process, so fetch it once
// and share it between pages instead of requesting it on every mount.
let cache = null;

export function useTestCatalogue() {
  const [tests, setTests] = useState(cache || []);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (cache) return undefined;
    let active = true;
    api
      .tests()
      .then((body) => {
        cache = body.tests || [];
        if (active) setTests(cache);
      })
      .catch((exception) => {
        if (active) setError(exception.message);
      });
    return () => {
      active = false;
    };
  }, []);

  return { tests, error };
}

/** Key → human label, falling back to the raw key if the catalogue is unavailable. */
export function labelsFrom(tests) {
  const map = {};
  for (const test of tests || []) map[test.key] = test.label;
  return map;
}
