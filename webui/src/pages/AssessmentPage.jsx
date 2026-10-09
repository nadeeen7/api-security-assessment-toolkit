import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAssessmentDraft } from "../hooks/useAssessmentDraft";
import { useTestCatalogue } from "../hooks/useTestCatalogue";

const MAX_SPEC_BYTES = 2_000_000;

const RECOMMENDED_BASE = [
  "endpoint_discovery",
  "openapi_analysis",
  "parameter_discovery",
  "method_analysis",
  "headers_analysis",
  "cors_analysis",
  // rate_limit is omitted from recommended — it requires a user-supplied path
  // and is still available under "Choose tests individually" + Advanced options.
];

const PRIMARY_SCHEMES = [
  { value: "bearer",  label: "Bearer",  hint: "JWT / Bearer token" },
  { value: "api_key", label: "API Key", hint: "Header-based API key" },
  { value: "basic",   label: "Basic",   hint: "Username & password" },
  { value: "header",  label: "Custom",  hint: "Custom request header" },
  { value: "none",    label: "None",    hint: "Unauthenticated" },
];

const CREDENTIAL_SCHEMES = [
  { value: "bearer",  label: "Bearer token" },
  { value: "api_key", label: "API key header" },
  { value: "basic",   label: "Basic auth" },
  { value: "header",  label: "Custom header" },
];

function authIdentity(auth, secret) {
  const value = secret.trim();
  if (!value) return null;
  if (auth.scheme === "bearer") return value;
  if (auth.scheme === "api_key" || auth.scheme === "header") {
    return { scheme: auth.scheme, header: auth.header.trim(), value };
  }
  return { scheme: "basic", username: auth.username.trim(), password: value };
}

function StepCard({ step, title, description, children, className = "" }) {
  return (
    <section className={`card p-3.5 sm:p-4 flex flex-col justify-between ${className}`}>
      <div>
        <header className="mb-2.5 flex items-start gap-2">
          <span className="step-badge mt-0.5">{step}</span>
          <div className="min-w-0">
            <h2 className="text-xs font-semibold text-white tracking-wide">{title}</h2>
            {description && (
              <p className="text-[11px] leading-tight text-info">{description}</p>
            )}
          </div>
        </header>
        {children}
      </div>
    </section>
  );
}

function Field({ label, hint, children, htmlFor }) {
  return (
    <div>
      {label && (
        <label className="field-label mb-1 text-xs" htmlFor={htmlFor}>
          {label}
        </label>
      )}
      {children}
      {hint && <p className="field-hint mt-0.5 text-[10px]">{hint}</p>}
    </div>
  );
}

function AdvancedGroup({ id, title, description, children }) {
  return (
    <div id={id} className="border-b border-line-soft pb-4 last:border-0 last:pb-0">
      <h3 className="text-xs font-semibold text-white mb-0.5">{title}</h3>
      {description && (
        <p className="text-[11px] leading-relaxed text-info mb-2">{description}</p>
      )}
      <div className="mt-1">{children}</div>
    </div>
  );
}

function CredentialField({ id, label, hint, value, onChange, auth, onAuthChange }) {
  return (
    <div className="space-y-1.5">
      <label className="field-label mb-0 text-xs" htmlFor={id}>{label}</label>
      <select
        className="field-input text-xs py-1"
        aria-label={`${label} scheme`}
        value={auth.scheme}
        onChange={(event) => onAuthChange({ ...auth, scheme: event.target.value })}
      >
        {CREDENTIAL_SCHEMES.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {(auth.scheme === "api_key" || auth.scheme === "header") && (
        <input
          className="field-input font-mono text-xs py-1"
          value={auth.header}
          onChange={(event) => onAuthChange({ ...auth, header: event.target.value })}
          spellCheck={false}
          placeholder={auth.scheme === "api_key" ? "X-API-Key" : "X-Auth"}
          aria-label={`${label} header name`}
        />
      )}
      {auth.scheme === "basic" && (
        <input
          className="field-input font-mono text-xs py-1"
          value={auth.username}
          onChange={(event) => onAuthChange({ ...auth, username: event.target.value })}
          spellCheck={false}
          autoComplete="off"
          placeholder="username"
          aria-label={`${label} username`}
        />
      )}
      <input
        id={id}
        type="password"
        className="field-input font-mono text-xs py-1"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete="off"
        spellCheck={false}
        placeholder={auth.scheme === "basic" ? "password" : "••••••••••••••••"}
      />
      {hint && <p className="field-hint text-[10px]">{hint}</p>}
    </div>
  );
}

export default function AssessmentPage() {
  const navigate = useNavigate();

  const { tests: catalogue, error: catalogueError } = useTestCatalogue();
  const { state, update, resetToClean } = useAssessmentDraft();

  const {
    target,
    openapiText,
    openapiName,
    authScheme,
    primaryHeader,
    primaryUsername,
    primaryToken,
    secondaryAuth,
    secondaryToken,
    endpointsText,
    jwtToken,
    bola,
    rateLimit,
    mode,
    customKeys,
    advancedOpen,
    acknowledged,
  } = state;

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const primaryAuth = {
    scheme: authScheme === "none" ? "bearer" : authScheme,
    header: primaryHeader,
    username: primaryUsername,
  };

  const hasPrimary   = Boolean(primaryToken.trim());
  const hasSecondary = Boolean(secondaryToken.trim());
  const hasJwt       = Boolean(jwtToken.trim());

  const recommendedKeys = useMemo(() => {
    const wanted = new Set(RECOMMENDED_BASE);
    if (hasPrimary) {
      wanted.add("auth_analysis");
      if (hasSecondary && Boolean(bola.path.trim())) wanted.add("authorization");
    }
    if (hasJwt) wanted.add("jwt_analysis");
    return catalogue.map((item) => item.key).filter((key) => wanted.has(key));
  }, [catalogue, hasPrimary, hasSecondary, hasJwt, bola.path]);

  const selected = mode === "custom" ? customKeys : recommendedKeys;
  const needsPrimaryToken = selected.includes("auth_analysis") || selected.includes("authorization");

  const problems = useMemo(() => {
    const list = [];
    if (!selected.length) list.push("Select at least one security test.");
    if (!target.trim() && !openapiText.trim() && !endpointsText.trim()) {
      list.push("Provide a target URL, an OpenAPI document, or an endpoint list.");
    }
    const trimmed = target.trim();
    if (trimmed && !/^https?:\/\//i.test(trimmed)) {
      list.push("The target must start with http:// or https://.");
    }
    if (trimmed && /^http:\/\//i.test(trimmed) && !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])/i.test(trimmed)) {
      list.push("Non-loopback targets must use HTTPS.");
    }
    if (!openapiText.trim() && !endpointsText.trim()) {
      list.push("Provide an OpenAPI specification or enter endpoints so the toolkit knows what to assess.");
    }
    if (openapiText.trim()) {
      const openapiTrimmed = openapiText.trim();
      const isUrl = /^https?:\/\//i.test(openapiTrimmed);
      if (!isUrl) {
        try {
          const parsed = JSON.parse(openapiTrimmed);
          if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
            list.push("OpenAPI specification must be a JSON object.");
          }
        } catch {
          list.push("OpenAPI specification must be valid JSON (or a fetchable URL).");
        }
      }
    }
    if (endpointsText.trim()) {
      try {
        const parsed = JSON.parse(endpointsText.trim());
        if (!Array.isArray(parsed)) {
          list.push("Endpoint list must be a JSON array of paths or objects.");
        }
      } catch {
        list.push("Endpoint list must be valid JSON.");
      }
    }
    if (!acknowledged) list.push("Confirm you have explicit authorization for this target.");
    if (needsPrimaryToken && !hasPrimary) {
      list.push("Authentication analysis needs a credential — enter it in Authentication.");
    }
    for (const [auth, secret, who] of [
      [primaryAuth, primaryToken, "Primary"],
      [secondaryAuth, secondaryToken, "Second"],
    ]) {
      if (!secret.trim()) continue;
      if ((auth.scheme === "api_key" || auth.scheme === "header") && !/^[A-Za-z0-9_-]{1,64}$/.test(auth.header.trim())) {
        list.push(`${who} credential needs a valid header name (letters, digits, dash, underscore).`);
      }
      if (auth.scheme === "basic" && !auth.username.trim()) {
        list.push(`${who} Basic credential needs a username.`);
      }
    }
    if (selected.includes("authorization")) {
      if (!hasSecondary) list.push("Authorization / BOLA needs a second credential in Advanced options.");
      if (primaryToken.trim() && primaryToken.trim() === secondaryToken.trim() && primaryAuth.scheme === secondaryAuth.scheme) {
        list.push("The two BOLA credentials must belong to different users.");
      }
      if (!bola.path.trim().startsWith("/") || !bola.identity_path.trim().startsWith("/")) {
        list.push("BOLA object and identity paths must start with /.");
      }
    }
    if (selected.includes("jwt_analysis") && !hasJwt) {
      list.push("JWT Analysis needs a token to inspect in Advanced options.");
    }
    if (selected.includes("rate_limit") && rateLimit.path.trim()) {
      const count = Number(rateLimit.count);
      const delay = Number(rateLimit.delay);
      if (!rateLimit.path.trim().startsWith("/")) list.push("Rate limit path must start with /.");
      if (!(count >= 1 && count <= 10)) list.push("Rate sample count must be between 1 and 10.");
      if (!(delay >= 0.2 && delay <= 10)) list.push("Rate sample delay must be between 0.2 and 10 seconds.");
    }
    return list;
  }, [
    acknowledged, bola, endpointsText, jwtToken, needsPrimaryToken, openapiText,
    primaryAuth, primaryToken, rateLimit, secondaryToken, selected, target,
  ]);

  function chooseScheme(value) {
    update((prev) => {
      const next = { ...prev, authScheme: value };
      if (value === "none") next.primaryToken = "";
      return next;
    });
  }

  function toggleTest(key) {
    const base = mode === "custom" ? customKeys : recommendedKeys;
    const next = base.includes(key) ? base.filter((item) => item !== key) : [...base, key];
    update((prev) => ({ ...prev, mode: "custom", customKeys: next, advancedOpen: true }));
  }

  function chooseIndividual() {
    update((prev) => ({
      ...prev,
      mode: "custom",
      customKeys: prev.customKeys.length ? prev.customKeys : recommendedKeys,
      advancedOpen: true,
    }));
    window.requestAnimationFrame(() => {
      document.getElementById("advanced-test-selection")?.scrollIntoView({ block: "center" });
    });
  }

  function resetToRecommended() {
    update((prev) => ({ ...prev, mode: "recommended", customKeys: [] }));
  }

  const [fetchingSpec, setFetchingSpec] = useState(false);

  async function handleFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_SPEC_BYTES) {
      setError("That document is larger than 2 MB, which the engine will not accept.");
      return;
    }
    const text = await file.text();
    update((prev) => ({ ...prev, openapiText: text, openapiName: file.name }));
  }

  async function handleLoadSample() {
    try {
      setFetchingSpec(true);
      setError(null);
      const res = await api.sampleOpenapi();
      if (res && res.content) {
        update((prev) => ({
          ...prev,
          openapiText: res.content,
          openapiName: "Lab Sample Spec (openapi.json)",
        }));
      }
    } catch (err) {
      setError("Could not load sample spec: " + (err.message || String(err)));
    } finally {
      setFetchingSpec(false);
    }
  }

  async function handleFetchUrl() {
    const url = openapiText.trim();
    if (!url) return;
    try {
      setFetchingSpec(true);
      setError(null);
      const res = await api.fetchOpenapi(url, acknowledged);
      if (res && res.content) {
        const titlePart = res.title ? res.title : (url.split("/").pop() || "Fetched Spec");
        const countPart = res.paths_count !== undefined ? ` (${res.paths_count} paths)` : "";
        update((prev) => ({
          ...prev,
          openapiText: res.content,
          openapiName: `${titlePart}${countPart}`,
        }));
      }
    } catch (err) {
      setError("Failed to fetch OpenAPI spec from URL: " + (err.message || String(err)));
    } finally {
      setFetchingSpec(false);
    }
  }

  async function start(event) {
    event.preventDefault();
    if (problems.length) return;
    setSubmitting(true);
    setError(null);

    const identities = {};
    const primaryIdentity = authIdentity(primaryAuth, primaryToken);
    const secondaryIdentity = authIdentity(secondaryAuth, secondaryToken);
    if (primaryIdentity) identities.primary = primaryIdentity;
    if (secondaryIdentity) identities.secondary = secondaryIdentity;

    // Strip rate_limit from the tests array when no path is configured — the
    // backend requires a path if rate_limit is selected (returns 400 otherwise).
    const effectiveTests = selected.filter(
      (key) => key !== "rate_limit" || rateLimit.path.trim()
    );
    const payload = {
      target: target.trim() || null,
      authorized: acknowledged,
      tests: effectiveTests,
      limits: { timeout: 5, max_requests: 100, delay: 0.2 },
    };
    if (openapiText.trim()) payload.openapi_text = openapiText;
    if (endpointsText.trim()) payload.endpoints_text = endpointsText;
    if (Object.keys(identities).length) {
      payload.identities = identities;
      payload.default_identity = "primary";
    }
    if (jwtToken.trim()) payload.jwt_token = jwtToken.trim();
    if (selected.includes("authorization") && bola.path.trim()) {
      payload.bola = {
        ...bola,
        owner_identity: "primary",
        other_identity: "secondary",
        expected_object_id: /^\d+$/.test(bola.expected_object_id)
          ? Number(bola.expected_object_id)
          : bola.expected_object_id,
      };
    }
    if (selected.includes("rate_limit") && rateLimit.path.trim()) {
      payload.rate_limit = {
        path: rateLimit.path,
        count: Number(rateLimit.count),
        delay: Number(rateLimit.delay),
      };
    }

    try {
      const created = await api.startAssessment(payload);
      navigate(`/assessment/${created.job_id}`);
    } catch (exception) {
      setError(exception.message);
      setSubmitting(false);
    }
  }

  const totalTests = catalogue.length || 10;

  return (
    <form className="space-y-3" onSubmit={start}>
      {/* ── Page Header ── */}
      <header className="mb-0.5">
        <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-accent-strong mb-0.5">
          API Security Assessment Toolkit
        </p>
        <h1 className="text-xl font-bold text-white leading-tight">
          New Assessment
        </h1>
        <p className="mt-0.5 text-xs text-info leading-snug">
          Assess any authorized REST API for common security issues using controlled, non-destructive checks.
        </p>
      </header>

      {/* ── Core Form Grid: 2 columns on desktop, 1 on mobile ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">

        {/* ── Left Column: Target & Specification / Endpoints ── */}
        <div className="space-y-3">
          {/* Card 1: Target API */}
          <StepCard
            step="1"
            title="Target API URL"
            description="Origin only. HTTP for loopback/lab; remote targets require HTTPS."
          >
            <Field htmlFor="target" hint="Example: https://api.example.com or http://127.0.0.1:8000">
              <div className="relative">
                <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500 text-xs font-mono select-none">
                  URL
                </span>
                <input
                  id="target"
                  className="field-input pl-10 text-xs font-mono py-1.5"
                  value={target}
                  onChange={(event) => update((prev) => ({ ...prev, target: event.target.value }))}
                  placeholder="https://api.example.com"
                  spellCheck={false}
                  autoComplete="off"
                />
              </div>
            </Field>
          </StepCard>

          {/* Card 2: API Specification & Endpoint list */}
          <StepCard
            step="2"
            title="API Specification & Endpoints"
            description="The engine never crawls or guesses paths. Supply OpenAPI JSON or enter endpoints."
          >
            <div className="space-y-2.5">
              {/* OpenAPI upload or paste */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="field-label mb-0 text-xs" htmlFor="openapiDocument">
                    OpenAPI / Swagger (JSON or YAML) <span className="text-slate-500 font-normal">(optional)</span>
                  </label>
                  {openapiName && (
                    <span className="text-[11px] text-ok truncate max-w-[200px]" title={openapiName}>
                      ✓ {openapiName}
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-2 mb-1.5">
                  <label className="btn btn-ghost text-[11px] py-1 px-2.5 cursor-pointer">
                    <span>Upload File</span>
                    <input
                      type="file"
                      accept=".json,application/json,.yaml,.yml,text/yaml,application/x-yaml"
                      className="hidden"
                      onChange={handleFile}
                    />
                  </label>
                  <button
                    type="button"
                    className="btn btn-ghost text-[11px] py-1 px-2.5"
                    disabled={fetchingSpec}
                    onClick={handleLoadSample}
                    title="Load built-in lab specification (input/openapi.json)"
                  >
                    {fetchingSpec ? "Loading..." : "Load Lab Spec"}
                  </button>
                  {/^https?:\/\//i.test(openapiText.trim()) && (
                    <button
                      type="button"
                      className="btn btn-primary text-[11px] py-1 px-2.5"
                      disabled={fetchingSpec}
                      onClick={handleFetchUrl}
                      title="Fetch OpenAPI specification from URL"
                    >
                      {fetchingSpec ? "Fetching..." : "Fetch Spec"}
                    </button>
                  )}
                  {openapiText && (
                    <button
                      type="button"
                      className="text-[11px] text-info hover:text-white"
                      onClick={() => update((prev) => ({ ...prev, openapiText: "", openapiName: "" }))}
                    >
                      Clear specification
                    </button>
                  )}
                </div>
                <textarea
                  id="openapiDocument"
                  className="field-input font-mono text-xs py-1"
                  rows={1}
                  value={openapiText}
                  onChange={(event) => update((prev) => ({ ...prev, openapiText: event.target.value }))}
                  placeholder='Paste OpenAPI JSON: {"openapi": "3.0.3", "paths": {...}}'
                  spellCheck={false}
                />
              </div>

              {/* Endpoint List */}
              <div className="border-t border-line-soft pt-2">
                <div className="flex items-center justify-between mb-1">
                  <label className="field-label mb-0 text-xs" htmlFor="endpoints">
                    Endpoint List{" "}
                    {!openapiText.trim() && (
                      <span className="text-accent-strong font-normal">(needed if no spec)</span>
                    )}
                  </label>
                </div>
                <textarea
                  id="endpoints"
                  className="field-input font-mono text-xs py-1"
                  rows={1}
                  value={endpointsText}
                  onChange={(event) => update((prev) => ({ ...prev, endpointsText: event.target.value }))}
                  placeholder='["/api/items", {"path": "/api/profile", "method": "GET"}]'
                  spellCheck={false}
                />
                {!openapiText.trim() && !endpointsText.trim() && (
                  <p className="mt-1 text-[10px] text-medium">
                    ⚠️ Provide an OpenAPI document or enter endpoints above so the toolkit knows what to assess.
                  </p>
                )}
              </div>
            </div>
          </StepCard>
        </div>

        {/* ── Right Column: Authentication & Security Tests ── */}
        <div className="space-y-3">
          {/* Card 3: Authentication */}
          <StepCard
            step="3"
            title="Authentication Scheme"
            description="Used for this assessment only. Never stored in browser storage, logs, or reports."
          >
            {/* Scheme pills */}
            <div className="flex flex-wrap gap-1.5 mb-2.5">
              {PRIMARY_SCHEMES.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => chooseScheme(option.value)}
                  className={`scheme-pill text-xs py-0.5 px-2.5 ${authScheme === option.value ? "scheme-pill-active" : ""}`}
                >
                  {option.label}
                </button>
              ))}
            </div>

            {authScheme === "none" ? (
              <p className="text-xs leading-relaxed text-info border border-line rounded-lg px-3 py-2 bg-surface/30">
                Anonymous mode: no credentials sent. Authentication checks will report as skipped with a clear reason.
              </p>
            ) : (
              <div className="space-y-2">
                {(authScheme === "api_key" || authScheme === "header") && (
                  <Field
                    label="Header name"
                    hint="HTTP header name for API key"
                    htmlFor="primaryHeader"
                  >
                    <input
                      id="primaryHeader"
                      className="field-input font-mono text-xs py-1"
                      value={primaryHeader}
                      onChange={(event) => update((prev) => ({ ...prev, primaryHeader: event.target.value }))}
                      spellCheck={false}
                      autoComplete="off"
                      placeholder={authScheme === "api_key" ? "X-API-Key" : "X-Auth"}
                    />
                  </Field>
                )}
                {authScheme === "basic" && (
                  <Field label="Username" htmlFor="primaryUsername">
                    <input
                      id="primaryUsername"
                      className="field-input font-mono text-xs py-1"
                      value={primaryUsername}
                      onChange={(event) => update((prev) => ({ ...prev, primaryUsername: event.target.value }))}
                      spellCheck={false}
                      autoComplete="off"
                      placeholder="username"
                    />
                  </Field>
                )}
                <Field
                  label="Primary credential"
                  hint="Cleared on refresh — never stored in browser storage."
                  htmlFor="primary"
                >
                  <input
                    id="primary"
                    aria-label="Primary credential"
                    type="password"
                    className="field-input font-mono text-xs py-1"
                    value={primaryToken}
                    onChange={(event) => update((prev) => ({ ...prev, primaryToken: event.target.value }))}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={authScheme === "basic" ? "password" : "••••••••••••••••"}
                  />
                </Field>
              </div>
            )}
          </StepCard>

          {/* Card 4: Recommended Security Tests */}
          <StepCard
            step="4"
            title="Security Tests"
            description={
              mode === "custom"
                ? `Custom selection: ${selected.length} of ${totalTests} checks`
                : "Recommended tests adapted to your inputs"
            }
          >
            {catalogueError ? (
              <p className="text-xs text-critical">{catalogueError}</p>
            ) : (
              <div className="space-y-2">
                {/* Mode selector tiles */}
                <div className="grid grid-cols-2 gap-2">
                  {[
                    {
                      value: "recommended",
                      label: "Recommended",
                      desc: `${recommendedKeys.length} checks enabled`,
                      onSelect: resetToRecommended,
                    },
                    {
                      value: "custom",
                      label: "Customize",
                      desc: "Select checks individually",
                      onSelect: chooseIndividual,
                    },
                  ].map((tile) => (
                    <label
                      key={tile.value}
                      className={[
                        "flex cursor-pointer items-start gap-1.5 rounded-lg border p-2 transition-all text-left",
                        mode === tile.value
                          ? "border-accent-strong/50 bg-accent-dim"
                          : "border-line bg-raised/20 hover:border-line/70",
                      ].join(" ")}
                    >
                      <input
                        type="radio"
                        name="testMode"
                        className="mt-0.5 h-3.5 w-3.5 accent-[#3bbfb5]"
                        checked={mode === tile.value}
                        onChange={tile.onSelect}
                      />
                      <span className="min-w-0">
                        <span className="block text-xs font-semibold text-white">{tile.label}</span>
                        <span className="mt-0.5 block text-[10px] text-info leading-tight">{tile.desc}</span>
                      </span>
                    </label>
                  ))}
                </div>

                {/* Recommended tests summary */}
                {mode === "recommended" && (
                  <div className="rounded-lg border border-line bg-surface/20 px-3 py-1.5">
                    <div className="flex items-center justify-between text-[11px] text-info">
                      <span className="font-semibold uppercase tracking-wider">Active checks</span>
                      <span className="text-accent-strong font-medium">{recommendedKeys.length} of {totalTests} active</span>
                    </div>
                    <p className="mt-0.5 text-[11px] text-slate-300 leading-snug">
                      Endpoint & parameter discovery, HTTP method analysis, security headers, CORS & rate limit included. Authenticated checks activate when credentials are provided.
                    </p>
                  </div>
                )}
              </div>
            )}
          </StepCard>
        </div>
      </div>

      {/* ── Advanced Options (Collapsed by Default) ── */}
      <section className="card overflow-hidden">
        <button
          type="button"
          className="collapsible-header py-2.5 px-3.5 sm:px-4"
          aria-expanded={advancedOpen}
          aria-controls="advanced-options"
          onClick={() => update((prev) => ({ ...prev, advancedOpen: !prev.advancedOpen }))}
        >
          <div className="min-w-0 flex-1 text-left">
            <span className="text-xs font-semibold text-white">Advanced options</span>
            <span className="mt-0.5 block text-[11px] text-info truncate pr-4">
              Multi-user BOLA case, rate-limit settings, second credentials, and offline JWT inspection
            </span>
          </div>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            className={`text-info flex-shrink-0 transition-transform duration-200 ${advancedOpen ? "rotate-180" : ""}`}
          >
            <path d="m6 9 6 6 6-6" />
          </svg>
        </button>

        {advancedOpen && (
          <div id="advanced-options" className="border-t border-line px-3.5 sm:px-4 py-3.5 space-y-4">

            {/* Individual test selection */}
            <AdvancedGroup
              id="advanced-test-selection"
              title="Individual test selection"
              description="Select exactly which checks to execute. Target applicability is determined by capability detection."
            >
              <div className="mb-2 flex items-center justify-between gap-2">
                <span className="text-xs text-info">
                  {mode === "custom"
                    ? `Custom selection: ${selected.length} of ${totalTests} checks`
                    : `Recommended: ${selected.length} of ${totalTests} checks`}
                </span>
                {mode === "custom" && (
                  <button type="button" className="btn btn-ghost text-xs py-0.5 px-2" onClick={resetToRecommended}>
                    Use recommended
                  </button>
                )}
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {catalogue.map((test) => (
                  <label
                    key={test.key}
                    className={[
                      "flex cursor-pointer items-start gap-2 rounded-lg border p-2 transition-colors",
                      selected.includes(test.key)
                        ? "border-accent-strong/40 bg-accent-dim"
                        : "border-line bg-transparent hover:border-line/80",
                    ].join(" ")}
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5 h-3.5 w-3.5 accent-[#3bbfb5]"
                      checked={selected.includes(test.key)}
                      onChange={() => toggleTest(test.key)}
                    />
                    <span className="min-w-0">
                      <span className="flex items-center gap-1.5 text-xs font-medium text-white">
                        {test.label}
                        <span
                          className={`rounded-full border px-1.5 py-0.2 text-[9px] font-semibold uppercase tracking-wide ${
                            test.requests
                              ? "border-medium/40 bg-medium/10 text-medium"
                              : "border-line bg-raised text-info"
                          }`}
                        >
                          {test.requests ? "Live" : "Offline"}
                        </span>
                      </span>
                      <span className="mt-0.5 block text-[10px] leading-relaxed text-info">
                        {test.description}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            </AdvancedGroup>

            {/* Second credential for BOLA */}
            <AdvancedGroup
              title="Second credential"
              description="A second verified identity required for Authorization / BOLA cross-user testing. Never stored."
            >
              <CredentialField
                id="secondary"
                label="Second credential"
                hint="Must belong to a different authorized user on the same target."
                value={secondaryToken}
                onChange={(value) => update((prev) => ({ ...prev, secondaryToken: value }))}
                auth={secondaryAuth}
                onAuthChange={(auth) => update((prev) => ({ ...prev, secondaryAuth: auth }))}
              />
            </AdvancedGroup>

            {/* BOLA case */}
            <AdvancedGroup
              title="Authorization / BOLA case configuration"
              description="Specify one explicit object path and identity endpoint. The toolkit never guesses or enumerates object IDs."
            >
              <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
                {[
                  { label: "Object path", key: "path", placeholder: "/api/resource/1" },
                  { label: "Identity path", key: "identity_path", placeholder: "/api/me", hint: "Returns caller subject" },
                  { label: "Expected object ID", key: "expected_object_id", placeholder: "e.g. 101 or obj_1" },
                  { label: "Owner subject", key: "owner_subject", placeholder: "e.g. user_primary" },
                  { label: "Other subject", key: "other_subject", placeholder: "e.g. user_secondary" },
                ].map(({ label, key, placeholder, hint }) => (
                  <Field key={key} label={label} hint={hint}>
                    <input
                      className="field-input font-mono text-xs py-1"
                      value={bola[key]}
                      onChange={(event) =>
                        update((prev) => ({
                          ...prev,
                          bola: { ...prev.bola, [key]: event.target.value },
                        }))
                      }
                      spellCheck={false}
                      placeholder={placeholder}
                    />
                  </Field>
                ))}
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: "ID field", key: "id_field", placeholder: "id" },
                    { label: "Owner field", key: "owner_field", placeholder: "owner" },
                  ].map(({ label, key, placeholder }) => (
                    <Field key={key} label={label}>
                      <input
                        className="field-input font-mono text-xs py-1"
                        value={bola[key]}
                        onChange={(event) =>
                          update((prev) => ({ ...prev, bola: { ...prev.bola, [key]: event.target.value } }))
                        }
                        placeholder={placeholder}
                        spellCheck={false}
                      />
                    </Field>
                  ))}
                </div>
              </div>
            </AdvancedGroup>

            {/* Rate limit sample */}
            <AdvancedGroup
              title="Rate limit sample settings"
              description="A small bounded sample on one endpoint. Halts immediately on 429, 5xx, or error."
            >
              <div className="grid gap-2.5 sm:grid-cols-3">
                <Field label="Path" hint="Must start with /">
                  <input
                    className="field-input font-mono text-xs py-1"
                    value={rateLimit.path}
                    onChange={(event) =>
                      update((prev) => ({ ...prev, rateLimit: { ...prev.rateLimit, path: event.target.value } }))
                    }
                    spellCheck={false}
                    placeholder="/api/resource"
                  />
                </Field>
                <Field label="Requests count (1–10)">
                  <input
                    type="number"
                    min="1"
                    max="10"
                    className="field-input text-xs py-1"
                    value={rateLimit.count}
                    onChange={(event) =>
                      update((prev) => ({ ...prev, rateLimit: { ...prev.rateLimit, count: event.target.value } }))
                    }
                  />
                </Field>
                <Field label="Pacing delay (0.2–10s)">
                  <input
                    type="number"
                    min="0.2"
                    max="10"
                    step="0.1"
                    className="field-input text-xs py-1"
                    value={rateLimit.delay}
                    onChange={(event) =>
                      update((prev) => ({ ...prev, rateLimit: { ...prev.rateLimit, delay: event.target.value } }))
                    }
                  />
                </Field>
              </div>
            </AdvancedGroup>

            {/* JWT inspection */}
            <AdvancedGroup
              title="JWT inspection"
              description="Offline inspection of token metadata and claims. Signature is never verified; claims are untrusted."
            >
              <Field label="JWT token" hint="No network request is sent for this test. Cleared on refresh." htmlFor="jwtToken">
                <input
                  id="jwtToken"
                  type="password"
                  className="field-input font-mono text-xs py-1"
                  value={jwtToken}
                  onChange={(event) => update((prev) => ({ ...prev, jwtToken: event.target.value }))}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="eyJhbGciOi..."
                />
              </Field>
            </AdvancedGroup>

          </div>
        )}
      </section>

      {/* ── Start Card ── */}
      <div className="card p-3.5 sm:p-4">
        {error && (
          <div className="mb-2.5 flex items-start gap-2 rounded-lg border border-critical/30 bg-critical/8 px-3 py-2">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="text-critical mt-0.5 flex-shrink-0">
              <circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" />
            </svg>
            <p className="text-xs text-critical leading-snug">{error}</p>
          </div>
        )}

        {problems.length > 0 ? (
          <div className="mb-2.5 rounded-lg border border-medium/30 bg-medium/5 px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-medium mb-1">
              Requirements before starting
            </p>
            <ul className="space-y-0.5">
              {problems.map((problem) => (
                <li key={problem} className="flex items-start gap-1.5 text-xs text-medium/90 leading-tight">
                  <span className="mt-1 h-1 w-1 rounded-full bg-medium flex-shrink-0" aria-hidden="true" />
                  <span>{problem}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="mb-2.5 flex items-center gap-2 rounded-lg border border-ok/30 bg-ok/5 px-3 py-2">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" className="text-ok flex-shrink-0">
              <path d="M20 6 9 17l-5-5" />
            </svg>
            <p className="text-xs text-ok font-medium">
              Ready — {selected.length} {mode === "custom" ? "custom" : "recommended"} test{selected.length !== 1 ? "s" : ""} selected
            </p>
          </div>
        )}

        {/* Authorization acknowledgement */}
        <label className="mb-3 flex items-start gap-2 rounded-lg border border-accent/25 bg-accent-dim px-3 py-2.5 cursor-pointer">
          <input
            id="acknowledge"
            type="checkbox"
            className="mt-0.5 h-3.5 w-3.5 accent-[#3bbfb5] flex-shrink-0"
            checked={acknowledged}
            onChange={(event) => update((prev) => ({ ...prev, acknowledged: event.target.checked }))}
          />
          <span className="text-[11px] leading-snug text-slate-200">
            <span className="font-semibold text-white">Authorization confirmed:</span>{" "}
            I confirm that I own or have explicit authorization to assess this target and understand tests are non-destructive.
          </span>
        </label>

        {/* Actions row */}
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <button type="button" className="btn btn-ghost text-xs py-1 px-2.5" onClick={() => resetToClean()}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
              <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
              <path d="M3 3v5h5" />
            </svg>
            Reset form
          </button>

          <div className="flex items-center gap-2.5">
            <span className="text-[11px] text-info hidden sm:block">
              {selected.length} of {totalTests} checks · {mode === "custom" ? "custom" : "recommended"}
            </span>
            <button
              type="submit"
              className="btn btn-primary px-4 py-1.5 text-xs font-semibold"
              disabled={problems.length > 0 || submitting}
            >
              {submitting ? (
                <>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" className="animate-spin">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                  </svg>
                  Starting…
                </>
              ) : (
                <>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                  Start assessment
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </form>
  );
}
