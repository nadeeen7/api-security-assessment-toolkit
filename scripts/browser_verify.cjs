/* Optional browser regression check. Requires Playwright + Chromium.
   All requests use the local lab; no mocks.

   Point it at either front end with UI_BASE_URL (or the first argument):
     - Vite development:  http://127.0.0.1:5173  (default; proxies /api)
     - Flask single-origin: http://127.0.0.1:5055  (serves the built webui/dist)
   The lab API for logins is always http://127.0.0.1:5000. */
let playwright;
try {
  playwright = require("playwright");
} catch {
  playwright = require(
    require.resolve("playwright", {
      paths: [require("node:path").resolve("webui")],
    }),
  );
}
const { chromium } = playwright;
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_EXECUTABLE || undefined,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => {
    errors.push(error.message);
    console.error("Browser error:", error.message);
  });
  const origin = (
    process.env.UI_BASE_URL ||
    process.argv[2] ||
    "http://127.0.0.1:5173"
  ).replace(/\/+$/, "");
  console.log("Verifying UI origin:", origin);
  const artifactDir = path.resolve("output/browser-verification");
  fs.mkdirSync(artifactDir, { recursive: true });
  const checks = [];
  // Count rows within a scope, so an extra table (e.g. the test-coverage
  // table on the Results page) does not break the endpoint/finding counts.
  const assertRows = async (expected, scope = page) => {
    const rows = scope.locator("tbody tr");
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      if ((await rows.count()) === expected) return;
      await page.waitForTimeout(100);
    }
    assert.equal(await rows.count(), expected);
  };
  const screenshot = async (name) => {
    await page.screenshot({
      path: path.join(artifactDir, name + ".png"),
      fullPage: true,
    });
    checks.push(name);
  };
  try {
    const tokens = {};
    for (const user of ["alice", "bob"]) {
      const response = await context.request.post(
        "http://127.0.0.1:5000/api/login",
        { data: { username: user, password: `${user}-lab-only` } },
      );
      assert.equal(response.status(), 200);
      tokens[user] = (await response.json()).token;
    }
    // API-error / disconnection branch: block the catalogue request and confirm
    // the UI surfaces a clear offline message instead of failing silently.
    await page.route("**/api/tests", (route) => route.abort());
    await page.goto(origin);
    await page
      .getByText(/Could not reach the local assessment API/i)
      .first()
      .waitFor({ timeout: 15000 });
    await page.unroute("**/api/tests");

    await page.goto(origin);
    // Simplified Assessment page: the default view must fit one desktop screen
    // and Advanced options must start collapsed.
    const advancedPanel = page.locator("#advanced-options");
    assert.equal(await advancedPanel.count(), 0);
    const defaultHeight = await page.evaluate(
      () => document.documentElement.scrollHeight,
    );
    const viewportHeight = await page.evaluate(() => window.innerHeight);
    assert(
      defaultHeight <= viewportHeight,
      `default Assessment view is ${defaultHeight}px, viewport is ${viewportHeight}px`,
    );
    const targetInput = page.locator("#target");
    if (!(await targetInput.inputValue())) {
      await targetInput.fill("http://127.0.0.1:5000");
    }
    await page
      .getByLabel("Primary credential", { exact: true })
      .fill(tokens.alice);
    await page
      .locator("#openapiDocument")
      .fill(fs.readFileSync("input/openapi.json", "utf8"));
    await page.locator("#acknowledge").check();
    await screenshot("assessment");
    // Every advanced control is still there, one disclosure away.
    await page.getByRole("button", { name: "Advanced options" }).click();
    await advancedPanel.waitFor();
    await page
      .getByLabel("Second credential", { exact: true })
      .fill(tokens.bob);
    await page.locator("#jwtToken").fill(tokens.alice);
    await screenshot("assessment-advanced");
    await page
      .getByRole("button", { name: "Start assessment", exact: true })
      .click();
    await page.waitForURL(/\/assessment\/[a-f0-9]{32}$/);
    const jobId = page.url().split("/").at(-1);
    await page.getByRole("heading", { name: "Selected tests" }).waitFor();
    await screenshot("progress");
    await page
      .getByRole("link", { name: "Results dashboard", exact: true })
      .waitFor({ timeout: 60000 });
    const response = await context.request.get(
      `${origin}/api/assessment/${jobId}/evidence.json`,
    );
    assert.equal(response.status(), 200);
    const evidence = await response.json();
    assert(evidence.findings.length > 0);
    assert(evidence.coverage.requests_sent > 0);
    await page
      .getByRole("link", { name: "Results dashboard", exact: true })
      .click();
    await page.getByRole("heading", { name: "Endpoint summary" }).waitFor();
    const endpointSection = page.locator("section", {
      has: page.getByRole("heading", { name: "Endpoint summary" }),
    });
    await assertRows(evidence.endpoints.length, endpointSection);
    for (const [severity, count] of Object.entries(evidence.severity_summary)) {
      const card = page
        .getByRole("region", { name: "Severity summary" })
        .locator("div")
        .filter({
          has: page.getByRole("heading", { name: severity, exact: true }),
        });
      assert.equal((await card.locator("p").innerText()).trim(), String(count));
    }
    await screenshot("results");
    await page.getByRole("link", { name: "Findings", exact: true }).click();
    await page
      .getByRole("heading", { name: "Findings", exact: true })
      .waitFor();
    await page.locator("tbody tr").first().waitFor();
    await assertRows(evidence.findings.length);
    for (const key of ["category", "endpoint", "confidence"]) {
      const value = evidence.findings.find((f) => f[key])[key];
      await page.getByLabel(key, { exact: true }).selectOption(value);
      await assertRows(
        evidence.findings.filter((f) => f[key] === value).length,
      );
      await page.getByRole("button", { name: "Clear filters" }).click();
      await assertRows(evidence.findings.length);
    }
    await page.getByLabel("severity", { exact: true }).selectOption("High");
    const high = evidence.findings.filter((f) => f.severity === "High");
    await assertRows(high.length);
    assert(high.length > 0);
    const index = evidence.findings.findIndex((f) => f.severity === "High");
    await page.getByRole("link", { name: high[0].title, exact: true }).click();
    await page.getByRole("dialog").waitFor();
    assert(page.url().includes(`/findings/${index}?`));
    assert(
      (await page.getByRole("dialog").innerText()).includes(
        high[0].recommendation,
      ),
    );
    assert(
      (await page.getByRole("dialog").innerText()).includes(
        high[0].severity_reason,
      ),
    );
    await screenshot("finding-detail");
    await page.keyboard.press("Escape");
    await page.getByRole("dialog").waitFor({ state: "detached" });
    await assertRows(high.length);
    await page.getByRole("button", { name: "Clear filters" }).click();
    await assertRows(evidence.findings.length);
    await page.getByLabel("severity", { exact: true }).selectOption("High");
    await page
      .getByLabel("category", { exact: true })
      .selectOption("Security headers");
    await page
      .getByText("No findings match these filters.", { exact: true })
      .waitFor();
    await assertRows(0);
    await page.getByRole("button", { name: "Clear filters" }).click();
    await assertRows(evidence.findings.length);
    await screenshot("findings");
    // Reload deep link directly; index refers to the unfiltered engine array.
    await page.goto(`${origin}/assessment/${jobId}/findings/${index}`);
    await page.getByRole("dialog").waitFor();
    await page.getByRole("button", { name: "Close finding" }).click();
    await page.getByRole("link", { name: "Reports", exact: true }).click();
    await page
      .getByRole("heading", { name: "HTML report", exact: true })
      .waitFor();
    await screenshot("reports");
    const popupPromise = page.waitForEvent("popup");
    await page.getByRole("link", { name: "Open HTML", exact: true }).click();
    const popup = await popupPromise;
    await popup.waitForLoadState();
    assert(
      (await popup.locator("body").innerText()).includes(
        evidence.findings[0].title,
      ),
    );
    await popup.close();
    for (const file of ["report.html", "report.md", "evidence.json"]) {
      const downloadPromise = page.waitForEvent("download");
      await page
        .getByRole("link", { name: `Download ${file}`, exact: true })
        .click();
      const download = await downloadPromise;
      assert.equal(download.suggestedFilename(), file);
      assert.equal(await download.failure(), null);
      const bytes = fs.readFileSync(await download.path(), "utf8");
      assert(bytes.length > 100);
      assert(!bytes.includes(tokens.alice) && !bytes.includes(tokens.bob));
      if (file === "evidence.json")
        assert.deepEqual(JSON.parse(bytes), evidence);
    }
    await page.getByRole("link", { name: "History", exact: true }).click();
    await page.getByRole("heading", { name: "Assessment history" }).waitFor();
    await page.locator("tbody tr").filter({ hasText: jobId }).waitFor();
    await screenshot("history");
    await page
      .locator("tbody tr")
      .filter({ hasText: jobId })
      .getByRole("link", { name: "View results" })
      .click();
    await page.getByRole("heading", { name: "Endpoint summary" }).waitFor();
    await page.setViewportSize({ width: 390, height: 844 });
    await screenshot("results-mobile");
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await page.goto(`${origin}/assessment/${jobId}/findings`);
    await page
      .getByRole("heading", { name: "Findings", exact: true })
      .waitFor();
    await page.locator("tbody tr").first().waitFor();
    await screenshot("findings-mobile");
    assert(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await page.goto(`${origin}/assessment/${jobId}/findings/999999`);
    await page
      .getByRole("alert")
      .filter({ hasText: "Finding not found" })
      .waitFor();
    await page.goto(`${origin}/assessment/${"0".repeat(32)}/results`);
    await page
      .getByRole("heading", { name: "Assessment unavailable" })
      .waitFor();
    // Unknown API routes must stay JSON, never the SPA shell.
    const missingApi = await context.request.get(`${origin}/api/does-not-exist`);
    assert.equal(missingApi.status(), 404);
    assert.match(missingApi.headers()["content-type"] || "", /application\/json/);
    const missingBody = await missingApi.text();
    assert(!missingBody.includes('<div id="root">'));
    assert(JSON.parse(missingBody).error);
    // Direct deep-link load and browser reload of a saved assessment must work.
    await page.goto(`${origin}/assessment/${jobId}/results`);
    await page.getByRole("heading", { name: "Endpoint summary" }).waitFor();
    await page.reload();
    await page.getByRole("heading", { name: "Endpoint summary" }).waitFor();
    await page.goto(`${origin}/history`);
    await page.getByRole("heading", { name: "Assessment history" }).waitFor();
    await page.reload();
    await page
      .locator("tbody tr")
      .filter({ hasText: jobId })
      .waitFor();
    // Phase E: the per-run session token is issued and the SPA shell is hardened.
    const session = await context.request.get(`${origin}/api/session`);
    assert.equal(session.status(), 200);
    const sessionBody = await session.json();
    assert(sessionBody.token && sessionBody.header === "X-Session-Token");
    const shell = await context.request.get(`${origin}/`);
    const csp = shell.headers()["content-security-policy"] || "";
    if (!origin.includes(":5173")) {
      // Vite's own dev server sets no CSP; Flask-served builds must.
      assert.match(csp, /script-src 'self'/);
      assert.match(csp, /frame-ancestors 'none'/);
    }
    // A state-changing call without the token is refused, not executed.
    const noToken = await context.request.post(`${origin}/api/assessment/start`, { data: {} });
    assert.equal(noToken.status(), 403);
    assert.deepEqual(errors, []);
    const result = {
      verified_at: new Date().toISOString(),
      job_id: jobId,
      default_assessment_height_px: defaultHeight,
      viewport_height_px: viewportHeight,
      checks,
      downloads: ["report.html", "report.md", "evidence.json"],
      severity_summary: evidence.severity_summary,
      endpoints: evidence.endpoints.length,
      findings: evidence.findings.length,
      requests: evidence.coverage.requests_sent,
      browser_errors: errors,
      additional_checks: [
        "all four finding filters",
        "empty filter result",
        "stable filtered finding index",
        "Escape closes drawer",
        "direct detail reload",
        "invalid finding",
        "unknown job",
        "mobile overflow",
        "download redaction",
        "unknown /api route stays JSON 404",
        "deep-link load and reload of saved results",
        "deep-link load and reload of history",
        "per-run session token issued",
        "SPA shell CSP present on Flask origin",
        "state-changing request without token is 403",
        "API error/disconnection branch shows an offline message",
        "default Assessment view fits one desktop screen",
        "Advanced options collapsed by default and still complete",
      ],
    };
    fs.writeFileSync(
      path.join(artifactDir, "verification.json"),
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    await page.screenshot({
      path: path.join(artifactDir, "failure.png"),
      fullPage: true,
    });
    console.error(await page.locator("body").innerText());
    throw error;
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
