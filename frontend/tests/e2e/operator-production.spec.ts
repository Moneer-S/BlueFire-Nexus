import { promises as fs } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import process from "node:process";
import { URL } from "node:url";
import { expect, test, type Download, type Locator, type Page } from "@playwright/test";

const CAPABILITY_FRAGMENT = /^#bluefire-session=[A-Za-z0-9_-]{64}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1"]);
const RUN_ID = /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/;
const PROFILE_ID = "gate08.operator.profile.v1";
const RUNNER_ID = "gate08.operator.runner.v1";
const DETECTION_TITLE = "Gate 08 operator hypothesis";
const SCREENSHOTS = ["operator-builder.png", "operator-run-review.png", "operator-compare.png"] as const;
const OPERATION_SEQUENCE = [
  "bootstrap_production_session",
  "export_scenario",
  "create_scenario_draft",
  "import_scenario",
  "edit_graph_and_history",
  "resize_collapse_and_focus_panels",
  "validate_and_version_scenario",
  "persist_strict_settings",
  "exercise_ai_modes_and_provider",
  "manage_runner_profile",
  "manage_runner_record",
  "review_action_package_controls",
  "review_source_and_detection_surfaces",
  "review_execute_approval_boundary",
  "run_production_preflight",
  "submit_and_observe_simulate_job",
  "review_canonical_run",
  "create_production_replay",
  "compare_material_run_delta",
] as const;

type JsonObject = Record<string, unknown>;

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Gate08 browser test is missing ${name}.`);
  return value;
}

function validatedLaunchUrl(): URL {
  let parsed: URL;
  try {
    parsed = new URL(requiredEnvironment("BLUEFIRE_PRODUCTION_URL"));
  } catch {
    throw new Error("Gate08 production launch URL is invalid.");
  }
  if (
    parsed.protocol !== "http:"
    || !LOOPBACK_HOSTS.has(parsed.hostname)
    || parsed.username
    || parsed.password
    || parsed.search
    || !["/", "/index.html"].includes(parsed.pathname)
    || !CAPABILITY_FRAGMENT.test(parsed.hash)
  ) {
    throw new Error("Gate08 production URL is not a constrained loopback capability URL.");
  }
  return parsed;
}

async function validatedNewReportPath(): Promise<string> {
  const value = requiredEnvironment("BLUEFIRE_BROWSER_REPORT_PATH");
  if (!isAbsolute(value) || !value.toLowerCase().endsWith(".json")) {
    throw new Error("Gate08 report path must be an absolute JSON path.");
  }
  await expect(fs.access(value).then(() => true, () => false)).resolves.toBe(false);
  return value;
}

async function validatedScreenshotDirectory(): Promise<string> {
  const value = requiredEnvironment("BLUEFIRE_BROWSER_SCREENSHOT_DIR");
  if (!isAbsolute(value) || await fs.realpath(value) !== resolve(value)) {
    throw new Error("Gate08 screenshot directory must be an existing non-aliased absolute directory.");
  }
  const details = await fs.lstat(value);
  if (!details.isDirectory() || details.isSymbolicLink()) {
    throw new Error("Gate08 screenshot directory is unsafe.");
  }
  for (const name of SCREENSHOTS) {
    if (await fs.access(join(value, name)).then(() => true, () => false)) {
      throw new Error("Gate08 screenshot output already exists.");
    }
  }
  return value;
}

async function writeExclusiveReport(path: string, report: JsonObject): Promise<void> {
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
  try {
    handle = await fs.open(path, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`, "utf8");
    await handle.sync();
  } catch {
    await handle?.close();
    handle = undefined;
    throw new Error("Gate08 browser report could not be created exclusively.");
  } finally {
    await handle?.close();
  }
}

async function downloadBuffer(download: Download): Promise<Buffer> {
  const stream = await download.createReadStream();
  if (!stream) throw new Error("The scenario export did not expose readable bytes.");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > 1024 * 1024) throw new Error("The scenario export exceeded its browser bound.");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function installFailureMonitors(page: Page): { assertClean: () => void } {
  const failures: string[] = [];
  const sessionAborts = { GET: 0, POST: 0 };
  page.on("console", (message) => {
    if (message.type() === "error") failures.push(`console_error:${message.text().slice(0, 400)}`);
  });
  page.on("pageerror", () => failures.push("page_error"));
  page.on("requestfailed", (request) => {
    const path = new URL(request.url()).pathname;
    const method = request.method() as "GET" | "POST";
    const error = request.failure()?.errorText ?? "unknown";
    if (
      (method === "GET" || method === "POST")
      && path === "/api/v1/session"
      && request.resourceType() === "fetch"
      && error === "net::ERR_ABORTED"
    ) {
      sessionAborts[method] += 1;
      if (sessionAborts[method] > 1) failures.push(`repeated_${method.toLowerCase()}_session_abort`);
      return;
    }
    failures.push(`request_failed:${request.method()}:${path}:${error}`);
  });
  page.on("response", (response) => {
    if (response.status() >= 400) {
      failures.push(`http_error:${response.status()}:${new URL(response.url()).pathname}`);
    }
  });
  return { assertClean: () => expect(failures, "Production UI emitted a browser or network failure.").toEqual([]) };
}

function installRequestCapture(page: Page): Record<string, JsonObject> {
  const bodies: Record<string, JsonObject> = {};
  page.on("request", (request) => {
    if (request.method() !== "POST") return;
    const path = new URL(request.url()).pathname;
    let key: string | undefined;
    if (path === "/api/v1/scenario-versions") key = "scenario_version";
    else if (path === "/api/v1/settings/ui.preferences") key = "settings";
    else if (path === "/api/v1/runs/preflight") key = "preflight";
    else if (path === "/api/v1/runs") key = "run";
    else if (/^\/api\/v1\/runs\/[^/]+\/replays$/.test(path)) key = "replay";
    else if (path === "/api/v1/comparisons") key = "comparison";
    else if (path.includes(`/api/v1/resources/runner-profiles/${PROFILE_ID}`)) key = "profile";
    else if (path.includes(`/api/v1/resources/runners/${RUNNER_ID}`)) key = "runner";
    if (!key) return;
    try {
      const parsed = JSON.parse(request.postData() ?? "null") as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid body");
      bodies[key] = parsed as JsonObject;
    } catch {
      bodies[key] = { capture_error: true };
    }
  });
  return bodies;
}

function keys(value: JsonObject): string[] {
  return Object.keys(value).sort();
}

function runCheckbox(page: Page, runId: string): Locator {
  return page.locator(`.run-select-list code[title="${runId}"]`).locator("xpath=ancestor::label").getByRole("checkbox");
}

test("production operator UI completes authoring, management, run, replay, and compare", async ({ page }) => {
  const launchUrl = validatedLaunchUrl();
  const reportPath = await validatedNewReportPath();
  const screenshotDirectory = await validatedScreenshotDirectory();
  const baselineRunId = requiredEnvironment("BLUEFIRE_BASELINE_RUN_ID");
  expect(baselineRunId).toMatch(RUN_ID);
  const monitoring = installFailureMonitors(page);
  const captured = installRequestCapture(page);
  const completed: string[] = [];

  await page.goto(launchUrl.href, { waitUntil: "domcontentloaded" });
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation).toBeVisible();
  await expect.poll(() => page.url()).not.toContain("bluefire-session=");
  completed.push("bootstrap_production_session");

  await navigation.getByRole("link", { name: "Scenarios" }).click();
  await expect(page.getByRole("heading", { name: "Reusable security experiments" })).toBeVisible();
  await expect(page.locator(".scenario-card").first()).toContainText(/Working copy · saved v\d+/);
  const initialCard = page.locator(".scenario-card").first();
  const exportedTitle = (await initialCard.getByRole("heading", { level: 2 }).innerText()).trim();
  const downloadEvent = page.waitForEvent("download");
  await initialCard.getByRole("button", { name: "Export" }).click();
  const exportedBytes = await downloadBuffer(await downloadEvent);
  const exportedScenario = JSON.parse(exportedBytes.toString("utf8")) as JsonObject;
  expect(exportedScenario.title).toBe(exportedTitle);
  expect(Array.isArray(exportedScenario.steps)).toBe(true);
  expect(Array.isArray(exportedScenario.edges)).toBe(true);
  completed.push("export_scenario");

  await page.getByRole("button", { name: "New scenario" }).click();
  await page.getByLabel("Scenario title").fill("Gate 08 authoring draft");
  await page.getByRole("button", { name: "Create draft" }).click();
  await expect(page.getByRole("heading", { name: "Compose a typed adaptive graph" })).toBeVisible();
  await expect(page.getByText("Start with a registered behavior")).toBeVisible();
  completed.push("create_scenario_draft");

  await navigation.getByRole("link", { name: "Scenarios" }).click();
  await page.getByLabel("Import scenario JSON file").setInputFiles({
    name: "gate08-exported-scenario.json",
    mimeType: "application/json",
    buffer: exportedBytes,
  });
  await expect(page.getByText(`Imported ${exportedTitle} as a local draft.`)).toBeVisible();
  const importedCard = page.locator(".scenario-card").filter({ has: page.getByRole("heading", { name: exportedTitle, level: 2 }) }).first();
  await importedCard.getByRole("button", { name: "Open builder" }).click();
  await expect(page.getByRole("heading", { name: "Compose a typed adaptive graph" })).toBeVisible();
  completed.push("import_scenario");

  const nodes = page.locator(".react-flow__node");
  const initialNodeCount = await nodes.count();
  expect(initialNodeCount).toBeGreaterThan(1);
  await expect.poll(() => page.locator(".react-flow__edge").count()).toBeGreaterThan(0);
  await expect.poll(() => page.locator(".typed-handle").count()).toBeGreaterThan(0);
  const graphEdgeCount = await page.locator(".react-flow__edge").count();
  const typedHandleCount = await page.locator(".typed-handle").count();
  const legend = page.getByLabel("Graph legend");
  for (const label of ["Environment", "Behavior", "Evidence", "Action", "Simulation", "Research", "Success", "Partial", "Blocked", "Failed", "Typed artifact"]) {
    await expect(legend.locator("span").filter({ hasText: new RegExp(`^${label}(?:\\s|$)`) }).first()).toBeVisible();
  }
  for (const heading of ["Action implementation", "Typed inputs", "Parameters", "Outcome routes", "Expected observables"]) {
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
  }
  await page.locator(".palette-list > button").first().click();
  await expect(nodes).toHaveCount(initialNodeCount + 1);
  await page.getByRole("button", { name: "Undo" }).click();
  await expect(nodes).toHaveCount(initialNodeCount);
  await page.getByRole("button", { name: "Redo" }).click();
  await expect(nodes).toHaveCount(initialNodeCount + 1);
  await page.getByRole("button", { name: "Undo" }).click();
  await nodes.first().click();
  await expect(page.getByRole("button", { name: "Duplicate selected node" })).toBeEnabled();
  await page.getByRole("button", { name: "Copy selected node" }).click();
  await expect(page.locator(".compatibility-banner")).toContainText("copied");
  await page.getByRole("button", { name: "Paste node" }).click();
  await expect(nodes).toHaveCount(initialNodeCount + 1);
  await page.getByRole("button", { name: "Undo" }).click();
  await expect(nodes).toHaveCount(initialNodeCount);
  completed.push("edit_graph_and_history");

  const layout = page.locator(".builder-layout");
  const columnsBefore = await layout.evaluate((element) => getComputedStyle(element).gridTemplateColumns);
  await page.getByLabel("Behavior palette width").fill("380");
  await page.getByLabel("Node inspector width").fill("420");
  await expect(page.getByText("380px", { exact: true })).toBeVisible();
  await expect(page.getByText("420px", { exact: true })).toBeVisible();
  const columnsAfter = await layout.evaluate((element) => getComputedStyle(element).gridTemplateColumns);
  expect(columnsAfter).not.toBe(columnsBefore);
  await page.getByRole("button", { name: "Hide behavior palette" }).click();
  await expect(page.locator(".palette-panel")).toBeHidden();
  await page.getByRole("button", { name: "Show behavior palette" }).click();
  await page.getByRole("button", { name: "Hide node inspector" }).click();
  await expect(page.locator(".inspector-panel")).toBeHidden();
  await page.getByRole("button", { name: "Show node inspector" }).click();
  await page.getByRole("button", { name: "Enter graph focus mode" }).click();
  await expect(page.locator(".builder-page")).toHaveClass(/builder-focus/);
  await page.keyboard.press("Control+K");
  await expect(page.getByRole("dialog", { name: "Builder commands" })).toBeVisible();
  await page.keyboard.press("Escape");
  await page.keyboard.press("Escape");
  await expect(page.locator(".builder-page")).not.toHaveClass(/builder-focus/);
  completed.push("resize_collapse_and_focus_panels");

  const versionedTitle = `${exportedTitle} · Gate 08 operator proof`;
  await page.getByLabel("Scenario name").fill(versionedTitle);
  const validationResponsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/scenarios/validate" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Validate", exact: true }).click();
  const validationResponse = await validationResponsePromise;
  const validationEnvelope = await validationResponse.json() as JsonObject;
  expect(validationResponse.ok(), JSON.stringify(validationEnvelope)).toBe(true);
  expect(validationEnvelope.valid).toBe(true);
  await expect(page.locator(".validation-bar")).toContainText("Deterministic validation passed");
  const scenarioVersionResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/scenario-versions" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save version" }).click();
  const scenarioVersionEnvelope = await (await scenarioVersionResponse).json() as JsonObject;
  await expect(page.locator(".compatibility-banner")).toContainText("Durable scenario version");
  await page.screenshot({ path: join(screenshotDirectory, SCREENSHOTS[0]), fullPage: true });
  completed.push("validate_and_version_scenario");

  await navigation.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings", level: 1 })).toBeVisible();
  await page.getByLabel("Effect mode").selectOption("execute");
  await page.getByLabel("Effect mode").selectOption("simulate");
  await page.getByLabel("AI autonomy").selectOption("off");
  await page.getByLabel("AI autonomy").selectOption("assist");
  await page.getByLabel("AI autonomy").selectOption("auto");
  await page.getByRole("button", { name: /^Light/ }).click();
  const settingsResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/settings/ui.preferences" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save settings" }).click();
  expect((await settingsResponse).ok()).toBe(true);
  await expect(page.getByText(/Preferences saved durably/)).toBeVisible();
  const browserPreferences = await page.evaluate(() => JSON.parse(window.localStorage.getItem("bluefire.local.run-config.v1") ?? "null") as unknown);
  expect(browserPreferences).toEqual({ schema_version: "bluefire.ui-preferences.v1", theme: "light", effect_mode: "simulate", autonomy: "auto" });
  completed.push("persist_strict_settings");

  await navigation.getByRole("link", { name: "AI Planner" }).click();
  await expect(page.getByRole("heading", { name: "AI Planner", level: 1 })).toBeVisible();
  for (const name of ["Off", "Assist", "Auto"]) {
    await page.locator(".autonomy-stack > button").filter({ hasText: name }).click();
  }
  const providerId = await page.getByLabel("Provider adapter").inputValue();
  expect(providerId).toBe("deterministic-offline.v1");
  await page.getByLabel("Experiment objective").fill("Compare a bounded evidence collection path and preserve replay lineage.");
  await page.getByRole("button", { name: "Generate registered draft" }).click();
  await expect(page.getByText("Unsaved preview", { exact: true })).toBeVisible();
  await expect(page.getByText("Not saved · not authorized")).toBeVisible();
  completed.push("exercise_ai_modes_and_provider");

  await navigation.getByRole("link", { name: "Runner Profiles" }).click();
  await expect(page.getByRole("heading", { name: "Runner profiles", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "New profile" }).click();
  await page.getByLabel("Profile ID").fill(PROFILE_ID);
  await page.getByLabel("Mode").selectOption("execute");
  const profileResponse = page.waitForResponse((response) => new URL(response.url()).pathname.endsWith(`/resources/runner-profiles/${PROFILE_ID}`) && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save durable draft" }).click();
  expect((await profileResponse).ok()).toBe(true);
  await expect(page.getByText(`${PROFILE_ID} saved as a durable draft.`)).toBeVisible();
  completed.push("manage_runner_profile");

  await navigation.getByRole("link", { name: "Runners", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Runners", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "Register record" }).click();
  await page.getByLabel("Runner record ID").fill(RUNNER_ID);
  await page.getByLabel("Display label").fill("Gate 08 operator runner record");
  await page.getByLabel("Platform").selectOption("windows");
  const runnerResponse = page.waitForResponse((response) => new URL(response.url()).pathname.endsWith(`/resources/runners/${RUNNER_ID}`) && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save runner record" }).click();
  expect((await runnerResponse).ok()).toBe(true);
  await expect(page.getByText(`${RUNNER_ID} saved as a runner record. No process was started and connectivity remains unverified.`)).toBeVisible();
  completed.push("manage_runner_record");

  await navigation.getByRole("link", { name: "Action Packages" }).click();
  await expect(page.getByRole("heading", { name: "Action packages", level: 1 })).toBeVisible();
  await expect(page.getByRole("button", { name: "Enroll publisher key" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Import signed package" })).toBeVisible();
  await expect(page.getByText(/arbitrary host code are never executed/i)).toBeVisible();
  completed.push("review_action_package_controls");

  await navigation.getByRole("link", { name: "Research Sources" }).click();
  await expect(page.getByRole("heading", { name: "Research sources", level: 1 })).toBeVisible();
  await expect(page.getByText(/MITRE ATT&CK/i).first()).toBeVisible();
  await navigation.getByRole("link", { name: "Detection Lab" }).click();
  await expect(page.getByRole("heading", { name: "Detection Lab", level: 1 })).toBeVisible();
  await page.getByLabel("Title", { exact: true }).fill(DETECTION_TITLE);
  await page.getByLabel("Target language").selectOption("internal");
  await page.getByRole("button", { name: "Save strict hypothesis" }).click();
  await expect(page.getByText(/saved as a strict hypothesis\. It has not been parsed or exercised\./)).toBeVisible();
  completed.push("review_source_and_detection_surfaces");

  await navigation.getByRole("link", { name: "Runs" }).click();
  await expect(page.getByRole("heading", { name: "Preflight every path. Observe every decision." })).toBeVisible();
  await page.getByRole("radio", { name: /Execute Approved runner actions/ }).check();
  await page.getByText("Policy, approval & budgets").click();
  await expect(page.getByRole("checkbox", { name: /I reviewed this exact displayed Execute envelope/ })).toBeDisabled();
  await expect(page.getByText("Run preflight first.")).toBeVisible();
  await page.getByRole("radio", { name: /Simulate Synthetic evidence only/ }).check();
  completed.push("review_execute_approval_boundary");

  await expect(page.getByRole("radio", { name: /Auto Policy-valid Simulate choices/ })).toBeChecked();
  await expect(page.getByLabel("Provider")).toHaveValue("deterministic-offline.v1");
  await expect(page.getByLabel("Runner profile")).toHaveValue("sandbox-simulate.v1");
  await page.getByLabel("Target scope").fill("sandbox.workspace");
  await page.getByText("Observation & detection").click();
  await expect(page.getByText("collector.filesystem.sandbox.v1", { exact: true })).toBeVisible();
  const preflightResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/runs/preflight" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Run preflight" }).click();
  const preflightReport = await (await preflightResponse).json() as JsonObject;
  expect(preflightReport.ready).toBe(true);
  await expect(page.getByText("Canonical preflight ready")).toBeVisible();
  await expect(page.getByLabel("Canonical preflight plan")).toContainText("Resolved canonical plan");
  completed.push("run_production_preflight");

  const submissionResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/runs" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Submit Simulate job" }).click();
  const submission = await (await submissionResponse).json() as JsonObject;
  expect(submission.schema_version).toBe("bluefire.run-job-submission.v1");
  const reviewLatest = page.getByRole("tab", { name: "Review latest" });
  await expect(reviewLatest).toBeEnabled({ timeout: 90_000 });
  const runTabs = page.getByRole("tablist", { name: "Run detail views" });
  for (const name of ["Timeline", "Planner", "Policy", "Runner", "Evidence", "Detections"]) {
    await runTabs.getByRole("tab", { name }).click();
  }
  await expect(page.locator(".live-path article").first()).toBeVisible();
  completed.push("submit_and_observe_simulate_job");

  await reviewLatest.click();
  await expect(page.getByRole("heading", { name: "Canonical run review" })).toBeVisible();
  const runMatch = new URL(page.url()).hash.match(/^#\/runs\/(run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16})$/);
  if (!runMatch) throw new Error("Canonical run review URL omitted the run identity.");
  const browserRunId = runMatch[1]!;
  await expect(page.getByRole("heading", { name: "Proposal, policy, and application trail" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provenance-separated records" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Candidate lifecycle" })).toBeVisible();
  await page.screenshot({ path: join(screenshotDirectory, SCREENSHOTS[1]), fullPage: true });
  completed.push("review_canonical_run");

  await navigation.getByRole("link", { name: "Compare" }).click();
  await expect(page.getByRole("heading", { name: "Measure what changed" })).toBeVisible();
  await page.getByLabel("Source run").selectOption(browserRunId);
  await expect(page.getByRole("radio", { name: /Exact Preserve declared inputs/ })).toBeChecked();
  const replayResponse = page.waitForResponse((response) => /^\/api\/v1\/runs\/[^/]+\/replays$/.test(new URL(response.url()).pathname) && response.request().method() === "POST");
  await page.getByRole("button", { name: "Create Simulate replay" }).click();
  const replayRun = await (await replayResponse).json() as JsonObject;
  const replayRunId = replayRun.run_id;
  expect(replayRunId).toMatch(RUN_ID);
  await expect(page.getByText("Replay created")).toBeVisible();
  completed.push("create_production_replay");

  await expect(runCheckbox(page, baselineRunId)).toBeVisible();
  await expect(runCheckbox(page, String(replayRunId))).toBeVisible();
  await runCheckbox(page, baselineRunId).check();
  await runCheckbox(page, String(replayRunId)).check();
  const comparisonResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/comparisons" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Compare selected" }).click();
  const comparison = await (await comparisonResponse).json() as JsonObject;
  const comparisonId = comparison.comparison_id;
  expect(comparisonId).toMatch(/^comparison-[0-9a-f]{20}$/);
  const material = page.locator(".stat").filter({ hasText: "Material deltas" });
  await expect(material).toBeVisible();
  expect(Number(await material.locator("strong").innerText())).toBeGreaterThan(0);
  await expect(page.getByRole("heading", { name: "Side-by-side execution lanes" })).toBeVisible();
  await page.screenshot({ path: join(screenshotDirectory, SCREENSHOTS[2]), fullPage: true });
  completed.push("compare_material_run_delta");

  expect(completed).toEqual(OPERATION_SEQUENCE);
  const canonicalKeys = ["ai_provider_id", "autonomy", "layout", "mode", "runner_profile_id", "scenario", "target_scope"];
  expect(Object.keys(captured).sort()).toEqual(["comparison", "preflight", "profile", "replay", "run", "runner", "scenario_version", "settings"]);
  expect(keys(captured.scenario_version!)).toEqual(["scenario"]);
  expect(keys(captured.settings!)).toEqual(["value"]);
  expect(keys(captured.preflight!)).toEqual(canonicalKeys);
  expect(keys(captured.run!)).toEqual(canonicalKeys);
  for (const request of [captured.preflight!, captured.run!]) {
    expect(request.mode).toBe("simulate");
    expect(request.autonomy).toBe("auto");
    expect(request.ai_provider_id).toBe("deterministic-offline.v1");
    expect(request.runner_profile_id).toBe("sandbox-simulate.v1");
    expect(request.target_scope).toEqual({ scope_refs: ["sandbox.workspace"] });
    expect((request.scenario as JsonObject).title).toBe(versionedTitle);
  }
  expect(captured.settings!.value).toEqual({ schema_version: "bluefire.ui-preferences.v1", theme: "light", effect_mode: "simulate", autonomy: "auto" });
  expect(captured.replay).toEqual({ exact: true });
  expect(captured.comparison).toEqual({ run_ids: [baselineRunId, replayRunId] });
  expect(keys(captured.profile!)).toEqual(["document", "status"]);
  expect((captured.profile!.document as JsonObject).secrets).toBeUndefined();
  expect(captured.profile!.status).toBe("draft");
  expect(keys(captured.runner!)).toEqual(["document", "status"]);
  monitoring.assertClean();

  await writeExclusiveReport(reportPath, {
    schema_version: "bluefire.operator-production-browser.v1",
    production_browser_interaction: true,
    demo_mode: false,
    origin: launchUrl.origin,
    operation_sequence: completed,
    scenario_authoring: {
      exported: true,
      created_draft: true,
      imported: true,
      validated: true,
      versioned: true,
      scenario_id: exportedScenario.id,
      scenario_title: versionedTitle,
      version: (scenarioVersionEnvelope.scenario as JsonObject).version,
      request_keys: keys(captured.scenario_version!),
    },
    graph_editor: {
      initial_nodes: initialNodeCount,
      graph_edges: graphEdgeCount,
      typed_handles: typedHandleCount,
      layers: ["environment", "behavior", "evidence"],
      branch_outcomes: ["success", "partial", "blocked", "failed"],
      undo_redo_copy_paste: true,
      keyboard_command_palette: true,
      focus_mode: true,
      collapsible_panels: true,
      resizable_panels: true,
      palette_width_px: 380,
      inspector_width_px: 420,
      compatibility_feedback: true,
      parameters_actions_observables_visible: true,
    },
    configuration: {
      effect_modes: ["simulate", "execute"],
      autonomy_levels: ["off", "assist", "auto"],
      provider_id: providerId,
      profile_id: captured.run!.runner_profile_id,
      target_scope: captured.run!.target_scope,
      settings_changed_backend_request: captured.run!.autonomy === "auto" && captured.run!.mode === "simulate",
      strict_preference_fields: keys(captured.settings!.value as JsonObject),
      approval_human_first: true,
      raw_shell_input: false,
    },
    management: {
      runner_profile_id: PROFILE_ID,
      runner_record_id: RUNNER_ID,
      profile_request_keys: keys(captured.profile!),
      runner_request_keys: keys(captured.runner!),
      signed_action_package_controls_visible: true,
      arbitrary_package_code_input: false,
      detection_hypothesis_saved: true,
      detection_hypothesis_title: DETECTION_TITLE,
    },
    live_workflow: {
      run_id: browserRunId,
      baseline_run_id: baselineRunId,
      replay_run_id: replayRunId,
      comparison_id: comparisonId,
      preflight_ready: preflightReport.ready,
      timeline: true,
      planner: true,
      policy: true,
      live_graph: true,
      runner: true,
      evidence: true,
      detections: true,
      ai_proposal_diff: true,
      replay_diff: true,
      source_provenance: true,
    },
    canonical_requests: {
      preflight_keys: keys(captured.preflight!),
      run_keys: keys(captured.run!),
      replay_keys: keys(captured.replay!),
      comparison_keys: keys(captured.comparison!),
      visible_controls_bound: true,
    },
    screenshots: [...SCREENSHOTS],
    observed_at: new Date().toISOString(),
  });
});
