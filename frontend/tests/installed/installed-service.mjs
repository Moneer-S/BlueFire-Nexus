// The copied driver talks only to a real, freshly installed loopback service.
/* global process, URL, document, requestAnimationFrame, sessionStorage, fetch, innerWidth, innerHeight */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL, URLSearchParams } from "node:url";

const [modulePath, output, port] = process.argv.slice(2);
assert.match(port ?? "", /^\d{1,5}$/);
let input = "";
for await (const chunk of process.stdin) {
  input += chunk;
  assert.ok(input.length <= 256);
}
let { capability } = JSON.parse(input);
input = "";
assert.match(capability ?? "", /^[A-Za-z0-9_-]{64}$/);
const { chromium } = await import(pathToFileURL(modulePath).href);
const origin = `http://127.0.0.1:${port}`;
const writes = new Set(["/api/v1/session", "/api/v1/scenario-versions", "/api/v1/scenarios/validate", "/api/v1/assistance/graph-context"]);
const report = { schema_version: "bluefire.installed-browser-journey.v1", real_service: true, mocked_responses: false, native_execution: false, live_model_inference: false, checks: [], screenshots: [], errors: [], blocked_requests: [] };
let browser, context, page, connected = false, stage = "launch", bootstrapSession401 = 0;

async function api(path, body) {
  return page.evaluate(async ({ path, body }) => {
    const session = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!session) throw new Error("Session missing");
    const response = await fetch(`/api/v1${path}`, {
      method: body ? "POST" : "GET", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": session, Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok) throw new Error("Installed API request failed");
    return response.json();
  }, { path, body });
}

async function capture(name) {
  assert.ok(connected, "Never capture connection credentials");
  await page.evaluate(async () => { await document.fonts.ready; await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); });
  const geometry = await page.evaluate(() => ({ width: innerWidth, height: innerHeight, document_width: document.documentElement.clientWidth, scroll_width: document.documentElement.scrollWidth, nodes: document.querySelectorAll(".react-flow__node").length, edges: document.querySelectorAll(".react-flow__edge").length }));
  assert.ok(geometry.scroll_width <= geometry.document_width, "Desktop page overflows horizontally");
  const screenshot = await page.screenshot({ fullPage: false, animations: "disabled", mask: [page.locator('input[type="password"]')] });
  writeFileSync(join(output, `${name}.png`), screenshot, { flag: "wx" });
  report.screenshots.push({ name, sha256: createHash("sha256").update(screenshot).digest("hex"), geometry });
}

try {
  browser = await chromium.launch({ headless: true, args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"] });
  report.browser_version = browser.version();
  context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 } });
  context.setDefaultTimeout(20_000);
  await context.routeWebSocket("**/*", socket => socket.close());
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    let allowed = ["GET", "HEAD"].includes(method) || (method === "POST" && writes.has(url.pathname));
    if (method === "POST" && ["/api/v1/runs/preflight", "/api/v1/runs"].includes(url.pathname)) {
      const body = request.postDataJSON();
      allowed = body.mode === "simulate" && body.autonomy === "off" && body.ai_provider_id === "deterministic-offline.v1" && body.runner_profile_id === "sandbox-simulate.v1";
    }
    if (url.origin !== origin || !allowed) {
      report.blocked_requests.push({ method, path: url.origin === origin ? url.pathname : "non-loopback" });
      await route.abort();
      return;
    }
    // No response substitution: the installed service owns every API result.
    await route.continue();
  });
  page = await context.newPage();
  page.on("response", response => {
    if (!connected && stage === "connect" && response.url() === `${origin}/api/v1/session` && response.request().method() === "GET" && response.status() === 401) bootstrapSession401 += 1;
  });
  page.on("pageerror", () => report.errors.push({ stage, kind: "page-error" }));
  page.on("console", message => {
    if (message.type() !== "error") return;
    if (!connected && stage === "connect" && bootstrapSession401 > 0 && message.location().url === `${origin}/api/v1/session` && /^Failed to load resource: the server responded with a status of 401\b/.test(message.text())) {
      bootstrapSession401 -= 1;
      report.checks.push("expected_unauthenticated_session_probe");
      return;
    }
    report.errors.push({ stage, kind: "console-error" });
  });
  page.on("dialog", async dialog => {
    if (dialog.type() === "confirm" && dialog.message().startsWith("Open this saved version and replace your current unsaved graph?")) await dialog.accept();
    else { report.errors.push({ stage, kind: "unexpected-dialog" }); await dialog.dismiss(); }
  });

  stage = "connect";
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  capability = "";
  await page.waitForFunction(() => sessionStorage.getItem("bluefire.browser-session.v1") !== null);
  connected = true;
  await page.getByRole("link", { name: "Build", exact: true }).waitFor();
  report.checks.push("normal_ephemeral_browser_session");

  stage = "saved-experiment";
  const catalog = await api("/scenarios");
  const source = catalog.scenarios.find(item => item.id === "scenario.endpoint.lab-collection-methods.v1");
  assert.ok(source);
  const title = "Installed browser collection comparison";
  const scenario = { ...source, id: "scenario.installed-browser.collection.v1", title };
  const saved = (await api("/scenario-versions", { scenario })).scenario;
  const savedRoute = `${origin}/#/builder?${new URLSearchParams({ saved_scenario: saved.scenario_id, version: String(saved.version), digest: saved.digest })}`;
  await page.goto(savedRoute);
  await page.getByRole("button", { name: "Open this version for editing", exact: true }).click();
  await page.locator(".react-flow__node").first().waitFor();
  await page.getByLabel("Experiment name", { exact: true }).fill(`${title} reviewed`);
  await page.getByRole("button", { name: "Auto-layout", exact: true }).click();
  await page.getByRole("button", { name: "Undo", exact: true }).click();
  await page.getByRole("button", { name: "Redo", exact: true }).click();
  const saveResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/scenario-versions" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save version", exact: true }).click();
  const updated = (await (await saveResponse).json()).scenario;
  assert.equal(updated.document.title, `${title} reviewed`);
  assert.equal(updated.version, saved.version + 1);
  assert.deepEqual(updated.document.steps, source.steps);
  assert.deepEqual(updated.document.edges, source.edges);
  report.checks.push("saved_graph_rename_layout_undo_redo_without_semantic_change");

  stage = "graph-interaction";
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.getByRole("textbox", { name: "Search palette", exact: true }).fill("collect");
  assert.ok(await page.locator(".palette-list button").count() > 0);
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.locator('.react-flow__node[data-id="stage_collection"]').click();
  const inspector = page.getByRole("button", { name: "Show node inspector", exact: true });
  if (await inspector.isVisible()) await inspector.click();
  await page.locator(".inspector-panel:not([hidden])").waitFor();
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    await page.setViewportSize(viewport);
    await page.getByRole("button", { name: "Fit graph", exact: true }).click();
    await capture(`graph-${viewport.width}x${viewport.height}`);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole("button", { name: "Assistant", exact: true }).click();
  await page.locator("#experiment-assistant").waitFor();
  await capture("graph-assistant");
  await page.getByRole("button", { name: "Close assistant", exact: true }).click();
  report.checks.push("graph_palette_selection_inspector_assistant_entry_without_model_request");

  stage = "simulate-open-review";
  await page.getByRole("link", { name: "Review run", exact: true }).click();
  stage = "simulate-select-mode";
  await page.getByRole("radio", { name: /^Simulate Synthetic evidence only/ }).check();
  stage = "simulate-select-autonomy";
  await page.getByRole("group", { name: "AI autonomy", exact: true }).getByRole("radio", { name: /^Off / }).check();
  stage = "simulate-open-provider-details";
  await page.getByText("AI provider & environment details", { exact: true }).click();
  stage = "simulate-select-provider";
  await page.getByRole("combobox", { name: "Provider", exact: true }).selectOption("deterministic-offline.v1");
  stage = "simulate-select-profile";
  await page.getByRole("combobox", { name: /^Environment profile\b/ }).selectOption("sandbox-simulate.v1");
  stage = "simulate-preflight";
  const preflightResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/runs/preflight" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Run preflight", exact: true }).click();
  assert.equal((await (await preflightResponse).json()).ready, true);
  stage = "simulate-submit";
  await page.getByRole("button", { name: "Submit Simulate job", exact: true }).click();
  stage = "simulate-wait-for-review";
  const review = page.getByRole("button", { name: "Review", exact: true });
  await review.waitFor({ timeout: 90_000 });
  stage = "simulate-open-result";
  await review.click();
  stage = "simulate-verify-result";
  await page.getByRole("heading", { name: `${title} reviewed`, exact: true, level: 1 }).waitFor();
  const runId = new URL(page.url()).hash.match(/^#\/runs\/(run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16})$/)?.[1];
  assert.ok(runId);
  report.simulation_run_id = runId;
  report.checks.push("normal_preflight_and_durable_ai_off_simulation_review");
  stage = "simulate-capture-review";
  await capture("simulation-review");

  stage = "reopen-saved-experiment";
  await page.goto(`${origin}/#/builder?${new URLSearchParams({ saved_scenario: updated.scenario_id, version: String(updated.version), digest: updated.digest })}`);
  await page.getByRole("button", { name: "Open this version for editing", exact: true }).waitFor();
  await page.reload();
  await page.getByRole("button", { name: "Open this version for editing", exact: true }).waitFor();
  const reopened = (await api(`/scenario-versions/${updated.scenario_id}/versions/${updated.version}`)).scenario;
  assert.equal(reopened.digest, updated.digest);
  const original = (await api(`/scenario-versions/${saved.scenario_id}/versions/${saved.version}`)).scenario;
  assert.equal(original.digest, saved.digest);
  report.checks.push("same_tab_reload_saved_reopen_and_prior_version_preserved");
  assert.equal(report.errors.length, 0);
  assert.equal(report.blocked_requests.length, 0);
  report.status = "passed";
} catch {
  report.status = "failed_or_incomplete";
  report.errors.push({ stage, kind: "journey-failed" });
  if (connected) await capture("failure-state").catch(() => {});
  process.exitCode = 1;
} finally {
  capability = "";
  await context?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "context-close" }); process.exitCode = 1; });
  await browser?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "browser-close" }); process.exitCode = 1; });
  if (process.exitCode) report.status = "failed_or_incomplete";
  writeFileSync(join(output, "browser-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}
