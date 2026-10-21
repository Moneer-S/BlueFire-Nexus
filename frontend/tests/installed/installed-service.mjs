// The copied driver talks only to a real, freshly installed loopback service.
/* global process, URL, document, requestAnimationFrame, localStorage, sessionStorage, fetch, innerWidth, innerHeight, getComputedStyle */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
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
const secrets = [capability];
const { chromium } = await import(pathToFileURL(modulePath).href);
const origin = `http://127.0.0.1:${port}`;
const ownedScenarioId = "scenario.installed-browser.collection.v1";
const title = "Installed browser collection comparison";
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const stableValue = value => Array.isArray(value) ? value.map(stableValue)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
    : value;
const sameStructure = (left, right) => JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
const withoutLayout = scenario => {
  if (!scenario || typeof scenario !== "object" || Array.isArray(scenario)) return null;
  const { layout: _layout, ...document } = scenario;
  void _layout;
  return document;
};
const report = { schema_version: "bluefire.installed-browser-journey.v1", real_service: true, mocked_responses: false, native_execution: false, live_model_inference: false, simulation_mode: "synthetic_only", simulation_autonomy: "off", checks: [], screenshots: [], errors: [], blocked_requests: [] };
let browser, context, page, connected = false, stage = "launch", bootstrapSession401 = 0;
let sessionPosts = 0, scenarioVersionPosts = 0, scenarioValidationPosts = 0, graphContextPosts = 0, controlListPosts = 0;
let preflightPosts = 0, simulationRunPosts = 0, comparisonPosts = 0;
let ownedRunIds = [];
let generatedScenario, savedScenarioDocument, reviewedScenarioDocument, ownedScenarioVersion;

function hasOwnedLayout(layout) {
  const nodeIds = reviewedScenarioDocument?.steps?.map(step => step.id);
  if (!Array.isArray(nodeIds) || !exactKeys(layout, ["schema_version", "nodes"]) || layout.schema_version !== "bluefire.layout.v1"
    || !Array.isArray(layout.nodes) || layout.nodes.length > nodeIds.length) return false;
  const expectedIds = new Set(nodeIds);
  const seenIds = new Set();
  return layout.nodes.every(node => {
    if (!exactKeys(node, ["id", "x", "y"]) || !expectedIds.has(node.id) || seenIds.has(node.id)
      || !Number.isFinite(node.x) || Math.abs(node.x) > 100000 || !Number.isFinite(node.y) || Math.abs(node.y) > 100000) return false;
    seenIds.add(node.id);
    return true;
  });
}

function isOwnedScenarioDocument(value) {
  return sameStructure(value, savedScenarioDocument) || sameStructure(value, reviewedScenarioDocument);
}

function hasOwnedScenarioLayout(scenario) {
  if (!scenario || typeof scenario !== "object" || Array.isArray(scenario)) return false;
  if (!Object.hasOwn(scenario ?? {}, "layout")) return true;
  const nodeIds = reviewedScenarioDocument?.steps?.map(step => step.id);
  const layout = scenario.layout;
  if (!Array.isArray(nodeIds) || !layout || typeof layout !== "object" || Array.isArray(layout)) return false;
  const expectedIds = new Set(nodeIds);
  const positionedIds = Object.keys(layout);
  if (positionedIds.length > nodeIds.length || positionedIds.some(id => !expectedIds.has(id))) return false;
  return Object.values(layout).every(position => exactKeys(position, ["x", "y"])
    && Number.isFinite(position.x) && Math.abs(position.x) <= 100000
    && Number.isFinite(position.y) && Math.abs(position.y) <= 100000);
}

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

async function visibleGraphTitles(selectedOnly = false) {
  const selector = selectedOnly ? ".react-flow__node:visible:has(.flow-node.selected)" : ".react-flow__node:visible";
  return page.locator(selector).evaluateAll(nodes => nodes.map(node => {
    const card = node.querySelector(".flow-node");
    const title = card?.querySelector(":scope > strong");
    if (!card || !title) return { title: "", fitsCard: false, fitsWidth: false };
    const cardBox = card.getBoundingClientRect();
    const titleBox = title.getBoundingClientRect();
    return {
      title: title.textContent?.trim() ?? "",
      fitsCard: titleBox.left >= cardBox.left - 1 && titleBox.right <= cardBox.right + 1
        && titleBox.top >= cardBox.top - 1 && titleBox.bottom <= cardBox.bottom + 1,
      fitsWidth: title.scrollWidth <= title.clientWidth + 1,
    };
  }));
}

function expectedCrossGroupBindings(visibleIds) {
  const steps = reviewedScenarioDocument.steps;
  const identities = new Set();
  const labels = [];
  for (const consumer of steps) {
    for (const [input, binding] of Object.entries(consumer.inputs ?? {})) {
      if (visibleIds.has(consumer.id) === visibleIds.has(binding.from_step)) continue;
      const identity = JSON.stringify([binding.from_step, consumer.id, input, binding.artifact]);
      if (identities.has(identity)) continue;
      identities.add(identity);
      labels.push({ artifact: binding.artifact, input: input.replaceAll("_", " ").replace(/^./, value => value.toUpperCase()) });
    }
  }
  return labels;
}

async function waitForGraphFrame(selectedOnly) {
  await page.waitForFunction(selected => {
    const canvas = document.querySelector(".graph-canvas");
    if (!canvas) return false;
    const boundary = canvas.getBoundingClientRect();
    const nodes = [...canvas.querySelectorAll(selected ? ".flow-node.selected" : ".react-flow__node")]
      .filter(node => getComputedStyle(node).display !== "none" && getComputedStyle(node).visibility !== "hidden");
    return nodes.length > 0 && nodes.every(node => {
      const box = node.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && box.left >= boundary.left - 1 && box.top >= boundary.top - 1
        && box.right <= boundary.right + 1 && box.bottom <= boundary.bottom + 1;
    });
  }, selectedOnly);
  // React Flow's viewport animation is JavaScript-driven, not a CSS animation.
  await page.evaluate(() => new Promise((resolve, reject) => {
    let previous = "", stable = 0, frames = 0;
    const sample = () => {
      const current = document.querySelector(".react-flow__viewport")?.getAttribute("style") ?? "";
      stable = current && current === previous ? stable + 1 : 0;
      previous = current;
      if (stable >= 4) resolve(true);
      else if (++frames >= 120) reject(new Error("Graph frame did not settle"));
      else requestAnimationFrame(sample);
    };
    requestAnimationFrame(sample);
  }));
}

try {
  browser = await chromium.launch({ headless: true, args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"] });
  report.browser_version = browser.version();
  context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 } });
  context.setDefaultTimeout(20_000);
  await context.routeWebSocket("**/*", socket => socket.close());
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    let allowed = url.origin === origin && ["GET", "HEAD"].includes(method), reason;
    if (url.origin !== origin) reason = "non_loopback";
    else if (!["GET", "HEAD", "POST"].includes(method)) reason = "method_not_allowed";
    else if (method === "POST") {
      let body;
      try { body = request.postData() ? request.postDataJSON() : null; }
      catch { reason = "invalid_json_body"; }
      if (!reason) {
        const bodyIsEmptyObject = body && typeof body === "object" && !Array.isArray(body) && Object.keys(body).length === 0;
        const isOwnedGraph = exactKeys(body, ["scenario"]) && (scenarioVersionPosts === 0
          ? sameStructure(body.scenario, generatedScenario)
          : scenarioVersionPosts === 1 && sameStructure(body.scenario, reviewedScenarioDocument));
        const hasNoExecutionOverrides = !["collectors", "collector_binding", "action_implementations", "action_overrides"].some(key => Object.hasOwn(body ?? {}, key));
        const isOwnedRunRequest = sameStructure(body?.scenario, reviewedScenarioDocument) && hasOwnedLayout(body?.layout)
          && body.mode === "simulate" && body.autonomy === "off"
          && body.ai_provider_id === "deterministic-offline.v1" && body.runner_profile_id === "sandbox-simulate.v1"
          && exactKeys(body, ["scenario", "layout", "mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope"])
          && exactKeys(body.target_scope, ["scope_refs"]) && Array.isArray(body.target_scope.scope_refs)
          && sameStructure(body.target_scope.scope_refs, ["sandbox.workspace"]) && hasNoExecutionOverrides;
        allowed = false;
        switch (url.pathname) {
          case "/api/v1/session":
            allowed = sessionPosts < 1 && !request.postData();
            if (allowed) sessionPosts += 1; else reason = "session_cap_or_body";
            break;
          case "/api/v1/scenario-versions":
            allowed = scenarioVersionPosts < 2 && isOwnedGraph;
            if (allowed) scenarioVersionPosts += 1; else reason = "scenario_write_cap_or_owner";
            break;
          case "/api/v1/scenarios/validate":
            allowed = scenarioValidationPosts < 1 && exactKeys(body, ["scenario", "layout"])
              && isOwnedScenarioDocument(body.scenario) && hasOwnedLayout(body.layout);
            if (allowed) scenarioValidationPosts += 1; else reason = "validation_cap_or_owner";
            break;
          case "/api/v1/assistance/graph-context":
            allowed = graphContextPosts < 1 && exactKeys(body, ["kind", "base_scenario", ...(Object.hasOwn(body ?? {}, "edit_step") ? ["edit_step"] : [])]) && body?.kind === "graph"
              && Object.hasOwn(body, "edit_step")
              && (body.base_scenario === null || (ownedScenarioVersion && sameStructure(body.base_scenario, ownedScenarioVersion)))
              && (exactKeys(body.edit_step, ["scenario", "step_id", "dirty"])
                && sameStructure(withoutLayout(body.edit_step.scenario), reviewedScenarioDocument)
                && hasOwnedScenarioLayout(body.edit_step.scenario)
                && reviewedScenarioDocument.steps.some(step => step.id === body.edit_step.step_id)
                && typeof body.edit_step.dirty === "boolean");
            if (allowed) graphContextPosts += 1; else reason = "graph_context_cap_or_owner";
            break;
          case "/api/v1/file-access/control-list":
            allowed = controlListPosts < 1 && bodyIsEmptyObject;
            if (allowed) controlListPosts += 1; else reason = "control_list_cap_or_body";
            break;
          case "/api/v1/runs/preflight":
            allowed = preflightPosts < 2 && isOwnedRunRequest;
            if (allowed) preflightPosts += 1; else reason = "preflight_cap_or_request_scope";
            break;
          case "/api/v1/runs":
            allowed = simulationRunPosts < 2 && isOwnedRunRequest;
            if (allowed) simulationRunPosts += 1; else reason = "run_cap_or_request_scope";
            break;
          case "/api/v1/comparisons":
            allowed = comparisonPosts < 1 && exactKeys(body, ["run_ids"]) && Array.isArray(body.run_ids) && body.run_ids.length === 2
              && JSON.stringify(body.run_ids) === JSON.stringify(ownedRunIds);
            if (allowed) comparisonPosts += 1; else reason = "comparison_cap_or_run_ids";
            break;
          default:
            reason = "write_not_allowlisted";
        }
      }
    }
    if (!allowed) {
      report.blocked_requests.push({ method, path: url.origin === origin ? url.pathname : "non-loopback", reason: reason ?? "request_not_allowed" });
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
  secrets.push(await page.evaluate(() => sessionStorage.getItem("bluefire.browser-session.v1")));
  connected = true;
  await page.getByRole("link", { name: "Build", exact: true }).waitFor();
  report.checks.push("normal_ephemeral_browser_session");

  stage = "saved-experiment";
  const catalog = await api("/scenarios");
  const source = catalog.scenarios.find(item => item.id === "scenario.endpoint.lab-collection-methods.v1");
  assert.ok(source);
  const scenario = { ...source, id: ownedScenarioId, title };
  generatedScenario = scenario;
  const saved = (await api("/scenario-versions", { scenario })).scenario;
  assert.equal(saved.scenario_id, ownedScenarioId);
  savedScenarioDocument = saved.document;
  reviewedScenarioDocument = { ...savedScenarioDocument, title: `${title} reviewed` };
  const savedRoute = `${origin}/#/builder?${new URLSearchParams({ saved_scenario: saved.scenario_id, version: String(saved.version), digest: saved.digest })}`;
  await page.goto(savedRoute);
  await page.getByRole("button", { name: "Open this version for editing", exact: true }).click();
  await page.locator(".react-flow__node").first().waitFor();
  await page.getByLabel("Experiment name", { exact: true }).fill(`${title} reviewed`);
  await page.getByRole("button", { name: "Arrange visible group", exact: true }).click();
  await page.getByRole("button", { name: "Undo", exact: true }).click();
  await page.getByRole("button", { name: "Redo", exact: true }).click();
  const saveResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/scenario-versions" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save version", exact: true }).click();
  const updated = (await (await saveResponse).json()).scenario;
  ownedScenarioVersion = { scenario_id: updated.scenario_id, version: updated.version, digest: updated.digest };
  assert.equal(updated.scenario_id, ownedScenarioId);
  assert.equal(updated.document.title, `${title} reviewed`);
  assert.equal(updated.version, saved.version + 1);
  assert.ok(sameStructure(updated.document, reviewedScenarioDocument));
  reviewedScenarioDocument = updated.document;
  assert.deepEqual(updated.document.steps, source.steps);
  assert.deepEqual(updated.document.edges, source.edges);
  report.checks.push("saved_graph_rename_layout_undo_redo_without_semantic_change");

  stage = "graph-export";
  await page.waitForFunction(title => {
    try { return JSON.parse(localStorage.getItem("bluefire.local.scenario.v1") ?? "null")?.title === title; }
    catch { return false; }
  }, reviewedScenarioDocument.title);
  const workingScenario = await page.evaluate(() => JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")));
  assert.ok(sameStructure(withoutLayout(workingScenario), reviewedScenarioDocument), "Working export must match the saved canonical document");
  assert.ok(hasOwnedScenarioLayout(workingScenario), "Working export must retain only owned finite layout positions");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export", exact: true }).click();
  const download = await downloadPromise;
  assert.equal(download.suggestedFilename(), `${ownedScenarioId}.json`);
  const stream = await download.createReadStream();
  assert.ok(stream, "Scenario export must be readable in memory");
  const chunks = [];
  let byteLength = 0;
  for await (const chunk of stream) {
    byteLength += chunk.length;
    assert.ok(byteLength <= 256 * 1024, "Scenario export exceeded the 256 KiB test bound");
    chunks.push(chunk);
  }
  const exportText = Buffer.concat(chunks).toString("utf8");
  const exportedScenario = JSON.parse(exportText);
  assert.ok(sameStructure(exportedScenario, workingScenario), "Export must match the complete working graph including layout");
  for (const secret of secrets) assert.ok(typeof secret === "string" && secret.length > 0 && !exportText.includes(secret), "Export must not contain browser connection credentials");
  secrets.fill("");
  report.checks.push("working_graph_json_export_preserves_canonical_document_and_layout_without_credentials");

  stage = "graph-default-group";
  assert.equal(await page.getByRole("combobox", { name: "Step group", exact: true }).inputValue(), "0");
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    await page.setViewportSize(viewport);
    await page.getByRole("button", { name: "Fit visible graph", exact: true }).click();
    await waitForGraphFrame(false);
    const visibleNodes = await page.locator(".react-flow__node:visible").count();
    assert.equal(visibleNodes, 3);
    const zoom = Number.parseInt(await page.getByLabel("Graph zoom", { exact: true }).textContent() ?? "0", 10);
    assert.ok(zoom >= 80, `Default three-step group is too small at ${viewport.width}px (${zoom}%)`);
    const titles = await visibleGraphTitles();
    assert.equal(titles.length, 3);
    assert.ok(titles.every(title => title.title && title.fitsCard && title.fitsWidth), "Default group titles must fit their cards");
    const visibleNodeIds = await page.locator(".react-flow__node:visible").evaluateAll(nodes => nodes.map(node => node.getAttribute("data-id")));
    assert.ok(visibleNodeIds.every(id => id && reviewedScenarioDocument.steps.some(step => step.id === id)), "Visible graph nodes must map to saved step IDs");
    const visibleIds = new Set(visibleNodeIds);
    const crossingRoutes = reviewedScenarioDocument.edges.filter(edge => visibleIds.has(edge.from_step) !== visibleIds.has(edge.to_step));
    assert.ok(crossingRoutes.length > 0, "Fixture must retain a conditional route across the visible group boundary");
    const groupConnections = page.locator(".graph-group-connections");
    assert.equal(await groupConnections.getAttribute("open"), null, "Group connections should be collapsed initially");
    await groupConnections.locator(":scope > summary").click();
    const boundaryText = await page.locator('.graph-group-boundaries[aria-label="Conditional execution routes"]').innerText();
    for (const outcome of new Set(crossingRoutes.map(edge => edge.outcome))) {
      const label = { success: "On success", partial: "When partly complete", blocked: "When blocked", failed: "On failure" }[outcome];
      assert.ok(label && boundaryText.includes(label), `Conditional route boundary is missing ${outcome}`);
    }
    const bindings = expectedCrossGroupBindings(visibleIds);
    assert.ok(bindings.length > 0, "Fixture must retain an artifact binding across the visible group boundary");
    const dependencyDetails = page.locator(".graph-data-boundaries");
    assert.equal(await dependencyDetails.locator("summary").innerText(), `Data dependencies (${bindings.length})`);
    await dependencyDetails.locator("summary").click();
    const dependencyText = await dependencyDetails.innerText();
    for (const binding of bindings) {
      assert.ok(dependencyText.includes(binding.artifact), `Artifact boundary is missing ${binding.artifact}`);
      assert.ok(dependencyText.includes(binding.input), `Artifact boundary is missing input ${binding.input}`);
    }
    await dependencyDetails.locator("summary").click();
    await groupConnections.locator(":scope > summary").click();
    await capture(`graph-default-group-${viewport.width}x${viewport.height}`);
  }
  report.checks.push("readable_default_group_desktop_framing");
  await page.setViewportSize({ width: 1440, height: 900 });

  stage = "graph-interaction";
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.getByRole("textbox", { name: "Search palette", exact: true }).fill("collect");
  assert.ok(await page.locator(".palette-list button").count() > 0);
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.getByRole("combobox", { name: "Step group", exact: true }).selectOption("all");
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  stage = "graph-select-ordered-step";
  await page.locator(".ordered-steps button").filter({ has: page.locator("strong").filter({ hasText: /^Collect selected records \(native JSONL\)$/ }) }).click();
  stage = "graph-frame-selection";
  await page.getByRole("button", { name: "Canvas", exact: true }).click();
  const inspector = page.getByRole("button", { name: "Show node inspector", exact: true });
  if (await inspector.isVisible()) await inspector.click();
  await page.locator(".inspector-panel:not([hidden])").waitFor();
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    await page.setViewportSize(viewport);
    await page.getByRole("button", { name: "Fit visible graph", exact: true }).click();
    await waitForGraphFrame(false);
    await capture(`graph-overview-${viewport.width}x${viewport.height}`);
    await page.getByRole("button", { name: "Focus selected step", exact: true }).click();
    await page.waitForFunction(() => Number.parseInt(document.querySelector('[aria-label="Graph zoom"]')?.textContent ?? "0", 10) >= 80);
    await waitForGraphFrame(true);
    const selectedTitle = await visibleGraphTitles(true);
    assert.equal(selectedTitle.length, 1);
    assert.equal(selectedTitle[0].title, "Collect selected records (native JSONL)");
    assert.ok(selectedTitle[0].fitsCard && selectedTitle[0].fitsWidth, "Long behavior title must fit the focused card");
    await capture(`graph-focused-${viewport.width}x${viewport.height}`);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole("button", { name: "Assistant", exact: true }).click();
  await page.locator("#experiment-assistant").waitFor();
  await waitForGraphFrame(true);
  await capture("graph-assistant");
  await page.getByRole("button", { name: "Close assistant", exact: true }).click();
  report.checks.push("graph_palette_selection_inspector_assistant_entry_without_model_request");

  async function simulateSavedScenario(screenshotName) {
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
    const id = new URL(page.url()).hash.match(/^#\/runs\/(run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16})$/)?.[1];
    assert.ok(id);
    ownedRunIds.push(id);
    await capture(screenshotName);
    return id;
  }

  const firstRunId = await simulateSavedScenario("simulation-review");
  report.simulation_run_id = firstRunId;
  report.checks.push("normal_preflight_and_durable_ai_off_simulation_review");

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

  stage = "second-saved-simulation";
  await page.getByRole("button", { name: "Open this version for editing", exact: true }).click();
  await page.locator(".react-flow__node").first().waitFor();
  const secondRunId = await simulateSavedScenario("simulation-review-second");
  assert.notEqual(firstRunId, secondRunId);
  report.simulation_run_ids = [...ownedRunIds];
  report.checks.push("two_owned_synthetic_ai_off_runs");

  stage = "detection-open-owned-run";
  await page.goto(`${origin}/#/runs/${encodeURIComponent(firstRunId)}`);
  const detectionLink = page.getByRole("link", { name: "Open Detection Lab", exact: true });
  await page.waitForFunction(id => Array.from(document.querySelectorAll("a")).some(link => link.textContent?.trim() === "Open Detection Lab" && new URL(link.href).hash.includes(`run=${encodeURIComponent(id)}`)), firstRunId);
  stage = "detection-follow-source-link";
  await detectionLink.click();
  stage = "detection-verify-owned-source";
  await page.getByRole("heading", { name: "Detection Lab", exact: true }).waitFor();
  stage = "detection-wait-owned-value";
  await page.waitForFunction(id => Array.from(document.querySelectorAll("select")).some(select => select.value === id), firstRunId);
  stage = "detection-assert-owned-value";
  assert.equal(await page.getByRole("combobox", { name: /^Detection source run\b/ }).inputValue(), firstRunId);
  stage = "detection-verify-observation-count";
  const sourceSummary = page.locator(".detection-source-details > summary").first();
  await sourceSummary.waitFor();
  const sourceCount = Number((await sourceSummary.innerText()).match(/^(\d+) independent observations/)?.[1]);
  assert.equal(sourceCount, 0);
  report.source_observation_count = sourceCount;
  await sourceSummary.click();
  await capture("detection-lab-source-run");
  report.checks.push("detection_lab_linked_to_owned_simulation_source");

  stage = "comparison-restore-owned-runs";
  const comparisonParams = new URLSearchParams({ compare_context: "1" });
  ownedRunIds.forEach(id => comparisonParams.append("compare_run", id));
  await page.goto(`${origin}/#/compare?${comparisonParams}`);
  await page.getByRole("button", { name: "Compare selected", exact: true }).waitFor();
  assert.equal(await page.getByRole("checkbox").count(), 2);
  stage = "comparison-submit-owned-runs";
  const comparisonResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/comparisons" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Compare selected", exact: true }).click();
  stage = "comparison-verify-saved-snapshot";
  const comparison = await (await comparisonResponse).json();
  assert.ok(comparison.saved_snapshot?.snapshot_id);
  assert.deepEqual(comparison.run_ids, ownedRunIds);
  assert.deepEqual(comparison.summaries?.map(run => run.run_id), ownedRunIds);
  assert.equal(comparison.baseline_run_id, ownedRunIds[0]);
  report.comparison_snapshot_id = comparison.saved_snapshot.snapshot_id;
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  await capture("saved-two-run-comparison");
  report.checks.push("one_saved_comparison_of_exact_owned_runs");

  stage = "environments-load-overview";
  await page.goto(`${origin}/#/environments`);
  await page.getByRole("heading", { name: "Environments", exact: true }).waitFor();
  for (const name of ["Cloud access", "File access", "Directory access", "Execution configuration", "Model access"]) {
    await page.getByRole("region", { name, exact: true }).waitFor();
  }
  stage = "environments-capture-overview";
  await capture("environments-overview");
  stage = "environments-capture-model-access";
  await page.getByRole("heading", { name: "Model access", exact: true }).scrollIntoViewIfNeeded();
  await capture("environments-model-access");
  report.checks.push("environments_saved_setup_and_inventory_overview");

  stage = "assistant-open-detached-selection";
  await page.getByRole("button", { name: "Assistant", exact: true }).click();
  const previousSelection = page.getByRole("region", { name: "Previous selection", exact: true });
  await previousSelection.waitFor();
  stage = "assistant-set-off-mode";
  const mode = page.getByRole("combobox", { name: /^(AI mode|Assistant mode)\b/ });
  await mode.selectOption("off");
  assert.equal(await page.getByRole("button", { name: /^Start work/ }).isDisabled(), true);
  stage = "assistant-capture-detached";
  await capture("assistant-detached");
  report.checks.push("detached_assistant_keeps_previous_selection_non_actionable");

  assert.equal(preflightPosts, 2);
  assert.equal(simulationRunPosts, 2);
  assert.equal(comparisonPosts, 1);
  assert.equal(sessionPosts, 1);
  assert.equal(scenarioVersionPosts, 2);
  assert.equal(controlListPosts, 1);
  report.request_caps = { session_posts: sessionPosts, scenario_version_posts: scenarioVersionPosts, scenario_validation_posts: scenarioValidationPosts, graph_context_posts: graphContextPosts, control_list_posts: controlListPosts, preflight_posts: preflightPosts, simulation_run_posts: simulationRunPosts, comparison_posts: comparisonPosts };
  assert.equal(report.errors.length, 0);
  assert.equal(report.blocked_requests.length, 0);
  report.status = "passed";
} catch {
  report.status = "failed_or_incomplete";
  report.errors.push({ stage, kind: "journey-failed" });
  if (connected && stage.startsWith("graph-")) {
    report.graph_failure_geometry = await page.evaluate(() => {
      const geometry = element => {
        if (!element) return null;
        const box = element.getBoundingClientRect(), style = getComputedStyle(element);
        return { x: box.x, y: box.y, width: box.width, height: box.height,
          client_width: element.clientWidth, client_height: element.clientHeight,
          min_height: style.minHeight, flex_basis: style.flexBasis, transform: style.transform };
      };
      return {
        canvas: geometry(document.querySelector(".graph-canvas")),
        stage: geometry(document.querySelector(".graph-stage")),
        viewport: geometry(document.querySelector(".react-flow__viewport")),
        nodes: [...document.querySelectorAll(".react-flow__node")].slice(0, 128)
          .filter(node => getComputedStyle(node).display !== "none" && getComputedStyle(node).visibility !== "hidden")
          .map(geometry),
      };
    }).catch(() => null);
  }
  if (connected) await capture("failure-state").catch(() => {});
  process.exitCode = 1;
} finally {
  capability = "";
  await context?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "context-close" }); process.exitCode = 1; });
  await browser?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "browser-close" }); process.exitCode = 1; });
  if (process.exitCode) report.status = "failed_or_incomplete";
  writeFileSync(join(output, "browser-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}
