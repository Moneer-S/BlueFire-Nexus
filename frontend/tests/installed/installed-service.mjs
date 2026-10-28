// The copied driver talks only to a real, freshly installed loopback service.
/* global process, URL, document, window, requestAnimationFrame, localStorage, sessionStorage, fetch, innerWidth, innerHeight, getComputedStyle */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout } from "node:timers";
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
const title = "Installed browser collection comparison";
const objectiveQuestion = "Does the collection plan retain the requested generated records in an AI-off simulation?";
const responsiveViewports = [
  { width: 1366, height: 768 },
  { width: 1440, height: 900 },
  { width: 1024, height: 768 },
  { width: 910, height: 512 },
];
const responsiveReadPaths = new Set([
  "/api/v1/session", "/api/v1/scenarios", "/api/v1/catalog", "/api/v1/runs",
  "/api/v1/comparison-snapshots", "/api/v1/detection-lab/health", "/api/v1/detections",
  "/api/v1/resources/research-sources", "/api/v1/resources/runner-profiles",
  "/api/v1/resources/runners", "/api/v1/resources/model-providers", "/api/v1/ai/authorizations",
  "/api/v1/receiver-defense/jobs",
  "/api/v1/s3-access/environments", "/api/v1/s3-access/exercises",
  "/api/v1/ad-smb/environments", "/api/v1/ad-smb/workflows",
  "/api/v1/file-access/status", "/api/v1/assistance/graph-context",
  "/ui/fonts/InterVariable.woff2",
]);
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const stableValue = value => Array.isArray(value) ? value.map(stableValue)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
    : value;
const sameStructure = (left, right) => JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
function responsiveReadAllowed(path) {
  if (responsiveReadPaths.has(path)) return true;
  const run = path.match(/^\/api\/v1\/runs\/(run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16})$/);
  if (run) return ownedRunIds.includes(run[1]);
  const detection = path.match(/^\/api\/v1\/detections\/(detection-[0-9a-f]{20})$/);
  if (detection) return detection[1] === ownedDetectionId || detection[1] === ownedDetectionRevisionId;
  const snapshot = path.match(/^\/api\/v1\/comparison-snapshots\/([A-Za-z0-9_-]+)$/);
  if (snapshot && snapshot[1] === report.comparison_snapshot_id) return true;
  const assistantContext = path.match(/^\/api\/v1\/comparison-snapshots\/([A-Za-z0-9_-]+)\/assistant-context$/);
  return Boolean(assistantContext && assistantContext[1] === report.comparison_snapshot_id);
}
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
let comparisonAssistantContextGets = 0, comparisonAssistantTurnPosts = 0, readOnlyPostAttempts = 0, detectionRunEvaluationPosts = 0;
let fontResponseResolve;
const fontResponsePromise = new Promise(resolve => { fontResponseResolve = resolve; });
let fontResponseEvidence;
let detectionFromRunPosts = 0, detectionParsePosts = 0, detectionFixturePosts = 0, detectionBenignPosts = 0;
let detectionRevisionClonePosts = 0, detectionRevisionParsePosts = 0;
let readOnlyCapturePhase = false;
let ownedRunIds = [];
let ownedScenarioId = "", generatedScenario, savedScenarioDocument, reviewedScenarioDocument, ownedScenarioVersion;
const runPlanFingerprints = [];
let sourceDetectionId, ownedDetectionId, ownedDetectionRevisionId, expectedOwnedRevisionCloneBody;
let expectedMaliciousFixtures, expectedBenignFixtures;

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

function syntheticFixture(selection, fixtureId) {
  assert.ok(selection && typeof selection === "object" && !Array.isArray(selection) && Object.keys(selection).length > 0);
  const fixture = { fixture_id: fixtureId };
  for (const [rawField, value] of Object.entries(selection)) {
    const [field, operator, extra] = rawField.split("|");
    assert.match(field ?? "", /^[A-Za-z_][A-Za-z0-9_]*$/);
    assert.equal(extra, undefined);
    assert.ok(operator === undefined || ["contains", "startswith", "endswith"].includes(operator));
    assert.ok(["string", "number", "boolean"].includes(typeof value));
    assert.equal(Object.hasOwn(fixture, field), false);
    fixture[field] = value;
  }
  return fixture;
}

function benignNonmatchFixture(selection, fixtureId) {
  const fixture = syntheticFixture(selection, fixtureId);
  for (const [rawField, value] of Object.entries(selection)) {
    const [field, operator] = rawField.split("|");
    if (operator) continue;
    if (typeof value === "string") fixture[field] = "__bluefire_benign_nonmatch__";
    else if (typeof value === "number") fixture[field] = value + 1;
    else fixture[field] = !value;
    return fixture;
  }
  throw new Error("The owned source detector has no exact-match field for a bounded benign nonmatch.");
}

function detectionDocument(envelope) {
  assert.ok(envelope?.candidate?.document && typeof envelope.candidate.document === "object");
  return envelope.candidate.document;
}

async function capture(name, metadata = {}) {
  assert.ok(connected, "Never capture connection credentials");
  await page.evaluate(async () => { await document.fonts.ready; await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); });
  const geometry = await page.evaluate(() => ({ width: innerWidth, height: innerHeight, document_width: document.documentElement.clientWidth, scroll_width: document.documentElement.scrollWidth, nodes: document.querySelectorAll(".react-flow__node").length, edges: document.querySelectorAll(".react-flow__edge").length }));
  assert.ok(geometry.scroll_width <= geometry.document_width, "Desktop page overflows horizontally");
  const screenshot = await page.screenshot({ fullPage: false, animations: "disabled", mask: [page.locator('input[type="password"]')] });
  writeFileSync(join(output, `${name}.png`), screenshot, { flag: "wx" });
  report.screenshots.push({ name, sha256: createHash("sha256").update(screenshot).digest("hex"), geometry, ...metadata });
}

async function captureResponsiveSurface({ name, heading, controls, scrollRoot }) {
  readOnlyCapturePhase = true;
  try {
    for (const viewport of responsiveViewports) {
      stage = `${name}-${viewport.width}x${viewport.height}`;
      await page.setViewportSize(viewport);
      await page.evaluate(selector => {
        window.scrollTo({ top: 0, left: 0, behavior: "instant" });
        document.getElementById("main-content")?.scrollTo({ top: 0, left: 0, behavior: "instant" });
        if (selector) document.querySelector(selector)?.scrollTo({ top: 0, left: 0, behavior: "instant" });
      }, scrollRoot);
      await page.evaluate(async () => { await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); });
      const headingLocator = page.getByRole("heading", { name: heading, exact: true }).first();
      await headingLocator.waitFor({ state: "visible" });
      const headingGeometry = await headingLocator.evaluate(element => {
        const box = element.getBoundingClientRect();
        return { visible: getComputedStyle(element).visibility !== "hidden" && box.width > 0 && box.height > 0,
          left: box.left, right: box.right, client_width: element.clientWidth, scroll_width: element.scrollWidth };
      });
      report.layout_probe = { surface: name, viewport, element: "heading", geometry: headingGeometry };
      assert.ok(headingGeometry.visible, `${name} heading must be visible`);
      assert.ok(headingGeometry.left >= -1 && headingGeometry.right <= viewport.width + 1, `${name} heading must fit the viewport`);
      assert.ok(headingGeometry.scroll_width <= headingGeometry.client_width + 1, `${name} heading text must not be clipped`);

      const checkedControls = [];
      for (const control of controls) {
        if (control.bringIntoView) await control.locator.evaluate(element => element.scrollIntoView({ block: "center", inline: "nearest", behavior: "instant" }));
        await control.locator.waitFor({ state: "visible" });
        const geometry = await control.locator.evaluate((element, selector) => {
          const box = element.getBoundingClientRect();
          const clip = selector ? element.closest(selector)?.getBoundingClientRect() : undefined;
          return { visible: getComputedStyle(element).visibility !== "hidden" && box.width > 0 && box.height > 0,
            left: box.left, right: box.right, top: box.top, bottom: box.bottom,
            clip_top: clip?.top, clip_bottom: clip?.bottom,
            client_width: element.clientWidth, scroll_width: element.scrollWidth };
        }, control.withinScroll ? scrollRoot : undefined);
        report.layout_probe = { surface: name, viewport, element: control.label, geometry };
        assert.ok(geometry.visible, `${name} ${control.label} must be visible`);
        assert.ok(geometry.left >= -1 && geometry.right <= viewport.width + 1, `${name} ${control.label} must fit the viewport`);
        assert.ok(geometry.top >= -1 && geometry.bottom <= viewport.height + 1, `${name} ${control.label} must fit the viewport height`);
        if (control.withinScroll) assert.ok(Number.isFinite(geometry.clip_top) && Number.isFinite(geometry.clip_bottom)
          && geometry.top >= geometry.clip_top - 1 && geometry.bottom <= geometry.clip_bottom + 1,
        `${name} ${control.label} must be reachable inside its scroll viewport`);
        if (control.textFits) assert.ok(geometry.scroll_width <= geometry.client_width + 1, `${name} ${control.label} text must not be clipped`);
        checkedControls.push(control.label);
      }

      const documentWidth = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
      assert.ok(documentWidth.scroll <= documentWidth.client + 1, `${name} must not overflow horizontally`);
      if (scrollRoot) await page.locator(scrollRoot).evaluate(element => element.scrollTo({ top: 0, left: 0, behavior: "instant" }));
      await capture(`${name}-${viewport.width}x${viewport.height}`, {
        surface: name,
        readable_heading: heading,
        readable_controls: checkedControls,
        layout_checks: ["heading_visible_and_unclipped", "controls_visible_and_in_viewport", "no_horizontal_overflow", ...(scrollRoot ? ["controls_reachable_in_scroll_viewport", "capture_scroll_reset"] : [])],
      });
      report.checks.push(`${name}_readable_at_${viewport.width}x${viewport.height}`);
      delete report.layout_probe;
    }
  } finally {
    readOnlyCapturePhase = false;
  }
}

async function visibleGraphTitles(selectedOnly = false) {
  const selector = selectedOnly ? ".react-flow__node:visible:has(.flow-node.selected)" : ".react-flow__node:visible";
  return page.locator(selector).evaluateAll(nodes => nodes.map(node => {
    const card = node.querySelector(".flow-node");
    const title = card?.querySelector(".node-title > strong");
    if (!card || !title) return { title: "", fitsCard: false, fitsWidth: false };
    const cardBox = card.getBoundingClientRect();
    const titleBox = title.getBoundingClientRect();
    const method = card.querySelector(".node-method");
    const methodBox = method?.getBoundingClientRect();
    const primary = title.textContent?.trim() ?? "";
    const qualifier = method?.textContent?.trim() ?? "";
    const fullTitle = title.getAttribute("title") ?? "";
    const identityPreserved = fullTitle === [primary, qualifier].filter(Boolean).join(" ");
    const methodFits = !method || Boolean(methodBox && methodBox.width > 0 && methodBox.height > 0
      && methodBox.left >= cardBox.left - 1 && methodBox.right <= cardBox.right + 1
      && methodBox.top >= cardBox.top - 1 && methodBox.bottom <= cardBox.bottom + 1
      && method.scrollWidth <= method.clientWidth + 1
      && getComputedStyle(method).visibility === "visible" && Number(getComputedStyle(method).opacity) > 0);
    return {
      title: identityPreserved ? fullTitle : "", primary, qualifier,
      fitsCard: methodFits && titleBox.left >= cardBox.left - 1 && titleBox.right <= cardBox.right + 1
        && titleBox.top >= cardBox.top - 1 && titleBox.bottom <= cardBox.bottom + 1,
      fitsWidth: title.scrollWidth <= title.clientWidth + 1,
    };
  }));
}

async function renderedGraphEdges(prefix) {
  return page.locator(`.react-flow__edge[data-id^="${prefix}"]`).evaluateAll(edges => edges.map(edge => {
    const paths = edge.querySelectorAll(".react-flow__edge-path");
    const path = paths[0];
    if (!path) return { id: edge.getAttribute("data-id"), pathCount: 0, visible: false };
    const style = getComputedStyle(path), box = path.getBoundingClientRect();
    let ancestorsVisible = true;
    for (let element = path; element; element = element.parentElement) {
      const ancestorStyle = getComputedStyle(element);
      if (ancestorStyle.display === "none" || ["hidden", "collapse"].includes(ancestorStyle.visibility) || Number(ancestorStyle.opacity) === 0) ancestorsVisible = false;
    }
    let length = null;
    try { length = path.getTotalLength(); } catch { /* Invalid path geometry is reported below. */ }
    const d = path.getAttribute("d");
    const strokeVisible = style.stroke !== "none" && style.stroke !== "transparent"
      && !/rgba\([^)]*,\s*0(?:\.0*)?\)$/.test(style.stroke)
      && Number.parseFloat(style.strokeWidth) > 0 && Number(style.strokeOpacity) > 0;
    return {
      id: edge.getAttribute("data-id"), name: edge.getAttribute("aria-label"), pathCount: paths.length,
      finitePath: Boolean(d && !/NaN|Infinity/.test(d)),
      length, width: box.width, height: box.height,
      // A painted vertical or horizontal SVG path can have one zero-sized axis.
      visible: ancestorsVisible && strokeVisible && [box.x, box.y, box.width, box.height].every(Number.isFinite)
        && box.width >= 0 && box.height >= 0 && (box.width > 0 || box.height > 0),
      strokeVisible, dashed: style.strokeDasharray !== "none",
    };
  }));
}

function assertGraphEdgeGeometry(edge, outcome) {
  assert.ok(edge, "An inspected connection must have its own rendered path");
  assert.equal(edge.pathCount, 1, "Each drawn connection must have one rendered path");
  assert.ok(edge.finitePath && Number.isFinite(edge.length) && edge.length > 0, "Drawn connections must have finite nonzero path geometry");
  assert.equal(edge.visible, true, "Drawn connections must have painted visible paths, including straight routes");
  if (outcome) assert.equal(edge.dashed, outcome !== "success", "Fallback and partial routes must remain visually distinct from success routes");
}

async function assertRenderedGraphEdges(prefix, expectedIds, routes) {
  const rendered = await renderedGraphEdges(prefix);
  report.graph_edge_probe = { kind: routes ? "outcome_routes" : "input_connections", expected_count: expectedIds.length, actual_count: rendered.length };
  const actualIds = rendered.map(edge => edge.id);
  assert.equal(new Set(actualIds).size, actualIds.length, "No connection may be drawn more than once");
  assert.ok(actualIds.every(id => expectedIds.includes(id)), "Drawn connections must retain saved identities");
  for (const [index, id] of expectedIds.entries()) {
    const edge = rendered.find(item => item.id === id);
    const route = routes?.[index];
    if (!edge && route && route.outcome !== "success") {
      const successIndex = routes.findIndex(other => other.outcome === "success" && other.from_step === route.from_step && other.to_step === route.to_step);
      const success = rendered.find(item => item.id === expectedIds[successIndex]);
      assert.ok(success && (success.name?.includes("Any outcome") || success.name?.includes(`Also ${route.outcome}`) || success.name?.includes(`, ${route.outcome}`)), "A folded condition must be named on its visible shared-destination route");
      continue;
    }
    assert.ok(edge, "Every nonfolded connection must be drawn");
    report.graph_edge_probe = { ...report.graph_edge_probe, checked_index: index, path_count: edge.pathCount,
      finite_path: edge.finitePath === true, length: Number.isFinite(edge.length) ? edge.length : null,
      width: Number.isFinite(edge.width) ? edge.width : null, height: Number.isFinite(edge.height) ? edge.height : null,
      visible: edge.visible, stroke_visible: edge.strokeVisible === true,
      dashed: edge.dashed, ...(route ? { expected_dashed: route.outcome !== "success" } : {}) };
    assertGraphEdgeGeometry(edge, route?.outcome);
  }
  report.graph_edge_probe.identities_match = true;
  delete report.graph_edge_probe;
}

async function graphOptions(open) {
  if (await page.locator("details.graph-options").evaluate(element => element.open) !== open) {
    await page.getByLabel("View options", { exact: true }).click();
  }
}

async function graphMenuAction(name) {
  await graphOptions(true);
  await page.getByRole("button", { name, exact: true }).click();
  await graphOptions(false);
}


async function graphZoomPercent(waitUntilReadable = false) {
  // Both responsive outputs reflect graphZoom; this named primary output is unique
  // even when compact CSS moves its visible presentation into View options.
  const selector = '.graph-view-actions > output.graph-scale[aria-label="Graph zoom"]';
  const indicator = page.locator(selector);
  const count = await indicator.count();
  report.graph_zoom_probe = { primary_indicator_count: count };
  assert.equal(count, 1, "Graph zoom must have exactly one primary state indicator");
  if (waitUntilReadable) {
    await page.waitForFunction(selector => {
      const matches = document.querySelectorAll(selector);
      if (matches.length !== 1) return false;
      const text = matches[0].textContent?.trim() ?? "";
      if (!/^(?:0|[1-9][0-9]{0,2})%$/.test(text)) return false;
      const percent = Number(text.slice(0, -1));
      return Number.isInteger(percent) && percent >= 80 && percent <= 160;
    }, selector);
  }
  const text = (await indicator.textContent() ?? "").trim();
  const validFormat = /^(?:0|[1-9][0-9]{0,2})%$/.test(text);
  report.graph_zoom_probe.valid_format = validFormat;
  assert.ok(validFormat, "Primary graph zoom must be a whole percentage");
  const percent = Number(text.slice(0, -1));
  const withinBounds = Number.isInteger(percent) && percent >= 0 && percent <= 160;
  report.graph_zoom_probe.within_bounds = withinBounds;
  assert.ok(withinBounds, "Primary graph zoom must fit the configured viewport range");
  report.graph_zoom_probe.percent = percent;
  delete report.graph_zoom_probe;
  return percent;
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
    if (method === "POST" && /^\/api\/v1\/detections\/detection-[0-9a-f]{20}\/evaluate-run$/.test(url.pathname)) detectionRunEvaluationPosts += 1;
    if (readOnlyCapturePhase && method === "POST") readOnlyPostAttempts += 1;
    if (url.origin !== origin) reason = "non_loopback";
    else if (readOnlyCapturePhase) {
      allowed = false;
      if (method === "GET" && responsiveReadAllowed(url.pathname)) allowed = true;
      else if (method === "POST" && url.pathname === "/api/v1/file-access/control-list") {
        let body;
        try { body = request.postData() ? request.postDataJSON() : null; }
        catch { reason = "invalid_json_body"; }
        allowed = !reason && controlListPosts < 2 && exactKeys(body, []);
        if (allowed) controlListPosts += 1; else reason ??= "read_only_history_lookup_cap_or_body";
      } else reason = "responsive_capture_read_only_allowlist";
    }
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
            allowed = controlListPosts < 2 && bodyIsEmptyObject;
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
            if (url.pathname === "/api/v1/detections/from-run") {
              allowed = detectionFromRunPosts < 1 && exactKeys(body, ["run_id", "candidate_id"])
                && body.run_id === ownedRunIds[0] && body.candidate_id === sourceDetectionId;
              if (allowed) detectionFromRunPosts += 1; else reason = "detection_import_cap_or_source";
            } else {
              const match = url.pathname.match(/^\/api\/v1\/detections\/(detection-[0-9a-f]{20})\/(clone|parse|exercise-fixtures|evaluate-benign)$/);
              if (match?.[2] === "clone") {
                allowed = match[1] === ownedDetectionId && detectionRevisionClonePosts < 1
                  && expectedOwnedRevisionCloneBody && exactKeys(body, Object.keys(expectedOwnedRevisionCloneBody))
                  && sameStructure(body, expectedOwnedRevisionCloneBody);
                if (allowed) detectionRevisionClonePosts += 1; else reason = "detection_revision_clone_cap_or_payload";
              } else if (match && match[1] === ownedDetectionId) {
                const action = match[2];
                if (action === "parse") {
                  allowed = detectionParsePosts < 1 && exactKeys(body, []);
                  if (allowed) detectionParsePosts += 1; else reason = "detection_parse_cap_or_owner";
                } else if (action === "exercise-fixtures") {
                  allowed = detectionFixturePosts < 1 && exactKeys(body, ["fixtures"])
                    && sameStructure(body.fixtures, expectedMaliciousFixtures);
                  if (allowed) detectionFixturePosts += 1; else reason = "detection_fixture_cap_or_payload";
                } else {
                  allowed = detectionBenignPosts < 1 && exactKeys(body, ["fixtures", "notes"])
                    && sameStructure(body.fixtures, expectedBenignFixtures)
                    && sameStructure(body.notes, ["Owned synthetic benign nonmatch fixture."]);
                  if (allowed) detectionBenignPosts += 1; else reason = "detection_benign_cap_or_payload";
                }
              } else if (match && ownedDetectionRevisionId && match[1] === ownedDetectionRevisionId && match[2] === "parse") {
                allowed = detectionRevisionParsePosts < 1 && exactKeys(body, []);
                if (allowed) detectionRevisionParsePosts += 1; else reason = "detection_revision_parse_cap_or_owner";
              } else reason = "write_not_allowlisted";
            }
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
  page.on("response", async response => {
    if (!connected && stage === "connect" && response.url() === `${origin}/api/v1/session` && response.request().method() === "GET" && response.status() === 401) bootstrapSession401 += 1;
    const url = new URL(response.url());
    if (url.origin !== origin || url.pathname !== "/ui/fonts/InterVariable.woff2" || fontResponseEvidence) return;
    try {
      const bytes = await response.body();
      fontResponseEvidence = { path: url.pathname, status: response.status(), content_type: response.headers()["content-type"] ?? "", bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    } catch {
      fontResponseEvidence = { path: url.pathname, status: response.status(), content_type: response.headers()["content-type"] ?? "", bytes: 0, sha256: "" };
    }
    fontResponseResolve(fontResponseEvidence);
  });
  page.on("request", request => {
    const url = new URL(request.url());
    if (url.origin !== origin) return;
    if (url.pathname === `/api/v1/comparison-snapshots/${report.comparison_snapshot_id}/assistant-context` && request.method() === "GET") comparisonAssistantContextGets += 1;
    if (url.pathname === "/api/v1/assistance/turns" && request.method() === "POST") comparisonAssistantTurnPosts += 1;
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
  await page.getByRole("heading", { name: "Overview", exact: true }).waitFor();
  await page.getByRole("link", { name: "Open experiments", exact: true }).click();
  await page.getByRole("heading", { name: "Experiments", exact: true }).waitFor();
  const catalog = await api("/scenarios");
  const source = catalog.scenarios.find(item => item.id === "scenario.endpoint.lab-collection-methods.v1");
  assert.ok(source);
  const sourceRow = page.locator(".experiment-row").filter({ has: page.getByRole("button", { name: source.title, exact: true }) });
  assert.equal(await sourceRow.count(), 1);
  await sourceRow.getByRole("button", { name: "Duplicate", exact: true }).click();
  const duplicateDraft = await page.evaluate(() => JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")));
  assert.ok(duplicateDraft?.id?.startsWith(`${source.id.replace(/\.v\d+$/, "")}.copy.`));
  assert.ok(duplicateDraft.id.endsWith(".v1"));
  assert.notEqual(duplicateDraft.id, source.id);
  ownedScenarioId = duplicateDraft.id;
  const duplicateRow = page.locator(".experiment-row").filter({ has: page.getByRole("button", { name: `${source.title} copy`, exact: true }) });
  await duplicateRow.getByRole("button", { name: "Continue editing", exact: true }).click();
  await page.getByLabel("Experiment name", { exact: true }).fill(title);
  const purposeField = page.getByLabel("Experiment question", { exact: true });
  if (!await purposeField.isVisible()) {
    await page.locator("details").filter({ has: purposeField }).getByText("Experiment purpose", { exact: true }).click();
  }
  await purposeField.fill(objectiveQuestion);
  await page.waitForFunction(({ title, purpose }) => {
    try {
      const draft = JSON.parse(localStorage.getItem("bluefire.local.scenario.v1") ?? "null");
      return draft?.title === title && draft?.purpose === purpose;
    } catch { return false; }
  }, { title, purpose: objectiveQuestion });
  const objectiveDraft = await page.evaluate(() => JSON.parse(localStorage.getItem("bluefire.local.scenario.v1")));
  generatedScenario = withoutLayout(objectiveDraft);
  assert.equal(generatedScenario.id, ownedScenarioId);
  assert.equal(generatedScenario.title, title);
  assert.equal(generatedScenario.purpose, objectiveQuestion);
  assert.deepEqual(generatedScenario.steps, source.steps);
  assert.deepEqual(generatedScenario.edges, source.edges);
  const firstSaveResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/scenario-versions" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save version", exact: true }).click();
  const saved = (await (await firstSaveResponse).json()).scenario;
  assert.equal(saved.scenario_id, ownedScenarioId);
  assert.equal(saved.version, 1);
  assert.equal(saved.document.purpose, objectiveQuestion);
  assert.deepEqual(saved.document.steps, source.steps);
  assert.deepEqual(saved.document.edges, source.edges);
  savedScenarioDocument = saved.document;
  reviewedScenarioDocument = { ...savedScenarioDocument, title: `${title} reviewed` };
  report.objective_continuity = {
    claim: "scenario-purpose objective continuity through owned AI-off simulation only",
    objective: objectiveQuestion,
    scenario_id: ownedScenarioId,
    source_scenario_id: source.id,
    saved_version: saved.version,
    saved_digest: saved.digest,
  };
  report.checks.push("overview_to_experiments_duplicate_and_scenario_purpose_authored_in_builder");
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
  ownedScenarioVersion = { scenario_id: updated.scenario_id, version: updated.version, digest: updated.digest };
  assert.equal(updated.scenario_id, ownedScenarioId);
  assert.equal(updated.document.title, `${title} reviewed`);
  assert.equal(updated.document.purpose, objectiveQuestion);
  assert.equal(updated.version, saved.version + 1);
  assert.ok(sameStructure(updated.document, reviewedScenarioDocument));
  reviewedScenarioDocument = updated.document;
  assert.deepEqual(updated.document.steps, source.steps);
  assert.deepEqual(updated.document.edges, source.edges);
  report.objective_continuity.reviewed_version = updated.version;
  report.objective_continuity.reviewed_digest = updated.digest;
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
  await graphMenuAction("Export");
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

  stage = "graph-dismiss-verified-save-notice";
  const savedGraphNotice = page.locator(".compatibility-banner");
  if (await savedGraphNotice.count()) {
    assert.equal(await savedGraphNotice.getAttribute("role"), "status");
    assert.ok((await savedGraphNotice.innerText()).includes(`Version ${updated.version} saved.`));
    await savedGraphNotice.getByRole("button", { name: "Dismiss compatibility message", exact: true }).click();
    await savedGraphNotice.waitFor({ state: "hidden" });
  }

  stage = "graph-connected-plan-scope";
  assert.equal(await page.getByRole("navigation", { name: "Focused connected path", exact: true }).count(), 0);
  stage = "graph-connected-plan-node-count";
  assert.equal(await page.locator(".react-flow__node:visible").count(), reviewedScenarioDocument.steps.length);
  stage = "graph-connected-plan-outcome-routes";
  const expectedRoutes = reviewedScenarioDocument.edges.map((route, index) => `route-${route.from_step}-${route.outcome}-${route.to_step}-${index}`);
  await assertRenderedGraphEdges("route-", expectedRoutes, reviewedScenarioDocument.edges);
  const expectedBindings = reviewedScenarioDocument.steps.flatMap(consumer => Object.entries(consumer.inputs ?? {}).map(([input, binding]) => `artifact-${binding.from_step}-${binding.artifact}-${consumer.id}-${input}`));
  stage = "graph-connected-plan-input-connections";
  await graphOptions(true);
  await page.getByLabel("Show input connections", { exact: true }).check();
  await graphOptions(false);
  await assertRenderedGraphEdges("artifact-", expectedBindings);
  stage = "graph-connected-plan-readable-routes";
  const selectedStepBeforeRoutes = await page.locator(".react-flow__node.selected").getAttribute("data-id");
  assert.ok(reviewedScenarioDocument.steps.some(step => step.id === selectedStepBeforeRoutes));
  await page.getByRole("button", { name: "Show route list", exact: true }).click();
  const routeButtons = page.getByRole("list", { name: "Visible routes", exact: true }).getByRole("button");
  assert.equal(await routeButtons.count(), reviewedScenarioDocument.edges.length);
  for (const [index, route] of reviewedScenarioDocument.edges.entries()) {
    const routeText = await routeButtons.nth(index).innerText();
    const outcome = { success: "On success", partial: "When partly complete", blocked: "When blocked", failed: "On failure" }[route.outcome];
    assert.ok(routeText.includes(outcome) && routeText.includes(route.from_step) && routeText.includes(route.to_step), "Route meaning and endpoints must remain available in the readable route list");
    if (index === 0) await routeButtons.first().focus();
    else await routeButtons.nth(index - 1).press("ArrowDown");
    await page.waitForFunction(id => {
      const button = [...document.querySelectorAll(".builder-routes button[data-route]")].find(item => item.getAttribute("data-route") === id);
      const edge = [...document.querySelectorAll(".react-flow__edge")].find(item => item.getAttribute("data-id") === id);
      return button === document.activeElement && button?.getAttribute("aria-pressed") === "true" && edge?.classList.contains("selected");
    }, expectedRoutes[index]);
    const inspected = (await renderedGraphEdges("route-")).find(edge => edge.id === expectedRoutes[index]);
    assertGraphEdgeGeometry(inspected, route.outcome);
  }
  await page.getByRole("button", { name: "Close route list", exact: true }).click();
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await page.locator(`.ordered-steps button[data-step-id="${selectedStepBeforeRoutes}"]`).click();
  await page.getByRole("button", { name: "Canvas", exact: true }).click();
  await graphOptions(true);
  await page.getByLabel("Show input connections", { exact: true }).uncheck();
  await graphOptions(false);
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1440, height: 900 }, { width: 1920, height: 1080 }]) {
    stage = `graph-connected-plan-focus-${viewport.width}x${viewport.height}`;
    await page.setViewportSize(viewport);
    stage = `graph-connected-plan-focus-${viewport.width}x${viewport.height}-focus`;
    await graphMenuAction("Focus selected step");
    stage = `graph-connected-plan-focus-${viewport.width}x${viewport.height}-frame`;
    await waitForGraphFrame(true);
    const visibleNodes = await page.locator(".react-flow__node:visible").count();
    assert.equal(visibleNodes, reviewedScenarioDocument.steps.length);
    stage = `graph-connected-plan-focus-${viewport.width}x${viewport.height}-zoom`;
    const zoom = await graphZoomPercent();
    assert.ok(zoom >= 80, `The selected step must be readable at ${viewport.width}px (${zoom}%)`);
    stage = `graph-connected-plan-focus-${viewport.width}x${viewport.height}-titles`;
    const titles = await visibleGraphTitles(true);
    assert.equal(titles.length, 1);
    assert.ok(titles.every(title => title.title && title.fitsCard && title.fitsWidth), "Focused titles must fit their cards");
    const visibleNodeIds = await page.locator(".react-flow__node:visible").evaluateAll(nodes => nodes.map(node => node.getAttribute("data-id")));
    assert.deepEqual(visibleNodeIds.sort(), reviewedScenarioDocument.steps.map(step => step.id).sort(), "All saved steps remain in the navigable canvas");
    await capture(`graph-connected-plan-${viewport.width}x${viewport.height}`);
  }
  report.checks.push("whole_plan_routes_dependencies_and_readable_selection_at_desktop_sizes");
  await page.setViewportSize({ width: 1440, height: 900 });

  stage = "graph-interaction";
  await page.getByRole("button", { name: "Add step", exact: true }).click();
  await page.getByRole("textbox", { name: "Search palette", exact: true }).fill("collect");
  assert.ok(await page.locator(".palette-list button").count() > 0);
  await page.getByRole("button", { name: "Add step", exact: true }).click();
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
    await page.getByRole("button", { name: "Fit view", exact: true }).click();
    await waitForGraphFrame(false);
    await capture(`graph-overview-${viewport.width}x${viewport.height}`);
    stage = `graph-focused-${viewport.width}x${viewport.height}-focus`;
    await graphMenuAction("Focus selected step");
    stage = `graph-focused-${viewport.width}x${viewport.height}-zoom`;
    await graphZoomPercent(true);
    stage = `graph-focused-${viewport.width}x${viewport.height}-frame`;
    await waitForGraphFrame(true);
    stage = `graph-focused-${viewport.width}x${viewport.height}-titles`;
    const selectedTitle = await visibleGraphTitles(true);
    assert.equal(selectedTitle.length, 1);
    assert.equal(selectedTitle[0].title, "Collect selected records (native JSONL)");
    assert.equal(selectedTitle[0].primary, "Collect selected records");
    assert.equal(selectedTitle[0].qualifier, "(native JSONL)");
    assert.ok(selectedTitle[0].fitsCard && selectedTitle[0].fitsWidth, "Long behavior title must fit the focused card");
    await capture(`graph-focused-${viewport.width}x${viewport.height}`);
  }
  async function reachableGraphElement(locator, description, checkText = true) {
    await locator.evaluate(element => element.scrollIntoView({ block: "center", inline: "nearest", behavior: "instant" }));
    const geometry = await locator.evaluate(element => {
      const box = element.getBoundingClientRect();
      const main = document.getElementById("main-content")?.getBoundingClientRect();
      return { left: box.left, right: box.right, top: box.top, bottom: box.bottom,
        width: box.width, height: box.height, clipTop: Math.max(0, main?.top ?? 0),
        clipBottom: Math.min(innerHeight, main?.bottom ?? innerHeight), viewportWidth: innerWidth,
        textFits: element.scrollWidth <= element.clientWidth + 1 };
    });
    report.layout_probe = { surface: "constrained-graph", element: description, geometry };
    assert.ok(geometry.width > 0 && geometry.height > 0 && (!checkText || geometry.textFits), `${description} must remain readable`);
    assert.ok(geometry.left >= -1 && geometry.right <= geometry.viewportWidth + 1
      && geometry.top >= geometry.clipTop - 1 && geometry.bottom <= geometry.clipBottom + 1,
    `${description} must be reachable within the desktop work area`);
    delete report.layout_probe;
  }
  for (const viewport of [{ width: 1024, height: 768 }, { width: 910, height: 512 }]) {
    stage = `graph-constrained-${viewport.width}x${viewport.height}`;
    await page.setViewportSize(viewport);
    for (const name of ["Fit view", "Steps", "Canvas", "Hide node inspector"]) {
      await reachableGraphElement(page.getByRole("button", { name, exact: true }), name);
    }
    await graphOptions(true);
    await reachableGraphElement(page.getByRole("button", { name: "Focus selected step", exact: true }), "Focus selected step");
    await graphOptions(false);
    await page.getByRole("button", { name: "Hide node inspector", exact: true }).click();
    const showInspector = page.getByRole("button", { name: "Show node inspector", exact: true });
    await reachableGraphElement(showInspector, "Show node inspector");
    await showInspector.click();
    await page.locator(".inspector-panel:not([hidden])").waitFor();
    await page.getByRole("button", { name: "Fit view", exact: true }).click();
    await waitForGraphFrame(false);
    await page.getByRole("button", { name: "Steps", exact: true }).click();
    const selectedStep = page.locator('.ordered-steps button[aria-pressed="true"]');
    assert.match(await selectedStep.innerText(), /Collect selected records \(native JSONL\)/);
    await page.getByRole("button", { name: "Canvas", exact: true }).click();
    stage = `graph-constrained-${viewport.width}x${viewport.height}-focus`;
    await graphMenuAction("Focus selected step");
    stage = `graph-constrained-${viewport.width}x${viewport.height}-frame`;
    await waitForGraphFrame(true);
    stage = `graph-constrained-${viewport.width}x${viewport.height}-zoom`;
    const zoom = await graphZoomPercent();
    assert.ok(zoom >= 80, "Selected step must retain a readable focused scale");
    stage = `graph-constrained-${viewport.width}x${viewport.height}-titles`;
    const selectedNode = page.locator(".react-flow__node:visible:has(.flow-node.selected)");
    assert.equal(await selectedNode.count(), 1);
    // Port handles extend outside the node; title fit is checked separately.
    await reachableGraphElement(selectedNode, "Focused step", false);
    const selectedTitles = await visibleGraphTitles(true);
    assert.ok(selectedTitles.every(title => title.fitsCard && title.fitsWidth));
    await capture(`graph-constrained-focus-${viewport.width}x${viewport.height}`);
    const inspectorHeading = page.locator(".inspector-panel:not([hidden])").getByRole("heading", { name: "Collect selected records (native JSONL)", exact: true });
    await reachableGraphElement(inspectorHeading, "Selected step inspector");
    await reachableGraphElement(page.getByRole("button", { name: "Close step details", exact: true }), "Close step details");
    await capture(`graph-constrained-inspector-${viewport.width}x${viewport.height}`);
    report.checks.push(`graph_selection_fit_ordered_view_and_inspector_reachable_at_${viewport.width}x${viewport.height}`);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator(".graph-topbar").evaluate(element => element.scrollIntoView({ block: "start", behavior: "instant" }));
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
    await page.getByRole("button", { name: "Check run", exact: true }).click();
    const preflight = await (await preflightResponse).json();
    assert.equal(preflight.ready, true);
    assert.equal(preflight.plan?.scenario_id, ownedScenarioId);
    assert.equal(preflight.plan?.scenario_digest, ownedScenarioVersion.digest);
    assert.equal(preflight.plan?.objective, objectiveQuestion);
    stage = "simulate-submit";
    await page.getByRole("button", { name: "Start simulation", exact: true }).click();
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
    const run = await api(`/runs/${id}`);
    assert.equal(run.run_id, id);
    assert.equal(run.scenario_id, ownedScenarioId);
    assert.equal(run.scenario?.title, reviewedScenarioDocument.title);
    assert.equal(run.objective, objectiveQuestion);
    assert.equal(run.mode, "simulate");
    assert.equal(run.autonomy ?? run.autonomy_level, "off");
    assert.ok(sameStructure(withoutLayout(run.scenario), reviewedScenarioDocument));
    assert.ok(sameStructure(run.plan, preflight.plan), "Finalized run must retain its reviewed preflight plan");
    const planFingerprint = createHash("sha256").update(JSON.stringify(stableValue(run.plan))).digest("hex");
    runPlanFingerprints.push({ run_id: id, plan_fingerprint: planFingerprint });
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
  assert.equal(reopened.document.id, ownedScenarioId);
  assert.equal(reopened.document.purpose, objectiveQuestion);
  const original = (await api(`/scenario-versions/${saved.scenario_id}/versions/${saved.version}`)).scenario;
  assert.equal(original.digest, saved.digest);
  assert.equal(original.document.id, ownedScenarioId);
  assert.equal(original.document.purpose, objectiveQuestion);
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
  const sourceEligibility = page.getByLabel("Selected source eligibility", { exact: true });
  await sourceEligibility.getByText("Synthetic simulation", { exact: true }).waitFor();
  await sourceEligibility.getByText("Source details", { exact: true }).click();
  await sourceEligibility.getByText("Run-linked records may inform a hypothesis, but cannot support observed exercise.", { exact: true }).waitFor();
  await sourceEligibility.getByText("Source details", { exact: true }).click();
  const sourceRun = await api("/runs/" + firstRunId);
  assert.equal(sourceRun.run_id, firstRunId);
  assert.equal(sourceRun.mode, "simulate");
  assert.notEqual(sourceRun.is_demo, true);
  const sourceCandidates = sourceRun.detections?.candidates;
  assert.ok(Array.isArray(sourceCandidates) && sourceCandidates.length > 0);
  const sourceCandidate = sourceCandidates[0];
  assert.equal(sourceCandidate.target_language, "internal");
  sourceDetectionId = sourceCandidate.candidate_id;
  assert.match(sourceDetectionId ?? "", /^detection-[0-9a-f]{20}$/);
  expectedMaliciousFixtures = [syntheticFixture(sourceCandidate.selection, "synthetic-selection-example")];
  expectedBenignFixtures = [benignNonmatchFixture(sourceCandidate.selection, "synthetic-benign-nonmatch")];
  const selectedSourceCandidate = page.locator(".candidate-list button[aria-pressed='true']");
  await selectedSourceCandidate.waitFor();
  assert.ok((await selectedSourceCandidate.innerText()).includes(sourceCandidate.title));
  await selectedSourceCandidate.click();
  await page.waitForFunction(({ runId, candidateId }) => {
    const params = new URLSearchParams(window.location.hash.split("?")[1]);
    return params.get("run") === runId && params.get("candidate") === candidateId && !params.has("candidate_scope");
  }, { runId: firstRunId, candidateId: sourceDetectionId });
  await sourceSummary.click();
  await capture("detection-lab-source-run-evidence");
  await sourceSummary.click();
  stage = "detection-save-source-hypothesis";
  const importResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/detections/from-run" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save hypothesis from run", exact: true }).click();
  const imported = await (await importResponse).json();
  const importedDocument = detectionDocument(imported);
  ownedDetectionId = imported.candidate.id;
  assert.match(ownedDetectionId ?? "", /^detection-[0-9a-f]{20}$/);
  assert.equal(importedDocument.candidate_id, ownedDetectionId);
  assert.equal(importedDocument.state, "hypothesis");
  assert.equal(importedDocument.revision, 1);
  assert.equal(imported.source_run_id, firstRunId);
  assert.equal(imported.source_candidate_id, sourceDetectionId);
  assert.deepEqual(importedDocument.selection, sourceCandidate.selection);
  stage = "detection-validate-owned-hypothesis";
  const parseResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/detections/" + ownedDetectionId + "/parse" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Validate source", exact: true }).click();
  const parsedDocument = detectionDocument(await (await parseResponse).json());
  assert.equal(parsedDocument.candidate_id, ownedDetectionId);
  assert.equal(parsedDocument.state, "parsed");
  stage = "detection-exercise-owned-fixture";
  await page.getByRole("tab", { name: "Fixtures", exact: true }).click();
  const maliciousInput = page.getByRole("textbox", { name: /^Malicious fixtures JSON\b/ });
  const uiMaliciousFixtures = JSON.parse(await maliciousInput.inputValue());
  assert.deepEqual(uiMaliciousFixtures, expectedMaliciousFixtures);
  const fixtureResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/detections/" + ownedDetectionId + "/exercise-fixtures" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Exercise malicious fixtures", exact: true }).click();
  const exercisedDocument = detectionDocument(await (await fixtureResponse).json());
  assert.equal(exercisedDocument.state, "fixture_exercised");
  assert.deepEqual(exercisedDocument.malicious_fixture_ids, ["synthetic-selection-example"]);
  assert.equal(exercisedDocument.match_count, 1);
  await page.waitForFunction(() => {
    const selected = document.querySelector(".candidate-list button[aria-pressed='true']");
    return selected?.textContent?.includes("Fixture exercised")
      && document.querySelector(".candidate-workspace")?.getAttribute("data-active-tab") === "fixtures";
  });
  stage = "detection-evaluate-benign-fixture";
  await page.getByRole("tab", { name: "Fixtures", exact: true }).click();
  await page.getByText("Advanced benign samples JSON", { exact: true }).click();
  await page.getByRole("textbox", { name: /^Benign fixtures JSON\b/ }).fill(JSON.stringify(expectedBenignFixtures, null, 2));
  await page.getByRole("textbox", { name: /^Benign evaluation notes\b/ }).fill("Owned synthetic benign nonmatch fixture.");
  const benignResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/detections/" + ownedDetectionId + "/evaluate-benign" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Evaluate benign fixtures", exact: true }).click();
  const benignDocument = detectionDocument(await (await benignResponse).json());
  assert.equal(benignDocument.state, "benign_evaluated");
  assert.deepEqual(benignDocument.benign_fixture_ids, ["synthetic-benign-nonmatch"]);
  assert.equal(benignDocument.benign_match_count, 0);
  assert.match(benignDocument.definition_digest ?? "", /^sha256:[0-9a-f]{64}$/);
  report.detection_fixture_evaluation = {
    source_run_id: firstRunId,
    source_run_mode: "simulate",
    source_candidate_id: sourceDetectionId,
    candidate_id: ownedDetectionId,
    revision: benignDocument.revision,
    revision_kind: benignDocument.revision_kind,
    definition_digest: benignDocument.definition_digest,
    state: benignDocument.state,
    matcher: "internal structured fixture matcher",
    fixture_only: true,
    evaluation_scope: "Synthetic matcher fixtures only; not a changed-environment retest.",
    malicious_fixture_ids: benignDocument.malicious_fixture_ids,
    malicious_match_count: benignDocument.match_count,
    benign_fixture_ids: benignDocument.benign_fixture_ids,
    benign_match_count: benignDocument.benign_match_count,
    independent_observations: 0,
    changed_environment_retest: false,
  };
  report.checks.push("run_linked_definition_saved_validated_and_fixture_evaluated");
  stage = "detection-reopen-saved-revision";
  const detectionParams = new URLSearchParams({ run: firstRunId, candidate: ownedDetectionId, candidate_scope: "registry" });
  const detectionReopenUrl = origin + "/#/detection-lab?" + detectionParams.toString();
  if (page.url() === detectionReopenUrl) await page.reload();
  else await page.goto(detectionReopenUrl);
  stage = "detection-reopen-selected-candidate";
  await page.getByRole("heading", { name: "Detection Lab", exact: true }).waitFor();
  const reopenedDetection = page.locator(".candidate-list button[aria-pressed='true']");
  await reopenedDetection.waitFor();
  await reopenedDetection.getByText("Benign fixtures evaluated", { exact: true }).waitFor();
  assert.ok((await reopenedDetection.innerText()).includes(sourceCandidate.title));
  assert.match(await reopenedDetection.innerText(), /Benign fixtures evaluated/);
  stage = "detection-reopen-server-revision";
  const detectionList = await api("/detections");
  const reopenedResource = detectionList.candidates.filter(candidate => candidate.id === ownedDetectionId);
  assert.equal(reopenedResource.length, 1);
  assert.equal(reopenedResource[0].document.revision, benignDocument.revision);
  assert.equal(reopenedResource[0].document.state, benignDocument.state);
  assert.equal(reopenedResource[0].document.definition_digest, benignDocument.definition_digest);
  report.checks.push("saved_detection_revision_reopened_from_registry");
  report.checks.push("detection_lab_linked_to_owned_simulation_source");
  report.checks.push("detection_fixture_tab_preserved_across_lifecycle_update");
  await page.getByRole("tab", { name: "Candidate", exact: true }).click();
  await captureResponsiveSurface({
    name: "detection-lab",
    heading: "Detection Lab",
    controls: [
      { label: "Detection source run", locator: page.getByRole("combobox", { name: /^Detection source run\b/ }), textFits: false, bringIntoView: true },
      { label: "Source evidence", locator: sourceSummary, textFits: true, bringIntoView: true },
    ],
  });

  stage = "detection-create-owned-navigation-revision";
  const parentBeforeNavigationRevision = JSON.parse(JSON.stringify(reopenedResource[0].document));
  const navigationRevisionTitle = "Installed comparison navigation revision";
  const navigationRevisionReason = "Create one owned child revision to verify missing-evaluation navigation and return to its saved comparison.";
  expectedOwnedRevisionCloneBody = {
    reason: navigationRevisionReason,
    title: navigationRevisionTitle,
    ...(importedDocument.provenance ? { provenance: importedDocument.provenance } : {}),
    ...(importedDocument.known_misses ? { known_misses: importedDocument.known_misses } : {}),
    public_baselines: importedDocument.public_baselines ?? [],
    ...(importedDocument.predicted_fields ? { predicted_fields: importedDocument.predicted_fields } : {}),
  };
  await page.getByRole("tab", { name: "Revisions", exact: true }).click();
  const advancedRevisions = page.locator("details.detection-advanced-revisions");
  if (!await advancedRevisions.evaluate(element => element.open)) await advancedRevisions.locator(":scope > summary").click();
  await page.getByRole("radio", { name: /^Clone unchanged rule behavior\b/ }).check();
  stage = "detection-navigation-revision-fill-title";
  await page.getByRole("textbox", { name: "Revision title", exact: true }).fill(navigationRevisionTitle);
  stage = "detection-navigation-revision-fill-reason";
  await advancedRevisions.getByRole("textbox", { name: "Required research reason", exact: true }).fill(navigationRevisionReason);
  stage = "detection-navigation-revision-clone-submit";
  const navigationRevisionResponsePromise = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/detections/${ownedDetectionId}/clone` && response.request().method() === "POST");
  await page.getByRole("button", { name: "Create immutable clone", exact: true }).click();
  const navigationRevisionResponse = await navigationRevisionResponsePromise;
  assert.equal(navigationRevisionResponse.status(), 201);
  const navigationRevisionEnvelope = await navigationRevisionResponse.json();
  const navigationRevisionDocument = detectionDocument(navigationRevisionEnvelope);
  ownedDetectionRevisionId = navigationRevisionEnvelope.candidate.id;
  assert.match(ownedDetectionRevisionId, /^detection-[0-9a-f]{20}$/);
  assert.notEqual(ownedDetectionRevisionId, ownedDetectionId);
  assert.equal(navigationRevisionDocument.candidate_id, ownedDetectionRevisionId);
  assert.equal(navigationRevisionDocument.revision, 2);
  assert.equal(navigationRevisionDocument.revision_root_id, ownedDetectionId);
  assert.equal(navigationRevisionDocument.parent_candidate_id, ownedDetectionId);
  assert.equal(navigationRevisionDocument.revision_kind, "clone");
  assert.equal(navigationRevisionDocument.state, "hypothesis");
  assert.equal(navigationRevisionDocument.title, navigationRevisionTitle);
  assert.deepEqual(navigationRevisionDocument.tuning_decisions?.slice(-1), [navigationRevisionReason]);
  await page.waitForFunction(id => {
    const params = new URLSearchParams(window.location.hash.split("?")[1]);
    return params.get("candidate") === id && params.get("candidate_scope") === "registry";
  }, ownedDetectionRevisionId);
  await page.getByRole("tab", { name: "Candidate", exact: true }).click();
  stage = "detection-navigation-revision-child-parse";
  const navigationRevisionParseResponsePromise = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/detections/${ownedDetectionRevisionId}/parse` && response.request().method() === "POST");
  await page.getByRole("button", { name: "Validate source", exact: true }).click();
  const navigationRevisionParseResponse = await navigationRevisionParseResponsePromise;
  assert.equal(navigationRevisionParseResponse.status(), 200);
  const parsedNavigationRevision = detectionDocument(await navigationRevisionParseResponse.json());
  assert.equal(parsedNavigationRevision.candidate_id, ownedDetectionRevisionId);
  assert.equal(parsedNavigationRevision.revision, 2);
  assert.equal(parsedNavigationRevision.revision_root_id, ownedDetectionId);
  assert.equal(parsedNavigationRevision.parent_candidate_id, ownedDetectionId);
  assert.equal(parsedNavigationRevision.revision_kind, "clone");
  assert.equal(parsedNavigationRevision.state, "parsed");
  const registeredNavigationFamily = (await api("/detections")).candidates.filter(candidate => candidate.document.revision_root_id === ownedDetectionId);
  assert.equal(registeredNavigationFamily.length, 2);
  const registeredParent = registeredNavigationFamily.find(candidate => candidate.id === ownedDetectionId);
  const registeredChild = registeredNavigationFamily.find(candidate => candidate.id === ownedDetectionRevisionId);
  assert.ok(registeredParent && registeredChild);
  assert.deepEqual(registeredParent.document, parentBeforeNavigationRevision);
  assert.equal(registeredParent.document.definition_digest, reopenedResource[0].document.definition_digest);
  assert.equal(registeredParent.document.state, reopenedResource[0].document.state);
  assert.equal(registeredChild.document.definition_digest, parsedNavigationRevision.definition_digest);
  assert.equal(registeredChild.document.state, "parsed");
  const parentRunEvaluations = await api(`/detections/${ownedDetectionId}/evaluations`);
  const childRunEvaluations = await api(`/detections/${ownedDetectionRevisionId}/evaluations`);
  assert.equal(parentRunEvaluations.candidate_id, ownedDetectionId);
  assert.equal(childRunEvaluations.candidate_id, ownedDetectionRevisionId);
  assert.deepEqual(parentRunEvaluations.evaluations, []);
  assert.deepEqual(childRunEvaluations.evaluations, []);
  report.detection_navigation_revision = {
    parent_candidate_id: ownedDetectionId,
    parent_revision: registeredParent.document.revision,
    parent_definition_digest: registeredParent.document.definition_digest,
    candidate_id: ownedDetectionRevisionId,
    revision: registeredChild.document.revision,
    revision_root_id: registeredChild.document.revision_root_id,
    parent_id: registeredChild.document.parent_candidate_id,
    definition_digest: registeredChild.document.definition_digest,
    revision_kind: registeredChild.document.revision_kind,
    state: registeredChild.document.state,
    evaluation_count: childRunEvaluations.evaluations.length,
    created_through: "Detection Lab clone and validate controls",
  };
  report.checks.push("one_owned_parsed_revision_created_for_missing_evaluation_navigation");

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
  const savedComparison = await api(`/comparison-snapshots/${report.comparison_snapshot_id}`);
  assert.equal(savedComparison.snapshot_id, report.comparison_snapshot_id);
  assert.deepEqual(savedComparison.comparison.run_ids, ownedRunIds);
  assert.deepEqual(savedComparison.source_bindings.map(binding => binding.run_id), ownedRunIds);
  assert.equal(savedComparison.source_integrity?.status, "verified");
  assert.ok(savedComparison.comparison.deltas?.every(delta => delta.objective_changed === false));
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  await capture("saved-two-run-comparison");
  report.objective_continuity.runs = runPlanFingerprints;
  report.objective_continuity.comparison_snapshot_id = report.comparison_snapshot_id;
  report.objective_continuity.comparison_run_ids = [...savedComparison.comparison.run_ids];
  await page.goto(`${origin}/#/compare`);
  const comparisonHistory = page.locator("details.saved-comparisons-browser");
  const comparisonHistorySummary = comparisonHistory.locator(":scope > summary");
  await comparisonHistorySummary.waitFor();
  if (!await comparisonHistory.evaluate(element => element.open)) await comparisonHistorySummary.click();
  await page.locator(`button[data-snapshot-id=${JSON.stringify(report.comparison_snapshot_id)}]`).click();
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  assert.match(new URL(page.url()).hash, new RegExp(`snapshot=${report.comparison_snapshot_id}`));
  const reopenedComparison = await api(`/comparison-snapshots/${report.comparison_snapshot_id}`);
  assert.deepEqual(reopenedComparison.comparison.run_ids, ownedRunIds);
  assert.deepEqual(reopenedComparison.source_bindings.map(binding => binding.run_id), ownedRunIds);
  report.checks.push("saved_comparison_reopened_with_exact_scenario_objective_and_plan_run_lineage");
  stage = "comparison-reload-saved-history";
  if (!await comparisonHistory.evaluate(element => element.open)) await comparisonHistorySummary.click();
  const historyReloadResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/comparison-snapshots" && response.request().method() === "GET");
  const snapshotReloadResponse = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/comparison-snapshots/${report.comparison_snapshot_id}` && response.request().method() === "GET");
  await comparisonHistory.getByRole("button", { name: "Reload saved comparisons", exact: true }).click();
  const reloadedHistory = await (await historyReloadResponse).json();
  const reloadedSnapshot = await (await snapshotReloadResponse).json();
  const reloadedHistoryItem = reloadedHistory.snapshots.find(item => item.snapshot_id === report.comparison_snapshot_id);
  assert.ok(reloadedHistoryItem);
  assert.deepEqual(reloadedHistoryItem.run_ids, ownedRunIds);
  assert.equal(reloadedSnapshot.snapshot_id, report.comparison_snapshot_id);
  assert.deepEqual(reloadedSnapshot.comparison.run_ids, ownedRunIds);
  assert.deepEqual(reloadedSnapshot.source_bindings.map(binding => binding.run_id), ownedRunIds);
  assert.equal(reloadedSnapshot.source_integrity?.status, "verified");
  assert.match(new URL(page.url()).hash, new RegExp(`snapshot=${report.comparison_snapshot_id}`));
  if (await comparisonHistory.evaluate(element => element.open)) await comparisonHistorySummary.click();
  await page.getByRole("region", { name: "Comparison conclusion", exact: true }).waitFor();
  report.checks.push("saved_comparison_history_reload_preserves_selected_snapshot_and_source_integrity");
  await capture("reopened-saved-comparison");
  await captureResponsiveSurface({
    name: "comparison",
    heading: "Compare runs",
    controls: [{ label: "Saved comparisons", locator: comparisonHistorySummary, textFits: true }],
  });

  stage = "comparison-select-owned-revisions-for-missing-evaluation";
  const snapshotBeforeHandoff = await api(`/comparison-snapshots/${report.comparison_snapshot_id}`);
  assert.equal(snapshotBeforeHandoff.digest, reloadedSnapshot.digest);
  assert.deepEqual(snapshotBeforeHandoff.comparison.run_ids, ownedRunIds);
  assert.deepEqual(snapshotBeforeHandoff.source_bindings, reloadedSnapshot.source_bindings);
  assert.equal(snapshotBeforeHandoff.source_integrity?.status, "verified");
  const currentDetectorEvaluations = page.getByRole("region", { name: "Current detector evaluations", exact: true });
  await currentDetectorEvaluations.waitFor();
  const originalDetectorSelect = currentDetectorEvaluations.getByRole("combobox", { name: "Original detector", exact: true });
  const revisedDetectorSelect = currentDetectorEvaluations.getByRole("combobox", { name: "Revised detector", exact: true });
  await originalDetectorSelect.selectOption(ownedDetectionId);
  await revisedDetectorSelect.selectOption(ownedDetectionRevisionId);
  const measuredDetectorComparison = page.getByRole("region", { name: "Measured detector comparison", exact: true });
  await measuredDetectorComparison.waitFor();
  assert.equal(await originalDetectorSelect.inputValue(), ownedDetectionId);
  assert.equal(await revisedDetectorSelect.inputValue(), ownedDetectionRevisionId);
  assert.equal(new URL(page.url()).hash.includes(`snapshot=${report.comparison_snapshot_id}`), true);
  const missingRevisionEvaluation = measuredDetectorComparison.getByRole("link", { name: "Evaluate revised on this run", exact: true }).first();
  await missingRevisionEvaluation.waitFor();
  const missingRevisionHref = await missingRevisionEvaluation.getAttribute("href");
  assert.ok(missingRevisionHref);
  const handoffHref = new URL(missingRevisionHref, origin);
  assert.equal(handoffHref.hash.split("?")[0], "#/detection-lab");
  const handoffQuery = new URLSearchParams(handoffHref.hash.slice(handoffHref.hash.indexOf("?") + 1));
  assert.equal(handoffQuery.get("run"), ownedRunIds[0]);
  assert.equal(handoffQuery.get("candidate"), ownedDetectionRevisionId);
  assert.equal(handoffQuery.get("candidate_scope"), "registry");
  assert.equal(handoffQuery.get("view"), "evaluations");
  assert.equal(handoffQuery.get("snapshot"), report.comparison_snapshot_id);
  assert.equal(handoffQuery.get("compare_context"), "1");
  assert.deepEqual(handoffQuery.getAll("compare_run"), ownedRunIds);
  assert.equal(handoffQuery.get("compare_baseline"), ownedDetectionId);
  assert.equal(handoffQuery.get("compare_revised"), ownedDetectionRevisionId);
  const comparisonPostsBeforeHandoff = comparisonPosts;
  const evaluationPostsBeforeHandoff = detectionRunEvaluationPosts;
  const blockedRequestsBeforeHandoff = report.blocked_requests.length;
  await missingRevisionEvaluation.click();
  stage = "comparison-missing-evaluation-handoff";
  await page.getByRole("heading", { name: "Detection Lab", exact: true }).waitFor();
  const returnToComparison = page.getByRole("button", { name: "Return to comparison", exact: true });
  await returnToComparison.waitFor();
  const eligibleRunEvaluation = page.getByRole("button", { name: "Evaluate full observed run", exact: true });
  await eligibleRunEvaluation.waitFor();
  assert.equal(await eligibleRunEvaluation.isEnabled(), true);
  const handoffLocation = new URL(page.url());
  assert.equal(handoffLocation.hash.split("?")[0], "#/detection-lab");
  const handoffLocationQuery = new URLSearchParams(handoffLocation.hash.slice(handoffLocation.hash.indexOf("?") + 1));
  assert.equal(handoffLocationQuery.get("run"), ownedRunIds[0]);
  assert.equal(handoffLocationQuery.get("candidate"), ownedDetectionRevisionId);
  assert.equal(handoffLocationQuery.get("candidate_scope"), "registry");
  assert.equal(handoffLocationQuery.get("view"), "evaluations");
  assert.equal(handoffLocationQuery.get("snapshot"), report.comparison_snapshot_id);
  const revisionHistoryAtHandoff = await api(`/detections/${ownedDetectionRevisionId}/evaluations`);
  assert.deepEqual(revisionHistoryAtHandoff.evaluations, []);
  await returnToComparison.click();
  stage = "comparison-return-saved-snapshot";
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  await page.getByRole("region", { name: "Current detector evaluations", exact: true }).waitFor();
  const returnedSnapshot = await api(`/comparison-snapshots/${report.comparison_snapshot_id}`);
  assert.equal(returnedSnapshot.snapshot_id, report.comparison_snapshot_id);
  assert.equal(returnedSnapshot.digest, snapshotBeforeHandoff.digest);
  assert.deepEqual(returnedSnapshot.comparison.run_ids, snapshotBeforeHandoff.comparison.run_ids);
  assert.deepEqual(returnedSnapshot.source_bindings, snapshotBeforeHandoff.source_bindings);
  assert.deepEqual(returnedSnapshot.source_bindings.map(binding => binding.run_id), ownedRunIds);
  assert.equal(returnedSnapshot.source_integrity?.status, "verified");
  assert.deepEqual(returnedSnapshot.source_integrity.runs.map(run => run.status), ["verified", "verified"]);
  const returnedLocation = new URL(page.url());
  assert.equal(returnedLocation.hash.split("?")[0], "#/compare");
  const returnedQuery = new URLSearchParams(returnedLocation.hash.slice(returnedLocation.hash.indexOf("?") + 1));
  assert.equal(returnedQuery.get("snapshot"), report.comparison_snapshot_id);
  assert.equal(returnedQuery.get("compare_context"), "1");
  assert.deepEqual(returnedQuery.getAll("compare_run"), ownedRunIds);
  assert.equal(returnedQuery.get("compare_baseline"), ownedDetectionId);
  assert.equal(returnedQuery.get("compare_revised"), ownedDetectionRevisionId);
  const returnedOriginalSelect = page.getByRole("region", { name: "Current detector evaluations", exact: true }).getByRole("combobox", { name: "Original detector", exact: true });
  const returnedRevisedSelect = page.getByRole("region", { name: "Current detector evaluations", exact: true }).getByRole("combobox", { name: "Revised detector", exact: true });
  assert.equal(await returnedOriginalSelect.inputValue(), ownedDetectionId);
  assert.equal(await returnedRevisedSelect.inputValue(), ownedDetectionRevisionId);
  const returnedMissingEvaluation = page.getByRole("region", { name: "Measured detector comparison", exact: true }).getByRole("link", { name: "Evaluate revised on this run", exact: true }).first();
  await returnedMissingEvaluation.waitFor();
  assert.equal(comparisonPosts, comparisonPostsBeforeHandoff);
  assert.equal(detectionRunEvaluationPosts, evaluationPostsBeforeHandoff);
  assert.equal(report.blocked_requests.length, blockedRequestsBeforeHandoff);
  const revisionHistoryAfterReturn = await api(`/detections/${ownedDetectionRevisionId}/evaluations`);
  assert.deepEqual(revisionHistoryAfterReturn.evaluations, []);
  report.comparison_missing_evaluation_handoff = {
    snapshot_id: report.comparison_snapshot_id,
    snapshot_digest: returnedSnapshot.digest,
    run_ids: returnedSnapshot.comparison.run_ids,
    source_integrity: returnedSnapshot.source_integrity.status,
    baseline_candidate_id: ownedDetectionId,
    revised_candidate_id: ownedDetectionRevisionId,
    missing_run_id: ownedRunIds[0],
    returned_same_snapshot: true,
    evaluation_submitted: false,
    comparison_posts_during_handoff: comparisonPosts - comparisonPostsBeforeHandoff,
    evaluation_posts_during_handoff: detectionRunEvaluationPosts - evaluationPostsBeforeHandoff,
    blocked_requests_during_handoff: report.blocked_requests.length - blockedRequestsBeforeHandoff,
  };
  report.checks.push("saved_comparison_missing_evaluation_return_preserves_exact_snapshot_and_revision_selection");

  stage = "comparison-assistant-explain-saved-snapshot";
  const comparisonAssistantPath = `/api/v1/comparison-snapshots/${report.comparison_snapshot_id}/assistant-context`;
  const blockedBeforeComparisonAssistant = report.blocked_requests.length;
  readOnlyCapturePhase = true;
  try {
    const contextResponsePromise = page.waitForResponse(response => new URL(response.url()).pathname === comparisonAssistantPath && response.request().method() === "GET");
    const comparisonConclusion = page.getByRole("region", { name: "Comparison conclusion", exact: true });
    const explainComparison = comparisonConclusion.getByRole("button", { name: "Explain comparison", exact: true });
    await explainComparison.waitFor({ state: "visible" });
    await explainComparison.click();
    const contextResponse = await contextResponsePromise;
    assert.equal(contextResponse.status(), 200);
    const assistantContext = await contextResponse.json();
    const expectedSelection = { kind: "comparison_snapshot", snapshot_id: report.comparison_snapshot_id, snapshot_digest: savedComparison.digest };
    assert.equal(assistantContext.schema_version, "bluefire.assistance-context.v1");
    assert.deepEqual(assistantContext.selected, expectedSelection);
    assert.match(assistantContext.context_digest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(assistantContext.analysis_only, true);
    assert.deepEqual(assistantContext.capabilities, []);
    assert.equal(assistantContext.reference_summary.schema_version, "bluefire.comparison-assistance-summary.v1");
    assert.equal(assistantContext.reference_summary.saved_comparison.run_count, 2);
    assert.equal(assistantContext.reference_summary.saved_comparison.baseline_position, 1);
    assert.equal(assistantContext.reference_summary.source_integrity.runs.length, 2);
    const assistant = page.getByRole("complementary", { name: "BlueFire Assistant", exact: true });
    const evidenceSummary = assistant.locator(".assistant-source-details > summary");
    await assistant.getByRole("region", { name: "Current selection", exact: true }).waitFor();
    await assistant.getByRole("group", { name: "Saved comparison summary", exact: true })
      .getByText(/saved runs · run 1 is the recorded baseline/i).waitFor();
    await evidenceSummary.waitFor({ state: "visible" });
    await evidenceSummary.click();
    await assistant.locator(".assistant-source-details").getByText(/saved runs · run 1 is the recorded baseline/i).waitFor();
    await assistant.getByRole("button", { name: "Assistant settings", exact: true }).click();
    const assistantMode = assistant.getByRole("combobox", { name: /^(AI mode|Assistant mode)\b/ });
    assert.ok((await assistantMode.locator("option").allTextContents()).includes("Assist · explanation only"));
    assert.equal(await assistantMode.locator("option:checked").innerText(), "Off");
    await assistant.getByRole("button", { name: "Assistant settings", exact: true }).click();
    report.checks.push("saved_comparison_assistant_fetches_exact_analysis_only_context_without_turn_submission");

    stage = "comparison-assistant-navigate-away-and-reopen";
    await page.getByRole("link", { name: "Overview", exact: true }).click();
    await page.getByRole("heading", { name: "Overview", exact: true }).waitFor();
    const previousSelection = assistant.getByRole("region", { name: "Previous selection", exact: true });
    await previousSelection.waitFor();
    assert.equal(await previousSelection.getByText("Saved comparison", { exact: true }).count(), 1);
    await previousSelection.getByRole("link", { name: "Reopen source", exact: true }).click();
    await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
    assert.ok(new URL(page.url()).hash.includes(`snapshot=${report.comparison_snapshot_id}`));
    await assistant.getByRole("region", { name: "Current selection", exact: true }).waitFor();
    await evidenceSummary.waitFor({ state: "visible" });

    const fontResponse = await Promise.race([
      fontResponsePromise,
      new Promise(resolve => setTimeout(() => resolve(undefined), 3000)),
    ]);
    assert.ok(fontResponse && fontResponse.status === 200 && fontResponse.bytes > 0 && /^[0-9a-f]{64}$/.test(fontResponse.sha256), "Installed Inter font must be fetched with nonempty response bytes.");
    const fontState = await page.evaluate(async () => {
      await document.fonts.ready;
      const faces = [...document.fonts].filter(face => face.family.replace(/["']/g, "") === "Inter");
      const conclusion = document.querySelector(".comparison-conclusion h2");
      return {
        font_set_status: document.fonts.status,
        faces: faces.map(face => ({ family: face.family.replace(/["']/g, ""), status: face.status, weight: face.weight })),
        check: document.fonts.check('400 16px "Inter"', "BlueFire comparison"),
        conclusion_family: conclusion ? getComputedStyle(conclusion).fontFamily : "",
      };
    });
    assert.ok(fontState.faces.some(face => face.status === "loaded"), "Inter must be loaded in document.fonts.");
    assert.equal(fontState.check, true);
    assert.match(fontState.conclusion_family, /Inter/);
    report.font_asset = { network_response: fontResponse, document_font_state: fontState };

    for (const viewport of [{ width: 1440, height: 900 }, { width: 1366, height: 768 }]) {
      stage = `comparison-assistant-${viewport.width}x${viewport.height}`;
      await page.setViewportSize(viewport);
      await page.evaluate(() => {
        window.scrollTo({ top: 0, left: 0, behavior: "instant" });
        document.getElementById("main-content")?.scrollTo({ top: 0, left: 0, behavior: "instant" });
        document.querySelector(".assistant-body")?.scrollTo({ top: 0, left: 0, behavior: "instant" });
      });
      await evidenceSummary.scrollIntoViewIfNeeded();
      await page.evaluate(async () => { await document.fonts.ready; await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); });
      const geometry = await assistant.evaluate(element => {
        const box = element.getBoundingClientRect();
        const summary = element.querySelector(".assistant-source-details > summary");
        const summaryBox = summary?.getBoundingClientRect();
        return { panel: { left: box.left, right: box.right, top: box.top, bottom: box.bottom }, summary: summaryBox ? { left: summaryBox.left, right: summaryBox.right, top: summaryBox.top, bottom: summaryBox.bottom } : null };
      });
      assert.ok(geometry.panel.left >= -1 && geometry.panel.right <= viewport.width + 1 && geometry.panel.top >= -1 && geometry.panel.bottom <= viewport.height + 1);
      assert.ok(geometry.summary && geometry.summary.left >= -1 && geometry.summary.right <= viewport.width + 1 && geometry.summary.top >= -1 && geometry.summary.bottom <= viewport.height + 1);
      assert.equal(await assistant.getByRole("region", { name: "Current selection", exact: true }).count(), 1);
      await capture(`comparison-assistant-${viewport.width}x${viewport.height}`, {
        surface: "saved-comparison-assistant",
        viewport,
        snapshot_id: report.comparison_snapshot_id,
        font_asset_sha256: fontResponse.sha256,
        loaded_font_faces: fontState.faces.filter(face => face.status === "loaded").length,
        layout_checks: ["assistant_panel_in_viewport", "saved_comparison_context_visible", "bundled_inter_loaded"],
      });
    }
    assert.ok(comparisonAssistantContextGets >= 1 && comparisonAssistantContextGets <= 2);
    assert.equal(comparisonAssistantTurnPosts, 0);
    assert.equal(readOnlyPostAttempts, 0);
    assert.equal(report.blocked_requests.length, blockedBeforeComparisonAssistant);
    report.comparison_assistant = {
      status: "passed",
      snapshot_id: report.comparison_snapshot_id,
      snapshot_digest: assistantContext.selected.snapshot_digest,
      context_digest: assistantContext.context_digest,
      saved_run_count: assistantContext.reference_summary.saved_comparison.run_count,
      selected_exactly: true,
      context_gets: comparisonAssistantContextGets,
      context_capabilities: assistantContext.capabilities.length,
      analysis_only_context: assistantContext.analysis_only,
      active_mode: "Off",
      explanation_mode_available: true,
      assistant_turn_posts: comparisonAssistantTurnPosts,
      read_only_post_attempts: readOnlyPostAttempts,
      reopened_same_snapshot: true,
      screenshots: ["comparison-assistant-1440x900", "comparison-assistant-1366x768"],
    };
    report.checks.push("saved_comparison_assistant_selection_survives_navigation_and_reopens_exact_snapshot");
    report.checks.push("bundled_inter_font_loaded_from_installed_service_and_captured_at_two_desktop_sizes");
    await assistant.getByRole("button", { name: "Close assistant", exact: true }).click();
    await assistant.waitFor({ state: "detached" });
  } finally {
    readOnlyCapturePhase = false;
  }

  stage = "environments-load-overview";
  await page.goto(`${origin}/#/environments`);
  await page.getByRole("heading", { name: "Environments", exact: true }).waitFor();
  for (const name of ["Environment access", "Workspace connections"]) {
    await page.getByRole("heading", { name, exact: true }).waitFor();
  }
  for (const name of ["Cloud access", "File access", "Directory access", "Execution configuration", "Model access"]) {
    await page.getByRole("region", { name, exact: true }).waitFor();
  }
  stage = "environments-capture-overview";
  await capture("environments-overview");
  stage = "environments-capture-model-access";
  await page.getByRole("heading", { name: "Model access", exact: true }).scrollIntoViewIfNeeded();
  await capture("environments-model-access");
  report.checks.push("environments_saved_setup_and_inventory_overview");
  await page.evaluate(() => window.scrollTo({ top: 0, left: 0, behavior: "instant" }));
  await captureResponsiveSurface({
    name: "environments",
    heading: "Environments",
    controls: [{ label: "Open S3 access", locator: page.getByRole("link", { name: "Open S3 access", exact: true }), textFits: true }],
  });

  stage = "file-access-open-unavailable-view";
  await page.getByRole("link", { name: "Open file access", exact: true }).click();
  await page.getByRole("heading", { name: "Effective file access", exact: true }).waitFor();
  const fileReadiness = page.getByRole("region", { name: "File-access enrollment", exact: true });
  await fileReadiness.waitFor();
  await page.getByText("Execution unavailable", { exact: true }).waitFor();
  const fileStatus = await api("/file-access/status");
  assert.equal(fileStatus.available, false);
  const taskReadiness = fileReadiness.locator(".file-access-readiness-facts > div").filter({ has: page.getByText("Task access", { exact: true }) });
  assert.equal(await taskReadiness.locator("dd").innerText(), "Unavailable");
  await page.getByRole("heading", { name: "Saved access work", exact: true }).waitFor();
  const requirements = page.getByText("Task access requirements", { exact: true });
  await page.getByRole("button", { name: "Review task access requirements", exact: true }).click();
  assert.equal(await requirements.evaluate(element => element.closest("details").open), true);
  assert.equal(await requirements.evaluate(element => element === document.activeElement), true);
  await requirements.click();
  report.checks.push("unavailable_file_access_opens_existing_requirements_without_authorizing_work");
  await capture("file-access-unavailable");
  report.checks.push("file_access_unavailable_state_opened_without_authorizing_work");
  await captureResponsiveSurface({
    name: "file-access-unavailable",
    heading: "Effective file access",
    controls: [
      { label: "Refresh state", locator: page.getByRole("button", { name: "Refresh state", exact: true }), textFits: true },
      { label: "Execution unavailable", locator: page.getByText("Execution unavailable", { exact: true }), textFits: true },
    ],
  });

  stage = "assistant-open-detached-selection";
  await page.getByRole("button", { name: "Assistant", exact: true }).click();
  const previousSelection = page.getByRole("region", { name: "Previous selection", exact: true });
  await previousSelection.waitFor();
  stage = "assistant-set-off-mode";
  await page.getByRole("button", { name: "Assistant settings", exact: true }).click();
  const mode = page.getByRole("combobox", { name: /^(AI mode|Assistant mode)\b/ });
  await mode.selectOption("off");
  assert.equal(await page.getByRole("button", { name: /^Start work/ }).isDisabled(), true);
  await page.getByRole("button", { name: "Assistant settings", exact: true }).click();
  stage = "assistant-capture-detached";
  await capture("assistant-detached");
  report.checks.push("detached_assistant_keeps_previous_selection_non_actionable");
  await captureResponsiveSurface({
    name: "docked-assistant",
    heading: "BlueFire Assistant",
    scrollRoot: ".assistant-body",
    controls: [
      { label: "Close assistant", locator: page.getByRole("button", { name: "Close assistant", exact: true }), textFits: false },
      { label: "Reopen source", locator: page.getByRole("link", { name: "Reopen source", exact: true }), textFits: true, bringIntoView: true, withinScroll: true },
      { label: "Assistant settings", locator: page.getByRole("button", { name: "Assistant settings", exact: true }), textFits: false },
      { label: "Message", locator: page.getByRole("textbox", { name: "What would you like to do?", exact: true }), textFits: false },
      { label: "Start work", locator: page.getByRole("button", { name: /^Start work/ }), textFits: false },
    ],
  });
  await page.getByRole("button", { name: "Assistant settings", exact: true }).click();
  await captureResponsiveSurface({
    name: "docked-assistant-settings",
    heading: "BlueFire Assistant",
    scrollRoot: ".assistant-body",
    controls: [
      { label: "AI mode", locator: mode, textFits: false, bringIntoView: true, withinScroll: true },
      { label: "Provider", locator: page.getByRole("combobox", { name: /^(Provider|Assistant provider)\b/ }), textFits: false, bringIntoView: true, withinScroll: true },
      { label: "Close assistant", locator: page.getByRole("button", { name: "Close assistant", exact: true }), textFits: false },
    ],
  });

  assert.equal(preflightPosts, 2);
  assert.equal(simulationRunPosts, 2);
  assert.equal(comparisonPosts, 1);
  assert.equal(sessionPosts, 1);
  assert.equal(scenarioVersionPosts, 2);
  assert.ok(controlListPosts >= 1 && controlListPosts <= 2);
  assert.equal(detectionFromRunPosts, 1);
  assert.equal(detectionParsePosts, 1);
  assert.equal(detectionRevisionClonePosts, 1);
  assert.equal(detectionRevisionParsePosts, 1);
  assert.equal(detectionRunEvaluationPosts, 0);
  assert.equal(detectionFixturePosts, 1);
  assert.equal(detectionBenignPosts, 1);
  report.request_caps = { session_posts: sessionPosts, scenario_version_posts: scenarioVersionPosts, scenario_validation_posts: scenarioValidationPosts, graph_context_posts: graphContextPosts, control_list_posts: controlListPosts, preflight_posts: preflightPosts, simulation_run_posts: simulationRunPosts, comparison_posts: comparisonPosts, detection_from_run_posts: detectionFromRunPosts, detection_parse_posts: detectionParsePosts, detection_revision_clone_posts: detectionRevisionClonePosts, detection_revision_parse_posts: detectionRevisionParsePosts, detection_run_evaluation_posts: detectionRunEvaluationPosts, detection_fixture_posts: detectionFixturePosts, detection_benign_posts: detectionBenignPosts };
  assert.equal(report.errors.length, 0);
  assert.equal(report.blocked_requests.length, 0);
  report.status = "passed";
} catch (error) {
  report.status = "failed_or_incomplete";
  const assertion = error instanceof assert.AssertionError ? {
    operator: ["==", "===", "deepStrictEqual", "notDeepStrictEqual", "notStrictEqual", "fail"].includes(error.operator) ? error.operator : "assertion",
    ...(typeof error.actual === "boolean" || Number.isFinite(error.actual) ? { actual: error.actual } : {}),
    ...(typeof error.expected === "boolean" || Number.isFinite(error.expected) ? { expected: error.expected } : {}),
  } : undefined;
  report.errors.push({ stage, kind: "journey-failed", error_type: error instanceof Error ? error.name : "unknown", ...(assertion ? { assertion } : {}) });
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
