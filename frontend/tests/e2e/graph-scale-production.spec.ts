import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { demoCatalog, demoScenario } from "../../src/lib/demo";
import { parseScenarioDocument } from "../../src/lib/scenario";
import type { Scenario } from "../../src/types";

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const bundle = process.env.BLUEFIRE_S3_BROWSER_BUNDLE!;
const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
const viewports = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];
const nodeCount = 128;
const edgeCount = 256;
const maximumGraphBytes = 65_536;
const warmupCount = 1;
const measuredCount = 5;
const firstId = "scale_step_000";
const behaviorId = "sandbox.fixture.create.v1";

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function graphFixture() {
  const behavior = demoCatalog.behaviors.find(item => item.id === behaviorId);
  const template = demoScenario.steps.find(step => step.behavior_id === behaviorId);
  if (!behavior || behavior.inputs.length !== 0 || !template) throw new Error("The no-input graph fixture behavior is unavailable.");
  const steps = Array.from({ length: nodeCount }, (_, index) => ({
    ...structuredClone(template),
    id: `scale_step_${String(index).padStart(3, "0")}`,
    inputs: {},
  }));
  const edges: Scenario["edges"] = [];
  for (let index = 0; index < nodeCount - 1; index += 1) {
    edges.push({ from_step: steps[index]!.id, outcome: "success", to_step: steps[index + 1]!.id });
  }
  const branchOutcomes = ["partial", "blocked", "failed"] as const;
  for (let index = 0; index < 43; index += 1) {
    branchOutcomes.forEach((outcome, offset) => {
      edges.push({ from_step: steps[index]!.id, outcome, to_step: steps[index + offset + 2]!.id });
    });
  }
  if (edges.length !== edgeCount) throw new Error("The graph fixture edge count is invalid.");
  const scenario = parseScenarioDocument({
    ...demoScenario,
    id: "graph.scale.offline.v1",
    title: "Graph scale offline qualification",
    purpose: "Measure the rendered local graph at the selected-step assistance boundary.",
    start: firstId,
    steps,
    edges,
    layout: {},
  });
  const canonical = canonicalJson(scenario);
  const bytes = Buffer.byteLength(canonical, "utf8");
  if (scenario.steps.length !== nodeCount || scenario.edges.length !== edgeCount || bytes > maximumGraphBytes) {
    throw new Error("The validated graph fixture exceeds its declared scale.");
  }
  return {
    scenario,
    serialized: JSON.stringify(scenario),
    canonicalBytes: bytes,
    canonicalSha256: createHash("sha256").update(canonical).digest("hex"),
  };
}

type RouteState = {
  connected: boolean;
  sessionChecks: number;
  apiReads: string[];
  effects: string[];
  unexpected: number;
  websockets: number;
  pageErrors: number;
  consoleErrors: number;
  errorDetails: string[];
};

async function syntheticSession(page: Page, scenario: Scenario) {
  const session = randomBytes(32).toString("hex");
  const state: RouteState = {
    connected: true, sessionChecks: 0, apiReads: [], effects: [],
    unexpected: 0, websockets: 0, pageErrors: 0, consoleErrors: 0, errorDetails: [],
  };
  const retainError = (message: string) => { if (state.errorDetails.length < 20) state.errorDetails.push(message.slice(0, 2000)); };
  page.on("pageerror", error => { state.pageErrors += 1; retainError(`${error.name}: ${error.message}\n${error.stack ?? ""}`); });
  page.on("console", message => { if (message.type() === "error") { state.consoleErrors += 1; retainError(message.text()); } });
  await page.context().routeWebSocket("**/*", socket => { state.websockets += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    const refuse = async () => { state.unexpected += 1; await route.abort(); };
    if (url.origin !== origin || url.username || url.password || url.search) { await refuse(); return; }
    if (["GET", "HEAD"].includes(method) && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) {
      await route.continue();
      return;
    }
    if (url.pathname === "/api/v1/session") {
      if (method === "GET" && request.headers()["x-bluefire-session"] === session) {
        state.sessionChecks += 1;
        await route.fulfill({ status: 204 });
        return;
      }
      if (method !== "GET") state.effects.push(`${method} ${url.pathname}`);
      await refuse();
      return;
    }
    if (!state.connected || request.headers()["x-bluefire-session"] !== session) { await refuse(); return; }
    if (method !== "GET") {
      state.effects.push(`${method} ${url.pathname}`);
      await refuse();
      return;
    }
    state.apiReads.push(`${method} ${url.pathname}`);
    if (url.pathname === "/api/v1/catalog") { await json(demoCatalog); return; }
    if (url.pathname === "/api/v1/scenarios") { await json({ scenarios: [scenario] }); return; }
    await refuse();
  });
  return { session, state };
}

async function stableFrames(page: Page) {
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
}

async function finishMeasure(page: Page, start: string, end: string): Promise<number> {
  return page.evaluate(async ({ start, end }) => {
    await new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
    performance.mark(end);
    return performance.measure(end, start, end).duration;
  }, { start, end });
}

async function navigationToStableGraphMs(page: Page): Promise<number> {
  return page.evaluate(async () => {
    await new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
    const navigation = performance.getEntriesByType("navigation")[0];
    if (!navigation) throw new Error("Navigation timing is unavailable.");
    return Number((performance.now() - navigation.startTime).toFixed(3));
  });
}

async function beginMeasure(page: Page, start: string) {
  await page.evaluate(name => performance.mark(name), start);
}

async function capture(page: Page, name: string) {
  const path = join(output, `${name}.png`);
  if (existsSync(path)) throw new Error("A graph scale screenshot already exists.");
  await page.locator(".graph-canvas:visible, .ordered-steps:visible").scrollIntoViewIfNeeded();
  await page.evaluate(async () => { await document.fonts.ready; });
  const geometry = await page.evaluate(() => {
    const canvas = document.querySelector<HTMLElement>(".graph-canvas");
    const list = document.querySelector<HTMLElement>(".ordered-steps");
    return {
      viewport: { width: innerWidth, height: innerHeight },
      documentWidth: document.documentElement.clientWidth,
      documentScroll: document.documentElement.scrollWidth,
      canvasWidth: canvas?.clientWidth ?? null,
      listWidth: list?.clientWidth ?? null,
      listScrollWidth: list?.scrollWidth ?? null,
      listScrollHeight: list?.scrollHeight ?? null,
    };
  });
  expect(geometry.documentScroll).toBeLessThanOrEqual(geometry.documentWidth);
  expect(geometry.canvasWidth === null || geometry.canvasWidth <= geometry.documentWidth).toBe(true);
  expect(geometry.listScrollWidth === null || geometry.listScrollWidth <= (geometry.listWidth ?? 0)).toBe(true);
  const image = await page.screenshot({ fullPage: false, animations: "disabled" });
  writeFileSync(path, image, { flag: "wx" });
  return geometry;
}

function percentile(values: number[], p: number): number {
  const ordered = [...values].sort((left, right) => left - right);
  return Number(ordered[Math.ceil(p * ordered.length) - 1]!.toFixed(3));
}

function sampleSummary(values: number[]) {
  const measured = values.slice(warmupCount);
  return {
    warmup_count: warmupCount,
    measured_count: measured.length,
    percentile_method: "nearest-rank",
    p50_ms: percentile(measured, 0.5),
    p95_ms: percentile(measured, 0.95),
  };
}

async function qualifyViewport(page: Page, browser: Browser, viewport: { width: number; height: number }) {
  const fixture = graphFixture();
  const { session, state } = await syntheticSession(page, fixture.scenario);
  const scenarioJson = fixture.serialized;
  await page.addInitScript(({ scenarioJson, scenarioId, behaviorId, session }) => {
    if (sessionStorage.getItem("bluefire.graph-scale-fixture-seeded") === "true") return;
    localStorage.setItem("bluefire.local.scenario.v1", scenarioJson);
    sessionStorage.setItem("bluefire.browser-session.v1", session);
    sessionStorage.setItem(`bluefire.working-graph-view.v1:${scenarioId}`, JSON.stringify({
      scenarioId,
      view: {
        selected: { id: "scale_step_000", behavior: behaviorId }, mode: "graph", allBranches: true,
        expanded: [], section: null, inspector: false, routes: false, inputs: false,
      },
    }));
    sessionStorage.setItem("bluefire.graph-scale-fixture-seeded", "true");
  }, { scenarioJson, scenarioId: fixture.scenario.id, behaviorId, session });
  await page.setViewportSize(viewport);
  await page.goto("./#/builder");
  const heading = page.getByRole("heading", { name: fixture.scenario.title, exact: true, level: 1 });
  await expect(heading).toBeVisible();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
  const initialGraphMountMs = await navigationToStableGraphMs(page);

  await page.getByLabel("Path section").selectOption("0");
  await page.getByRole("button", { name: "Focus on success path", exact: true }).click();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(8);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(7);
  await stableFrames(page);
  const focusedGeometry = await capture(page, `graph-scale-focused-${viewport.width}`);
  const expectedDraft = scenarioJson;
  const readDraft = () => page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"));
  const measures: Record<"focused_to_full_graph" | "full_graph_to_focused_section" | "full_graph_to_ordered_steps" | "retained_full_graph_remount", number[]> = {
    focused_to_full_graph: [],
    full_graph_to_focused_section: [],
    full_graph_to_ordered_steps: [],
    retained_full_graph_remount: [initialGraphMountMs],
  };
  const geometries: Record<string, unknown> = { focused: focusedGeometry };

  const showAll = page.getByRole("button", { name: "Show all branches", exact: true });
  await beginMeasure(page, "warmup-focused-to-full-start");
  await showAll.click();
  await page.getByLabel("Path section").selectOption("all");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
  measures.focused_to_full_graph.push(await finishMeasure(page, "warmup-focused-to-full-start", "warmup-focused-to-full-end"));
  geometries.full_graph = await capture(page, `graph-scale-full-${viewport.width}`);
  expect(await readDraft()).toBe(expectedDraft);

  await beginMeasure(page, "warmup-full-to-steps-start");
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(nodeCount);
  measures.full_graph_to_ordered_steps.push(await finishMeasure(page, "warmup-full-to-steps-start", "warmup-full-to-steps-end"));
  geometries.ordered_steps = await capture(page, `graph-scale-steps-${viewport.width}`);
  expect(await readDraft()).toBe(expectedDraft);

  await page.getByRole("button", { name: "Canvas", exact: true }).click();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await beginMeasure(page, "warmup-full-to-focus-start");
  await page.getByRole("button", { name: "Focus on success path", exact: true }).click();
  await page.getByLabel("Path section").selectOption("0");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(8);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(7);
  measures.full_graph_to_focused_section.push(await finishMeasure(page, "warmup-full-to-focus-start", "warmup-full-to-focus-end"));

  await page.getByRole("button", { name: "Show all branches", exact: true }).click();
  await page.getByLabel("Path section").selectOption("all");
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
  await expect(page.getByRole("button", { name: "Steps", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(nodeCount);
  await page.getByRole("button", { name: "Canvas", exact: true }).click();

  for (let iteration = 1; iteration <= measuredCount; iteration += 1) {
    await beginMeasure(page, `full-to-focus-${iteration}-start`);
    await page.getByRole("button", { name: "Focus on success path", exact: true }).click();
    await page.getByLabel("Path section").selectOption("0");
    await expect(page.locator(".react-flow__node:visible")).toHaveCount(8);
    await expect(page.locator(".react-flow__edge:visible")).toHaveCount(7);
    measures.full_graph_to_focused_section.push(await finishMeasure(page, `full-to-focus-${iteration}-start`, `full-to-focus-${iteration}-end`));
    expect(await readDraft()).toBe(expectedDraft);

    await beginMeasure(page, `focus-to-full-${iteration}-start`);
    await page.getByRole("button", { name: "Show all branches", exact: true }).click();
    await page.getByLabel("Path section").selectOption("all");
    await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
    await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
    measures.focused_to_full_graph.push(await finishMeasure(page, `focus-to-full-${iteration}-start`, `focus-to-full-${iteration}-end`));
    expect(await readDraft()).toBe(expectedDraft);

    await beginMeasure(page, `full-to-steps-${iteration}-start`);
    await page.getByRole("button", { name: "Steps", exact: true }).click();
    await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(nodeCount);
    measures.full_graph_to_ordered_steps.push(await finishMeasure(page, `full-to-steps-${iteration}-start`, `full-to-steps-${iteration}-end`));
    expect(await readDraft()).toBe(expectedDraft);

    await page.getByRole("button", { name: "Canvas", exact: true }).click();
    await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
    const retainedView = await page.evaluate(key => sessionStorage.getItem(key), `bluefire.working-graph-view.v1:${fixture.scenario.id}`);
    const parsedView = retainedView ? JSON.parse(retainedView) as { view?: { section?: number | null; allBranches?: boolean } } : null;
    expect(parsedView?.view).toMatchObject({ section: null, allBranches: true });
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: fixture.scenario.title, exact: true, level: 1 })).toBeVisible();
    await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
    await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
    measures.retained_full_graph_remount.push(await navigationToStableGraphMs(page));
    expect(await readDraft()).toBe(expectedDraft);
  }

  expect(state.connected).toBe(true);
  expect(state.sessionChecks).toBeGreaterThan(0);
  expect(state.apiReads).toContain("GET /api/v1/catalog");
  expect(state.apiReads).toContain("GET /api/v1/scenarios");
  expect(state.apiReads.every(path => ["GET /api/v1/catalog", "GET /api/v1/scenarios"].includes(path))).toBe(true);
  expect(state.effects).toEqual([]);
  expect(await readDraft()).toBe(expectedDraft);
  expect(measures.retained_full_graph_remount).toHaveLength(warmupCount + measuredCount);
  const report = {
    proof: "synthetic-production-bundle-graph-scale-ui-only",
    real_service: false,
    universal_saved_graph_limit: false,
    workload: {
      nodes: nodeCount,
      outcome_edges: edgeCount,
      graph_bytes_limit: maximumGraphBytes,
      canonical_graph_bytes: fixture.canonicalBytes,
      canonical_graph_sha256: fixture.canonicalSha256,
      behavior_id: behaviorId,
      behavior_inputs: 0,
    },
    browser: { engine: "chromium", version: browser.version() },
    bundle: ["app.js", "index.html", "styles.css"].map(name => {
      const bytes = readFileSync(join(bundle, name));
      return { name, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    }),
    viewport,
    methodology: {
      warmup_count: warmupCount,
      measured_count: measuredCount,
      timer: "in-page performance.mark/measure around Playwright UI action through two animation frames after stable DOM assertions",
      remount_timer: "document navigation timing from navigation start through Playwright stable graph assertions and two animation frames; includes app/session/catalog/scenario startup and browser-clock gaps, not isolated React render time",
      harness_overhead: "UI transition samples include Playwright action and locator assertion round trips; retained remount samples use document navigation elapsed time and exclude synthetic code entry",
      percentile_method: "nearest-rank",
    },
    retained_initial_full_graph_mount_ms: initialGraphMountMs,
    geometry: geometries,
    raw_samples_ms: measures,
    summaries: Object.fromEntries(Object.entries(measures).map(([name, values]) => [name, sampleSummary(values)])),
    effect_audit: {
      synthetic_session_seeded: true,
      session_checks: state.sessionChecks,
      api_reads: state.apiReads,
      effects: state.effects,
      unexpected_routes: state.unexpected,
      websockets: state.websockets,
      page_errors: state.pageErrors,
      console_errors: state.consoleErrors,
      error_details: state.errorDetails,
      serialized_draft_unchanged: true,
    },
  };
  const reportPath = join(output, `graph-scale-${viewport.width}-report.json`);
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
  expect({ unexpected: state.unexpected, websockets: state.websockets, pageErrors: state.pageErrors, consoleErrors: state.consoleErrors })
    .toEqual({ unexpected: 0, websockets: 0, pageErrors: 0, consoleErrors: 0 });
}

for (const viewport of viewports) {
  test(`offline graph scale remains usable at ${viewport.width}px`, async ({ page, browser }) => {
    await qualifyViewport(page, browser, viewport);
  });
}
