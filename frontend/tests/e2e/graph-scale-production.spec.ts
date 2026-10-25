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
const viewports = [{ width: 1440, height: 900 }, { width: 1366, height: 768 }];
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

async function viewOptions(page: Page, open: boolean) {
  if (await page.locator("details.graph-options").evaluate(element => (element as HTMLDetailsElement).open) !== open) {
    await page.getByLabel("View options", { exact: true }).click();
  }
}

async function expectReadableSelection(page: Page) {
  await expect(page.locator(".flow-node.selected")).toHaveCount(1);
  await expect.poll(() => page.locator(".flow-node.selected").evaluate(node => {
    const card = node.getBoundingClientRect(), canvas = node.closest(".graph-canvas")!.getBoundingClientRect();
    const title = node.querySelector<HTMLElement>(".node-title > strong");
    const titleBox = title?.getBoundingClientRect();
    return {
      readableScale: card.width >= 176 && card.height > 0,
      withinCanvas: card.left >= canvas.left - 1 && card.right <= canvas.right + 1
        && card.top >= canvas.top - 1 && card.bottom <= canvas.bottom + 1,
      readableTitle: Boolean(title?.textContent?.trim() && titleBox && title.scrollWidth <= title.clientWidth + 1
        && titleBox.left >= card.left - 1 && titleBox.right <= card.right + 1
        && titleBox.top >= card.top - 1 && titleBox.bottom <= card.bottom + 1),
    };
  })).toEqual({ readableScale: true, withinCanvas: true, readableTitle: true });
}

async function focusConnectedTail(page: Page) {
  const previousSelection = await page.locator(".react-flow__node.selected").getAttribute("data-id");
  await viewOptions(page, true);
  // The last branch rejoins at zero-based step 46. Its 82-step continuation is
  // a connected path in this fixture, not a numeric page of arbitrary size.
  await page.getByLabel("Step group", { exact: true }).selectOption({ label: "Join at step 47 · 82 steps" });
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(82);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(81);
  await viewOptions(page, false);
  const expectedSelection = previousSelection && Number(previousSelection.slice(-3)) >= 46 ? previousSelection : "scale_step_046";
  await expect(page.locator(".react-flow__node.selected")).toHaveAttribute("data-id", expectedSelection);
  await expectReadableSelection(page);
}

async function showWholePlan(page: Page) {
  const selected = await page.locator(".react-flow__node.selected").getAttribute("data-id");
  expect(selected).not.toBeNull();
  await page.getByRole("button", { name: "Return to whole plan", exact: true }).click();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
  await expect(page.locator(".react-flow__node.selected")).toHaveAttribute("data-id", selected!);
  await expectReadableSelection(page);
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
    const selected = canvas?.querySelector<HTMLElement>(".flow-node.selected");
    const selectedBox = selected?.getBoundingClientRect();
    return {
      viewport: { width: innerWidth, height: innerHeight },
      documentWidth: document.documentElement.clientWidth,
      documentScroll: document.documentElement.scrollWidth,
      canvasWidth: canvas?.clientWidth ?? null,
      listWidth: list?.clientWidth ?? null,
      listScrollWidth: list?.scrollWidth ?? null,
      listScrollHeight: list?.scrollHeight ?? null,
      selectedCardWidth: selectedBox?.width ?? null,
      selectedCardHeight: selectedBox?.height ?? null,
      zoomPercent: canvas ? Number.parseInt(document.querySelector('[aria-label="Graph zoom"]')?.textContent ?? "", 10) : null,
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
    sessionStorage.setItem(`bluefire.working-graph-view.v2:${scenarioId}`, JSON.stringify({
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

  await focusConnectedTail(page);
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

  await beginMeasure(page, "warmup-focused-to-full-start");
  await showWholePlan(page);
  measures.focused_to_full_graph.push(await finishMeasure(page, "warmup-focused-to-full-start", "warmup-focused-to-full-end"));
  geometries.full_graph = await capture(page, `graph-scale-full-${viewport.width}`);
  expect(await readDraft()).toBe(expectedDraft);

  const selectedBeforeOverview = await page.locator(".react-flow__node.selected").getAttribute("data-id");
  expect(selectedBeforeOverview).not.toBeNull();
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
  await expect.poll(() => page.locator(".react-flow__node:visible").evaluateAll(nodes => {
    const canvas = document.querySelector(".graph-canvas")!.getBoundingClientRect();
    return nodes.every(node => {
      const card = node.getBoundingClientRect();
      return card.width > 0 && card.height > 0 && card.left >= canvas.left - 1 && card.right <= canvas.right + 1
        && card.top >= canvas.top - 1 && card.bottom <= canvas.bottom + 1;
    });
  })).toBe(true);
  await expect(page.locator(".react-flow__node.selected")).toHaveAttribute("data-id", selectedBeforeOverview!);
  expect(await page.locator(".flow-node.selected").evaluate(node => node.getBoundingClientRect().width)).toBeLessThan(176);
  geometries.explicit_overview = await capture(page, `graph-scale-explicit-overview-${viewport.width}`);
  expect(await readDraft()).toBe(expectedDraft);
  await viewOptions(page, true);
  await page.getByRole("button", { name: "Focus selected step", exact: true }).click();
  await viewOptions(page, false);
  await expectReadableSelection(page);
  await expect(page.locator(".react-flow__node.selected")).toHaveAttribute("data-id", selectedBeforeOverview!);
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(edgeCount);
  geometries.readable_after_explicit_overview = await capture(page, `graph-scale-overview-restored-${viewport.width}`);
  expect(await readDraft()).toBe(expectedDraft);

  await beginMeasure(page, "warmup-full-to-steps-start");
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(nodeCount);
  measures.full_graph_to_ordered_steps.push(await finishMeasure(page, "warmup-full-to-steps-start", "warmup-full-to-steps-end"));
  geometries.ordered_steps = await capture(page, `graph-scale-steps-${viewport.width}`);
  expect(await readDraft()).toBe(expectedDraft);
  await page.locator('.ordered-steps button[data-step-id="scale_step_127"]').click();

  await page.getByRole("button", { name: "Canvas", exact: true }).click();
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
  await expect(page.locator('.react-flow__node[data-id="scale_step_127"]')).toHaveClass(/selected/);
  await page.getByRole("button", { name: "Hide node inspector", exact: true }).click();
  await beginMeasure(page, "warmup-full-to-focus-start");
  await focusConnectedTail(page);
  measures.full_graph_to_focused_section.push(await finishMeasure(page, "warmup-full-to-focus-start", "warmup-full-to-focus-end"));

  await showWholePlan(page);
  await expect(page.getByRole("button", { name: "Steps", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(nodeCount);
  await page.getByRole("button", { name: "Canvas", exact: true }).click();

  for (let iteration = 1; iteration <= measuredCount; iteration += 1) {
    await beginMeasure(page, `full-to-focus-${iteration}-start`);
    await focusConnectedTail(page);
    measures.full_graph_to_focused_section.push(await finishMeasure(page, `full-to-focus-${iteration}-start`, `full-to-focus-${iteration}-end`));
    expect(await readDraft()).toBe(expectedDraft);

    await beginMeasure(page, `focus-to-full-${iteration}-start`);
    await showWholePlan(page);
    measures.focused_to_full_graph.push(await finishMeasure(page, `focus-to-full-${iteration}-start`, `focus-to-full-${iteration}-end`));
    expect(await readDraft()).toBe(expectedDraft);

    await beginMeasure(page, `full-to-steps-${iteration}-start`);
    await page.getByRole("button", { name: "Steps", exact: true }).click();
    await expect(page.getByRole("list", { name: "Experiment steps" }).locator(":scope > li")).toHaveCount(nodeCount);
    measures.full_graph_to_ordered_steps.push(await finishMeasure(page, `full-to-steps-${iteration}-start`, `full-to-steps-${iteration}-end`));
    expect(await readDraft()).toBe(expectedDraft);

    await page.getByRole("button", { name: "Canvas", exact: true }).click();
    await expect(page.locator(".react-flow__node:visible")).toHaveCount(nodeCount);
    const retainedView = await page.evaluate(key => sessionStorage.getItem(key), `bluefire.working-graph-view.v2:${fixture.scenario.id}`);
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
      focus_group: { meaning: "connected continuation after the final join", first_step: "scale_step_046", nodes: 82, outcome_edges: 81 },
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
      focus_transition: "Connected-path selection and Return to whole plan automatically retain a readable selected card and title; navigation samples contain no manual focus action",
      explicit_overview: "Fit view separately places all 128 nodes inside the canvas while retaining 256 routes at an intentionally reduced scale; Focus selected step restores readable framing before continuing, outside transition timing samples",
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

test("offline branch, join and returning retry remain inspectable with reduced motion", async ({ page, browser }) => {
  // Reuse graph-view.test.ts's branchedScenario topology and saved entry position.
  // Zero-input catalog steps keep this a valid presentation fixture; no run is dispatched.
  const template = demoScenario.steps.find(step => step.behavior_id === behaviorId)!;
  const scenario = parseScenarioDocument({ ...structuredClone(demoScenario),
    id: "graph.loop-join.offline.v1", title: "Graph loop and join visual qualification",
    purpose: "Inspect a saved branch, join and returning retry without executing a method.",
    start: "first", steps: ["first", "normal", "alternative", "cleanup", "detached"].map(id => ({ ...structuredClone(template), id, inputs: {} })),
    edges: [
      { from_step: "first", outcome: "success", to_step: "normal" },
      { from_step: "first", outcome: "blocked", to_step: "alternative" },
      { from_step: "normal", outcome: "success", to_step: "cleanup" },
      { from_step: "alternative", outcome: "success", to_step: "cleanup" },
      { from_step: "cleanup", outcome: "failed", to_step: "first" },
    ], layout: { first: { x: 915, y: 21 } },
  });
  const expectedDraft = JSON.stringify(scenario);
  const { session, state } = await syntheticSession(page, scenario);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.addInitScript(({ scenarioJson, scenarioId, session, behaviorId }) => {
    localStorage.setItem("bluefire.local.scenario.v1", scenarioJson);
    sessionStorage.setItem("bluefire.browser-session.v1", session);
    sessionStorage.setItem(`bluefire.working-graph-view.v2:${scenarioId}`, JSON.stringify({ scenarioId,
      view: { selected: { id: "first", behavior: behaviorId }, mode: "graph", allBranches: true,
        expanded: [], section: null, inspector: false, routes: false, inputs: false } }));
  }, { scenarioJson: expectedDraft, scenarioId: scenario.id, session, behaviorId });
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("./#/builder");
  await expect(page.getByRole("heading", { name: scenario.title, exact: true, level: 1 })).toBeVisible();
  expect(await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(true);
  await expect(page.locator(".react-flow__node:visible")).toHaveCount(5);
  await expect(page.locator(".react-flow__edge:visible")).toHaveCount(5);
  const readDraft = () => page.evaluate(() => localStorage.getItem("bluefire.local.scenario.v1"));
  expect(await readDraft()).toBe(expectedDraft);

  const fit = page.getByRole("button", { name: "Fit view", exact: true });
  const assertWholeGraphFits = async () => expect.poll(() => page.locator(".react-flow__node:visible").evaluateAll(nodes => {
    const canvas = document.querySelector(".graph-canvas")!.getBoundingClientRect();
    return nodes.length === 5 && nodes.every(node => {
      const box = node.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && box.left >= canvas.left - 1 && box.right <= canvas.right + 1
        && box.top >= canvas.top - 1 && box.bottom <= canvas.bottom + 1;
    });
  })).toBe(true);
  await fit.focus(); await fit.press("Enter");
  await assertWholeGraphFits();

  await page.getByRole("button", { name: "Show route list", exact: true }).click();
  const routes = page.getByRole("list", { name: "Visible routes", exact: true });
  await expect(routes.getByRole("button")).toHaveCount(5);
  const retryId = "route-cleanup-failed-first-4";
  const retry = routes.locator(`button[data-route="${retryId}"]`);
  await retry.focus(); await retry.press("Enter");
  await expect(retry).toHaveAttribute("aria-pressed", "true");
  await expect(retry).toContainText("On failure");
  await expect(retry).toContainText("cleanup → first");
  await expect(page.locator(`.react-flow__edge[data-id="${retryId}"]`)).toHaveClass(/selected/);
  await page.getByRole("button", { name: "Close route list", exact: true }).click();
  await fit.focus(); await fit.press("Enter");
  await assertWholeGraphFits();
  await stableFrames(page);
  const routing = await page.locator(".react-flow__edge:visible").evaluateAll((edges, definitions) => {
    const cards = [...document.querySelectorAll<HTMLElement>(".react-flow__node")]
      .filter(card => getComputedStyle(card).display !== "none" && getComputedStyle(card).visibility !== "hidden");
    const endpoints = new Map(definitions.map(edge => [edge.id, edge]));
    return edges.map(edge => {
      const path = edge.querySelector<SVGPathElement>(".react-flow__edge-path")!;
      const length = path.getTotalLength(), matrix = path.getScreenCTM()!;
      const id = edge.getAttribute("data-id") ?? "";
      let intersections = 0;
      for (let index = 1; index < 256; index += 1) {
        const point = path.getPointAtLength(length * index / 256).matrixTransform(matrix);
        for (const card of cards) {
          const cardId = card.getAttribute("data-id")!;
          // Endpoint cards are joined through handles; inspect only unrelated cards.
          if (cardId === endpoints.get(id)?.source || cardId === endpoints.get(id)?.target) continue;
          const box = card.getBoundingClientRect();
          if (point.x > box.left + 1 && point.x < box.right - 1 && point.y > box.top + 1 && point.y < box.bottom - 1) intersections += 1;
        }
      }
      return { id, path_count: edge.querySelectorAll(".react-flow__edge-path").length,
        length, obstructed: Boolean(edge.querySelector('[data-route-obstructed="true"]')), unrelated_card_intersections: intersections,
        path: path.getAttribute("d") };
    });
  }, scenario.edges.map((edge, index) => ({ id: `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`, source: edge.from_step, target: edge.to_step })));
  expect(routing.map(route => route.id).sort()).toEqual(scenario.edges.map((edge, index) => `route-${edge.from_step}-${edge.outcome}-${edge.to_step}-${index}`).sort());
  expect(routing.every(route => route.path_count === 1 && Number.isFinite(route.length) && route.length > 0
    && !route.obstructed && route.unrelated_card_intersections === 0)).toBe(true);
  const wholeGeometry = await capture(page, "graph-loop-join-reduced-overview-1366");
  expect(await readDraft()).toBe(expectedDraft);

  await page.getByRole("button", { name: "Find step", exact: true }).click();
  const search = page.getByRole("dialog", { name: "Find a step in this experiment", exact: true });
  await search.getByRole("textbox", { name: "Find a step", exact: true }).fill("cleanup");
  const result = search.getByRole("button").filter({ has: page.locator("code", { hasText: /\bcleanup$/ }) });
  await expect(result).toHaveCount(1);
  await result.focus(); await result.press("Enter");
  await expect(page.locator('.react-flow__node[data-id="cleanup"]')).toHaveClass(/selected/);
  await expectReadableSelection(page);
  await page.getByRole("button", { name: "Steps", exact: true }).click();
  const steps = page.getByRole("list", { name: "Experiment steps", exact: true });
  await expect(steps.locator(":scope > li")).toHaveCount(5);
  await expect(steps.locator('button[data-step-id="cleanup"]')).toHaveAttribute("aria-pressed", "true");
  const alternative = steps.locator('button[data-step-id="alternative"]');
  await alternative.focus(); await alternative.press("Enter");
  await page.getByRole("button", { name: "Canvas", exact: true }).click();
  await expect(page.locator('.react-flow__node[data-id="alternative"]')).toHaveClass(/selected/);
  await expectReadableSelection(page);
  await viewOptions(page, true);
  await page.getByRole("button", { name: "Focus selected step", exact: true }).click();
  await viewOptions(page, false);
  const motionFrames = await page.evaluate(() => new Promise<string[]>(resolve => {
    const frames: string[] = [];
    const sample = () => {
      frames.push(document.querySelector(".react-flow__viewport")?.getAttribute("style") ?? "");
      if (frames.length === 8) resolve(frames); else requestAnimationFrame(sample);
    };
    requestAnimationFrame(sample);
  }));
  expect(motionFrames.every(Boolean)).toBe(true);
  expect(new Set(motionFrames).size).toBe(1);
  await expectReadableSelection(page);
  const focusedGeometry = await capture(page, "graph-loop-join-reduced-focused-1366");
  expect(await readDraft()).toBe(expectedDraft);
  expect(state.effects).toEqual([]);
  expect({ unexpected: state.unexpected, websockets: state.websockets, pageErrors: state.pageErrors, consoleErrors: state.consoleErrors })
    .toEqual({ unexpected: 0, websockets: 0, pageErrors: 0, consoleErrors: 0 });
  writeFileSync(join(output, "graph-loop-join-reduced-report.json"), `${JSON.stringify({
    proof: "synthetic-production-bundle-loop-join-reduced-motion-ui-only", real_service: false,
    browser: { engine: "chromium", version: browser.version() },
    bundle: ["app.js", "index.html", "styles.css"].map(name => { const bytes = readFileSync(join(bundle, name)); return { name, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") }; }),
    workload: { scenario, canonical_graph_sha256: createHash("sha256").update(canonicalJson(scenario)).digest("hex") },
    reduced_motion: { media_matches: true, viewport_frames: motionFrames, distinct_viewport_frames: 1 },
    geometry: { overview: wholeGeometry, focused: focusedGeometry }, routing,
    checks: ["five_saved_steps_and_five_exact_routes", "returning_failure_route_keyboard_selected", "join_and_retry_paths_clear_of_unrelated_cards",
      "keyboard_fit_whole_graph", "keyboard_exact_id_search", "steps_and_canvas_share_selection", "focus_readable_without_intermediate_animation", "saved_document_and_positions_unchanged"],
    effect_audit: { ...state, serialized_draft_unchanged: true },
  }, null, 2)}\n`, { flag: "wx" });
});
