import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { expect, test, type Locator, type Page } from "@playwright/test";
import { demoCatalog, demoScenario } from "../../src/lib/demo";
import { graphDocument } from "../../src/lib/graph-assistance";
import { contextFixture, controlId, objectiveFixture, ownerId, proposalFixture, proposalId } from "../composition-fixture";

const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const savedRoute = `./#/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`;
const viewportName = (page: Page) => `${page.viewportSize()!.width}x${page.viewportSize()!.height}`;

async function fixture(page: Page, route = savedRoute, graphContext = false) {
  const session = "b".repeat(64);
  const bootstrap = "a".repeat(64);
  const objective = objectiveFixture();
  const context = contextFixture();
  const proposal = proposalFixture();
  const methods = demoCatalog.behaviors.map(behavior => ({ ...context.snapshot.methods[0]!, behavior_id: behavior.id, behavior,
    action_id: behavior.action_ids[0] ?? context.snapshot.methods[0]!.action_id,
    action: demoCatalog.actions.find(action => action.id === behavior.action_ids[0]) ?? context.snapshot.methods[0]!.action }));
  context.snapshot.methods = methods;
  objective.grant.document.snapshot = context.snapshot;
  context.initial_proposal = { ...context.initial_proposal!, start: demoScenario.start, steps: demoScenario.steps.map(step => ({ id: step.id, behavior_id: step.behavior_id, parameters: step.parameters })), edges: demoScenario.edges };
  proposal.proposal!.candidate = context.initial_proposal;
  const counts = { connected: false, contexts: 0, lists: 0, attempts: 0, graph_contexts: 0, unexpected: 0, pageErrors: 0, sockets: 0 };
  page.on("pageerror", () => { counts.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { counts.sockets += 1; void socket.close(); });
  await page.context().route("**/*", async intercepted => {
    const request = intercepted.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => intercepted.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    const refuse = async () => { counts.unexpected += 1; await intercepted.abort(); };
    if (url.origin !== origin || url.search || url.username || url.password) { await refuse(); return; }
    if (method === "GET" && url.pathname === "/ui/fonts/InterVariable.woff2") {
      await intercepted.fulfill({ path: resolve("public/fonts/InterVariable.woff2"), contentType: "font/woff2" }); return;
    }
    if (method === "GET" && ["/ui/", "/ui/index.html", "/ui/app.js", "/ui/styles.css"].includes(url.pathname)) { await intercepted.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !counts.connected && request.headers()["x-bluefire-browser-bootstrap"] === bootstrap) { counts.connected = true; await json({ session }); return; }
      if (method === "GET" && counts.connected && request.headers()["x-bluefire-session"] === session) { await intercepted.fulfill({ status: 204 }); return; }
      if (method === "GET" && !counts.connected) { await json({ error: { code: "browser_session_unavailable", message: "Synthetic session unavailable." } }, 401); return; }
      await refuse(); return;
    }
    if (!counts.connected || request.headers()["x-bluefire-session"] !== session) { await refuse(); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json(demoCatalog); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [demoScenario] }); return; }
    if (method === "GET" && url.pathname === `/api/v1/composition/objectives/${ownerId}`) { await json(objective); return; }
    if (method === "GET" && url.pathname === `/api/v1/composition/proposals/${proposalId}`) { await json(proposal); return; }
    if (graphContext && ["GET", "POST"].includes(method) && url.pathname === "/api/v1/assistance/graph-context" && counts.graph_contexts < 4) {
      const body = method === "GET" ? { kind: "graph", base_scenario: null } : request.postDataJSON();
      expect(body).toEqual(method === "GET" ? { kind: "graph", base_scenario: null } : { kind: "graph", base_scenario: null, edit_step: { scenario: graphDocument(demoScenario), step_id: demoScenario.steps[0]!.id, dirty: false } });
      counts.graph_contexts += 1;
      await json({ schema_version: "bluefire.assistance-context.v1", context_digest: `sha256:${"d".repeat(64)}`, selected: body, capabilities: [], limitations: ["Synthetic layout fixture; no model or execution work."] }); return;
    }
    if (method === "POST" && url.pathname === "/api/v1/composition/objective-list" && counts.lists < 4
      && JSON.stringify(request.postDataJSON()) === JSON.stringify({ control_owner_id: controlId })) {
      counts.lists += 1; await json({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: objective.grant.document.objective.question, status: "active", job_state: "completed" }] }); return;
    }
    if (method === "POST" && url.pathname === `/api/v1/composition/objectives/${ownerId}/proposal-context` && counts.contexts < 3
      && JSON.stringify(request.postDataJSON()) === JSON.stringify({ prior_attempt_id: null })) { counts.contexts += 1; await json(context); return; }
    if (method === "POST" && url.pathname === `/api/v1/composition/objectives/${ownerId}/attempts` && counts.attempts === 0) {
      const body = request.postDataJSON();
      expect(Object.keys(body).sort()).toEqual(["prior_attempt_id", "proposal", "submission_id"]);
      expect(body.proposal).toEqual(context.initial_proposal);
      expect(body.prior_attempt_id).toBeNull();
      expect(body.submission_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      counts.attempts += 1;
      // Intercept-only acknowledgment: no backend ever receives an attempt.
      await json({ error: { code: "service_unavailable", message: "Synthetic UI interception; no execution occurred." } }, 503); return;
    }
    await refuse();
  });
  await page.goto(route);
  await page.getByLabel("One-time connection code", { exact: false }).fill(bootstrap);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  return counts;
}

async function geometry(page: Page, name: string) {
  const value = await page.evaluate(() => {
    const main = document.getElementById("main-content")!;
    const button = [...document.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent?.trim() === "Start fresh attempt within grant");
    const bounds = button?.getBoundingClientRect();
    const x = bounds ? bounds.left + bounds.width / 2 : -1;
    const y = bounds ? bounds.top + bounds.height / 2 : -1;
    const hit = x >= 0 && y >= 0 && x < innerWidth && y < innerHeight ? document.elementFromPoint(x, y) : null;
    const mainStyle = getComputedStyle(main);
    const topbar = document.querySelector(".workspace-topbar")!.getBoundingClientRect();
    return { main_overflow_y: mainStyle.overflowY, main_height: main.clientHeight, main_scroll_height: main.scrollHeight,
      main_padding: [mainStyle.paddingTop, mainStyle.paddingRight, mainStyle.paddingBottom, mainStyle.paddingLeft] as const,
      main_bounds: main.getBoundingClientRect().toJSON(), direct_builder: Boolean(main.querySelector(":scope > .workbench-builder")),
      topbar_height: topbar.height, viewport_height: innerHeight,
      workspace_bounds: document.querySelector(".workspace-content")!.getBoundingClientRect().toJSON(),
      assistant_bounds: document.getElementById("experiment-assistant")?.getBoundingClientRect().toJSON() ?? null,
      document_width: document.documentElement.clientWidth, document_scroll_width: document.documentElement.scrollWidth,
      main_width: main.clientWidth, main_scroll_width: main.scrollWidth,
      button_enabled: button ? !button.disabled : null, button_bounds: bounds?.toJSON() ?? null,
      center_hit: !hit ? "out_of_view" : hit === button ? "self" : button?.contains(hit) ? "descendant" : "other" };
  });
  const unique = `${viewportName(page)}-${name}`;
  writeFileSync(join(output, `${unique}-geometry.json`), `${JSON.stringify({ proof: "synthetic-production-ui-only", real_service: false, ...value }, null, 2)}\n`, { flag: "wx" });
  await page.screenshot({ path: join(output, `${unique}.png`), fullPage: false, animations: "disabled" });
  return value;
}

async function pageTop(page: Page) {
  await page.evaluate(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    document.getElementById("main-content")!.scrollTo({ top: 0, left: 0, behavior: "instant" });
  });
}

async function graphControls(page: Page, scope: Locator) {
  const canvas = scope.getByLabel("Scenario graph canvas");
  await expect(canvas).toBeVisible();
  const transform = () => canvas.locator(".react-flow__viewport").evaluate(element => {
    const matrix = new DOMMatrixReadOnly(getComputedStyle(element).transform);
    return { x: matrix.m41, y: matrix.m42, zoom: matrix.m11 };
  });
  const original = await transform();
  await canvas.locator(".react-flow__controls-zoomin").click();
  await expect.poll(async () => (await transform()).zoom).toBeGreaterThan(original.zoom);
  await scope.getByRole("button", { name: "Fit view", exact: true }).click();
  await canvas.locator(".react-flow__viewport").evaluate(element => new Promise<void>((resolveStable, reject) => {
    let previous = "";
    let stable = 0;
    const until = performance.now() + 1500;
    const frame = () => {
      const current = getComputedStyle(element).transform;
      stable = current === previous ? stable + 1 : 0;
      previous = current;
      if (stable >= 5) resolveStable();
      else if (performance.now() >= until) reject(new Error("Graph fit did not settle."));
      else requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  }));
  const box = await canvas.boundingBox();
  if (!box) throw new Error("The rendered graph canvas has no geometry.");
  const panBefore = await transform();
  await page.mouse.move(box.x + 8, box.y + 8);
  await page.mouse.down();
  await page.mouse.move(box.x + 68, box.y + 48, { steps: 5 });
  await page.mouse.up();
  await expect.poll(async () => (await transform()).x).not.toBe(panBefore.x);
  await scope.getByRole("button", { name: "Show node inspector", exact: true }).click();
  await expect(scope.locator(".inspector-panel")).toBeVisible();
}

function noHorizontalOverflow(value: Awaited<ReturnType<typeof geometry>>) {
  expect(value.document_scroll_width).toBeLessThanOrEqual(value.document_width + 1);
  expect(value.main_scroll_width).toBeLessThanOrEqual(value.main_width + 1);
}

for (const reopen of ["same-url", "new-document"] as const) {
  test(`embedded composition graph keeps attempt actionable after ${reopen} reopen`, async ({ page }) => {
    const counts = await fixture(page);
    const start = page.getByRole("button", { name: "Start fresh attempt within grant", exact: true });
    await expect(start).toBeEnabled();
    await pageTop(page);
    const closed = await geometry(page, `${reopen}-closed`);
    await page.getByRole("button", { name: "Inspect graph", exact: true }).click();
    await expect(page.locator(".composition-graph")).toBeVisible();
    const saved = page.url();
    if (reopen === "new-document") await page.goto("about:blank");
    await page.goto(saved);
    if (reopen === "new-document") {
      await expect(start).toBeEnabled();
      await page.getByRole("button", { name: "Inspect graph", exact: true }).click();
    }
    await expect(page.getByRole("button", { name: "Close graph", exact: true })).toBeVisible();
    await pageTop(page);
    const open = await geometry(page, `${reopen}-open-page`);
    await page.getByRole("button", { name: "Close graph", exact: true }).click();
    await pageTop(page);
    const closedAgain = await geometry(page, `${reopen}-closed-again`);
    await page.getByRole("button", { name: "Inspect graph", exact: true }).click();
    const graph = page.locator(".composition-graph");
    await graphControls(page, graph);
    const graphView = await geometry(page, `${reopen}-graph-controls`);
    await start.scrollIntoViewIfNeeded();
    const before = await geometry(page, `${reopen}-before-click`);
    let clicked = true;
    try { await start.click({ timeout: 3000 }); } catch { clicked = false; }
    const after = await geometry(page, `${reopen}-after-click`);
    writeFileSync(join(output, `${viewportName(page)}-${reopen}-result.json`), `${JSON.stringify({ proof: "synthetic-production-ui-only", clicked, counts }, null, 2)}\n`, { flag: "wx" });
    expect(closed.direct_builder).toBe(false);
    expect(open.direct_builder).toBe(false);
    expect(parseFloat(closed.main_padding[1])).toBeGreaterThan(0);
    expect(parseFloat(closed.main_padding[3])).toBeGreaterThan(0);
    expect(open.main_padding).toEqual(closed.main_padding);
    expect(open.main_overflow_y).toBe(closed.main_overflow_y);
    expect(closedAgain.main_padding).toEqual(closed.main_padding);
    for (const value of [closed, open, closedAgain, graphView, before, after]) noHorizontalOverflow(value);
    expect(before.button_enabled).toBe(true);
    expect(["self", "descendant"]).toContain(before.center_hit);
    expect(after.main_overflow_y).not.toBe("hidden");
    expect(clicked).toBe(true);
    expect(counts.attempts).toBe(1);
    expect(counts.unexpected).toBe(0);
    expect(counts.pageErrors).toBe(0);
    expect(counts.sockets).toBe(0);
  });
}

test("ordinary Build keeps its viewport and graph controls", async ({ page }) => {
  const counts = await fixture(page, "./#/builder");
  const canvas = page.getByLabel("Scenario graph canvas");
  await expect(canvas).toBeVisible();
  const before = await geometry(page, "ordinary-builder");
  expect(before.main_overflow_y).toBe("auto");
  expect(before.direct_builder).toBe(true);
  expect(Math.abs(before.main_height - (before.viewport_height - before.topbar_height))).toBeLessThanOrEqual(1);
  await graphControls(page, page.locator(".workbench-builder"));
  const after = await geometry(page, "ordinary-builder-controls");
  noHorizontalOverflow(before);
  noHorizontalOverflow(after);
  expect(counts.attempts).toBe(0);
  expect(counts.unexpected).toBe(0);
  expect(counts.pageErrors).toBe(0);
});

test("constrained desktop preserves Composition and Build with Assistant open", async ({ page }) => {
  const counts = await fixture(page, savedRoute, true);
  const start = page.getByRole("button", { name: "Start fresh attempt within grant", exact: true });
  await expect(start).toBeEnabled();
  await page.getByRole("button", { name: "Assistant", exact: true }).click();
  await expect(page.getByRole("complementary", { name: "BlueFire Assistant" })).toBeVisible();
  await pageTop(page);
  const closed = await geometry(page, "assistant-closed");
  await page.getByRole("button", { name: "Inspect graph", exact: true }).click();
  await pageTop(page);
  const open = await geometry(page, "assistant-open-page");
  const graph = page.locator(".composition-graph");
  let controls = true;
  try { await graphControls(page, graph); } catch { controls = false; }
  const graphView = await geometry(page, "assistant-graph-controls");
  await start.click({ trial: true });
  await page.getByRole("button", { name: "Close graph", exact: true }).click();
  await pageTop(page);
  const closedAgain = await geometry(page, "assistant-closed-again");
  await page.goto("./#/builder");
  await expect(page.getByRole("complementary", { name: "BlueFire Assistant" })).toBeVisible();
  await expect(page.getByLabel("Scenario graph canvas")).toBeVisible();
  const builder = await geometry(page, "assistant-ordinary-builder");
  let builderControls = true;
  try { await graphControls(page, page.locator(".workbench-builder")); } catch { builderControls = false; }
  const builderView = await geometry(page, "assistant-ordinary-builder-controls");
  writeFileSync(join(output, `${viewportName(page)}-assistant-result.json`), `${JSON.stringify({ proof: "synthetic-production-ui-only", controls, builderControls, counts }, null, 2)}\n`, { flag: "wx" });
  expect(open.main_padding).toEqual(closed.main_padding);
  expect(closedAgain.main_padding).toEqual(closed.main_padding);
  expect(Math.abs(open.main_height - closed.main_height)).toBeLessThanOrEqual(1);
  expect(Math.abs(closedAgain.main_height - closed.main_height)).toBeLessThanOrEqual(1);
  for (const value of [closed, open, graphView, closedAgain, builder, builderView]) {
    noHorizontalOverflow(value);
    expect(value.assistant_bounds).not.toBeNull();
    expect(Math.abs(value.main_bounds.bottom - value.assistant_bounds!.top)).toBeLessThanOrEqual(1);
    expect(Math.abs(value.main_bounds.height + value.assistant_bounds!.height - value.workspace_bounds.height)).toBeLessThanOrEqual(1);
  }
  expect(controls).toBe(true);
  expect(builderControls).toBe(true);
  expect(builder.direct_builder).toBe(true);
  expect(counts.attempts).toBe(0);
  expect(counts.graph_contexts).toBeGreaterThan(0);
  expect(counts.unexpected).toBe(0);
  expect(counts.pageErrors).toBe(0);
  expect(counts.sockets).toBe(0);
});
