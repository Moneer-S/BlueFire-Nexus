import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { expect, test, type Page } from "@playwright/test";
import { demoCatalog, demoScenario } from "../../src/lib/demo";
import { contextFixture, controlId, objectiveFixture, ownerId, proposalFixture, proposalId } from "../composition-fixture";

const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const savedRoute = `./#/composition?control=${controlId}&objective=${ownerId}&proposal=${proposalId}`;

async function fixture(page: Page, route = savedRoute) {
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
  const counts = { connected: false, contexts: 0, lists: 0, attempts: 0, unexpected: 0, pageErrors: 0, sockets: 0 };
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
    return { main_overflow_y: getComputedStyle(main).overflowY, main_height: main.clientHeight, main_scroll_height: main.scrollHeight,
      button_enabled: button ? !button.disabled : null, button_bounds: bounds?.toJSON() ?? null,
      center_hit: !hit ? "out_of_view" : hit === button ? "self" : button?.contains(hit) ? "descendant" : "other" };
  });
  writeFileSync(join(output, `${name}-geometry.json`), `${JSON.stringify({ proof: "synthetic-production-ui-only", real_service: false, ...value }, null, 2)}\n`, { flag: "wx" });
  await page.screenshot({ path: join(output, `${name}.png`), fullPage: false, animations: "disabled" });
  return value;
}

for (const reopen of ["same-url", "new-document"] as const) {
  test(`embedded composition graph keeps attempt actionable after ${reopen} reopen`, async ({ page }) => {
    const counts = await fixture(page);
    const start = page.getByRole("button", { name: "Start fresh attempt within grant", exact: true });
    await expect(start).toBeEnabled();
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
    const before = await geometry(page, `${reopen}-before-click`);
    let clicked = true;
    try { await start.click({ timeout: 3000 }); } catch { clicked = false; }
    const after = await geometry(page, `${reopen}-after-click`);
    writeFileSync(join(output, `${reopen}-result.json`), `${JSON.stringify({ proof: "synthetic-production-ui-only", clicked, counts }, null, 2)}\n`, { flag: "wx" });
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
  expect(before.main_height).toBe(840);
  const transform = () => canvas.locator(".react-flow__viewport").evaluate(element => {
    const matrix = new DOMMatrixReadOnly(getComputedStyle(element).transform);
    return { x: matrix.m41, y: matrix.m42, zoom: matrix.m11 };
  });
  const original = await transform();
  await canvas.locator(".react-flow__controls-zoomin").click();
  await expect.poll(async () => (await transform()).zoom).toBeGreaterThan(original.zoom);
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  const box = await canvas.boundingBox();
  if (!box) throw new Error("The rendered graph canvas has no geometry.");
  const panBefore = await transform();
  await page.mouse.move(box.x + 8, box.y + 8);
  await page.mouse.down();
  await page.mouse.move(box.x + 68, box.y + 48, { steps: 5 });
  await page.mouse.up();
  await expect.poll(async () => (await transform()).x).not.toBe(panBefore.x);
  await page.getByRole("button", { name: "Show node inspector", exact: true }).click();
  await expect(page.locator(".inspector-panel")).toBeVisible();
  expect(counts.attempts).toBe(0);
  expect(counts.unexpected).toBe(0);
  expect(counts.pageErrors).toBe(0);
});
