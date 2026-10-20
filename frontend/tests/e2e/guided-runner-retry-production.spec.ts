import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { demoCatalog, demoScenario } from "../../src/lib/demo";

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
const profileId = "sandbox-execute.v1";
const diagnosticDetail = `Synthetic runner detail: ${"x".repeat(160)}`;
const viewports = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];

async function fixture(page: Page) {
  const code = randomBytes(32).toString("hex");
  const session = randomBytes(32).toString("hex");
  const state = { connected: false, runnerReads: [] as string[], effects: [] as string[], unexpected: 0, sockets: 0, pageErrors: 0 };
  let releaseReady!: () => void;
  const readyGate = new Promise<void>(resolve => { releaseReady = resolve; });
  page.on("pageerror", () => { state.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { state.sockets += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    const refuse = async () => { state.unexpected += 1; await route.abort(); };
    if (url.origin !== origin || url.username || url.password || (url.search && !(url.pathname === "/api/v1/runner" && url.search === `?profile_id=${profileId}`))) { await refuse(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !state.connected && request.headers()["x-bluefire-browser-bootstrap"] === code) {
        state.connected = true;
        await json({ session });
        return;
      }
      if (method === "GET" && state.connected && request.headers()["x-bluefire-session"] === session) {
        await route.fulfill({ status: 204 });
        return;
      }
      if (method === "GET" && !state.connected) {
        await json({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }, 401);
        return;
      }
      await refuse();
      return;
    }
    if (!state.connected || request.headers()["x-bluefire-session"] !== session) { await refuse(); return; }
    if (method !== "GET") { state.effects.push(`${method} ${url.pathname}`); await refuse(); return; }
    if (url.pathname === "/api/v1/catalog") { await json(demoCatalog); return; }
    if (url.pathname === "/api/v1/scenarios") { await json({ scenarios: [demoScenario] }); return; }
    if (url.pathname === "/api/v1/runs") { await json({ runs: [], unavailable_run_count: 0 }); return; }
    if (url.pathname === "/api/v1/jobs") { await json({ schema_version: "bluefire.active-job-list.v1", jobs: [] }); return; }
    if (url.pathname === "/api/v1/runner") {
      state.runnerReads.push(`${method} ${url.pathname}${url.search}`);
      if (state.runnerReads.length === 1) {
        await json({ error: { code: "runner_status_unavailable", message: "Synthetic runner status unavailable.", details: [diagnosticDetail] } }, 503);
        return;
      }
      if (state.runnerReads.length === 2) {
        await readyGate;
        await json({ schema_version: "bluefire.runner-lifecycle-status.v1", state: "ready", runner_id: "synthetic-runner", profile_id: profileId, loopback_only: true, enrollment: "active", process: "authenticated", runner: null, health: { accepting_execute: true } });
        return;
      }
    }
    await refuse();
  });

  await page.goto("./#/runs?setup=execute#guided-execute");
  await expect(page.getByRole("heading", { name: "Connect to your workspace" })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  const guide = page.getByRole("region", { name: "Guided local Execute" });
  await expect(guide).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Environment profile" })).toHaveValue(profileId);
  return { state, guide, releaseReady };
}

async function capture(page: Page, name: string) {
  const guide = page.getByRole("region", { name: "Guided local Execute" });
  await guide.evaluate(node => node.scrollIntoView({ block: "start", behavior: "instant" }));
  await page.evaluate(async () => { await document.fonts.ready; });
  const geometry = await page.evaluate(() => {
    const main = document.querySelector("main")!;
    const bounds = main.getBoundingClientRect();
    const outside = [...main.querySelectorAll("h1,h2,h3,p,button,a,article,li")].filter(node => {
      const child = node.getBoundingClientRect();
      return child.width > 0 && child.height > 0 && (child.left < bounds.left - 1 || child.right > bounds.right + 1);
    }).map(node => node.tagName);
    const guideTop = document.getElementById("guided-execute")!.getBoundingClientRect().top;
    const headerBottom = Math.max(0, ...[...document.querySelectorAll(".mobile-header,.workspace-topbar")].map(node => node.getBoundingClientRect()).filter(rect => rect.width > 0 && rect.top <= 0).map(rect => rect.bottom));
    return { viewport: { width: innerWidth, height: innerHeight }, documentWidth: document.documentElement.clientWidth, documentScroll: document.documentElement.scrollWidth, mainWidth: main.clientWidth, mainScroll: main.scrollWidth, guideTop, headerBottom, outside };
  });
  expect(geometry.documentScroll).toBeLessThanOrEqual(geometry.documentWidth);
  expect(geometry.mainScroll).toBeLessThanOrEqual(geometry.mainWidth);
  expect(geometry.outside).toEqual([]);
  expect(geometry.guideTop).toBeGreaterThanOrEqual(geometry.headerBottom);
  const screenshot = join(output, `${name}.png`);
  if (existsSync(screenshot)) throw new Error("The guided runner screenshot already exists.");
  await page.screenshot({ path: screenshot, fullPage: false, animations: "disabled" });
  writeFileSync(join(output, `${name}-geometry.json`), `${JSON.stringify({ proof: "synthetic-production-bundle-ui-only", real_service: false, geometry }, null, 2)}\n`, { flag: "wx" });
}

for (const viewport of viewports) {
  test(`guided runner status retry stays read-only at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const { state, guide, releaseReady } = await fixture(page);
    const step = guide.locator(".execute-onboarding-steps > li").first();
    await expect(step.getByText("Unavailable", { exact: true })).toBeVisible();
    await expect(guide.getByText("Local service unavailable", { exact: true })).toBeVisible();
    await expect(guide.getByText("Synthetic runner status unavailable.", { exact: true })).toBeVisible();
    await expect(guide.getByText(diagnosticDetail, { exact: true })).toBeVisible();
    await expect(guide.getByRole("button", { name: "Try again" })).toBeVisible();
    const errorBounds = await guide.getByRole("alert").boundingBox();
    expect(errorBounds?.height).toBeLessThan(280);
    await capture(page, `runner-error-${viewport.width}`);

    await guide.getByRole("button", { name: "Try again" }).click();
    try {
      await expect(step.getByText("Checking", { exact: true })).toBeVisible();
      await expect(guide.getByRole("button", { name: "Try again" })).toHaveCount(0);
      await capture(page, `runner-checking-${viewport.width}`);
    } finally {
      releaseReady();
    }
    await expect(step.getByText("Ready", { exact: true })).toBeVisible();
    await expect(guide.getByText("Synthetic runner status unavailable.", { exact: true })).toHaveCount(0);
    await expect(guide.getByText(diagnosticDetail, { exact: true })).toHaveCount(0);
    await capture(page, `runner-ready-${viewport.width}`);
    expect(state.runnerReads).toEqual(Array(2).fill(`GET /api/v1/runner?profile_id=${profileId}`));
    expect(state.effects).toEqual([]);
    expect({ unexpected: state.unexpected, sockets: state.sockets, pageErrors: state.pageErrors }).toEqual({ unexpected: 0, sockets: 0, pageErrors: 0 });
    writeFileSync(join(output, `runner-retry-${viewport.width}-summary.json`), `${JSON.stringify({ proof: "synthetic-production-bundle-ui-only", real_service: false, viewport, runnerReads: state.runnerReads, effects: state.effects, unexpected: state.unexpected, sockets: state.sockets, pageErrors: state.pageErrors }, null, 2)}\n`, { flag: "wx" });
  });
}
