import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { s3Exercise, s3Hash, s3Observed, s3Operation, s3Owner, s3Review } from "../s3-access-fixture";
import type { S3Exercise, S3Phase } from "../../src/lib/s3-access";

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const viewports = [{ width: 1366, height: 900 }, { width: 1440, height: 900 }, { width: 390, height: 844 }];

async function fixture(page: Page, initial: S3Exercise | null) {
  let value = initial;
  let connected = false;
  // These random values authorize nothing: every API request is fulfilled here.
  const code = randomBytes(32).toString("hex");
  const session = randomBytes(32).toString("hex");
  const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
  const counts = { review: 0, stage: 0, stop: 0, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 };
  page.on("pageerror", () => { counts.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { counts.websocket += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (url.origin !== origin || url.search || url.username || url.password) { counts.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !connected && request.headers()["x-bluefire-browser-bootstrap"] === code) { connected = true; await json({ session }); return; }
      if (method === "GET" && connected && request.headers()["x-bluefire-session"] === session) { await route.fulfill({ status: 204 }); return; }
      await json({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }, 401); return;
    }
    if (!connected || request.headers()["x-bluefire-session"] !== session) { counts.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [] } }); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/environments") { await json({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: "No S3 environment is enrolled." }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/exercises") { await json({ schema_version: "bluefire.s3-exercise-list.v1", exercises: value ? [{ workflow_job_id: s3Owner, name: "Synthetic S3 review", bucket: value.environment.scope.bucket, policy_state: value.policy_state, updated_at: "2026-10-09T00:00:00Z" }] : [], truncated: false }); return; }
    const root = `/api/v1/s3-access/exercises/${s3Owner}`;
    if (method === "GET" && url.pathname === root && value) { await json(value); return; }
    if (method === "POST" && url.pathname === `${root}/review` && value) {
      const body = request.postDataJSON() as { phase: S3Phase };
      if (!value.allowed_phases.includes(body.phase)) { counts.unexpected += 1; await route.abort(); return; }
      counts.review += 1;
      await json({ ...s3Review(body.phase), revision: value.revision,
        reserved: { api_calls: 4, business_attempts: 0, sessions: 0, policy_changes: 0, rollbacks: 1 },
        required_remaining: { api_calls: 6, business_attempts: 0, sessions: 0, policy_changes: 0, rollbacks: 1 },
        policy_change: { before: { Statement: [] }, after: { Statement: [] } },
      }); return;
    }
    if (method === "POST" && url.pathname === `${root}/operations` && value) {
      const body = request.postDataJSON() as { phase: S3Phase; submission_id: string; review_digest: string; reviewed_by: string };
      if (!value.allowed_phases.includes(body.phase) || body.review_digest !== s3Hash || body.reviewed_by !== "synthetic operator") { counts.unexpected += 1; await route.abort(); return; }
      counts.stage += 1;
      value = { ...value, allowed_phases: [], active_job: { job_id: `job-${body.submission_id.replaceAll("-", "")}`, state: "running", request: { s3_access: { workflow_job_id: s3Owner, phase: body.phase, review: { review_digest: s3Hash } } } } };
      await json(value); return;
    }
    if (method === "POST" && url.pathname === `${root}/stop` && value) { counts.stop += 1; value = { ...value, stopped: true, allowed_phases: [] }; await json(value); return; }
    counts.unexpected += 1; await route.abort();
  });
  await page.goto(`./#/s3-access${initial ? `?exercise=${s3Owner}` : ""}`);
  await expect(page.getByRole("heading", { name: "Connect to your workspace", exact: true })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: initial ? "Synthetic S3 review" : "S3 access", exact: true })).toBeVisible();
  await expect(page.getByLabel("One-time connection code", { exact: false })).toHaveCount(0);
  return { counts, set: (next: S3Exercise) => { value = next; } };
}

async function geometry(page: Page, targetSelector?: string) {
  return page.evaluate(selector => {
    const bounds = (node: Element | null) => {
      if (!node || getComputedStyle(node).display === "none") return null;
      const rect = node.getBoundingClientRect();
      return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
    };
    const main = document.querySelector("main")!;
    const target = selector ? document.querySelector(selector) : null;
    const rect = target?.getBoundingClientRect();
    const hit = rect ? document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2) : null;
    const visual = window.visualViewport;
    return {
      window: { width: innerWidth, height: innerHeight, x: scrollX, y: scrollY },
      document: { height: document.documentElement.clientHeight, scrollHeight: document.documentElement.scrollHeight },
      visual: visual ? { width: visual.width, height: visual.height, x: visual.offsetLeft, y: visual.offsetTop, pageTop: visual.pageTop, scale: visual.scale } : null,
      main: { bounds: bounds(main), x: main.scrollLeft, y: main.scrollTop, scrollHeight: main.scrollHeight },
      header: bounds(document.querySelector(".mobile-header")),
      review: bounds(document.querySelector(".s3-review")),
      target: { bounds: bounds(target), hit: Boolean(target && hit && target.contains(hit)) },
    };
  }, targetSelector);
}

async function capture(page: Page, name: string, viewport: { width: number; height: number }, targetSelector?: string) {
  const initial = await geometry(page, targetSelector);
  const current = page.viewportSize();
  if (current?.width !== viewport.width || current?.height !== viewport.height) await page.setViewportSize(viewport);
  await page.evaluate(async () => { await document.fonts.ready; });
  const samples: Awaited<ReturnType<typeof geometry>>[] = [];
  let matching = 0;
  const stable = await expect.poll(async () => {
    const next = await geometry(page, targetSelector);
    matching = JSON.stringify(samples.at(-1)) === JSON.stringify(next) ? matching + 1 : 0;
    samples.push(next);
    return matching;
  }, { timeout: 3_000, intervals: [50] }).toBeGreaterThanOrEqual(4).then(() => true, () => false);
  const dimensions = await page.evaluate(() => {
    const main = document.querySelector("main")!;
    const rect = main.getBoundingClientRect();
    const outside = [...main.querySelectorAll<HTMLElement>("h1,h2,h3,p,button,input,summary,a,article")].filter(node => {
      const child = node.getBoundingClientRect();
      return child.width > 0 && child.height > 0 && (child.left < rect.left - 1 || child.right > rect.right + 1);
    }).map(node => node.tagName);
    return { document: { client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }, main: { client: main.clientWidth, scroll: main.scrollWidth }, outside };
  });
  const target = join(output, `${name}-${viewport.width}.png`);
  if (existsSync(target)) throw new Error("A browser screenshot already exists.");
  const beforeScreenshot = await geometry(page, targetSelector);
  await page.screenshot({ path: target, fullPage: false, animations: "disabled" });
  const afterScreenshot = await geometry(page, targetSelector);
  const result = { viewport, dimensions, vertical: { initial, stable, samples, beforeScreenshot, afterScreenshot }, screenshot: `${name}-${viewport.width}.png` };
  report(`${name}-${viewport.width}-geometry`, result);
  expect(dimensions.document.scroll).toBeLessThanOrEqual(dimensions.document.client);
  expect(dimensions.main.scroll).toBeLessThanOrEqual(dimensions.main.client);
  expect(dimensions.outside).toEqual([]);
  return result;
}

function assertVerticalCapture(result: Awaited<ReturnType<typeof capture>>, requireTarget = false) {
  expect(result.vertical.stable).toBe(true);
  expect(result.vertical.afterScreenshot).toEqual(result.vertical.beforeScreenshot);
  for (const sample of [result.vertical.beforeScreenshot, result.vertical.afterScreenshot]) {
    if (sample.header) expect(Math.abs(sample.header.y)).toBeLessThanOrEqual(1);
    if (requireTarget) expect(sample.target.hit).toBe(true);
  }
}

function report(name: string, value: unknown) {
  writeFileSync(join(output, `${name}.json`), `${JSON.stringify({ proof: "synthetic-api-production-bundle-ui-only", real_service: false, cloud_calls: 0, enrollment: false, details: value }, null, 2)}\n`, { flag: "wx" });
}

test("synthetic production bundle: unavailable enrollment remains truthful and responsive", async ({ page }) => {
  const fixtureState = await fixture(page, null);
  await expect(page.getByText("No S3 environment is enrolled.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Open exercise" })).toHaveCount(0);
  const captures = [];
  for (const viewport of viewports) captures.push(await capture(page, "unavailable", viewport));
  captures.forEach(value => assertVerticalCapture(value));
  await page.getByRole("button", { name: "Open navigation", exact: true }).click();
  await page.getByRole("link", { name: "S3 access", exact: true }).click();
  await expect(page.getByRole("button", { name: "Open navigation", exact: true })).toHaveAttribute("aria-expanded", "false");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.reload();
  await expect(page.getByText("No S3 environment is enrolled.", { exact: true })).toBeVisible();
  expect(fixtureState.counts).toEqual({ review: 0, stage: 0, stop: 0, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("unavailable", { captures, counts: fixtureState.counts });
});

test("synthetic production bundle: evidence, review and reload preserve explicit control", async ({ page }) => {
  const value = s3Observed();
  const retest = structuredClone(value.operations[0]!);
  retest.phase = "retest"; retest.operation_job_id = `job-${"5".repeat(32)}`;
  retest.run_ids = [`run-20261009T000001Z-${"7".repeat(16)}`, `run-20261009T000001Z-${"8".repeat(16)}`];
  retest.outcome.state = "denied_with_legitimate_reads"; retest.outcome.facts[0]!.result = "service_denied";
  value.operations.push(retest); value.policy_state = "hardened"; value.allowed_phases = ["rollback", "reconcile"];
  const fixtureState = await fixture(page, value);
  const comparison = page.getByRole("region", { name: "Access comparison" });
  await expect(comparison.getByText("Service denied", { exact: true })).toBeVisible();
  await expect(page.getByText("Synthetic", { exact: true })).toHaveCount(2);
  await expect(page.getByText("No live defensive effectiveness has been independently verified.", { exact: true })).toBeVisible();
  const captures = [];
  for (const viewport of viewports) captures.push(await capture(page, "saved-evidence", viewport));
  captures.forEach(value => assertVerticalCapture(value));
  await page.getByText("Technical evidence", { exact: true }).first().click();
  await expect(page.locator("details[open] pre").first()).toContainText('"provenance": "synthetic"');
  await expect(comparison.getByRole("link", { name: "Compare saved runs" })).toHaveAttribute("href", /^#\/compare\?/);
  await expect(page.getByRole("link", { name: "Run evidence 1", exact: true }).first()).toHaveAttribute("href", /^#\/runs\/run-/);
  await page.getByRole("button", { name: "Restore reviewed policy", exact: true }).click();
  const confirm = page.getByRole("button", { name: "Confirm stage", exact: true });
  await expect(confirm).toBeDisabled();
  await page.getByLabel("Reviewed by", { exact: true }).fill("synthetic operator");
  await expect(confirm).toBeDisabled();
  await page.getByRole("checkbox").check();
  await expect(confirm).toBeEnabled();
  const originalReview = await capture(page, "explicit-review", viewports[2]!, ".s3-consent input");
  await confirm.evaluate(node => node.scrollIntoView({ behavior: "instant", block: "center" }));
  const framedReview = await capture(page, "explicit-review-framed", viewports[2]!, ".s3-review > button");
  captures.push(originalReview, framedReview);
  assertVerticalCapture(originalReview, true);
  assertVerticalCapture(framedReview, true);
  await confirm.click();
  await expect(page.getByText("Original operation in progress", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText("Original operation in progress", { exact: true })).toBeVisible();
  expect(fixtureState.counts).toEqual({ review: 1, stage: 1, stop: 0, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("saved-evidence", { captures, counts: fixtureState.counts });
});

test("synthetic production bundle: active recovery Stop remains usable without reload replay", async ({ page }) => {
  const value = s3Exercise(); value.stopped = true; value.allowed_phases = [];
  value.active_job = { job_id: s3Operation, state: "running", request: { s3_access: { workflow_job_id: s3Owner, phase: "rollback", review: { review_digest: s3Hash } } } };
  const fixtureState = await fixture(page, value);
  await page.getByRole("button", { name: "Stop current operation", exact: true }).click();
  await expect(page.getByRole("button", { name: "Retry stop", exact: true })).toBeEnabled();
  const captureResult = await capture(page, "pending-stop", viewports[2]!);
  assertVerticalCapture(captureResult);
  await page.reload();
  await expect(page.getByRole("button", { name: "Retry stop", exact: true })).toBeEnabled();
  expect(fixtureState.counts.stop).toBe(1);
  fixtureState.set({ ...value, active_job: null });
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("button", { name: "Stopped", exact: true })).toBeDisabled();
  expect(fixtureState.counts).toEqual({ review: 0, stage: 0, stop: 1, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("pending-stop", { capture: captureResult, counts: fixtureState.counts });
});
