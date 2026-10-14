import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { adHash, adOwner, rawAdEnvironments, rawAdOperation, rawAdReview, rawAdWorkflow } from "../ad-smb-browser-fixture";
import type { AdPhase } from "../../src/lib/ad-smb";

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const viewports = [{ width: 1366, height: 900 }, { width: 1440, height: 900 }, { width: 390, height: 844 }];
type FixtureWorkflow = ReturnType<typeof rawAdWorkflow>;

async function fixture(page: Page, initial: FixtureWorkflow | null, loseAcknowledgement = false) {
  let value = initial;
  let environmentOverride: unknown;
  let environmentChecks = 0;
  let connected = false;
  let acknowledgement: unknown;
  let acknowledgementId = "";
  let submittedPhase: AdPhase = "rollback";
  // These random values authorize nothing; every API response is synthetic.
  const code = randomBytes(32).toString("hex");
  const session = randomBytes(32).toString("hex");
  const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
  const counts = { review: 0, stage: 0, stop: 0, recover: 0, saved: 0, unexpected: 0, pageErrors: 0, websocket: 0 };
  page.on("pageerror", () => { counts.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { counts.websocket += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    const refuse = async () => { counts.unexpected += 1; await route.abort(); };
    if (url.origin !== origin || url.search || url.username || url.password) { await refuse(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !connected && request.headers()["x-bluefire-browser-bootstrap"] === code) { connected = true; await json({ session }); return; }
      if (method === "GET" && connected && request.headers()["x-bluefire-session"] === session) { await route.fulfill({ status: 204 }); return; }
      await json({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }, 401); return;
    }
    if (!connected || request.headers()["x-bluefire-session"] !== session) { await refuse(); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [] } }); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/ad-smb/environments") { environmentChecks += 1; await json(environmentOverride ?? (value ? rawAdEnvironments() : { environments: [], native_execution_available: false })); return; }
    if (method === "GET" && url.pathname === "/api/v1/ad-smb/workflows") { await json({ workflows: value ? [value] : [] }); return; }
    const root = `/api/v1/ad-smb/workflows/${adOwner}`;
    if (method === "GET" && url.pathname === root && value) { await json(value); return; }
    if (method === "GET" && acknowledgement && url.pathname === `/api/v1/jobs/${acknowledgementId}`) { counts.saved += 1; await json(acknowledgement); return; }
    if (method === "POST" && url.pathname === `${root}/review` && value) {
      const body = request.postDataJSON() as { phase: AdPhase };
      if (Object.keys(body).join() !== "phase" || !value.allowed_phases.includes(body.phase)) { await refuse(); return; }
      counts.review += 1;
      await json(rawAdReview(body.phase, value.workflow.progress.revision)); return;
    }
    if (method === "POST" && url.pathname === `${root}/operations` && value) {
      const body = request.postDataJSON() as { phase: AdPhase; submission_id: string; review_digest: string; reviewed_by: string };
      if (Object.keys(body).sort().join() !== "phase,review_digest,reviewed_by,submission_id" || !value.allowed_phases.includes(body.phase) || body.review_digest !== adHash || body.reviewed_by !== "synthetic operator" || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(body.submission_id)) { await refuse(); return; }
      counts.stage += 1;
      submittedPhase = body.phase;
      acknowledgementId = `job-${body.submission_id.replaceAll("-", "")}`;
      acknowledgement = { job_id: acknowledgementId, kind: "ad_smb.operation", request: { submitted_request: { workflow_job_id: adOwner, phase: body.phase, review_digest: adHash, reviewed_by: body.reviewed_by } } };
      value = { ...value, allowed_phases: [], workflow: { ...value.workflow, progress: { ...value.workflow.progress, pending_operation: acknowledgementId } } };
      if (loseAcknowledgement) { await json({ error: { code: "fixture_lost_acknowledgement", message: "Synthetic acknowledgement was not returned." } }, 503); return; }
      await json(acknowledgement); return;
    }
    if (method === "POST" && url.pathname === `${root}/stop` && value && JSON.stringify(request.postDataJSON()) === "{}") {
      counts.stop += 1;
      value = { ...value, allowed_phases: [], workflow: { ...value.workflow, progress: { ...value.workflow.progress, stopped: true } } };
      await json(value); return;
    }
    if (method === "POST" && url.pathname === `${root}/recover` && value && JSON.stringify(request.postDataJSON()) === "{}") {
      counts.recover += 1;
      // First response stays unsettled. The second adopts a retained original fixture.
      if (counts.recover === 2) {
        const original = rawAdOperation(submittedPhase);
        original.job_id = value.workflow.progress.pending_operation!;
        value = { ...value, workflow: { ...value.workflow, progress: { ...value.workflow.progress, pending_operation: null, revision: value.workflow.progress.revision + 1, operations: [...value.workflow.progress.operations, original] } } };
      }
      await json(value); return;
    }
    await refuse();
  });
  await page.goto(`./#/ad-smb${initial ? `?workflow=${adOwner}` : ""}`);
  await expect(page.getByRole("heading", { name: "Connect to your workspace", exact: true })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "AD share access", exact: true })).toBeVisible();
  await expect(page.getByLabel("One-time connection code", { exact: false })).toHaveCount(0);
  return { counts, set: (next: FixtureWorkflow) => { value = next; }, setEnvironments: (next: unknown) => { environmentOverride = next; }, environmentChecks: () => environmentChecks };
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
      review: bounds(document.querySelector(".ad-smb-review")),
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
  writeFileSync(join(output, `${name}.json`), `${JSON.stringify({ proof: "synthetic-api-production-bundle-ui-only", real_service: false, domain_calls: 0, native_calls: 0, enrollment: false, details: value }, null, 2)}\n`, { flag: "wx" });
}

async function confirmReview(page: Page) {
  const confirm = page.getByRole("button", { name: "Submit reviewed stage", exact: true });
  await expect(confirm).toBeDisabled();
  await page.getByLabel("Reviewed by", { exact: true }).fill("synthetic operator");
  await expect(confirm).toBeDisabled();
  await page.getByRole("checkbox").check();
  await expect(confirm).toBeEnabled();
  return confirm;
}

function assertNoUnexpected(counts: Awaited<ReturnType<typeof fixture>>["counts"]) {
  expect({ unexpected: counts.unexpected, pageErrors: counts.pageErrors, websocket: counts.websocket }).toEqual({ unexpected: 0, pageErrors: 0, websocket: 0 });
}

test("synthetic production bundle: unavailable AD enrollment remains explicit at all widths", async ({ page }) => {
  const state = await fixture(page, null);
  await expect(page.getByText("Live AD execution unavailable", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save exercise", exact: true })).toHaveCount(0);
  const captures = [];
  for (const viewport of viewports) captures.push(await capture(page, "unavailable", viewport));
  captures.forEach(value => assertVerticalCapture(value));
  await page.getByRole("button", { name: "Open navigation", exact: true }).click();
  await page.getByRole("link", { name: "AD share access", exact: true }).click();
  await expect(page.getByRole("button", { name: "Open navigation", exact: true })).toHaveAttribute("aria-expanded", "false");
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await page.reload();
  await expect(page.getByText("Live AD execution unavailable", { exact: true })).toBeVisible();
  expect(state.counts).toEqual({ review: 0, stage: 0, stop: 0, recover: 0, saved: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("unavailable", { captures, counts: state.counts });
});

for (const width of [1366, 390, 320]) test(`synthetic AD enrollment refresh and partial-channel recovery at ${width}`, async ({ page }) => {
  const viewport = { width, height: 900 };
  await page.setViewportSize(viewport);
  const state = await fixture(page, null);
  await expect(page.getByText("Not tested", { exact: true })).toBeVisible();
  const ready = rawAdEnvironments();
  const entry = ready.environments[0]!;
  state.setEnvironments({ ...ready, environments: [{ ...entry, available: false, readiness: { ...entry.readiness, available: false, client_read_admission: false, secret_channel_available: false, problem: "client_channel_unavailable" } }] });
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await expect(page.getByText("The client channel did not confirm its enrolled configuration.", { exact: true })).toBeVisible();
  await expect(page.getByText("Configuration confirmed", { exact: true })).toHaveCount(1);
  const save = page.getByRole("button", { name: "Save exercise", exact: true });
  await expect(save).toBeDisabled();
  await save.scrollIntoViewIfNeeded();
  const partial = await capture(page, "partial-channel", viewport, ".ad-smb-environment button");
  assertVerticalCapture(partial, true);
  state.setEnvironments(ready);
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await expect(save).toBeEnabled();
  await expect(page.getByText("Configuration confirmed", { exact: true })).toHaveCount(3);
  await expect(page.getByText("Enrollment needs attention", { exact: true })).toHaveCount(0);
  await page.reload();
  await expect(save).toBeEnabled();
  await expect(page.getByText(/Configuration checks only/)).toBeVisible();
  await save.scrollIntoViewIfNeeded();
  const recovered = await capture(page, "refreshed-enrollment", viewport, ".ad-smb-environment button");
  assertVerticalCapture(recovered, true);
  expect(state.environmentChecks()).toBe(4);
  expect(state.counts).toEqual({ review: 0, stage: 0, stop: 0, recover: 0, saved: 0, unexpected: 0, pageErrors: 0, websocket: 0 });
  report(`readiness-refresh-${width}`, { partial, recovered, counts: state.counts, environmentChecks: state.environmentChecks() });
});

test("synthetic production bundle: settled counterexample, exact restore review and pending reload", async ({ page }) => {
  const value = rawAdWorkflow({ phases: ["inspect", "baseline", "harden", "retest"], expectation: "not_met", allowed: ["rollback"] });
  const state = await fixture(page, value);
  const comparison = page.getByRole("region", { name: "Baseline and fresh read comparison" });
  await expect(comparison.getByText("Content matched", { exact: true })).toHaveCount(6);
  await expect(page.getByText("Read expectations not met", { exact: true })).toBeVisible();
  await expect(page.getByText("Synthetic fixture", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Audit not collected. No independent observation is reported.", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open retained run" }).first()).toHaveAttribute("href", "#/runs/run-ad-inspect");
  const captures = [];
  for (const viewport of viewports) captures.push(await capture(page, "saved-counterexample", viewport));
  captures.forEach(value => assertVerticalCapture(value));
  await page.getByRole("button", { name: "Review restore share access", exact: true }).click();
  const review = page.getByRole("region", { name: "Explicit AD stage review" });
  await expect(review.getByText("Restore direction", { exact: true })).toBeVisible();
  await expect(review.getByRole("row", { name: "Principal Current Restored" })).toBeVisible();
  await expect(review.getByRole("row", { name: "Probe No explicit allow Read" })).toBeVisible();
  await expect(review.getByText("Explicit allow removed", { exact: true })).toHaveCount(0);
  const confirm = await confirmReview(page);
  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    await confirm.evaluate(node => node.scrollIntoView({ behavior: "instant", block: "center" }));
    const result = await capture(page, "explicit-restore-review", viewport, ".ad-smb-review .ad-smb-actions button");
    assertVerticalCapture(result, true); captures.push(result);
  }
  await confirm.click();
  await expect(page.getByText("Original operation unsettled", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText("Original operation unsettled", { exact: true })).toBeVisible();
  expect(state.counts.stage).toBe(1);
  expect(state.counts.review).toBe(1);
  expect(state.counts.recover).toBe(0);
  assertNoUnexpected(state.counts);
  report("saved-counterexample", { captures, counts: state.counts });
});

test("synthetic production bundle: absent audit and observed zero are distinct", async ({ page }) => {
  const missing = rawAdWorkflow({ phases: ["audit"], allowed: [] });
  const audit = missing.workflow.progress.operations[0]!;
  Object.assign(audit.outcome, { state: "not_started" });
  Object.assign(audit.executions[0]!, { dispatch: "not_started", observation: null });
  const state = await fixture(page, missing);
  await expect(page.getByText("No audit observation retained. No independent observation is reported.", { exact: true })).toBeVisible();
  await expect(page.getByText(/^Audit retained:/)).toHaveCount(0);
  const absent = await capture(page, "audit-absent", viewports[2]!);
  assertVerticalCapture(absent);
  const observed = rawAdWorkflow({ phases: ["audit"], allowed: [] });
  Object.assign(observed.workflow.progress.operations[0]!.executions[0]!.observation!, { events: 0, truncated: false });
  state.set(observed);
  await page.getByRole("button", { name: "Refresh state", exact: true }).click();
  await expect(page.getByText("Audit retained: 0 events. Source authentication and independence are not established.", { exact: true })).toBeVisible();
  const zero = await capture(page, "audit-observed-zero", viewports[2]!);
  assertVerticalCapture(zero);
  assertNoUnexpected(state.counts);
  report("audit", { absent, zero, counts: state.counts });
});

test("synthetic production bundle: original acknowledgement and retained result recovery never replay", async ({ page }) => {
  const initial = rawAdWorkflow({ phases: ["inspect", "baseline", "harden"], allowed: ["rollback"], stopped: true });
  const state = await fixture(page, initial, true);
  await page.getByRole("button", { name: "Review restore share access", exact: true }).click();
  await (await confirmReview(page)).click();
  await expect(page.getByText("Original request not yet confirmed", { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText("Original request not yet confirmed", { exact: true })).toBeVisible();
  expect(state.counts.stage).toBe(1);
  await page.getByRole("button", { name: "Check saved request", exact: true }).click();
  await expect(page.getByText("Original request not yet confirmed", { exact: true })).toHaveCount(0);
  expect(state.counts.saved).toBe(1);
  const stop = page.getByRole("button", { name: "Stop current operation", exact: true });
  await expect(stop).toBeEnabled();
  await stop.click();
  await expect(page.getByRole("button", { name: "Check original results", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Check original results", exact: true }).click();
  await expect(page.getByText("Original operation unsettled", { exact: true })).toBeVisible();
  const pending = await capture(page, "original-unsettled", viewports[2]!);
  assertVerticalCapture(pending);
  await page.reload();
  expect(state.counts.recover).toBe(1);
  await page.getByRole("button", { name: "Check original results", exact: true }).click();
  await expect(page.getByText("Original operation unsettled", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Open retained run" })).toHaveCount(4);
  await expect(page.getByRole("button", { name: "Stop new work", exact: true })).toBeDisabled();
  await page.reload();
  await expect(page.getByRole("link", { name: "Open retained run" })).toHaveCount(4);
  expect(state.counts).toEqual({ review: 1, stage: 1, stop: 1, recover: 2, saved: 1, unexpected: 0, pageErrors: 0, websocket: 0 });
  report("original-recovery", { pending, counts: state.counts, same_original_job: true, business_replay: false });
});
