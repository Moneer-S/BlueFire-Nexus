import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page } from "@playwright/test";
import productCorpus from "../../tests_platform/fixtures/s3_fixture_product_v2.json" with { type: "json" };
import type { S3Exercise, S3Review } from "../src/lib/s3-access";

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
export const desktop = { width: 1440, height: 900 };
export const mobile = { width: 390, height: 844 };
export interface FixtureSnapshot { name: string; exercise: S3Exercise; review: S3Review | null }

export function snapshot(name: string): FixtureSnapshot {
  const rows = productCorpus.snapshots.filter(row => row.name === name);
  if (rows.length !== 1 || productCorpus.provenance !== "synthetic") throw new Error("A closed synthetic corpus state is required.");
  const value = structuredClone(rows[0]) as unknown as FixtureSnapshot;
  return value;
}

export async function fixture(page: Page, initial: FixtureSnapshot) {
  let selected = initial;
  let value = structuredClone(initial.exercise);
  let admittedReview: S3Review | null = null;
  let connected = false;
  const owner = value.workflow_job_id;
  // These values only bind this closed synthetic route; they authorize no service.
  const code = randomBytes(32).toString("hex");
  const session = randomBytes(32).toString("hex");
  const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
  const counts = { review: 0, stage: 0, stop: 0, recover: 0, unexpected: 0, pageErrors: 0, websocket: 0 };
  const exact = (body: unknown, keys: string[]) => body !== null && typeof body === "object" && !Array.isArray(body)
    && JSON.stringify(Object.keys(body).sort()) === JSON.stringify([...keys].sort());
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
    if (method === "GET" && url.pathname === "/api/v1/s3-access/environments") { await json({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: "No S3 environment is enrolled." }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/exercises") {
      await json({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [{ workflow_job_id: owner, name: value.environment.display_name,
        bucket: value.environment.scope.bucket, policy_state: value.policy_state, updated_at: "2026-10-09T00:00:00Z" }], truncated: false }); return;
    }
    const root = `/api/v1/s3-access/exercises/${owner}`;
    if (method === "GET" && url.pathname === root) { await json(value); return; }
    if (method === "POST" && url.pathname === `${root}/review`) {
      const body = request.postDataJSON() as Record<string, unknown>;
      if (!exact(body, ["phase"]) || !selected.review || body.phase !== selected.review.phase || !value.allowed_phases.includes(selected.review.phase)) { await refuse(); return; }
      counts.review += 1; admittedReview = structuredClone(selected.review);
      await json(admittedReview); return;
    }
    if (method === "POST" && url.pathname === `${root}/operations`) {
      const body = request.postDataJSON() as Record<string, unknown>;
      if (!exact(body, ["phase", "submission_id", "review_digest", "reviewed_by"]) || !admittedReview
        || body.phase !== admittedReview.phase || body.review_digest !== admittedReview.review_digest || body.reviewed_by !== "synthetic operator"
        || admittedReview.revision !== value.revision || !value.allowed_phases.includes(admittedReview.phase)
        || typeof body.submission_id !== "string" || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(body.submission_id)) { await refuse(); return; }
      counts.stage += 1;
      value = { ...value, allowed_phases: [], active_job: { job_id: `job-${body.submission_id.replaceAll("-", "")}`, state: "running",
        request: { s3_access: { workflow_job_id: owner, phase: admittedReview.phase, review: { review_digest: admittedReview.review_digest } } } } };
      admittedReview = null;
      await json(value); return;
    }
    if (method === "POST" && url.pathname === `${root}/stop` && exact(request.postDataJSON(), [])) {
      counts.stop += 1; value = { ...value, stopped: true, allowed_phases: [] };
      await json(value); return;
    }
    await refuse();
  });
  await page.goto(`./#/s3-access?exercise=${owner}`);
  await expect(page.getByRole("heading", { name: "Connect to your workspace", exact: true })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("region", { name: "Generated test objects", exact: true })).toBeVisible();
  await expect(page.getByLabel("One-time connection code", { exact: false })).toHaveCount(0);
  return { counts, replace(next: FixtureSnapshot) {
    if (next.exercise.workflow_job_id !== owner) throw new Error("Saved corpus owner changed.");
    selected = next; value = structuredClone(next.exercise); admittedReview = null;
  } };
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

export async function capture(page: Page, name: string, viewport: { width: number; height: number }, targetSelector?: string) {
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

export function assertVerticalCapture(result: Awaited<ReturnType<typeof capture>>, requireTarget = false) {
  expect(result.vertical.stable).toBe(true);
  expect(result.vertical.afterScreenshot).toEqual(result.vertical.beforeScreenshot);
  for (const sample of [result.vertical.beforeScreenshot, result.vertical.afterScreenshot]) {
    if (sample.header) expect(Math.abs(sample.header.y)).toBeLessThanOrEqual(1);
    if (requireTarget) expect(sample.target.hit).toBe(true);
  }
}

export function report(name: string, value: unknown) {
  writeFileSync(join(output, `${name}.json`), `${JSON.stringify({ proof: "synthetic-api-production-bundle-ui-only", real_service: false, cloud_calls: 0, enrollment: false, details: value }, null, 2)}\n`, { flag: "wx" });
}
