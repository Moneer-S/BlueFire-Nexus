import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import corpus from "../../../tests_platform/fixtures/s3_audit_reviews_v1.json" with { type: "json" };
import exercise from "../../../tests_platform/fixtures/s3_audit_exercise_v1.json" with { type: "json" };

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const source = corpus.cases[0]!;
const owner = corpus.history.workflow_job_id;

async function fixture(page: Page) {
  const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
  const code = randomBytes(32).toString("hex"), session = randomBytes(32).toString("hex");
  const state = { connected: false, saves: 0, opens: 0, unexpected: [] as string[], pageErrors: [] as string[], sockets: 0 };
  let saved = structuredClone(source.review);
  page.on("pageerror", error => state.pageErrors.push(error.message));
  await page.context().routeWebSocket("**/*", socket => { state.sockets++; socket.close(); });
  await page.context().route("**/*", async route => {
    const req = route.request(), url = new URL(req.url()), method = req.method();
    const json = (value: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(value) });
    if (url.origin !== origin || url.username || url.password || url.search) { state.unexpected.push(method + " " + url.pathname); await route.abort(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !state.connected && req.headers()["x-bluefire-browser-bootstrap"] === code) { state.connected = true; await json({ session }); return; }
      if (method === "GET" && state.connected && req.headers()["x-bluefire-session"] === session) { await route.fulfill({ status: 204 }); return; }
      if (method === "GET" && !state.connected) { await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ error: { code: "browser_session_unavailable", message: "Synthetic session required." } }) }); return; }
    }
    if (!state.connected || req.headers()["x-bluefire-session"] !== session) { state.unexpected.push("session"); await route.abort(); return; }
    if (method === "GET" && url.pathname === "/api/v1/resources/runner-profiles") { await json({ schema_version: "bluefire.resource-list.v1", kind: "runner-profiles", resources: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [] } }); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/environments") { await json({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: "No S3 environment is enrolled." }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/exercises") { await json({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [], truncated: false }); return; }
    if (method === "GET" && url.pathname === `/api/v1/s3-access/exercises/${owner}`) { await json(exercise); return; }
    if (method === "GET" && url.pathname === `/api/v1/s3-access/exercises/${owner}/audit-reviews`) { const history = structuredClone(corpus.history); if (state.saves) history.reviews = [{ ...history.reviews.find(r => r.source.reader === "probe")!, review_id: saved.review_id }]; await json(history); return; }
    if (method === "GET" && url.pathname === `/api/v1/s3-access/exercises/${owner}/audit-reviews/${saved.review_id}`) { state.opens++; await json(saved); return; }
    if (method === "POST" && url.pathname === `/api/v1/s3-access/exercises/${owner}/audit-reviews`) {
      const body = req.postDataJSON() as typeof source.input;
      expect(Object.keys(body).sort()).toEqual(["delivery_state", "logs", "run_id", "submission_id"]);
      expect(body.run_id).toBe(source.input.run_id); expect(body.delivery_state).toBe(source.input.delivery_state); expect(body.logs).toEqual(source.input.logs);
      expect(body.submission_id).toMatch(/^[0-9a-f-]{36}$/);
      const canonical = JSON.stringify({ delivery_state: body.delivery_state, logs: body.logs.map(row => ({ data: row.data, encoding: row.encoding })), run_id: body.run_id, submission_id: body.submission_id });
      saved = { ...structuredClone(source.review), review_id: "job-" + body.submission_id.replaceAll("-", ""), input_digest: "sha256:" + createHash("sha256").update(canonical).digest("hex") };
      state.saves++; await route.abort("failed"); return;
    }
    state.unexpected.push(method + " " + url.pathname); await route.abort();
  });
  await page.goto(`./#/s3-access?exercise=${owner}`);
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Cloud audit", exact: true })).toBeVisible();
  return state;
}

async function capture(page: Page, name: string) {
  await page.evaluate(async () => { await document.fonts.ready; });
  const bounds = await page.evaluate(() => {
    const main = document.querySelector("main")!, rect = main.getBoundingClientRect();
    const outside = [...main.querySelectorAll("h1,h2,h3,p,button,select,input,a,article")].filter(node => { const box = node.getBoundingClientRect(); return box.width > 0 && box.height > 0 && (box.left < rect.left - 1 || box.right > rect.right + 1); }).map(node => node.tagName);
    return { width: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth, mainWidth: main.clientWidth, mainScroll: main.scrollWidth, outside };
  });
  expect(bounds.scroll).toBeLessThanOrEqual(bounds.width); expect(bounds.mainScroll).toBeLessThanOrEqual(bounds.mainWidth); expect(bounds.outside).toEqual([]);
  await page.screenshot({ path: join(output, `${name}.png`), fullPage: false, animations: "disabled" });
  writeFileSync(join(output, `${name}.json`), JSON.stringify({ proof: "synthetic API production UI only", bounds }, null, 2), { flag: "wx" });
}

for (const width of [1366, 390, 320]) {
  test(`saved audit recovery and honest evidence at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width < 500 ? 844 : 900 });
    const state = await fixture(page);
    await page.getByLabel("Original read attempt").selectOption(source.input.run_id);
    await page.getByLabel("Reported delivery").selectOption("complete");
    await page.getByLabel("Audit files").setInputFiles({ name: "synthetic-audit.json.gz", mimeType: "application/gzip", buffer: Buffer.from(source.input.logs[0]!.data, "base64") });
    await page.getByRole("heading", { name: "Cloud audit", exact: true }).scrollIntoViewIfNeeded();
    await capture(page, `audit-import-${width}`);
    await page.getByRole("button", { name: "Save audit review", exact: true }).click();
    await expect(page.getByText("Import confirmation pending", { exact: true })).toBeVisible();
    await expect(page.getByText("Audit review not confirmed", { exact: true })).toBeVisible();
    const retained = await page.evaluate(id => localStorage.getItem(`bluefire.s3.audit.pending.v1.${id}`), owner);
    expect(retained).not.toContain(source.input.logs[0]!.data); expect(retained).not.toContain("synthetic-audit");
    await page.reload();
    const check = page.getByRole("button", { name: "Check saved review", exact: true }); await expect(check).toBeVisible();
    await check.focus(); await page.keyboard.press("Enter");
    const detail = page.getByLabel("Saved audit review detail"); await expect(detail).toBeVisible();
    await expect(page.getByText("Import confirmation pending", { exact: true })).toHaveCount(0);
    await expect(detail.getByText("Matched", { exact: true })).toBeVisible();
    await expect(detail.getByText("Not proven", { exact: true })).toBeVisible();
    await expect(detail.getByRole("link", { name: "Original run evidence" })).toHaveAttribute("href", `#/runs/${source.input.run_id}`);
    await detail.scrollIntoViewIfNeeded(); await capture(page, `audit-recovered-${width}`);
    expect(state.saves).toBe(1); expect(state.opens).toBe(1); expect(state.unexpected).toEqual([]); expect(state.pageErrors).toEqual([]); expect(state.sockets).toBe(0);
    writeFileSync(join(output, `audit-journey-${width}.json`), JSON.stringify({ proof: "synthetic API production UI only", cloud_calls: 0, real_service: false, state }, null, 2), { flag: "wx" });
  });
}
