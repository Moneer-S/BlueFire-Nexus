import { randomBytes } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import captured from "../../../tests_platform/fixtures/s3_comparison_v1.json" with { type: "json" };
import { capture, report } from "../s3-fixture-browser-support";

type CapturedRoute = { method: string; path: string; status: number; body_utf8: string; request_body?: Record<string, unknown> };
type SnapshotDetail = {
  snapshot_id: string;
  digest: string;
  created_at: string;
  comparison: { run_ids: string[]; baseline_run_id: string; summaries: Array<{ run_id: string }> };
  source_bindings: Array<{ run_id: string; bundle_hash: string }>;
  source_integrity: { status: "verified" | "unavailable"; runs: Array<{ run_id: string; status: string }> };
};

const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
const compareReadPaths = new Set(["/api/v1/catalog", "/api/v1/scenarios", "/api/v1/detections", "/api/v1/runs"]);
const captureFile = captured as unknown as { browser: { routes: CapturedRoute[] }; cases: Array<{ name: string; request: { run_ids: string[] } }> };
const route = (method: string, path: string, predicate: (item: CapturedRoute) => boolean = () => true) => {
  const matches = captureFile.browser.routes.filter((item) => item.method === method && item.path === path && predicate(item));
  if (!matches.length) throw new Error(`The saved-comparison browser capture is missing ${method} ${path}.`);
  return matches[matches.length - 1]!;
};
const pairedCase = captureFile.cases.find((item) => item.name === "paired_denied");
if (!pairedCase) throw new Error("The paired synthetic comparison capture is unavailable.");
const runIds = pairedCase.request.run_ids;
const postRoute = route("POST", "/api/v1/comparisons", (item) => JSON.stringify(item.request_body?.run_ids) === JSON.stringify(runIds));
const postResponse = JSON.parse(postRoute.body_utf8) as { saved_snapshot?: { snapshot_id: string; digest: string; created_at: string } };
if (!postResponse.saved_snapshot?.snapshot_id) throw new Error("The captured comparison response has no saved snapshot identity.");
const snapshotId = postResponse.saved_snapshot.snapshot_id;
const listRoute = route("GET", "/api/v1/comparison-snapshots");
const listResponse = JSON.parse(listRoute.body_utf8) as { snapshots: Array<{ snapshot_id: string; digest: string; created_at: string; run_ids: string[]; baseline_run_id: string }> };
if (!listResponse.snapshots.some((item) => item.snapshot_id === snapshotId)) throw new Error("The captured snapshot list does not contain the comparison response.");
const detailPath = `/api/v1/comparison-snapshots/${snapshotId}`;
const detailRoute = route("GET", detailPath);
const detailResponse = JSON.parse(detailRoute.body_utf8) as SnapshotDetail;
if (detailResponse.snapshot_id !== snapshotId || JSON.stringify(detailResponse.comparison.run_ids) !== JSON.stringify(runIds)) throw new Error("The captured saved comparison is not bound to the paired run selection.");
const runsRoute = route("GET", "/api/v1/runs");
const runsResponse = JSON.parse(runsRoute.body_utf8) as { runs: Array<{ run_id: string }> };
if (runIds.some((id) => !runsResponse.runs.some((run) => run.run_id === id))) throw new Error("The captured run history is missing a comparison source.");

async function captureAtTop(page: Page, name: string, viewport: { width: number; height: number }) {
  await page.setViewportSize(viewport);
  await page.evaluate(() => window.scrollTo(0, 0));
  return capture(page, name, viewport);
}

async function captureS3Section(page: Page, viewport: { width: number; height: number }) {
  await page.setViewportSize(viewport);
  const section = page.locator('[aria-label="S3 access comparison"]');
  await section.scrollIntoViewIfNeeded();
  const result = await capture(page, "saved-comparison-s3-access", viewport, '[aria-label="S3 access comparison"]');
  expect(result.vertical.beforeScreenshot.target.hit).toBe(true);
  return result;
}

async function closedFixture(page: Page, missingSourceVariant = false, runNames?: ReadonlyMap<string, string>) {
  let connected = false;
  const code = randomBytes(32).toString("hex");
  const session = randomBytes(32).toString("hex");
  const counts = { comparePost: 0, snapshotListGet: 0, snapshotDetailGet: 0, unexpected: 0, pageErrors: 0, websockets: 0 };
  const normalDetail = structuredClone(detailResponse);
  const variantId = "synthetic-missing-source-variant";
  const variant: SnapshotDetail = {
    ...structuredClone(normalDetail), snapshot_id: variantId, digest: "synthetic-ui-variant-only",
    source_integrity: { status: "unavailable", runs: normalDetail.source_integrity.runs.map((item, index) => ({ ...item, status: index === 0 ? "verified" : "missing" })) },
  };
  page.on("pageerror", () => { counts.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", (socket) => { counts.websockets += 1; socket.close(); });
  await page.context().route("**/*", async (intercept) => {
    const request = intercept.request();
    const url = new URL(request.url());
    const method = request.method();
    const refuse = async () => { counts.unexpected += 1; await intercept.abort(); };
    const respond = async (value: unknown, status = 200) => intercept.fulfill({ status, contentType: "application/json; charset=utf-8", body: JSON.stringify(value) });
    if (url.origin !== origin || url.search || url.username || url.password) { await refuse(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await intercept.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !connected && request.headers()["x-bluefire-browser-bootstrap"] === code) { connected = true; await respond({ session }); return; }
      if (method === "GET" && connected && request.headers()["x-bluefire-session"] === session) { await intercept.fulfill({ status: 204 }); return; }
      await respond({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }, 401); return;
    }
    if (!connected || request.headers()["x-bluefire-session"] !== session) { await refuse(); return; }
    if (method === "POST" && url.pathname === "/api/v1/comparisons") {
      const body = request.postDataJSON() as { run_ids?: string[] };
      if (counts.comparePost !== 0 || JSON.stringify(body.run_ids) !== JSON.stringify(runIds)) { await refuse(); return; }
      counts.comparePost += 1;
      await intercept.fulfill({ status: postRoute.status, contentType: "application/json; charset=utf-8", body: postRoute.body_utf8 });
      return;
    }
    if (method === "GET" && url.pathname === "/api/v1/comparison-snapshots") {
      counts.snapshotListGet += 1;
      if (!missingSourceVariant) {
        await intercept.fulfill({ status: listRoute.status, contentType: "application/json; charset=utf-8", body: listRoute.body_utf8 });
        return;
      }
      const value = JSON.parse(listRoute.body_utf8) as typeof listResponse;
      value.snapshots.push({ snapshot_id: variantId, digest: variant.digest, created_at: variant.created_at, run_ids: runIds, baseline_run_id: runIds[0]! });
      await intercept.fulfill({ status: listRoute.status, contentType: "application/json; charset=utf-8", body: JSON.stringify(value) });
      return;
    }
    if (method === "GET" && url.pathname === detailPath) {
      counts.snapshotDetailGet += 1;
      await intercept.fulfill({ status: detailRoute.status, contentType: "application/json; charset=utf-8", body: detailRoute.body_utf8 });
      return;
    }
    if (missingSourceVariant && method === "GET" && url.pathname === `/api/v1/comparison-snapshots/${encodeURIComponent(variantId)}`) {
      counts.snapshotDetailGet += 1;
      await respond(variant);
      return;
    }
    const recordedGet = compareReadPaths.has(url.pathname)
      ? captureFile.browser.routes.find((item) => item.method === "GET" && item.path === url.pathname)
      : undefined;
    if (method === "GET" && recordedGet) {
      if (url.pathname === "/api/v1/runs" && runNames) {
        const value = JSON.parse(recordedGet.body_utf8) as typeof runsResponse;
        value.runs = value.runs.map(run => runNames.has(run.run_id) ? { ...run, presentation: {
          schema_version: "bluefire.run-presentation.v1", run_id: run.run_id, display_name: runNames.get(run.run_id), default_name: runNames.get(run.run_id), updated_at: null,
        } } : run);
        await respond(value, recordedGet.status);
        return;
      }
      await intercept.fulfill({ status: recordedGet.status, contentType: "application/json; charset=utf-8", body: recordedGet.body_utf8 });
      return;
    }
    await refuse();
  });
  await page.goto("./#/compare");
  await expect(page.getByRole("heading", { name: "Connect to your workspace", exact: true })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Compare runs", exact: true })).toBeVisible();
  return { counts, variantId };
}

test("saved comparison: captured create, reload, independent reopen and responsive history", async ({ page }) => {
  const state = await closedFixture(page);
  const checkboxes = page.locator(".run-select-list input[type=checkbox]");
  for (const id of runIds) {
    const index = runsResponse.runs.findIndex((run) => run.run_id === id);
    if (index < 0) throw new Error(`The captured run list does not contain ${id}.`);
    await checkboxes.nth(index).check();
  }
  await page.getByRole("button", { name: "Compare selected", exact: true }).click();
  await expect(page.getByRole("region", { name: "Comparison results" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Current detector evaluations", exact: true })).toBeVisible();
  await expect.poll(() => new URL(page.url()).hash).toContain(`snapshot=${encodeURIComponent(snapshotId)}`);
  await expect.poll(() => state.counts.comparePost).toBe(1);
  await page.reload();
  await expect(page.getByRole("region", { name: "Comparison results" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Current detector evaluations", exact: true })).toBeVisible();
  expect(state.counts.comparePost).toBe(1);

  await page.goto("./#/compare");
  await page.locator(`button[data-snapshot-id=${JSON.stringify(snapshotId)}]`).click();
  await expect(page.getByRole("region", { name: "Comparison results" })).toBeVisible();
  expect(state.counts.comparePost).toBe(1);
  const captures = [];
  captures.push(await captureAtTop(page, "saved-comparison-history", { width: 1366, height: 900 }));
  captures.push(await captureAtTop(page, "saved-comparison-history", { width: 390, height: 844 }));
  captures.push(await captureS3Section(page, { width: 1366, height: 900 }));
  captures.push(await captureS3Section(page, { width: 390, height: 844 }));
  captures.forEach((result) => expect(result.vertical.stable).toBe(true));
  expect(state.counts).toMatchObject({ comparePost: 1, unexpected: 0, pageErrors: 0, websockets: 0 });
  report("saved-comparison-history", { snapshot_id: snapshotId, captures, counts: state.counts, source: "captured S3 comparison fixture" });
});

test("saved comparison UI variant: missing source is historical and not reevaluated", async ({ page }) => {
  const state = await closedFixture(page, true);
  await page.locator(`button[data-snapshot-id=${JSON.stringify(state.variantId)}]`).click();
  await expect(page.getByText(/shown as saved and was not recomputed/)).toBeVisible();
  await expect(page.getByRole("region", { name: "Comparison results" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Current detector evaluations", exact: true })).toHaveCount(0);
  expect(state.counts.comparePost).toBe(0);
  expect(state.counts).toMatchObject({ unexpected: 0, pageErrors: 0, websockets: 0 });
  report("saved-comparison-missing-source-ui-variant", { variant: "synthetic missing-source UI-only variant", counts: state.counts, live_api_calls: 0 });
});

test("saved comparison purpose labels and record details remain reachable on desktop", async ({ page }) => {
  const longName = ["Verify", "Generated", "Collection", "Permission", "Recovery", "Across", "The", "Authorized", "Desktop", "Workspace", "Without", "Changing", "The", "Original", "Run"].join("");
  const names = new Map(runIds.map((id, index) => [id, index === 0
    ? longName
    : `Fresh permission retest ${index}: preserve legitimate collection and verify the retained defensive change`]));
  const state = await closedFixture(page, false, names);
  const buttonSelector = `button[data-snapshot-id=${JSON.stringify(snapshotId)}]`;
  const button = page.locator(buttonSelector);
  const row = button.locator("..");
  const details = row.locator("details");
  const summary = details.locator("summary");
  const expectedLabels = runIds.map((id, index) => `${index === 0 ? "Baseline" : `Compared run ${index}`}: ${names.get(id)}`);
  await expect(button.locator("strong")).toHaveText(expectedLabels);
  await expect(button).toHaveAccessibleName(new RegExp(`^Open saved comparison\\. Baseline: ${names.get(runIds[0]!)}`));
  const captures = [];
  const layoutChecks = [];
  for (const viewport of [{ width: 1366, height: 768 }, { width: 1440, height: 900 }, { width: 1920, height: 1080 }, { width: 1024, height: 768 }]) {
    await page.setViewportSize(viewport);
    await page.locator(".saved-comparisons-list").evaluate(node => { node.scrollTop = 0; });
    await button.scrollIntoViewIfNeeded();
    const labelGeometry = await button.evaluate(node => ({ width: node.clientWidth, scrollWidth: node.scrollWidth,
      labels: [...node.querySelectorAll("strong")].map(label => ({ width: label.clientWidth, scrollWidth: label.scrollWidth })) }));
    expect(labelGeometry.scrollWidth).toBeLessThanOrEqual(labelGeometry.width + 1);
    labelGeometry.labels.forEach(label => expect(label.scrollWidth).toBeLessThanOrEqual(label.width + 1));
    const layout = await page.evaluate(() => {
      const names = [...document.querySelectorAll<HTMLElement>(".run-select-list strong")].map(node => {
        const badge = node.closest("label")!.querySelector("span:last-child")!.getBoundingClientRect();
        const rect = node.getBoundingClientRect();
        return { width: node.clientWidth, scrollWidth: node.scrollWidth, right: rect.right, badgeLeft: badge.left };
      });
      const footer = document.querySelector(".history-panel > footer")!;
      const note = footer.querySelector(".workspace-note")!.getBoundingClientRect();
      const action = footer.querySelector("button")!.getBoundingClientRect();
      return { names, footerSeparated: note.right <= action.left || note.bottom <= action.top || action.bottom <= note.top };
    });
    layout.names.forEach(name => {
      expect(name.scrollWidth).toBeLessThanOrEqual(name.width + 1);
      expect(name.right).toBeLessThanOrEqual(name.badgeLeft - 1);
    });
    expect(layout.footerSeparated).toBe(true);
    layoutChecks.push({ viewport, labelGeometry, ...layout });
    captures.push(await capture(page, "saved-comparison-purpose-labels", viewport));
    await summary.focus();
    await expect(summary).toBeFocused();
    await summary.press("Enter");
    await expect(details).toHaveAttribute("open", "");
    await expect(details.locator("ol code")).toHaveText(runIds);
    const digest = details.getByText(detailResponse.digest, { exact: true });
    await digest.scrollIntoViewIfNeeded();
    const digestReachable = await digest.evaluate(node => {
      const rect = node.getBoundingClientRect();
      const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return Boolean(hit && node.contains(hit));
    });
    expect(digestReachable).toBe(true);
    captures.push(await capture(page, "saved-comparison-record-details", viewport));
    await summary.focus();
    await summary.press("Enter");
    await expect(details).not.toHaveAttribute("open", "");
  }
  captures.forEach(result => expect(result.vertical.stable).toBe(true));
  expect(state.counts).toMatchObject({ comparePost: 0, snapshotDetailGet: 0, unexpected: 0, pageErrors: 0, websockets: 0 });
  await button.click();
  await expect(page.getByRole("region", { name: "Comparison results" })).toBeVisible();
  await expect(button).toHaveAttribute("aria-current", "page");
  await expect.poll(() => new URL(page.url()).hash).toContain(`snapshot=${encodeURIComponent(snapshotId)}`);
  expect(state.counts).toMatchObject({ comparePost: 0, snapshotDetailGet: 1, unexpected: 0, pageErrors: 0, websockets: 0 });
  report("saved-comparison-purpose-labels", { captures, layoutChecks, counts: state.counts, source: "captured S3 comparison fixture with synthetic presentation names", live_api_calls: 0 });
});
