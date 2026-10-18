import { expect, test, type Page, type TestInfo } from "@playwright/test";
import process from "node:process";
import { macOSControlFixture, macOSOperationFixture, macOSOwner, macOSReviewFixture, macOSStatusFixture } from "../macos-file-access-fixture";
import { macObjectiveFixture } from "../macos-composition-fixture";
import type { CompositionObjective } from "../../src/lib/composition";
import { ownerId } from "../composition-fixture";
import type { FileAccessOperationEnvelope, FileAccessReviewRequest, FileAccessSubmission, MacOSFileAccessControl } from "../../src/lib/file-access";

const viewports = [{ width: 1440, height: 900 }, { width: 390, height: 844 }] as const;
const MACOS_FILE_ACCESS_PACK = "bluefire.macos-file-access-pack.v1";

async function syntheticSession(page: Page) {
  const port = process.env.BLUEFIRE_S3_BROWSER_PORT;
  if (!/^\d{4,5}$/.test(port ?? "") || Number(port) > 65535) throw new Error("A dedicated loopback browser port is required.");
  const origin = `http://127.0.0.1:${port}`;
  const code = "a".repeat(64);
  const session = "b".repeat(64);
  let connected = false;
  let control: MacOSFileAccessControl = macOSControlFixture("created");
  const operations = new Map<string, FileAccessOperationEnvelope>();
  const counts = { review: 0, submit: 0, unexpected: 0, pageErrors: 0, websocket: 0 };
  page.on("pageerror", () => { counts.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { counts.websocket += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (url.origin !== origin || url.search || url.username || url.password) { counts.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && /^\/ui\/[a-zA-Z0-9_.-]*$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !connected && request.headers()["x-bluefire-browser-bootstrap"] === code) {
        connected = true; await json({ session }); return;
      }
      if (method === "GET" && connected && request.headers()["x-bluefire-session"] === session) { await route.fulfill({ status: 204 }); return; }
      await json({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }, 401); return;
    }
    if (!connected || request.headers()["x-bluefire-session"] !== session) { counts.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [] } }); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/file-access/status") {
      const status = macOSStatusFixture();
      if (status.enrollment) status.enrollment.expires_at_ms = Date.now() + 600_000;
      await json(status); return;
    }
    if (method === "POST" && url.pathname === "/api/v1/file-access/control-list") {
      if (JSON.stringify(request.postDataJSON()) !== "{}") { counts.unexpected += 1; await route.abort(); return; }
      await json({ schema_version: "bluefire.file-access-control-list.v1", controls: [{ platform: "macos", control_owner_id: macOSOwner, status: control.status, revision: control.revision }] }); return;
    }
    if (method === "GET" && /^\/api\/v1\/file-access\/operations\/job-[0-9a-f]{32}$/.test(url.pathname)) {
      const operation = operations.get(url.pathname.split("/").at(-1)!);
      if (operation) await json(operation);
      else await json({ error: { code: "not_found", message: "The synthetic operation has not been submitted." } }, 404);
      return;
    }
    if (method === "GET" && url.pathname === `/api/v1/file-access/controls/${macOSOwner}`) { await json(control); return; }
    if (method === "POST" && url.pathname === "/api/v1/file-access/review") {
      const body = request.postDataJSON() as FileAccessReviewRequest;
      if (body.control_owner_id !== macOSOwner || !control.allowed_operations.includes(body.operation as "baseline" | "harden" | "rollback")) {
        counts.unexpected += 1; await route.abort(); return;
      }
      counts.review += 1;
      await json({ ...macOSReviewFixture(body.operation as "baseline" | "harden" | "rollback", control), expires_at_ms: Date.now() + 120_000 }); return;
    }
    if (method === "POST" && url.pathname === "/api/v1/file-access/operations") {
      const body = request.postDataJSON() as FileAccessSubmission;
      const nextStatus = body.review.operation === "baseline" ? "baseline_verified" : body.review.operation === "harden" ? "hardened" : "rolled_back";
      if (body.review.control_owner_id !== macOSOwner || !control.allowed_operations.includes(body.review.operation as "baseline" | "harden" | "rollback")
        || !body.reviewed_by.trim() || body.review_digest !== "sha256:" + "d".repeat(64)) {
        counts.unexpected += 1; await route.abort(); return;
      }
      counts.submit += 1;
      const next = macOSControlFixture(nextStatus);
      const operation = macOSOperationFixture(body, next);
      next.operations = [...control.operations, operation.job];
      next.revision = control.revision + 1;
      control = next;
      operations.set(operation.job.job_id, operation);
      await json(operation); return;
    }
    counts.unexpected += 1;
    await route.abort();
  });

  await page.goto(`./#/file-access?control=${macOSOwner}`);
  await expect(page.getByRole("heading", { name: "Connect to your workspace" })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "macOS protected workspace", exact: true })).toBeVisible();
  return { counts, getControl: () => control };
}

async function capture(page: Page, info: TestInfo, viewport: typeof viewports[number], name: string) {
  await page.setViewportSize(viewport);
  const control = page.getByRole("region", { name: "Saved macOS workspace control" });
  await control.scrollIntoViewIfNeeded();
  await expect(control).toBeVisible();
  await page.evaluate(async () => { await document.fonts.ready; });
  const geometry = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
    main: document.querySelector("main")?.getBoundingClientRect().toJSON() ?? null,
  }));
  expect(geometry.scrollWidth, `${viewport.width}px document overflow`).toBeLessThanOrEqual(geometry.clientWidth);
  const path = info.outputPath(`${name}-${viewport.width}.png`);
  await page.screenshot({ path, fullPage: false, animations: "disabled" });
  await info.attach(`${name}-${viewport.width}`, { path, contentType: "image/png" });
}

async function syntheticRecoverySession(page: Page, initialState: "available" | "unavailable" | "unresolved") {
  const port = process.env.BLUEFIRE_S3_BROWSER_PORT;
  if (!/^\d{4,5}$/.test(port ?? "") || Number(port) > 65535) throw new Error("A dedicated loopback browser port is required.");
  const origin = `http://127.0.0.1:${port}`;
  const code = "e".repeat(64);
  const session = "f".repeat(64);
  let connected = false;
  let recovered = false;
  const objectiveFor = (state: "available" | "unavailable" | "unresolved" | "closed"): CompositionObjective => {
    const objective = macObjectiveFixture("unknown");
    objective.attempts[0]!.progress.macos_recovery = { state, scope: "close_only" };
    if (state === "closed") {
      objective.attempts[0]!.progress.settlement = "settled";
      objective.attempts[0]!.progress.macos_file_access_request_state = "not_sent";
    }
    return objective;
  };
  let objective = objectiveFor(initialState);
  const attemptId = objective.attempts[0]!.request.composition_attempt.attempt_id;
  const counts = { recovery: 0, unexpected: 0, pageErrors: 0, websocket: 0 };
  page.on("pageerror", () => { counts.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { counts.websocket += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    if (url.origin !== origin || url.search || url.username || url.password) { counts.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && /^\/ui\/[a-zA-Z0-9_.-]*$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !connected && request.headers()["x-bluefire-browser-bootstrap"] === code) {
        connected = true; await json({ session }); return;
      }
      if (method === "GET" && connected && request.headers()["x-bluefire-session"] === session) { await route.fulfill({ status: 204 }); return; }
      await json({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }, 401); return;
    }
    if (!connected || request.headers()["x-bluefire-session"] !== session) { counts.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [] } }); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "POST" && url.pathname === "/api/v1/composition/objective-list") {
      if (JSON.stringify(request.postDataJSON()) !== JSON.stringify({ control_owner_id: macOSOwner })) { counts.unexpected += 1; await route.abort(); return; }
      await json({ schema_version: "bluefire.composition-objective-list.v1", objectives: [{ owner_id: ownerId, title: "Verify the retained Mac control", status: "active", job_state: "completed" }] }); return;
    }
    if (method === "GET" && url.pathname === `/api/v1/composition/objectives/${ownerId}`) { await json(objective); return; }
    if (method === "GET" && url.pathname === "/api/v1/file-access/status") {
      const status = macOSStatusFixture();
      if (status.enrollment) status.enrollment.expires_at_ms = Date.now() + 600_000;
      await json(status); return;
    }
    if (method === "GET" && url.pathname === `/api/v1/file-access/controls/${macOSOwner}`) { await json(macOSControlFixture("hardened")); return; }
    if (method === "POST" && url.pathname === `/api/v1/composition/objectives/${ownerId}/recover`) {
      const body = request.postDataJSON() as { attempt_id?: unknown };
      if (initialState !== "available" || recovered || body.attempt_id !== attemptId) { counts.unexpected += 1; await route.abort(); return; }
      counts.recovery += 1;
      recovered = true;
      objective = objectiveFor("closed");
      await json(objective); return;
    }
    counts.unexpected += 1;
    await route.abort();
  });

  await page.goto(`./#/composition?control=${macOSOwner}&objective=${ownerId}&pack=${MACOS_FILE_ACCESS_PACK}`);
  await expect(page.getByRole("heading", { name: "Connect to your workspace" })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Verify the retained Mac control" })).toBeVisible();
  return { counts, getObjective: () => objective, attemptId };
}

async function captureRecovery(page: Page, info: TestInfo, viewport: typeof viewports[number], name: string) {
  await page.setViewportSize(viewport);
  const recoveryTitle = page.getByText(/^(Attempt closure pending|Original attempt close needs review)$/);
  await (await recoveryTitle.count() ? recoveryTitle : page.getByRole("heading", { name: "Verify the retained Mac control" })).scrollIntoViewIfNeeded();
  await page.evaluate(async () => { await document.fonts.ready; });
  const geometry = await page.evaluate(() => ({ clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth }));
  expect(geometry.scrollWidth, `${viewport.width}px document overflow`).toBeLessThanOrEqual(geometry.clientWidth);
  const path = info.outputPath(`${name}-${viewport.width}.png`);
  await page.screenshot({ path, fullPage: false, animations: "disabled" });
  await info.attach(`${name}-${viewport.width}`, { path, contentType: "image/png" });
}

test.use({ trace: "off", video: "off", screenshot: "off", serviceWorkers: "block" });

for (const viewport of viewports) {
  test(`synthetic macOS file-access workflow is usable at ${viewport.width}x${viewport.height}`, async ({ page }, info) => {
    await page.setViewportSize(viewport);
    const fixture = await syntheticSession(page);
    const mutations: string[] = [];
    page.on("request", request => {
      if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) mutations.push(new URL(request.url()).pathname);
    });

    const control = page.getByRole("region", { name: "Saved macOS workspace control" });
    await expect(control).toContainText("Baseline not established");
    await page.getByRole("button", { name: "Review verify baseline access", exact: true }).click();
    const review = page.getByRole("region", { name: "File-access operation review" });
    await expect(review.getByText("Review the original macOS workspace baseline operation.", { exact: true })).toBeVisible();
    await expect(review.getByRole("button", { name: "Verify baseline access", exact: true })).toBeDisabled();
    await review.getByLabel("Operation reviewed by", { exact: true }).fill("synthetic operator");
    await review.getByRole("checkbox").check();
    await review.getByRole("button", { name: "Verify baseline access", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Recorded baseline", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Review apply owner-only access", exact: true })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await capture(page, info, viewport, "macos-file-access-baseline");

    await page.getByRole("button", { name: "Review apply owner-only access", exact: true }).click();
    const hardenReview = page.getByRole("region", { name: "File-access operation review" });
    await expect(hardenReview.getByText("Review the original macOS workspace harden operation.", { exact: true })).toBeVisible();
    await hardenReview.getByLabel("Operation reviewed by", { exact: true }).fill("synthetic operator");
    await hardenReview.getByRole("checkbox").check();
    await hardenReview.getByRole("button", { name: "Apply owner-only access", exact: true }).click();
    await expect(page.getByRole("link", { name: "Open composition workspace", exact: true })).toBeVisible();
    await expect(control.getByText(/hardened/i)).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    await capture(page, info, viewport, "macos-file-access-hardened");

    expect(fixture.counts).toMatchObject({ review: 2, submit: 2, unexpected: 0, pageErrors: 0, websocket: 0 });
    expect(mutations.filter(path => path === "/api/v1/file-access/review")).toHaveLength(2);
    expect(mutations.filter(path => path === "/api/v1/file-access/operations")).toHaveLength(2);
    expect(mutations.every(path => ["/api/v1/session", "/api/v1/file-access/control-list", "/api/v1/file-access/review", "/api/v1/file-access/operations"].includes(path))).toBe(true);
    expect(fixture.getControl().status).toBe("hardened");
  });

  for (const state of ["available", "unavailable", "unresolved"] as const) {
    test(`synthetic macOS attempt recovery ${state} state is bounded at ${viewport.width}x${viewport.height}`, async ({ page }, info) => {
      await page.setViewportSize(viewport);
      const fixture = await syntheticRecoverySession(page, state);
      const mutations: string[] = [];
      page.on("request", request => {
        if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) mutations.push(new URL(request.url()).pathname);
      });

      if (state === "available") {
        const close = page.getByRole("button", { name: "Close undispatched attempt" });
        await expect(close).toBeEnabled();
        await captureRecovery(page, info, viewport, "macos-recovery-before-close");
        await close.click();
        await expect(page.getByRole("button", { name: "Close undispatched attempt" })).toHaveCount(0);
        await expect(page.getByLabel("Attempt evidence").getByText("Settled", { exact: true })).toBeVisible();
        expect(fixture.getObjective().attempts[0]!.progress.macos_recovery).toMatchObject({ state: "closed", scope: "close_only" });
        expect(fixture.getObjective().attempts[0]!.progress.verified_result).toBeUndefined();
        expect(fixture.counts.recovery).toBe(1);
      } else {
        await expect(page.getByText(state === "unavailable"
          ? "The original process authority is unavailable. No workspace was re-adopted and no new attempt was started."
          : "The original close could not be verified. Review retained evidence before taking any further action.")).toBeVisible();
        await expect(page.getByRole("button", { name: "Close undispatched attempt" })).toHaveCount(0);
        expect(fixture.counts.recovery).toBe(0);
      }

      await expect(page.getByRole("alert")).toHaveCount(0);
      await captureRecovery(page, info, viewport, `macos-recovery-${state}`);
      expect(fixture.counts).toMatchObject({ recovery: state === "available" ? 1 : 0, unexpected: 0, pageErrors: 0, websocket: 0 });
      const effectRequests = mutations.filter(path => path !== "/api/v1/composition/objective-list");
      expect(effectRequests).toEqual(state === "available" ? [`/api/v1/composition/objectives/${ownerId}/recover`] : []);
      expect(fixture.getObjective().attempts[0]!.request.composition_attempt.attempt_id).toBe(fixture.attemptId);
    });
  }
}
