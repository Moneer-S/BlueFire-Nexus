import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import type { S3SetupCheck } from "../../src/lib/s3-setup";
import configuration from "../../../tests_platform/fixtures/s3_setup_draft_v1.json" with { type: "json" };

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const hash = `sha256:${"a".repeat(64)}`;
const profiles = ["linux-s3-validation-primary", "s3-test"].map(profile_id => ({ profile_id, profile_digest: hash }));
const draftSource = `${JSON.stringify(configuration, null, 2)}\n`;
test.use({ acceptDownloads: true });

async function fixture(page: Page) {
  const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
  const code = randomBytes(32).toString("hex"), session = randomBytes(32).toString("hex");
  const state = { connected: false, started: false, configured: false, checks: 0, starts: 0, reviews: 0, unexpected: 0, pageErrors: 0, sockets: 0 };
  page.on("pageerror", () => { state.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { state.sockets += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    const json = (value: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(value) });
    const profile = url.searchParams.get("profile_id");
    if (url.origin !== origin || url.username || url.password || (url.search && !(url.pathname === "/api/v1/runner" && [...url.searchParams].length === 1 && profiles.some(row => row.profile_id === profile)))) { state.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !state.connected && request.headers()["x-bluefire-browser-bootstrap"] === code) { state.connected = true; await json({ session }); return; }
      if (method === "GET" && state.connected && request.headers()["x-bluefire-session"] === session) { await route.fulfill({ status: 204 }); return; }
      if (method === "GET" && !state.connected) { await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }) }); return; }
    }
    if (!state.connected || request.headers()["x-bluefire-session"] !== session) { state.unexpected += 1; await route.abort(); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") { await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [] } }); return; }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/environments") { await json({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: "No S3 environment is enrolled." }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/exercises") { await json({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [], truncated: false }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/setup") { await json({ schema_version: "bluefire.s3-onboarding.v1", profiles, truncated: false }); return; }
    const runnerStatus = (profile_id: string | null) => ({ schema_version: "bluefire.runner-lifecycle-status.v1", state: state.started ? "ready" : "stopped", runner_id: "synthetic-runner", profile_id, loopback_only: true, enrollment: "active", process: state.started ? "authenticated" : "absent", runner: null, health: state.started ? { accepting_execute: true } : null });
    if (method === "GET" && url.pathname === "/api/v1/runner" && profile) { await json(runnerStatus(profile)); return; }
    if (method === "POST" && url.pathname === "/api/v1/runner/start") {
      const body = request.postDataJSON() as { profile_id: string };
      if (Object.keys(body).length !== 1 || !profiles.some(row => row.profile_id === body.profile_id)) { state.unexpected += 1; await route.abort(); return; }
      state.starts += 1; state.started = true; await json(runnerStatus(body.profile_id)); return;
    }
    if (method === "POST" && url.pathname === "/api/v1/s3-access/setup/check") {
      const body = request.postDataJSON() as { profile_id: string; profile_digest: string };
      if (Object.keys(body).length !== 2 || body.profile_digest !== hash || !profiles.some(row => row.profile_id === body.profile_id)) { state.unexpected += 1; await route.abort(); return; }
      state.checks += 1;
      const value: S3SetupCheck = { schema_version: "bluefire.s3-onboarding-check.v1", ...body, context_digest: hash, host_state: state.started ? "authenticated" : "unavailable", setup: state.started ? { schema_version: "bluefire.s3-setup-status.v1", profile_id: body.profile_id, context_digest: hash, configuration_state: state.configured ? "configured" : "missing", revision_digest: state.configured ? hash : null, environments: state.configured ? [{ environment_id: "synthetic-review-environment", runtime_state: "verified", access_reference_state: "expired", scope_state: "not_current", fixture_generation: 2 }] : [] } : null };
      await json(value); return;
    }
    if (method === "POST" && url.pathname === "/api/v1/s3-access/setup/review") {
      const body = request.postDataJSON() as { profile_id: string; profile_digest: string; configuration_json: string };
      if (Object.keys(body).length !== 3 || body.profile_id !== "s3-test" || body.profile_digest !== hash || body.configuration_json !== draftSource) { state.unexpected += 1; await route.abort(); return; }
      state.reviews += 1;
      await json({ schema_version: "bluefire.s3-onboarding-draft-review.v1", profile_id: body.profile_id, profile_digest: body.profile_digest, validation_scope: "structural_only", source_sha256: `sha256:${createHash("sha256").update(draftSource).digest("hex")}`, configuration_digest: hash, environments: configuration.environments.map(row => ({ environment_id: row.environment_id, display_name: row.display_name, account_id: row.scope.account_id, region: row.scope.region, bucket: row.scope.bucket, expires_at: row.scope.expires_at, fixture_generation: 1 })) }); return;
    }
    state.unexpected += 1; await route.abort();
  });
  await page.goto("./#/s3-access");
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.getByRole("button", { name: "Set up connection", exact: true }).click();
  await expect(page.getByRole("region", { name: "S3 connection setup" })).toBeVisible();
  return state;
}

async function capture(page: Page, name: string) {
  await page.evaluate(async () => { await document.fonts.ready; });
  const bounds = await page.evaluate(() => {
    const main = document.querySelector("main")!;
    const rect = main.getBoundingClientRect();
    const outside = [...main.querySelectorAll("h1,h2,h3,p,button,select,a,article")].filter(node => {
      const box = node.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && (box.left < rect.left - 1 || box.right > rect.right + 1);
    }).map(node => node.tagName);
    return { documentWidth: document.documentElement.clientWidth, documentScroll: document.documentElement.scrollWidth, mainWidth: main.clientWidth, mainScroll: main.scrollWidth, outside };
  });
  expect(bounds.documentScroll).toBeLessThanOrEqual(bounds.documentWidth);
  expect(bounds.mainScroll).toBeLessThanOrEqual(bounds.mainWidth);
  expect(bounds.outside).toEqual([]);
  await page.screenshot({ path: join(output, `${name}.png`), fullPage: false, animations: "disabled" });
  writeFileSync(join(output, `${name}.json`), JSON.stringify({ proof: "synthetic production UI only", cloud_calls: 0, bounds }, null, 2), { flag: "wx" });
}

for (const width of [1366, 390]) {
  test(`S3 connection setup preserves explicit control at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    const state = await fixture(page);
    await page.getByLabel("Linux S3 profile").selectOption(profiles[1]!.profile_id);
    await expect(page.getByRole("button", { name: "Start runner", exact: true })).toBeEnabled();
    expect(state.checks).toBe(0); expect(state.starts).toBe(0);
    await page.getByRole("button", { name: "Check connection", exact: true }).click();
    await expect(page.getByText("Runner unavailable", { exact: true })).toBeVisible();
    await capture(page, `setup-stopped-${width}`);
    await page.reload();
    await expect(page.getByLabel("Linux S3 profile")).toHaveValue(profiles[1]!.profile_id);
    expect(state.checks).toBe(1); expect(state.starts).toBe(0);
    await expect(page.getByText("No current S3 connection check.", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Start runner", exact: true }).click();
    await expect(page.getByText("Runner authenticated", { exact: true })).toBeVisible();
    expect(state.starts).toBe(1);
    await page.getByRole("button", { name: "Check connection", exact: true }).click();
    await expect(page.getByRole("heading", { name: "S3 configuration missing" })).toBeVisible();
    await capture(page, `setup-missing-${width}`);
    state.configured = true;
    await page.getByRole("button", { name: "Check connection", exact: true }).click();
    await expect(page.getByText("Expired", { exact: true })).toBeVisible();
    await expect(page.getByText("Not checked", { exact: true })).toBeVisible();
    await page.getByRole("heading", { name: "Local checks recorded" }).scrollIntoViewIfNeeded();
    await capture(page, `setup-expired-${width}`);
    await page.getByLabel("Non-secret configuration file", { exact: true }).setInputFiles({ name: "synthetic-configuration.json", mimeType: "application/json", buffer: Buffer.from(draftSource) });
    expect(state.reviews).toBe(0);
    await expect(page.getByRole("button", { name: "Export configuration", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "Review configuration", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Structure checked", exact: true })).toBeVisible();
    await page.getByRole("heading", { name: "Structure checked", exact: true }).scrollIntoViewIfNeeded();
    await capture(page, `setup-draft-${width}`);
    const downloaded = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export configuration", exact: true }).click();
    const artifact = await downloaded;
    expect(artifact.suggestedFilename()).toBe("bluefire-s3-configuration.json");
    const file = join(output, `configuration-export-${width}.json`);
    await artifact.saveAs(file);
    expect(readFileSync(file, "utf-8")).toBe(draftSource);
    await page.getByText("Configuration JSON", { exact: true }).click();
    await page.getByRole("textbox", { name: "Non-secret configuration JSON", exact: true }).fill(`${draftSource}\n`);
    await expect(page.getByRole("button", { name: "Export configuration", exact: true })).toBeDisabled();
    expect(state.reviews).toBe(1);
    await page.getByRole("button", { name: "Back to workspace", exact: true }).click();
    await expect(page.getByRole("region", { name: "S3 connection setup" })).toHaveCount(0);
    expect(state.checks).toBe(3); expect(state.unexpected).toBe(0); expect(state.pageErrors).toBe(0); expect(state.sockets).toBe(0);
    writeFileSync(join(output, `setup-journey-${width}.json`), JSON.stringify({ proof: "synthetic API production UI only", real_service: false, cloud_calls: 0, state }, null, 2), { flag: "wx" });
  });
}
