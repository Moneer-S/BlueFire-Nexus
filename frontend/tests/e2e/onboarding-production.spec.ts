import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";

const output = process.env.BLUEFIRE_S3_BROWSER_OUTPUT!;
const origin = `http://127.0.0.1:${process.env.BLUEFIRE_S3_BROWSER_PORT}`;
const viewports = [{ width: 320, height: 800 }, { width: 390, height: 844 }, { width: 1440, height: 900 }];
const windowsStatus = {
  schema_version: "bluefire.file-access-status.v1",
  available: false,
  problem: { code: "windows_native_admission_unavailable", message: "Protected setup is verified. Native task admission is unavailable." },
  enrollment: null,
  allowed_operations: [],
  setup: { enrollment_id: "win-file-enrollment-0123456789abcdef0123456789abcdef", enrollment_digest: `sha256:${"a".repeat(64)}`, expires_at_ms: 4_102_444_800_000, verification: "protected_setup_only" },
};
const windowsControlList = {
  schema_version: "bluefire.file-access-control-list.v1",
  controls: [{ control_owner_id: "win-file-control-0123456789abcdef0123456789abcdef", status: "setup_verified", revision: 1, platform: "windows" }],
};

type Counts = {
  unexpected: number;
  websocket: number;
  pageErrors: number;
  fileStatus: number;
  controlList: number;
  adEnvironment: number;
  s3Environment: number;
  providerProbe: number;
  chooserEnvironmentProbe: number;
  chooserProviderProbe: number;
};

async function connect(page: Page) {
  const code = randomBytes(32).toString("hex");
  const session = randomBytes(32).toString("hex");
  const connected = { value: false };
  const counts: Counts = {
    unexpected: 0, websocket: 0, pageErrors: 0, fileStatus: 0, controlList: 0,
    adEnvironment: 0, s3Environment: 0, providerProbe: 0, chooserEnvironmentProbe: 0, chooserProviderProbe: 0,
  };
  const passiveReads: Array<{ method: string; path: string; body: string | null }> = [];
  page.on("pageerror", () => { counts.pageErrors += 1; });
  await page.context().routeWebSocket("**/*", socket => { counts.websocket += 1; socket.close(); });
  await page.context().route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
    const refuse = async () => { counts.unexpected += 1; await route.abort(); };
    const chooser = new URL(page.url()).hash.startsWith("#/getting-started");
    if (url.origin !== origin || url.search || url.username || url.password) { await refuse(); return; }
    if (method === "GET" && /^\/ui\/(?:[a-zA-Z0-9_.-]+)?$/.test(url.pathname)) { await route.continue(); return; }
    if (url.pathname === "/api/v1/session") {
      if (method === "POST" && !connected.value && request.headers()["x-bluefire-browser-bootstrap"] === code) {
        connected.value = true;
        await json({ session });
        return;
      }
      if (method === "GET" && connected.value && request.headers()["x-bluefire-session"] === session) {
        await route.fulfill({ status: 204 });
        return;
      }
      await json({ error: { code: "browser_session_unavailable", message: "Synthetic browser session unavailable." } }, 401);
      return;
    }
    if (!connected.value || request.headers()["x-bluefire-session"] !== session) { await refuse(); return; }
    if (method === "GET" && url.pathname === "/api/v1/catalog") {
      await json({ behaviors: [], actions: [], runner_profiles: [], runners: [], ai: { providers: [] } });
      return;
    }
    if (method === "GET" && url.pathname === "/api/v1/scenarios") { await json({ scenarios: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/runs") { await json({ runs: [], unavailable_run_count: 0 }); return; }
    if (method === "GET" && url.pathname === "/api/v1/detection-lab/health") { await json({ ready: false }); return; }
    if (method === "GET" && url.pathname === "/api/v1/file-access/status") {
      counts.fileStatus += 1;
      passiveReads.push({ method, path: url.pathname, body: null });
      await json(windowsStatus);
      return;
    }
    if (method === "POST" && url.pathname === "/api/v1/file-access/control-list") {
      const body = request.postData() ?? "";
      if (body !== "{}" || request.headers()["content-type"]?.split(";")[0] !== "application/json") { await refuse(); return; }
      counts.controlList += 1;
      passiveReads.push({ method, path: url.pathname, body });
      await json(windowsControlList);
      return;
    }
    if (url.pathname.startsWith("/api/v1/ad-smb/environments")) {
      counts.adEnvironment += 1;
      if (chooser) counts.chooserEnvironmentProbe += 1;
      if (method === "GET") { await json({ environments: [], native_execution_available: false }); return; }
    }
    if (url.pathname.startsWith("/api/v1/s3-access/environments")) {
      counts.s3Environment += 1;
      if (chooser) counts.chooserEnvironmentProbe += 1;
      if (method === "GET") { await json({ schema_version: "bluefire.s3-environments.v1", environments: [], problem: "No S3 environment is enrolled." }); return; }
    }
    if (url.pathname.includes("/providers") || url.pathname.includes("/provider/")) {
      counts.providerProbe += 1;
      if (chooser) counts.chooserProviderProbe += 1;
    }
    if (method === "GET" && url.pathname === "/api/v1/ad-smb/workflows") { await json({ workflows: [] }); return; }
    if (method === "GET" && url.pathname === "/api/v1/s3-access/exercises") {
      await json({ schema_version: "bluefire.s3-exercise-list.v1", exercises: [], truncated: false });
      return;
    }
    await refuse();
  });

  await page.goto("./#/getting-started?context=onboarding&source=saved-run&retest=retained");
  await expect(page.getByRole("heading", { name: "Connect to your workspace", exact: true })).toBeVisible();
  await page.getByLabel("One-time connection code", { exact: false }).fill(code);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Start an experiment", exact: true })).toBeVisible();
  return { counts, passiveReads };
}

async function capture(page: Page, name: string, viewport: { width: number; height: number }) {
  await page.setViewportSize(viewport);
  await page.evaluate(async () => { await document.fonts.ready; });
  const geometry = await page.evaluate(() => {
    const bounds = (node: Element | null) => {
      if (!node || getComputedStyle(node).display === "none") return null;
      const rect = node.getBoundingClientRect();
      return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
    };
    const main = document.querySelector("main")!;
    const context = document.querySelector(".objective-start");
    const rect = main.getBoundingClientRect();
    const outside = [...main.querySelectorAll<HTMLElement>("h1,h2,h3,p,button,input,select,a,article")].filter(node => {
      const child = node.getBoundingClientRect();
      return child.width > 0 && child.height > 0 && (child.left < rect.left - 1 || child.right > rect.right + 1);
    }).map(node => node.tagName);
    return {
      viewport: { width: innerWidth, height: innerHeight },
      document: { clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth, clientHeight: document.documentElement.clientHeight, scrollHeight: document.documentElement.scrollHeight },
      main: { bounds: bounds(main), scrollWidth: main.scrollWidth, clientWidth: main.clientWidth },
      chooser: bounds(context),
      objectiveContext: bounds(document.querySelector(".objective-context")),
      outside,
    };
  });
  const screenshot = join(output, `${name}-${viewport.width}.png`);
  if (existsSync(screenshot)) throw new Error("An onboarding screenshot already exists.");
  await page.screenshot({ path: screenshot, fullPage: false, animations: "disabled" });
  const record = { screenshot: `${name}-${viewport.width}.png`, ...geometry };
  writeFileSync(join(output, `${name}-${viewport.width}-geometry.json`), `${JSON.stringify({ proof: "synthetic-production-bundle-ui-only", real_service: false, details: record }, null, 2)}\n`, { flag: "wx" });
  expect(geometry.document.scrollWidth).toBeLessThanOrEqual(geometry.document.clientWidth);
  expect(geometry.main.scrollWidth).toBeLessThanOrEqual(geometry.main.clientWidth);
  expect(geometry.outside).toEqual([]);
  return record;
}

function assertQuiet(counts: Counts) {
  expect({ unexpected: counts.unexpected, websocket: counts.websocket, pageErrors: counts.pageErrors, chooserEnvironmentProbe: counts.chooserEnvironmentProbe, chooserProviderProbe: counts.chooserProviderProbe }).toEqual({ unexpected: 0, websocket: 0, pageErrors: 0, chooserEnvironmentProbe: 0, chooserProviderProbe: 0 });
}

test("file-access selection is passive, honest about protected setup, and keeps its objective context", async ({ page }) => {
  const fixture = await connect(page);
  await page.getByRole("combobox", { name: "Objective" }).selectOption("file-access");
  await expect(page.getByText("Setup receipt found", { exact: true })).toBeVisible();
  await expect(page.getByText("1 saved control", { exact: true })).toBeVisible();
  const accessRow = page.locator(".objective-start .data-list > div").filter({ has: page.getByText("Effective access", { exact: true }) });
  await expect(accessRow.getByText("Not tested", { exact: true })).toBeVisible();
  const passiveReads = [...fixture.passiveReads].sort((left, right) => `${left.method} ${left.path} ${left.body ?? ""}`.localeCompare(`${right.method} ${right.path} ${right.body ?? ""}`));
  expect(passiveReads).toEqual([
    { method: "POST", path: "/api/v1/file-access/control-list", body: "{}" },
    { method: "GET", path: "/api/v1/file-access/status", body: null },
  ].sort((left, right) => `${left.method} ${left.path} ${left.body ?? ""}`.localeCompare(`${right.method} ${right.path} ${right.body ?? ""}`)));
  expect(fixture.counts.fileStatus).toBe(1);
  expect(fixture.counts.controlList).toBe(1);
  expect(fixture.counts.adEnvironment + fixture.counts.s3Environment + fixture.counts.providerProbe).toBe(0);
  const captures = [];
  for (const viewport of viewports) captures.push(await capture(page, "file-objective", viewport));
  await page.getByRole("link", { name: "Review environment", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Effective file access", exact: true })).toBeVisible();
  await expect(page.getByRole("complementary", { name: "Selected objective" })).toContainText("Can we remove a test identity's file access while preserving the application's access?");
  for (const viewport of viewports) captures.push(await capture(page, "file-destination", viewport));
  await expect(page.getByRole("link", { name: "Change objective" })).toHaveAttribute("href", "#/getting-started?context=onboarding&source=saved-run&retest=retained&goal=file-access");
  await page.getByRole("link", { name: "Change objective" }).click();
  await expect(page.getByRole("heading", { name: "Start an experiment", exact: true })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Objective" })).toHaveValue("file-access");
  await expect(page).toHaveURL(/#\/getting-started\?context=onboarding&source=saved-run&retest=retained&goal=file-access$/);
  expect(fixture.passiveReads).toHaveLength(2);
  assertQuiet(fixture.counts);
  writeFileSync(join(output, "file-objective-summary.json"), `${JSON.stringify({ proof: "synthetic-production-bundle-ui-only", counts: fixture.counts, passiveReads: fixture.passiveReads, captures }, null, 2)}\n`, { flag: "wx" });
});

for (const goal of ["ad-access", "s3-access"] as const) test(`${goal} chooser stays passive and carries context to its workspace and back`, async ({ page }) => {
  const fixture = await connect(page);
  await page.getByRole("combobox", { name: "Objective" }).selectOption(goal);
  await expect(page.getByText("Not checked here", { exact: true })).toBeVisible();
  expect(fixture.counts.adEnvironment + fixture.counts.s3Environment).toBe(0);
  expect(fixture.counts.providerProbe).toBe(0);
  expect(fixture.passiveReads).toEqual([]);
  await page.getByRole("link", { name: "Review environment", exact: true }).click();
  const heading = goal === "ad-access" ? "AD share access" : "S3 access";
  await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
  const objective = page.getByRole("complementary", { name: "Selected objective" });
  await expect(objective).toBeVisible();
  await expect(objective).toContainText(goal === "ad-access" ? "Can we remove the probe identity's share access while preserving legitimate domain reads?" : "Can we remove the probe role's S3 access while preserving legitimate reads?");
  const captures = [];
  for (const viewport of viewports) captures.push(await capture(page, `${goal}-destination`, viewport));
  const envCount = goal === "ad-access" ? fixture.counts.adEnvironment : fixture.counts.s3Environment;
  expect(envCount).toBeGreaterThan(0);
  expect(fixture.counts.chooserEnvironmentProbe).toBe(0);
  await page.getByRole("link", { name: "Change objective" }).click();
  await expect(page.getByRole("combobox", { name: "Objective" })).toHaveValue(goal);
  await expect(page).toHaveURL(new RegExp(`#\\/getting-started\\?context=onboarding&source=saved-run&retest=retained&goal=${goal}$`));
  expect(fixture.counts.chooserEnvironmentProbe).toBe(0);
  expect(fixture.counts.chooserProviderProbe).toBe(0);
  assertQuiet(fixture.counts);
  writeFileSync(join(output, `${goal}-summary.json`), `${JSON.stringify({ proof: "synthetic-production-bundle-ui-only", counts: fixture.counts, passiveReads: fixture.passiveReads, captures }, null, 2)}\n`, { flag: "wx" });
});

test("an unknown objective remains unselected and does not probe destination services", async ({ page }) => {
  const fixture = await connect(page);
  await page.goto("./#/getting-started?goal=unknown-objective");
  await expect(page.getByRole("alert")).toContainText("This objective is unavailable");
  await expect(page.getByRole("combobox", { name: "Objective" })).toHaveValue("");
  await expect(page.getByRole("button", { name: "Review environment" })).toBeDisabled();
  expect(fixture.counts.adEnvironment + fixture.counts.s3Environment + fixture.counts.providerProbe).toBe(0);
  expect(fixture.passiveReads).toEqual([]);
  assertQuiet(fixture.counts);
});
