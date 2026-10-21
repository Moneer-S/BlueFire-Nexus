// Bounded browser driver for an installed CLI restart and fixture reopen.
/* global process, Buffer, fetch, sessionStorage, URL, URLSearchParams */
import assert from "node:assert/strict";
import { writeFileSync, readFileSync, statSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [playwrightPath, mode, output, portText, statePath] = process.argv.slice(2);
assert.ok(["create", "reopen"].includes(mode));
assert.match(portText ?? "", /^\d{1,5}$/);
const port = Number(portText);
assert.ok(port > 0 && port <= 65535);
let input = "";
for await (const chunk of process.stdin) {
  input += chunk;
  assert.ok(Buffer.byteLength(input, "utf8") <= 256);
}
let { capability } = JSON.parse(input);
input = "";
assert.match(capability ?? "", /^[A-Za-z0-9_-]{64}$/);
const origin = `http://127.0.0.1:${port}`;
const scenarioId = "scenario.installed-reopen.fixture.v1";
const sourceId = "scenario.endpoint.lab-collection-methods.v1";
const stable = value => Array.isArray(value) ? value.map(stable)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]))
    : value;
const same = (left, right) => JSON.stringify(stable(left)) === JSON.stringify(stable(right));
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && same(Object.keys(value).sort(), [...keys].sort());
const report = {
  schema_version: "bluefire.installed-reopen.browser-report.v1",
  mode,
  status: "failed_or_incomplete",
  fixture_identity: "packaged collection example copied to owned fixture scenario",
  native_execution: false,
  live_model_inference: false,
  checks: [],
  blocked_requests: [],
  errors: [],
};
let browser, context, page, session = "", stage = "launch";
let scenarioPosts = 0, bootstrapPosts = 0;
let generatedScenario = null, savedDocuments = [];

function isReadPath(path) {
  return path === "/api/v1/session"
    || path === "/api/v1/scenarios"
    || path === "/api/v1/catalog"
    || path === "/api/v1/build-info"
    || path === "/api/v1/runs"
    || path === "/api/v1/receiver-defense/jobs"
    || path === "/api/v1/scenario-versions"
    || path === `/api/v1/scenario-versions/${scenarioId}/versions`
    || new RegExp(`^/api/v1/scenario-versions/${scenarioId}/versions/[1-2]$`).test(path);
}

async function readSession() {
  session = await page.evaluate(() => sessionStorage.getItem("bluefire.browser-session.v1") ?? "");
  assert.match(session, /^[A-Za-z0-9_-]{64}$/);
}

async function get(path) {
  await readSession();
  return page.evaluate(async ({ path, session }) => {
    const response = await fetch(path, {
      method: "GET", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": session, Accept: "application/json" },
    });
    if (!response.ok) throw new Error("server_read_failed");
    return response.json();
  }, { path: `/api/v1${path}`, session });
}

async function createFirstVersion() {
  const catalog = await get("/scenarios");
  const source = catalog.scenarios?.find(item => item.id === sourceId);
  assert.ok(source && Array.isArray(source.steps) && source.steps.length > 0);
  generatedScenario = { ...source, id: scenarioId, title: "Installed reopen fixture v1" };
  const result = await page.evaluate(async ({ scenario, session }) => {
    const response = await fetch("/api/v1/scenario-versions", {
      method: "POST", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": session, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ scenario }),
    });
    if (!response.ok) throw new Error("fixture_save_failed");
    return response.json();
  }, { scenario: generatedScenario, session });
  assert.equal(result.scenario.scenario_id, scenarioId);
  assert.equal(result.scenario.version, 1);
  assert.match(result.scenario.digest, /^sha256:[0-9a-f]{64}$/);
  savedDocuments.push({ version: 1, digest: result.scenario.digest, document: result.scenario.document });
  await page.goto(`${origin}/#/builder?${new URLSearchParams({ saved_scenario: scenarioId, version: "1", digest: result.scenario.digest })}`);
  await page.getByRole("button", { name: "Open this version for editing", exact: true }).click();
  await page.locator(".react-flow__node").first().waitFor();
  await page.getByLabel("Experiment name", { exact: true }).fill("Installed reopen fixture v2");
  const responsePromise = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/scenario-versions" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Save version", exact: true }).click();
  const saved = (await (await responsePromise).json()).scenario;
  assert.equal(saved.scenario_id, scenarioId);
  assert.equal(saved.version, 2);
  assert.match(saved.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(saved.document.title, "Installed reopen fixture v2");
  savedDocuments.push({ version: 2, digest: saved.digest, document: saved.document });
  const state = {
    schema_version: "bluefire.installed-reopen.fixture-state.v1",
    scenario_id: scenarioId,
    source_example_id: sourceId,
    versions: savedDocuments,
  };
  const serialized = `${JSON.stringify(state, null, 2)}\n`;
  assert.ok(Buffer.byteLength(serialized) <= 512 * 1024);
  writeFileSync(`${output}/fixture-state.json`, serialized, { flag: "wx", mode: 0o600 });
  report.checks.push("packaged_example_seeded_as_owned_fixture_then_second_version_saved_through_ui");
}

async function reopenSavedVersions() {
  assert.notEqual(statePath, "-");
  assert.ok(statSync(statePath).size <= 512 * 1024);
  const state = JSON.parse(readFileSync(statePath, "utf8"));
  assert.equal(state.schema_version, "bluefire.installed-reopen.fixture-state.v1");
  assert.equal(state.scenario_id, scenarioId);
  assert.equal(state.versions.length, 2);
  for (const expected of state.versions) {
    stage = `open-version-${expected.version}`;
    await page.goto(`${origin}/#/builder?${new URLSearchParams({ saved_scenario: scenarioId, version: String(expected.version), digest: expected.digest })}`);
    await page.getByRole("button", { name: "Open this version for editing", exact: true }).waitFor();
    await page.getByRole("button", { name: "Open this version for editing", exact: true }).click();
    await page.locator(".react-flow__node").first().waitFor();
  }
  const verifiedVersions = [];
  for (const expected of state.versions) {
    const payload = await get(`/scenario-versions/${scenarioId}/versions/${expected.version}`);
    const actual = payload.scenario;
    assert.equal(actual.scenario_id, scenarioId);
    assert.equal(actual.version, expected.version);
    assert.equal(actual.digest, expected.digest);
    assert.ok(same(actual.document, expected.document));
    verifiedVersions.push({ version: actual.version, digest: actual.digest, document: actual.document });
  }
  assert.ok(!same(verifiedVersions[0].document, verifiedVersions[1].document));
  const history = await get(`/scenario-versions/${scenarioId}/versions`);
  assert.equal(history.schema_version, "bluefire.scenario-version-list.v1");
  assert.deepEqual(history.scenarios.map(item => item.version), [2, 1]);
  assert.equal(history.scenarios[0].scenario_id, scenarioId);
  assert.equal(history.scenarios[0].digest, verifiedVersions[1].digest);
  assert.ok(same(history.scenarios[0].document, verifiedVersions[1].document));
  report.checks.push("both_versions_opened_and_reread_with_current_head_from_fresh_server");
  report.verified_state = {
    schema_version: state.schema_version,
    scenario_id: state.scenario_id,
    source_example_id: state.source_example_id,
    versions: verifiedVersions,
  };
}

try {
  const { chromium } = await import(pathToFileURL(playwrightPath).href);
  browser = await chromium.launch({
    headless: true,
    args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"],
  });
  context = await browser.newContext({ serviceWorkers: "block" });
  context.setDefaultTimeout(15_000);
  await context.routeWebSocket("**/*", socket => socket.close());
  await context.route("**/*", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    let allowed = url.origin === origin && ["GET", "HEAD", "POST"].includes(method);
    let reason = allowed ? undefined : url.origin === origin ? "method_not_allowed" : "non_loopback";
    if (allowed && url.pathname.startsWith("/api/") && url.search) {
      allowed = false;
      reason = "api_query_not_allowlisted";
    }
    if (allowed && ["GET", "HEAD"].includes(method) && !url.pathname.startsWith("/api/")) {
      // Packaged UI assets are immutable reads on this loopback origin.
    } else if (allowed && ["GET", "HEAD"].includes(method) && url.pathname.startsWith("/api/")) {
      allowed = isReadPath(url.pathname);
      if (!allowed) reason = "read_not_allowlisted";
    }
    if (allowed && method === "POST") {
      let body;
      const rawBody = request.postData() ?? "";
      if (Buffer.byteLength(rawBody, "utf8") > 128 * 1024) reason = "write_body_too_large";
      try { if (!reason) body = rawBody ? request.postDataJSON() : null; }
      catch { reason = "invalid_json_body"; }
      if (!reason && url.pathname === "/api/v1/session") {
        allowed = bootstrapPosts === 0 && body === null;
        if (allowed) bootstrapPosts += 1;
        else reason = "bootstrap_cap_or_body";
      } else if (!reason && url.pathname === "/api/v1/scenario-versions" && mode === "create") {
        const scenario = body?.scenario;
        allowed = scenarioPosts < 2 && exactKeys(body, ["scenario"])
          && (scenarioPosts === 0
            ? same(scenario, generatedScenario)
            : same(scenario, { ...savedDocuments[0].document, title: "Installed reopen fixture v2" }))
          && Buffer.byteLength(request.postData() ?? "", "utf8") <= 128 * 1024
          && (scenarioPosts === 0
            ? scenario.title === "Installed reopen fixture v1"
            : scenario.title === "Installed reopen fixture v2");
        if (allowed) scenarioPosts += 1;
        else reason = "owned_version_cap_or_document";
      } else {
        allowed = false;
        reason ??= "write_not_allowlisted";
      }
    }
    if (!allowed) {
      report.blocked_requests.push({ method, path: url.origin === origin ? url.pathname : "non-loopback", reason: reason ?? "request_not_allowed" });
      await route.abort();
      return;
    }
    await route.continue();
  });
  page = await context.newPage();
  page.on("pageerror", () => report.errors.push({ stage, kind: "page_error" }));
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  capability = "";
  await page.getByRole("link", { name: "Build", exact: true }).waitFor();
  await readSession();
  if (mode === "create") {
    stage = "create-fixture";
    await createFirstVersion();
    assert.equal(scenarioPosts, 2);
  } else {
    stage = "reopen-fixture";
    assert.equal(scenarioPosts, 0);
    await reopenSavedVersions();
  }
  assert.equal(bootstrapPosts, 1);
  assert.deepEqual(report.blocked_requests, []);
  assert.deepEqual(report.errors, []);
  report.status = "passed";
} catch {
  capability = "";
  session = "";
  report.status = "failed_or_incomplete";
  report.errors.push({ stage, kind: "journey_failed" });
  process.exitCode = 1;
} finally {
  capability = "";
  session = "";
  await context?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "context_close" }); process.exitCode = 1; });
  await browser?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "browser_close" }); process.exitCode = 1; });
  if (report.errors.length || report.blocked_requests.length || process.exitCode) report.status = "failed_or_incomplete";
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  assert.ok(Buffer.byteLength(serialized) <= 1024 * 1024);
  writeFileSync(`${output}/${mode}-report.json`, serialized, { flag: "wx", mode: 0o600 });
}
