// Installed packaged-UI check for the fail-closed engine-experiment shell.
/* global process, Buffer, fetch, sessionStorage, URL */
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [playwrightPath, output, portText] = process.argv.slice(2);
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
const experimentId = `experiment-${"a".repeat(32)}`;
const digest = suffix => `sha256:${suffix.repeat(64)}`;
const createRequest = {
  schema_version: "bluefire.engine-experiment-create.v1",
  experiment_id: experimentId,
  objective_ref: digest("1"),
  environment_ref: digest("2"),
  scope_ref: digest("3"),
  scope_version: "bluefire.engine-capability-delegation.v1",
  target_snapshot_ref: digest("4"),
};
const checks = [
  "packaged_ui_rendered_with_real_local_service",
  "empty_engine_history_read_from_installed_service",
  "create_refused_without_controller_presentation_metadata",
  "refused_create_left_no_saved_experiment",
  "engine_route_rendered_recoverable_unavailable_state",
];
const report = {
  schema_version: "bluefire.installed-engine-experiment.browser-report.v1",
  status: "failed_or_incomplete",
  installed_service: true,
  packaged_ui: false,
  external_engine_executed: false,
  controlled_provider_mechanics: false,
  live_model_inference: false,
  target_execution: false,
  defensive_change_applied: false,
  creation_error_code: null,
  checks: [],
  blocked_requests: [],
  errors: [],
  browser_context_closed: false,
  browser_closed: false,
};
let browser, context, page, session = "", stage = "launch";
let sessionPosts = 0, createPosts = 0;

async function readSession() {
  session = await page.evaluate(() => sessionStorage.getItem("bluefire.browser-session.v1") ?? "");
  assert.match(session, /^[A-Za-z0-9_-]{64}$/);
}
async function engineList() {
  await readSession();
  return page.evaluate(async sessionValue => {
    const response = await fetch("/api/v1/engine-experiments", {
      method: "GET", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": sessionValue, Accept: "application/json" },
    });
    if (!response.ok) throw new Error("installed_service_response_failed");
    return response.json();
  }, session);
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
    if (allowed && method === "POST") {
      const raw = request.postData() ?? "";
      let body = null;
      if (Buffer.byteLength(raw, "utf8") > 4096) reason = "write_body_too_large";
      try { if (!reason && raw) body = request.postDataJSON(); }
      catch { reason = "invalid_json_body"; }
      if (!reason && url.pathname === "/api/v1/session") {
        allowed = sessionPosts === 0 && body === null;
        if (allowed) sessionPosts += 1;
        else reason = "session_bootstrap_cap_or_body";
      } else if (!reason && url.pathname === "/api/v1/engine-experiments") {
        allowed = createPosts === 0 && JSON.stringify(body) === JSON.stringify(createRequest);
        if (allowed) createPosts += 1;
        else reason = "engine_create_cap_or_body";
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
  report.packaged_ui = true;
  report.checks.push(checks[0]);

  stage = "initial-engine-list";
  const initial = await engineList();
  assert.deepEqual(initial, { schema_version: "bluefire.engine-experiment-list.v1", experiments: [] });
  report.checks.push(checks[1]);

  stage = "fail-closed-create";
  await readSession();
  const rejected = await page.evaluate(async ({ request, sessionValue }) => {
    const response = await fetch("/api/v1/engine-experiments", {
      method: "POST", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": sessionValue, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(request),
    });
    return { status: response.status, body: await response.json() };
  }, { request: createRequest, sessionValue: session });
  assert.equal(rejected.status, 409);
  assert.equal(rejected.body?.error?.code, "engine_workspace_unavailable");
  report.creation_error_code = rejected.body.error.code;
  report.checks.push(checks[2]);

  stage = "post-refusal-engine-list";
  const after = await engineList();
  assert.deepEqual(after, initial);
  report.checks.push(checks[3]);

  stage = "recoverable-route";
  await page.goto(`${origin}/#/composition?engine_experiment=${experimentId}`, { waitUntil: "domcontentloaded" });
  await page.getByText("Engine experiment unavailable", { exact: true }).waitFor();
  await page.getByRole("link", { name: "Composition workspace", exact: true }).waitFor();
  report.checks.push(checks[4]);
  assert.equal(sessionPosts, 1);
  assert.equal(createPosts, 1);
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
  await context?.close().then(() => { report.browser_context_closed = true; }).catch(() => { report.errors.push({ stage: "cleanup", kind: "context_close" }); process.exitCode = 1; });
  await browser?.close().then(() => { report.browser_closed = true; }).catch(() => { report.errors.push({ stage: "cleanup", kind: "browser_close" }); process.exitCode = 1; });
  if (report.errors.length || report.blocked_requests.length || process.exitCode) report.status = "failed_or_incomplete";
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  assert.ok(Buffer.byteLength(serialized, "utf8") <= 512 * 1024);
  writeFileSync(`${output}/browser-report.json`, serialized, { flag: "wx", mode: 0o600 });
}
