// Runs only against the harness-owned installed service, without response substitution.
/* global process, document, sessionStorage, fetch, AbortController, setTimeout, clearTimeout, TextDecoder, requestAnimationFrame, innerWidth, innerHeight */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash, randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL, URL } from "node:url";

const [modulePath, output, portText] = process.argv.slice(2);
const PROFILE = "sandbox-execute.v1";
const CREATE = "sandbox.fixture.create.v1";
const CLEANUP = "sandbox.cleanup.v1";
const COLLECTOR = "collector.filesystem.sandbox.v1";
const TITLE = "Installed macOS generated-file journey";
const TERMINAL = new Set(["completed", "cancelled", "failed", "interrupted"]);
const BINDING_FIELDS = ["state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"];
const startedAt = performance.now();
const mainDeadline = startedAt + 120_000;
let deadline = mainDeadline;
let stage = "input";
let origin, capability = "", browser, context, page;
let connected = false, cleanupPhase = false, bootstrapAttempted = false;
let ownedScenario, savedScenario, runRequest, jobId = "", runId = "", terminalJob;
const secrets = [];
const counts = { session: 0, scenario_save: 0, bootstrap: 0, start: 0, stop: 0, preflight: 0, submit: 0, approval: 0, cancel: 0, reads: 0, websockets: 0 };
const report = {
  schema_version: "bluefire.installed-macos-native-desktop.v1",
  status: "failed_or_incomplete",
  real_service: true,
  mocked_responses: false,
  native_execution: false,
  live_model_inference: false,
  effective_access: false,
  profile_id: PROFILE,
  checks: [],
  screenshots: [],
  errors: [],
  blocked_requests: [],
  request_counts: counts,
  cleanup: { runner_stopped: false, job_settled: true },
};
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const stable = value => Array.isArray(value) ? value.map(stable)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const same = (left, right) => JSON.stringify(stable(left)) === JSON.stringify(stable(right));
const errorType = error => error instanceof Error ? error.name : "unknown";

function remaining(maximum = 10_000) {
  const value = Math.floor(deadline - performance.now());
  assert.ok(value > 0, "journey deadline expired");
  return Math.min(value, maximum);
}

function enter(next) {
  stage = next;
  if (context) context.setDefaultTimeout(remaining());
  if (page) page.setDefaultNavigationTimeout(remaining());
}

async function bounded(task, milliseconds) {
  let timer;
  try {
    return await Promise.race([task, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("bounded operation expired")), milliseconds);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

async function ui(action, maximum = 10_000) {
  const timeout = remaining(maximum);
  return bounded(action(timeout), timeout);
}

async function readCapability() {
  let input = "";
  await bounded((async () => {
    for await (const chunk of process.stdin) {
      input += chunk;
      assert.ok(Buffer.byteLength(input, "utf8") <= 256);
    }
  })(), remaining(5_000));
  const value = JSON.parse(input);
  input = "";
  assert.ok(exactKeys(value, ["capability"]));
  assert.match(value.capability ?? "", /^[A-Za-z0-9_-]{64}$/);
  capability = value.capability;
  secrets.push(capability);
}

const readPaths = new Set([
  "/api/v1/session", "/api/v1/catalog", "/api/v1/scenarios", "/api/v1/scenario-versions",
  "/api/v1/runs", "/api/v1/jobs", "/api/v1/comparison-snapshots", "/api/v1/detections",
  "/api/v1/detection-lab/health", "/api/v1/resources/research-sources",
  "/api/v1/resources/runner-profiles", "/api/v1/resources/runners",
  "/api/v1/resources/model-providers", "/api/v1/ai/authorizations",
  "/api/v1/file-access/status", "/api/v1/ad-smb/environments", "/api/v1/ad-smb/workflows",
  "/api/v1/s3-access/environments", "/api/v1/s3-access/exercises",
]);

function readAllowed(url) {
  if (!url.search && (readPaths.has(url.pathname) || url.pathname === "/"
    || /^\/ui\/[A-Za-z0-9/_\-.]+$/.test(url.pathname))) return true;
  if (url.pathname === "/api/v1/runner") return url.search === `?profile_id=${PROFILE}`;
  if (jobId && !url.search && url.pathname === `/api/v1/jobs/${jobId}`) return true;
  return Boolean(runId && !url.search && url.pathname === `/api/v1/runs/${runId}`);
}

function take(counter, cap, condition) {
  if (!condition || counts[counter] >= cap) return false;
  counts[counter] += 1;
  return true;
}

function writeAllowed(path, body, request) {
  if (cleanupPhase && path !== "/api/v1/runner/stop" && path !== `/api/v1/jobs/${jobId}/cancel`) return false;
  if (path === "/api/v1/session") return take("session", 1, !request.postData());
  if (path === "/api/v1/scenario-versions") return take("scenario_save", 1, exactKeys(body, ["scenario"]) && same(body.scenario, ownedScenario));
  if (path === "/api/v1/runner/bootstrap") return take("bootstrap", 1, same(body, { profile_id: PROFILE }));
  if (path === "/api/v1/runner/start") return take("start", 1, counts.bootstrap === 1 && same(body, { profile_id: PROFILE }));
  if (path === "/api/v1/runner/stop") return take("stop", 1, bootstrapAttempted && same(body, { profile_id: PROFILE }));
  if (path === "/api/v1/runs/preflight") return take("preflight", 1, runRequest && same(body, runRequest));
  if (path === "/api/v1/runs") return take("submit", 1, runRequest && counts.preflight === 1 && same(body, runRequest));
  if (jobId && path === `/api/v1/jobs/${jobId}/approval`) return take("approval", 1, same(body, { approved_by: "installed-macos-native-reviewer" }));
  if (jobId && path === `/api/v1/jobs/${jobId}/cancel`) return take("cancel", 1, exactKeys(body, []));
  return false;
}

async function api(path, body, maxMs = 10_000) {
  const timeoutMs = remaining(maxMs);
  return bounded(page.evaluate(async ({ path, body, timeoutMs }) => {
    const session = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!session) throw new Error("browser session missing");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(`/api/v1${path}`, {
        method: body === undefined ? "GET" : "POST", redirect: "error", credentials: "omit", signal: controller.signal,
        headers: { "X-BlueFire-Session": session, Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) throw new Error("installed service refused request");
      const reader = response.body?.getReader();
      if (!reader) throw new Error("installed service response was empty");
      let size = 0, text = "";
      const decoder = new TextDecoder();
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 1_048_576) { await reader.cancel(); throw new Error("response exceeded bound"); }
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
      } finally { reader.releaseLock(); }
      return JSON.parse(text);
    } finally { clearTimeout(timer); }
  }, { path, body, timeoutMs }), timeoutMs);
}

async function waitForJob(accepted, transient) {
  while (remaining() > 0) {
    const job = await api(`/jobs/${jobId}`);
    assert.equal(job.job_id, jobId);
    assert.equal(job.kind, "scenario.run");
    if (TERMINAL.has(job.state)) {
      terminalJob = job;
      report.cleanup.job_settled = true;
    }
    if (accepted.has(job.state)) return job;
    assert.ok(transient.has(job.state), "owned job entered an unexpected state");
    await delay(remaining(250));
  }
  throw new Error("owned job did not settle");
}

function verifyPreflight(value) {
  assert.equal(value.status, "approval_required");
  assert.equal(value.autonomy, "off");
  assert.equal(value.runner_profile, PROFILE);
  assert.deepEqual(value.scope, { scope_refs: ["sandbox.workspace"] });
  assert.deepEqual(value.problems, ["Explicit operator approval is required."]);
  assert.equal(value.plan?.mode, "execute");
  assert.equal(value.plan?.autonomy, "off");
  assert.equal(value.plan?.scenario_id, savedScenario.scenario_id);
  assert.equal(value.plan?.scenario_digest, savedScenario.digest);
  assert.deepEqual(value.plan.steps.map(step => [step.step_id, step.behavior_id, step.action_id]), [
    ["create_fixture", CREATE, CREATE], ["cleanup", CLEANUP, CLEANUP],
  ]);
  assert.ok(value.approval_envelope?.steps?.length === 2);
  assert.match(value.approval_envelope.envelope_digest ?? "", /^sha256:[0-9a-f]{64}$/);
  for (const field of BINDING_FIELDS) assert.equal(typeof value.approval_binding?.[field], "string");
  assert.equal(value.approval_binding.profile_id, PROFILE);
}

function verifyRun(run) {
  assert.equal(run.run_id, runId);
  assert.equal(run.status, "completed");
  assert.equal(run.mode, "execute");
  assert.equal(run.autonomy, "off");
  assert.equal(run.runner_profile_id, PROFILE);
  assert.equal(run.scenario_id, savedScenario.scenario_id);
  assert.deepEqual(run.scenario, savedScenario.document);
  assert.equal(run.plan?.scenario_digest, savedScenario.digest);
  assert.equal(run.plan?.scenario_id, savedScenario.scenario_id);
  assert.equal(run.plan?.mode, "execute");
  assert.equal(run.plan?.autonomy, "off");
  assert.equal(run.plan?.runner_profile_id, PROFILE);
  assert.equal(run.profile?.id, PROFILE);
  assert.deepEqual(run.steps.map(step => [step.step_id, step.behavior_id, step.action_id, step.status, step.runner_status, step.execution_disposition]), [
    ["create_fixture", CREATE, CREATE, "success", "success", "execute"],
    ["cleanup", CLEANUP, CLEANUP, "success", "success", "execute"],
  ]);
  const [created, cleaned] = run.steps;
  assert.equal(created.artifacts?.workspace?.record_count, 1);
  assert.equal(created.artifacts.workspace.fixture_path, "fixtures/input.jsonl");
  const records = run.evidence?.records;
  assert.ok(Array.isArray(records));
  const producer = step => {
    const matches = records.filter(row => row.step_id === step.step_id && row.provenance === "executed" && row.producer === "bluefire-rust-runner");
    assert.equal(matches.length, 1);
    const row = matches[0];
    assert.equal(row.run_id, runId);
    assert.equal(row.behavior_id, step.behavior_id);
    assert.equal(row.action_id, step.action_id);
    assert.equal(row.runner_profile_id, PROFILE);
    assert.equal(row.environment?.platform, "macos");
    assert.equal(row.content?.runner_status, "success");
    assert.equal(row.content.request_hash, step.request_hash);
    assert.match(row.content.request_hash ?? "", /^sha256:[0-9a-f]{64}$/);
    assert.ok(step.evidence_ids.includes(row.evidence_id));
    return row;
  };
  const createEvidence = producer(created), cleanupEvidence = producer(cleaned);
  const observations = records.filter(row => row.step_id === "create_fixture" && row.provenance === "observed" && row.producer === COLLECTOR);
  assert.equal(observations.length, 1);
  const observation = observations[0], content = observation.content;
  assert.equal(observation.run_id, runId);
  assert.equal(observation.behavior_id, CREATE);
  assert.equal(observation.action_id, CREATE);
  assert.equal(observation.runner_profile_id, PROFILE);
  assert.ok(created.evidence_ids.includes(observation.evidence_id));
  assert.ok(observation.parent_evidence_ids.includes(createEvidence.evidence_id));
  assert.equal(content?.artifact_type, "collector_observation");
  assert.equal(content.observation_kind, "filesystem");
  assert.equal(content.mechanism, "independent-file-handle-read");
  assert.equal(content.path, "fixtures/input.jsonl");
  assert.ok(Number.isSafeInteger(content.size_bytes) && content.size_bytes > 0);
  assert.match(content.sha256 ?? "", /^[0-9a-f]{64}$/);
  for (const field of ["path", "size_bytes", "sha256"]) assert.equal(content.observed_fields?.[field], content[field]);
  assert.equal(createEvidence.content.output?.record_count, 1);
  assert.equal(createEvidence.content.output?.sha256, content.sha256);
  assert.equal(createEvidence.content.output?.size, content.size_bytes);
  const times = [createEvidence.timestamp, observation.timestamp, cleanupEvidence.timestamp].map(Date.parse);
  assert.ok(times.every(Number.isFinite) && times[0] <= times[1] && times[1] <= times[2]);
  assert.equal(run.cleanup?.success, true);
  assert.equal(run.cleanup.outstanding_receipt_count, 0);
  if (Object.hasOwn(run.cleanup, "outstanding_receipts")) assert.equal(run.cleanup.outstanding_receipts, 0);
  assert.equal(run.manifest?.run_id, runId);
  assert.match(run.manifest.bundle_hash ?? "", /^sha256:[0-9a-f]{64}$/);
  report.observed = { filesystem_records: observations.length, executed_steps: 2, generated_records: 1 };
  report.observation_sha256 = content.sha256;
  report.bundle_hash = run.manifest.bundle_hash;
  report.native_execution = true;
}

async function capture(name) {
  assert.ok(connected);
  remaining();
  const visible = await ui(timeout => page.locator("body").innerText({ timeout }));
  assert.ok(secrets.every(secret => !visible.includes(secret)), "credentials cannot appear in captured UI");
  await ui(() => page.evaluate(async () => { await document.fonts.ready; await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); }));
  const geometry = await ui(() => page.evaluate(() => ({ width: innerWidth, height: innerHeight, document_width: document.documentElement.clientWidth, scroll_width: document.documentElement.scrollWidth })));
  assert.equal(geometry.width, 1440);
  assert.equal(geometry.height, 900);
  assert.ok(geometry.scroll_width <= geometry.document_width);
  const bytes = await ui(timeout => page.screenshot({ fullPage: false, animations: "disabled", mask: [page.locator('input[type="password"]')], timeout }));
  writeFileSync(join(output, `${name}.png`), bytes, { flag: "wx" });
  report.screenshots.push({ name, sha256: createHash("sha256").update(bytes).digest("hex"), geometry });
}

async function main() {
  assert.match(portText ?? "", /^\d{1,5}$/);
  assert.ok(Number(portText) > 0 && Number(portText) <= 65535);
  origin = `http://127.0.0.1:${Number(portText)}`;
  await readCapability();
  enter("browser-launch");
  const { chromium } = await ui(() => import(pathToFileURL(modulePath).href));
  browser = await ui(timeout => chromium.launch({ headless: true, timeout, args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"] }), 15_000);
  report.browser_version = browser.version();
  context = await ui(() => browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" }));
  context.setDefaultTimeout(remaining());
  await ui(() => context.routeWebSocket("**/*", socket => { counts.websockets += 1; socket.close(); }));
  await ui(() => context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    let allowed = false;
    if (url.origin === origin && !url.username && !url.password) {
      if (method === "GET" && counts.reads < 500 && readAllowed(url)) { counts.reads += 1; allowed = true; }
      else if (method === "POST" && !url.search) {
        let body;
        try { body = request.postData() ? request.postDataJSON() : null; } catch { body = undefined; }
        allowed = writeAllowed(url.pathname, body, request);
      }
    }
    if (!allowed) {
      // Do not retain an unexpected URL or body, which could contain a credential.
      report.blocked_requests.push({ method: ["GET", "POST", "HEAD"].includes(method) ? method : "other", destination: url.origin === origin ? "local-unapproved" : "external" });
      await route.abort();
      return;
    }
    await route.continue();
  }));
  page = await ui(() => context.newPage());
  let connectionProbes = 0;
  page.on("response", response => {
    if (!connected && stage === "connect" && response.url() === `${origin}/api/v1/session`
      && response.request().method() === "GET" && response.status() === 401) connectionProbes += 1;
  });
  page.on("pageerror", () => report.errors.push({ stage, kind: "page-error" }));
  page.on("console", message => {
    if (message.type() !== "error") return;
    if (!connected && stage === "connect" && connectionProbes > 0
      && message.location().url === `${origin}/api/v1/session`
      && /^Failed to load resource: the server responded with a status of 401\b/.test(message.text())) {
      connectionProbes -= 1;
      return;
    }
    report.errors.push({ stage, kind: "console-error" });
  });
  page.on("dialog", async dialog => { report.errors.push({ stage, kind: "unexpected-dialog" }); await dialog.dismiss(); });
  enter("connect");
  const documentResponse = await ui(timeout => page.goto(`${origin}/#/scenarios`, { waitUntil: "domcontentloaded", timeout }));
  assert.equal(documentResponse?.status(), 200);
  await ui(timeout => page.getByLabel("One-time connection code", { exact: false }).fill(capability, { timeout }));
  await ui(timeout => page.getByRole("button", { name: "Connect", exact: true }).click({ timeout }));
  capability = "";
  await ui(timeout => page.waitForFunction(() => sessionStorage.getItem("bluefire.browser-session.v1") !== null, null, { timeout }));
  const session = await ui(() => page.evaluate(() => sessionStorage.getItem("bluefire.browser-session.v1")));
  assert.match(session ?? "", /^[A-Za-z0-9_-]{64}$/);
  secrets.push(session);
  connected = true;
  await ui(timeout => page.getByRole("heading", { name: "Experiments", exact: true }).waitFor({ timeout }));
  report.checks.push("normal_ephemeral_browser_session");

  enter("profile-authority");
  const catalog = await api("/catalog");
  const profile = catalog.runner_profiles.find(row => row.id === PROFILE);
  assert.equal(profile?.mode, "execute");
  assert.equal(profile.approval_required, true);
  assert.ok(profile.platforms.includes("macos") && profile.scope.includes("sandbox.workspace"));
  assert.equal(profile.cleanup_policy, "always");
  assert.ok([CREATE, CLEANUP].every(action => profile.enabled_actions.includes(action) && !profile.blocked_actions.includes(action)));
  report.checks.push("shipped_execute_profile_verified");
  enter("runner-bootstrap-start");
  bootstrapAttempted = true;
  await api("/runner/bootstrap", { profile_id: PROFILE }, 35_000);
  await api("/runner/start", { profile_id: PROFILE }, 15_000);
  const runner = await api(`/runner?profile_id=${PROFILE}`);
  assert.equal(runner.profile_id, PROFILE);
  assert.equal(runner.state, "ready");
  report.checks.push("managed_runner_started");

  enter("save-generated-plan");
  const scenarioId = `scenario.installed-macos-native.${randomUUID()}.v1`;
  ownedScenario = {
    schema_version: "bluefire.scenario.v1", id: scenarioId, title: TITLE,
    purpose: "Create one generated record, observe its file, and verify receipt-bound cleanup.", start: "create_fixture",
    steps: [
      { id: "create_fixture", behavior_id: CREATE, parameters: { record_count: 1 } },
      { id: "cleanup", behavior_id: CLEANUP, parameters: { verify_removal: true }, inputs: { workspace: { from_step: "create_fixture", artifact: "workspace" } } },
    ],
    edges: [{ from_step: "create_fixture", to_step: "cleanup", outcome: "success" }],
    provenance: { source: "BlueFire installed macOS verifier", reference: scenarioId, license: "MIT", derived: false, notes: "Owned generated sandbox records only." },
    limitations: ["This journey does not establish effective access, AD, cloud, external telemetry, or model inference."],
  };
  savedScenario = (await api("/scenario-versions", { scenario: ownedScenario })).scenario;
  assert.equal(savedScenario.scenario_id, scenarioId);
  assert.equal(savedScenario.version, 1);
  assert.match(savedScenario.digest ?? "", /^sha256:[0-9a-f]{64}$/);
  assert.equal(savedScenario.document?.id, scenarioId);
  assert.equal(savedScenario.document?.title, TITLE);
  assert.deepEqual(savedScenario.document.steps.map(step => [step.id, step.behavior_id]), [["create_fixture", CREATE], ["cleanup", CLEANUP]]);
  report.scenario_id = scenarioId;
  report.scenario_version = savedScenario.version;
  report.scenario_digest = savedScenario.digest;
  report.checks.push("saved_generated_two_step_plan");

  enter("preflight-and-submit");
  runRequest = {
    scenario: savedScenario.document, layout: { schema_version: "bluefire.layout.v1", nodes: [] },
    mode: "execute", autonomy: "off", ai_provider_id: null, runner_profile_id: PROFILE,
    target_scope: { scope_refs: ["sandbox.workspace"] }, collectors: [COLLECTOR],
  };
  const preflight = await api("/runs/preflight", runRequest);
  verifyPreflight(preflight);
  report.cleanup.job_settled = false;
  const submitted = await api("/runs", runRequest);
  assert.match(submitted.job?.job_id ?? "", /^job-[0-9a-f]{32}$/);
  jobId = submitted.job.job_id;
  report.job_id = jobId;
  verifyPreflight(submitted.preflight);
  const pending = await waitForJob(new Set(["awaiting_approval"]), new Set(["queued", "planning"]));
  assert.equal(pending.approval_request?.status, "pending");
  assert.ok(Date.parse(pending.approval_request.expires_at) > Date.now());
  for (const field of BINDING_FIELDS) assert.equal(pending.approval_request[field], submitted.preflight.approval_binding[field]);
  assert.equal(pending.request?.approval_request_id, pending.approval_request.approval_id);
  enter("explicit-approval-and-execution");
  await api(`/jobs/${jobId}/approval`, { approved_by: "installed-macos-native-reviewer" });
  report.checks.push("exact_preflight_and_approval");
  const finished = await waitForJob(TERMINAL, new Set(["queued", "planning", "awaiting_approval", "running", "cancelling"]));
  assert.equal(finished.state, "completed");
  assert.ok(["claimed", "consumed"].includes(finished.approval_request?.status));
  const links = [finished.result_ref, finished.progress?.run_id].filter(value => value != null);
  assert.ok(links.length > 0 && links.every(value => value === links[0]));
  assert.match(links[0], /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/);
  runId = links[0];
  report.run_id = runId;
  enter("native-result-observation-cleanup");
  const run = await api(`/runs/${runId}`);
  verifyRun(run);
  report.checks.push("two_native_steps_completed", "independent_fixture_observed_before_cleanup", "receipt_cleanup_complete");

  enter("saved-run-ui");
  await ui(timeout => page.goto(`${origin}/#/runs/${runId}`, { waitUntil: "domcontentloaded", timeout }));
  await ui(timeout => page.getByRole("heading", { name: TITLE, exact: true }).waitFor({ timeout }));
  await ui(timeout => page.getByRole("navigation", { name: "Run review sections" }).waitFor({ timeout }));
  await capture("macos-native-result");
  report.checks.push("saved_run_reopened_in_packaged_ui");
  enter("evidence-ui");
  await ui(timeout => page.getByRole("navigation", { name: "Run review sections" }).getByRole("button", { name: "Evidence", exact: true }).click({ timeout }));
  const evidence = page.locator("details.run-review-details").filter({ has: page.locator("summary").filter({ hasText: /^Inspect evidence records/ }) });
  assert.equal(await ui(() => evidence.count()), 1);
  if (!await ui(timeout => evidence.evaluate(element => element.open, undefined, { timeout }))) await ui(timeout => evidence.locator(":scope > summary").click({ timeout }));
  const observation = evidence.locator("article").filter({ has: page.getByText("File metadata observed", { exact: true }) });
  assert.equal(await ui(() => observation.count()), 1);
  await ui(timeout => observation.getByText("fixtures/input.jsonl", { exact: true }).waitFor({ timeout }));
  await ui(timeout => observation.getByText(report.observation_sha256, { exact: true }).waitFor({ timeout }));
  await ui(timeout => observation.scrollIntoViewIfNeeded({ timeout }));
  await capture("macos-native-evidence");
  enter("cleanup-ui");
  await ui(timeout => page.getByRole("navigation", { name: "Run review sections" }).getByRole("button", { name: "Cleanup", exact: true }).click({ timeout }));
  const cleanup = page.getByRole("region", { name: "Cleanup and retained changes" });
  await ui(timeout => cleanup.getByRole("heading", { name: "Cleanup record", exact: true }).waitFor({ timeout }));
  await ui(timeout => cleanup.getByText("Recorded cleanup details", { exact: true }).click({ timeout }));
  assert.equal(await ui(timeout => cleanup.locator("details").evaluate(element => element.open, undefined, { timeout })), true);
  await ui(timeout => cleanup.scrollIntoViewIfNeeded({ timeout }));
  await capture("macos-native-cleanup");
  report.checks.push("evidence_and_cleanup_views_inspected");
  enter("same-tab-reload");
  await ui(timeout => page.reload({ waitUntil: "domcontentloaded", timeout }));
  await ui(timeout => page.getByRole("heading", { name: TITLE, exact: true }).waitFor({ timeout }));
  assert.equal(new URL(page.url()).hash, `#/runs/${runId}`);
  const reopened = await api(`/runs/${runId}`);
  assert.equal(reopened.run_id, runId);
  assert.equal(reopened.manifest?.bundle_hash, report.bundle_hash);
  assert.deepEqual(reopened.steps, run.steps);
  assert.deepEqual(reopened.cleanup, run.cleanup);
  assert.deepEqual(reopened.evidence, run.evidence);
  await capture("macos-native-reopened");
  report.checks.push("same_tab_reload_preserved_run");
}

try {
  await main();
} catch (error) {
  report.errors.push({ stage, kind: "journey-failed", error_type: errorType(error) });
} finally {
  capability = "";
  process.stdin.destroy();
  cleanupPhase = true;
  const cleanupDeadline = performance.now() + 20_000;
  deadline = cleanupDeadline;
  enter("cleanup");
  if (connected && jobId && !terminalJob) {
    report.cleanup.cancel_attempted = true;
    try {
      deadline = Math.min(cleanupDeadline, performance.now() + 9_000);
      await api(`/jobs/${jobId}/cancel`, {}, 5_000);
      await waitForJob(TERMINAL, new Set(["queued", "planning", "awaiting_approval", "running", "paused", "cancelling"]));
    } catch (error) { report.errors.push({ stage, kind: "job-settlement", error_type: errorType(error) }); }
    finally { deadline = cleanupDeadline; }
  }
  if (connected && bootstrapAttempted) {
    try {
      await api("/runner/stop", { profile_id: PROFILE }, 7_000);
      const stopped = await api(`/runner?profile_id=${PROFILE}`, undefined, 3_000);
      assert.equal(stopped.profile_id, PROFILE);
      assert.ok(["stopped", "unbootstrapped"].includes(stopped.state));
      report.cleanup.runner_stopped = true;
      report.checks.push("managed_runner_stopped");
    } catch (error) { report.errors.push({ stage, kind: "runner-stop", error_type: errorType(error) }); }
  }
  try { if (context) await ui(() => context.close(), 3_000); }
  catch (error) { report.errors.push({ stage, kind: "context-close", error_type: errorType(error) }); }
  try { if (browser) await ui(() => browser.close(), 3_000); }
  catch (error) { report.errors.push({ stage, kind: "browser-close", error_type: errorType(error) }); }
  if (report.blocked_requests.length === 0 && counts.websockets === 0) report.checks.push("scope_guard_no_unexpected_requests");
  else report.errors.push({ stage, kind: "scope-guard" });
  const requiredCounts = { session: 1, scenario_save: 1, bootstrap: 1, start: 1, stop: 1, preflight: 1, submit: 1, approval: 1, cancel: 0 };
  const success = report.errors.length === 0 && report.native_execution && report.cleanup.runner_stopped && report.cleanup.job_settled
    && report.screenshots.length === 4 && Object.entries(requiredCounts).every(([key, count]) => counts[key] === count);
  report.elapsed_seconds = Math.round((performance.now() - startedAt) / 10) / 100;
  report.credentials_absent = secrets.every(secret => !JSON.stringify(report).includes(secret));
  if (report.credentials_absent) report.checks.push("report_credentials_absent");
  if (success && report.credentials_absent) report.status = "passed";
  // The report contains only projected identifiers, hashes, counts, and bounded error categories.
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  assert.ok(secrets.every(secret => !serialized.includes(secret)));
  writeFileSync(join(output, "macos-native-browser-report.json"), serialized, { flag: "wx" });
  process.exitCode = report.status === "passed" ? 0 : 1;
}
