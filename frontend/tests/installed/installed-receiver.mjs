// One installed-wheel native baseline through the ordinary runner and receiver UI.
/* global process, URL, document, fetch, sessionStorage, location, structuredClone */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { classifyRequest, consumeRequestBudget } from "./receiver-guards.mjs";

const [modulePath, output, port] = process.argv.slice(2);
assert.match(port ?? "", /^\d{1,5}$/);
const inputChunks = [];
let inputBytes = 0;
for await (const chunk of process.stdin) {
  inputBytes += chunk.length;
  assert.ok(inputBytes <= 256, "Capability input exceeded its limit");
  inputChunks.push(chunk);
}
let { capability } = JSON.parse(Buffer.concat(inputChunks).toString("utf8"));
inputChunks.length = 0;
assert.match(capability ?? "", /^[A-Za-z0-9_-]{64}$/);

const PROFILE = "sandbox-endpoint-deep-lab.v1";
const STARTER = "scenario.receiver-defense.redaction-validation.v1";
const STARTER_TITLE = "Validate receiver redaction and legitimate use";
const FILESYSTEM_COLLECTOR = "collector.filesystem.sandbox.v1";
const ORIGIN = `http://127.0.0.1:${port}`;
const ID = /^job-[0-9a-f]{32}$/;
const RUN_ID = /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/;
const COPY_ID = /^scenario\.receiver-defense\.redaction-validation\.copy\.[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.v1$/;
const ROUTE_LIMITS = {
  session: 1,
  bootstrap: 1,
  start: 1,
  stop: 1,
  context: 8,
  save_scenario: 1,
  owner: 1,
  prepare: 1,
  review: 1,
  approval: 1,
  cancel: 1,
};
const counts = Object.fromEntries(Object.keys(ROUTE_LIMITS).map((key) => [key, 0]));
const report = {
  schema_version: "bluefire.installed-receiver-baseline.v1",
  status: "failed_or_incomplete",
  installed_wheel_service: true,
  native_execution_required: true,
  workflow: "retained_redaction_baseline_only",
  external_credentials: false,
  live_model_inference: false,
  generated_record_count: 8,
  target_scope: ["sandbox.workspace", "network.loopback"],
  runner_profile: PROFILE,
  checks: [],
  blocked_requests: [],
  errors: [],
};

const exactKeys = (value, names) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...names].sort());
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const boundedString = (value, max = 128) => typeof value === "string" && value.trim().length > 0 && value.length <= max;
const count = (key) => consumeRequestBudget(counts, ROUTE_LIMITS, key);
let browser, context, page;
let connected = false;
let stage = "launch";
let expected401 = 0;
let receiverJobId;
let executionJobId;
let runId;
let receiverStarted = false;
let runnerStarted = false;
let savedSelection;
let packagedStarter;
let expectedScenarioCopy;
let latestContext;
let latestOwner;
let latestPreparationDigest;

function allowedRead(url) {
  const path = url.pathname;
  if (["/", "/index.html", "/ui/app.js", "/ui/styles.css"].includes(path)) return !url.search;
  if ([
    "/api/v1/session",
    "/api/v1/catalog",
    "/api/v1/scenarios",
    "/api/v1/scenario-versions",
    "/api/v1/resources/runner-profiles",
    "/api/v1/resources/runners",
    "/api/v1/receiver-defense/jobs",
    "/api/v1/jobs",
    "/api/v1/runs",
  ].includes(path)) return !url.search;
  if (path === "/api/v1/runner") return url.search === `?profile_id=${PROFILE}`;
  if (/^\/api\/v1\/receiver-defense\/jobs\/job-[0-9a-f]{32}$/.test(path)) return !url.search;
  if (/^\/api\/v1\/jobs\/job-[0-9a-f]{32}$/.test(path)) return !url.search;
  if (/^\/api\/v1\/runs\/run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/.test(path)) return !url.search;
  if (/^\/api\/v1\/runs\/run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\/events$/.test(path)) {
    return /^\?after_sequence=\d+&limit=\d+$/.test(url.search);
  }
  return false;
}

function validateContext(body) {
  if (!exactKeys(body, ["selection", "run_intent", "workflow"]) || body.workflow !== "retained_redaction"
    || !same(body.selection, savedSelection)
    || !exactKeys(body.run_intent, ["mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope", "collectors"])
    || body.run_intent.mode !== "execute" || body.run_intent.autonomy !== "off"
    || body.run_intent.ai_provider_id !== null || body.run_intent.runner_profile_id !== PROFILE
    || !exactKeys(body.run_intent.target_scope, ["scope_refs"])
    || !Array.isArray(body.run_intent.target_scope.scope_refs)
    || !same([...body.run_intent.target_scope.scope_refs].sort(), ["network.loopback", "sandbox.workspace"])
    || !same(body.run_intent.collectors, [FILESYSTEM_COLLECTOR])) return false;
  return true;
}

function validateScenarioCopy(value) {
  if (!packagedStarter) return false;
  const expected = structuredClone(packagedStarter);
  delete expected.layout;
  if (!exactKeys(value, Object.keys(expected))) return false;
  if (!COPY_ID.test(value.id ?? "") || value.title !== `${STARTER_TITLE} copy`) return false;
  expected.id = value.id;
  expected.title = `${STARTER_TITLE} copy`;
  if (!same(value, expected)) return false;
  expectedScenarioCopy = expected;
  return true;
}

function authorizePost(url, body) {
  const path = url.pathname;
  if (path === "/api/v1/session") return count("session") && body === null;
  if (path === "/api/v1/runner/bootstrap") {
    return count("bootstrap") && exactKeys(body, ["profile_id"]) && body.profile_id === PROFILE;
  }
  if (path === "/api/v1/runner/start") {
    const ok = count("start") && exactKeys(body, ["profile_id"]) && body.profile_id === PROFILE;
    if (ok) runnerStarted = true;
    return ok;
  }
  if (path === "/api/v1/runner/stop") {
    return count("stop") && exactKeys(body, ["profile_id"]) && body.profile_id === PROFILE;
  }
  if (path === "/api/v1/scenario-versions") {
    return count("save_scenario") && exactKeys(body, ["scenario"]) && validateScenarioCopy(body.scenario);
  }
  if (path === "/api/v1/receiver-defense/context") {
    return count("context") && validateContext(body);
  }
  if (path === "/api/v1/receiver-defense/jobs") {
    return count("owner") && exactKeys(body, ["selection", "run_intent", "workflow", "submission_id", "context_digest"])
      && validateContext({ selection: body.selection, run_intent: body.run_intent, workflow: body.workflow })
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id)
      && body.context_digest === latestContext?.context_digest;
  }
  const preparePath = receiverJobId && `/api/v1/receiver-defense/jobs/${receiverJobId}/prepare`;
  if (path === preparePath) {
    return count("prepare") && exactKeys(body, ["submission_id", "phase", "reviewed_by"])
      && body.phase === "baseline" && boundedString(body.reviewed_by)
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id);
  }
  const reviewPath = receiverJobId && `/api/v1/receiver-defense/jobs/${receiverJobId}/review`;
  if (path === reviewPath) {
    return count("review") && exactKeys(body, ["submission_id", "phase", "preparation_digest", "decision", "reviewed_by"])
      && body.phase === "baseline" && body.preparation_digest === latestPreparationDigest
      && body.decision === "accept" && boundedString(body.reviewed_by)
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id);
  }
  const approvalPath = executionJobId && `/api/v1/jobs/${executionJobId}/approval`;
  if (path === approvalPath) {
    return count("approval") && exactKeys(body, ["approved_by"]) && boundedString(body.approved_by);
  }
  const cancelPath = receiverJobId && `/api/v1/jobs/${receiverJobId}/cancel`;
  if (path === cancelPath) return count("cancel") && exactKeys(body, []);
  return false;
}

async function appApi(path) {
  return page.evaluate(async (apiPath) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!token) throw new Error("Session unavailable");
    const response = await fetch(`/api/v1${apiPath}`, {
      method: "GET", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": token, Accept: "application/json" },
    });
    if (!response.ok) throw new Error("Owned status read failed");
    return response.json();
  }, path);
}

async function waitOwner(predicate, timeout = 120_000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    latestOwner = await appApi(`/receiver-defense/jobs/${receiverJobId}`);
    if (predicate(latestOwner)) return latestOwner;
    await delay(500);
  }
  throw new Error("Receiver baseline did not reach the expected saved state");
}

async function readRunnerStatus() {
  return appApi(`/runner?profile_id=${PROFILE}`);
}

async function stopOwnerNormally() {
  if (!receiverJobId || !connected || !page || page.isClosed()) return;
  try {
    latestOwner = await appApi(`/receiver-defense/jobs/${receiverJobId}`);
    if (["completed", "stopped"].includes(latestOwner.status)) return;
    const response = await page.evaluate(async (jobId) => {
      const token = sessionStorage.getItem("bluefire.browser-session.v1");
      return fetch(`/api/v1/jobs/${encodeURIComponent(jobId)}/cancel`, {
        method: "POST", redirect: "error", credentials: "omit",
        headers: { "X-BlueFire-Session": token, "Content-Type": "application/json", Accept: "application/json" },
        body: "{}",
      }).then((result) => result.ok);
    }, receiverJobId);
    if (!response) throw new Error("Receiver test cancellation was refused");
    latestOwner = await waitOwner((value) => value.status === "stopped", 30_000);
  } catch {
    report.cleanup = { ...(report.cleanup ?? {}), receiver_control_stopped: false };
  }
}

async function stopRunnerNormally() {
  if (!runnerStarted || !connected || !page || page.isClosed()) return;
  try {
    const status = await readRunnerStatus();
    if (status.state === "ready") {
      const stopped = await page.evaluate(async (profileId) => {
        const token = sessionStorage.getItem("bluefire.browser-session.v1");
        const response = await fetch("/api/v1/runner/stop", {
          method: "POST", redirect: "error", credentials: "omit",
          headers: { "X-BlueFire-Session": token, "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ profile_id: profileId }),
        });
        return response.ok ? response.json() : null;
      }, PROFILE);
      if (!stopped || stopped.state !== "stopped") throw new Error("Runner stop was not confirmed");
    }
    await page.waitForFunction(async ({ origin, profile }) => {
      const token = sessionStorage.getItem("bluefire.browser-session.v1");
      const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, { headers: { "X-BlueFire-Session": token } });
      return response.ok && (await response.json()).state === "stopped";
    }, { origin: ORIGIN, profile: PROFILE }, { timeout: 45_000 });
    assert.equal((await readRunnerStatus()).state, "stopped");
    report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: true };
  } catch {
    report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: false };
  }
}

try {
  const { chromium } = await import(pathToFileURL(modulePath).href);
  browser = await chromium.launch({
    headless: true,
    args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"],
  });
  report.browser_version = browser.version();
  context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 } });
  context.setDefaultTimeout(120_000);
  await context.routeWebSocket("**/*", async (socket) => {
    report.blocked_requests.push({ kind: "websocket", destination: "blocked" });
    await socket.close();
  });
  await context.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    let body;
    let bodyError = false;
    if (url.origin === ORIGIN && method === "POST") {
      try { body = request.postData() ? request.postDataJSON() : null; }
      catch { bodyError = true; }
    }
    const decision = classifyRequest({
      origin: url.origin,
      expectedOrigin: ORIGIN,
      method,
      url,
      body,
      bodyError,
      allowedRead,
      authorizePost,
    });
    if (!decision.allowed) {
      report.blocked_requests.push({ method, path: url.origin === ORIGIN ? url.pathname : "non_loopback", reason: decision.reason });
      await route.abort();
      return;
    }
    await route.continue();
  });
  page = await context.newPage();
  page.on("response", async (response) => {
    const request = response.request();
    if (new URL(response.url()).origin !== ORIGIN) return;
    const path = new URL(response.url()).pathname;
    if (request.method() === "GET" && path === "/api/v1/session" && response.status() === 401) expected401 += 1;
    if (request.method() !== "POST") return;
    try {
      const data = await response.json();
      if (path === "/api/v1/receiver-defense/context" && response.ok()) latestContext = data;
      else if (path === "/api/v1/receiver-defense/jobs" && response.ok()) {
        receiverJobId = data.job?.job_id;
        latestOwner = data;
        receiverStarted = Boolean(receiverJobId);
      } else if (receiverJobId && path === `/api/v1/receiver-defense/jobs/${receiverJobId}/prepare` && response.ok()) {
        latestOwner = data;
      } else if (receiverJobId && path === `/api/v1/receiver-defense/jobs/${receiverJobId}/review` && response.ok()) {
        latestOwner = data;
        executionJobId = data.phases?.find((phase) => phase.phase === "baseline")?.execution_job?.job_id;
      }
    } catch { /* Error details stay out of the retained report. */ }
  });
  page.on("pageerror", () => report.errors.push({ stage, kind: "page_error" }));
  page.on("console", (message) => {
    if (message.type() !== "error") return;
    if (!connected && stage === "connect" && expected401 > 0 && message.location().url === `${ORIGIN}/api/v1/session`
      && /^Failed to load resource: the server responded with a status of 401\b/.test(message.text())) {
      expected401 -= 1;
      return;
    }
    report.errors.push({ stage, kind: "console_error" });
  });

  stage = "connect";
  await page.goto(ORIGIN, { waitUntil: "domcontentloaded" });
  await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  capability = "";
  await page.waitForFunction(() => sessionStorage.getItem("bluefire.browser-session.v1") !== null);
  connected = true;
  await page.getByRole("link", { name: "Build", exact: true }).waitFor();
  report.checks.push("installed_service_ephemeral_session");

  stage = "runner-lifecycle";
  await page.goto(`${ORIGIN}/#/runners?profile=${encodeURIComponent(PROFILE)}`);
  await page.getByRole("combobox", { name: "Experiment runner profile", exact: true }).selectOption(PROFILE);
  const beforeRunner = await readRunnerStatus();
  assert.equal(beforeRunner.state, "unbootstrapped", "Refuse to modify a runner that predates this owned test");
  await page.getByRole("button", { name: "Verify & enroll", exact: true }).click();
  await page.waitForFunction(async ({ origin, profile }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, { headers: { "X-BlueFire-Session": token } });
    return response.ok && (await response.json()).state === "stopped";
  }, { origin: ORIGIN, profile: PROFILE }, { timeout: 120_000 });
  const afterBootstrap = await readRunnerStatus();
  if (afterBootstrap.state !== "ready") {
    assert.equal(afterBootstrap.state, "stopped", "Only the exact newly enrolled runner can be started");
    await page.getByRole("button", { name: "Start authenticated host", exact: true }).click();
  }
  await page.waitForFunction(async ({ origin, profile }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, { headers: { "X-BlueFire-Session": token } });
    return response.ok && (await response.json()).state === "ready";
  }, { origin: ORIGIN, profile: PROFILE }, { timeout: 45_000 });
  const ready = await readRunnerStatus();
  assert.equal(ready.profile_id, PROFILE);
  assert.equal(ready.enrollment, "active");
  assert.equal(ready.process, "running");
  report.checks.push("packaged_runner_enrolled_and_started_through_ui");

  stage = "baseline-setup";
  const packagedList = await appApi("/scenarios");
  packagedStarter = packagedList.scenarios.find((item) => item.id === STARTER);
  assert.ok(packagedStarter && packagedStarter.title === STARTER_TITLE);
  assert.equal(packagedStarter.steps.length, 6);
  assert.equal(packagedStarter.steps.find((step) => step.id === "create_fixture").parameters.record_count, 8);
  assert.equal(packagedStarter.steps.find((step) => step.id === "transform_fixture").parameters.redact_values, false);

  await page.goto(`${ORIGIN}/#/scenarios?selected=${encodeURIComponent(STARTER)}&view=packaged`);
  const packagedRow = page.getByRole("article", { name: `${STARTER_TITLE} - Packaged`, exact: true });
  await packagedRow.getByRole("button", { name: "Duplicate", exact: true }).click();
  const draftTitle = `${STARTER_TITLE} copy`;
  const draftRow = page.getByRole("article", { name: `${draftTitle} - Working draft`, exact: true });
  await draftRow.getByRole("button", { name: "Continue editing", exact: true }).click();
  await page.waitForFunction(() => location.hash.startsWith("#/builder"));

  const saveResponsePromise = page.waitForResponse((response) => {
    const request = response.request();
    return request.method() === "POST" && new URL(response.url()).pathname === "/api/v1/scenario-versions";
  }, { timeout: 30_000 });
  await page.getByRole("button", { name: "Save version", exact: true }).click();
  const saveResponse = await saveResponsePromise;
  assert.equal(saveResponse.ok(), true, "The UI must save its generated duplicate as a version");
  const saveEnvelope = await saveResponse.json();
  assert.equal(saveEnvelope.schema_version, "bluefire.scenario-version.v1");
  const saved = saveEnvelope.scenario;
  assert.ok(exactKeys(saved, ["scenario_id", "title", "version", "digest", "created_at", "updated_at", "document"]));
  assert.match(saved.scenario_id, COPY_ID);
  assert.equal(saved.title, draftTitle);
  assert.equal(saved.version, 1);
  assert.match(saved.digest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(expectedScenarioCopy && same(saved.document, expectedScenarioCopy));
  const persistedCopies = (await appApi("/scenario-versions")).scenarios.filter((item) => item.scenario_id === saved.scenario_id);
  assert.equal(persistedCopies.length, 1, "Exactly one saved copy must be retained");
  assert.equal(persistedCopies[0].version, 1);
  assert.equal(persistedCopies[0].digest, saved.digest);
  assert.ok(same(persistedCopies[0].document, expectedScenarioCopy));
  savedSelection = { kind: "saved_scenario", scenario_id: saved.scenario_id, version: saved.version, digest: saved.digest };
  report.source_starter_scenario_id = STARTER;
  report.saved_scenario_copy = { scenario_id: saved.scenario_id, version: saved.version, digest: saved.digest };
  report.checks.push("packaged_starter_duplicated_and_saved_through_ui");

  await page.goto(`${ORIGIN}/#/compare?receiver=1`);
  await page.getByRole("radio", { name: "Retain redaction and verify legitimate use", exact: true }).check();
  await page.getByLabel("Saved experiment", { exact: true }).selectOption(`${saved.scenario_id}:${saved.version}:${saved.digest}`);
  await page.getByRole("radio", { name: /^Execute / }).check();
  await page.getByLabel("Environment profile", { exact: true }).selectOption(PROFILE);
  for (const label of ["Files in the selected workspace", "Connections to the local lab receiver"]) {
    const scope = page.getByRole("checkbox", { name: label, exact: true });
    if (!(await scope.isChecked())) await scope.check();
  }
  const saveControl = page.getByRole("button", { name: "Save control test", exact: true });
  await saveControl.waitFor({ state: "visible" });
  await page.waitForFunction(() => {
    const button = [...document.querySelectorAll("button")].find((item) => item.textContent?.trim() === "Save control test");
    return Boolean(button && !button.disabled);
  }, undefined, { timeout: 30_000 });
  await saveControl.click();
  await page.waitForFunction(() => location.hash.includes("receiver_job=job-"));
  assert.match(receiverJobId ?? "", ID);
  assert.equal(latestOwner?.context?.workflow, "retained_redaction");
  assert.equal(latestOwner?.admission?.accepted, true);
  report.receiver_job_id = receiverJobId;
  report.checks.push("saved_scenario_context_and_receiver_admission");

  stage = "baseline-preparation";
  await page.getByRole("button", { name: "Prepare baseline receiver", exact: true }).waitFor({ state: "visible" });
  await page.getByLabel("Prepared by", { exact: true }).fill("Installed receiver baseline verifier");
  await page.getByRole("button", { name: "Prepare baseline receiver", exact: true }).click();
  await waitOwner((owner) => owner.next_action?.kind === "review_replay" && owner.phases?.[0]?.review_ready === true);
  const phase = latestOwner.phases.find((item) => item.phase === "baseline");
  latestPreparationDigest = phase.preparation.preparation_digest;
  receiverStarted = true;
  report.receiver_preparation = {
    phase: phase.phase,
    policy_id: phase.policy_id,
    preparation_digest: latestPreparationDigest,
    preflight_ready: phase.preparation.preflight?.status === "approval_required",
    target_effects_started_before_review: phase.preparation.target_effects_started,
  };
  assert.equal(report.receiver_preparation.preflight_ready, true);
  assert.equal(report.receiver_preparation.target_effects_started_before_review, false);

  stage = "baseline-review";
  await page.getByRole("checkbox", { name: "I reviewed this receiver policy and the complete run plan.", exact: true }).check();
  await page.getByLabel("Reviewed by", { exact: true }).fill("Installed receiver baseline verifier");
  await page.getByRole("button", { name: "Accept and review run approval", exact: true }).click();
  await page.getByRole("button", { name: "Approve and release job", exact: true }).waitFor({ state: "visible" });
  assert.match(executionJobId ?? "", ID);
  report.execution_job_id = executionJobId;

  stage = "execute-approval";
  await page.getByRole("checkbox", { name: "I approve this exact immutable job envelope once", exact: true }).check();
  await page.getByLabel("Operator identity for this job", { exact: true }).fill("Installed receiver baseline verifier");
  await page.getByRole("button", { name: "Approve and release job", exact: true }).click();
  await waitOwner((owner) => owner.phases?.[0]?.status === "completed");
  const baseline = latestOwner.phases.find((item) => item.phase === "baseline");
  const result = baseline.result;
  assert.ok(result);
  assert.equal(baseline.execution_job.kind, "scenario.run");
  assert.equal(baseline.execution_job.state, "completed");
  assert.equal(result.decision, "accepted");
  assert.equal(result.phase, "baseline");
  assert.equal(result.run_id, baseline.execution_job.result_ref);
  assert.match(result.run_id, RUN_ID);
  assert.equal(result.run?.mode, "execute");
  assert.equal(result.run?.is_demo, false);
  assert.equal(result.run?.runner_profile_id, PROFILE);
  assert.equal(result.run?.plan?.autonomy, "off");
  assert.equal(result.receiver_observation?.state, "verified");
  assert.equal(result.receiver_observation?.terminal?.decision?.decision, "accepted");
  assert.equal(result.receiver_observation?.terminal?.decision?.semantics?.record_count, 8);
  assert.equal(result.cleanup?.receiver, "verified_closed");
  assert.equal(result.cleanup?.run, "complete");
  assert.equal(baseline.cleanup?.receiver, "verified_closed");
  assert.equal(baseline.cleanup?.run, "complete");
  runId = result.run_id;
  report.run_id = runId;
  report.baseline = {
    status: baseline.status,
    execution_state: baseline.execution_job.state,
    mode: result.run.mode,
    scenario_id: result.run.scenario_id,
    run_profile: result.run.runner_profile_id,
    receiver_decision: result.decision,
    observation_state: result.receiver_observation.state,
    receiver_terminal: {
      decision: result.receiver_observation.terminal.decision.decision,
      authenticated: result.receiver_observation.terminal.decision.authenticated,
      record_count: result.receiver_observation.terminal.decision.semantics.record_count,
      redacted_record_count: result.receiver_observation.terminal.decision.semantics.redacted_record_count,
      retained_record_count: result.receiver_observation.terminal.decision.semantics.retained_record_count,
    },
    run_cleanup: result.cleanup.run,
    receiver_cleanup: result.cleanup.receiver,
    result_digest: baseline.result_digest,
  };
  assert.equal(report.baseline.scenario_id, savedSelection.scenario_id);
  assert.equal(report.baseline.receiver_terminal.authenticated, true);
  report.checks.push("native_execute_baseline_and_authenticated_receiver_terminal");

  stage = "owner-cleanup";
  await page.getByRole("button", { name: "Stop control test", exact: true }).click();
  await waitOwner((owner) => owner.status === "stopped", 30_000);
  assert.equal(latestOwner.phases[0].cleanup.receiver, "verified_closed");
  assert.equal(latestOwner.phases[0].cleanup.run, "complete");
  report.cleanup = { receiver_control_stopped: true, phase_receiver: latestOwner.phases[0].cleanup.receiver, phase_run: latestOwner.phases[0].cleanup.run };
  report.checks.push("receiver_owner_stopped_after_baseline_without_opening_later_phases");

  stage = "runner-cleanup";
  await page.goto(`${ORIGIN}/#/runners?profile=${encodeURIComponent(PROFILE)}`);
  await page.getByRole("button", { name: "Stop safely", exact: true }).waitFor({ state: "visible" });
  await page.getByRole("button", { name: "Stop safely", exact: true }).click();
  await page.waitForFunction(async ({ origin, profile }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, { headers: { "X-BlueFire-Session": token } });
    return response.ok && (await response.json()).state === "stopped";
  }, { origin: ORIGIN, profile: PROFILE }, { timeout: 45_000 });
  runnerStarted = false;
  report.cleanup.runner_stopped = true;
  report.checks.push("managed_runner_stopped_through_ui");

  const finalOwner = await appApi(`/receiver-defense/jobs/${receiverJobId}`);
  assert.equal(finalOwner.status, "stopped");
  assert.equal(finalOwner.phases[0].cleanup.receiver, "verified_closed");
  assert.equal(finalOwner.phases[0].cleanup.run, "complete");
  assert.equal(finalOwner.phases[1].status, "not_started");
  assert.equal(finalOwner.phases[2].status, "not_started");
  report.owner_status = finalOwner.status;
  report.request_counts = counts;
  assert.equal(report.blocked_requests.length, 0);
  assert.equal(report.errors.length, 0);
  assert.equal(counts.owner, 1);
  assert.equal(counts.save_scenario, 1);
  assert.equal(counts.prepare, 1);
  assert.equal(counts.review, 1);
  assert.equal(counts.approval, 1);
  assert.equal(counts.cancel, 1);
  assert.ok(runId);
  report.status = "passed";
} catch {
  report.errors.push({ stage, kind: "journey_failed" });
  report.request_counts = counts;
  if (receiverStarted) await stopOwnerNormally();
} finally {
  capability = "";
  if (runnerStarted) await stopRunnerNormally();
  await context?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "browser_context_close" }); });
  await browser?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "browser_close" }); });
  if (report.cleanup?.receiver_control_stopped === false || report.cleanup?.runner_stopped === false) {
    report.status = "failed_or_incomplete";
  }
  if (report.errors.length || report.blocked_requests.length) report.status = "failed_or_incomplete";
  writeFileSync(join(output, "installed-receiver-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}
