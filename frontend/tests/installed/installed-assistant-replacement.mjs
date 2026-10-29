/* global process, Buffer, fetch, sessionStorage, structuredClone, AbortSignal, URL, document, setTimeout */
// Copied outside the checkout. All API responses come from the installed service.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const [modulePath, output, portText, fixturePortText] = process.argv.slice(2);
assert.match(portText ?? "", /^\d{1,5}$/);
assert.match(fixturePortText ?? "", /^\d{1,5}$/);
const origin = `http://127.0.0.1:${portText}`;
const fixtureOrigin = `http://127.0.0.1:${fixturePortText}`;
const model = "bluefire-local-comparison-replacement-v1";
const providerId = "provider.installed-comparison-replacement.v1";
const scenarioId = "scenario.installed-comparison-replacement.v1";
const prompt = "Explain this saved synthetic comparison and its evidence limits.";
const report = {
  schema_version: "bluefire.installed-assistant-replacement.browser.v1",
  status: "failed_or_incomplete", installed_service: true,
  native_execution: false, live_model_inference: false,
  same_turn_continuation: false, same_run_inspection_retry: false,
  checks: [], blocked_requests: [], errors: [], observed_states: {}, screenshots: [],
};
const stable = value => Array.isArray(value) ? value.map(stable)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value;
const same = (left, right) => JSON.stringify(stable(left)) === JSON.stringify(stable(right));
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && same(Object.keys(value).sort(), [...keys].sort());
const sha = value => createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
const jobPattern = /^job-[0-9a-f]{32}$/;
const runPattern = /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const sessionPattern = /^[A-Za-z0-9_-]{64}$/;
const staticReadPaths = new Set(["/", "/ui/app.js", "/ui/styles.css", "/ui/fonts/InterVariable.woff2", "/favicon.ico"]);
const apiReadPaths = new Set([
  "/api/v1/session", "/api/v1/build-info", "/api/v1/catalog", "/api/v1/scenarios", "/api/v1/runs",
  "/api/v1/receiver-defense/jobs", "/api/v1/comparison-snapshots", "/api/v1/settings",
  "/api/v1/resources/model-providers", "/api/v1/ai/authorizations", "/api/v1/detections",
]);
const capabilityInput = createInterface({ input: process.stdin, crlfDelay: Infinity });
const commandLines = capabilityInput[Symbol.asyncIterator]();
async function nextCapability() {
  const next = await commandLines.next();
  assert.equal(next.done, false, "Supervisor closed before the fresh CLI session");
  assert.ok(next.value.length <= 256);
  const value = JSON.parse(next.value);
  assert.ok(exactKeys(value, ["capability"]));
  assert.match(value.capability, sessionPattern);
  return value.capability;
}
let browser, context, page, stage = "launch", scenario, payload, comparison, expectedContext;
let originalId, replacementId, firstSessionPosts = 0, secondSessionPosts = 0;
let runPreflightPosts = 0, runPosts = 0, comparisonPosts = 0;
let providerPosts = 0, activationPosts = 0, authorizationPosts = 0, turnPosts = 0;
let providerConfig, runIds = [], phaseOne, firstGrant, secondGrant, firstAuthorizationContext;
let recoveryPhaseWriteAttempts = 0;
let replacementSubstage, replacementObserved, replacementHttpStatus;
const setupJobIds = new Set();
const setupRunIds = new Set();
const turnJobIds = new Set();

function allowedRead(url, method) {
  if (url.username || url.password || url.search) return false;
  if (staticReadPaths.has(url.pathname)) return method === "GET" || method === "HEAD";
  if (method !== "GET") return false;
  if (apiReadPaths.has(url.pathname)) return true;
  const run = url.pathname.match(/^\/api\/v1\/runs\/(run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16})$/);
  if (run && setupRunIds.has(run[1])) return true;
  const job = url.pathname.match(/^\/api\/v1\/jobs\/(job-[0-9a-f]{32})$/);
  if (job && setupJobIds.has(job[1])) return true;
  const turn = url.pathname.match(/^\/api\/v1\/assistance\/turns\/(job-[0-9a-f]{32})$/);
  if (turn && turnJobIds.has(turn[1])) return true;
  const snapshot = url.pathname.match(/^\/api\/v1\/comparison-snapshots\/(run-comparison-[0-9a-f]{64})(\/assistant-context)?$/);
  return Boolean(snapshot && snapshot[1] === report.snapshot_id);
}

function allowedWrite(path, body, raw) {
  if (Buffer.byteLength(raw, "utf8") > 262144) return false;
  if (phaseOne && !["/api/v1/session", "/api/v1/ai/authorizations", "/api/v1/assistance/turns"].includes(path)) {
    recoveryPhaseWriteAttempts += 1;
    return false;
  }
  if (path === "/api/v1/session") {
    if (raw) return false;
    if (!phaseOne && firstSessionPosts++ === 0) return true;
    return Boolean(phaseOne && secondSessionPosts++ === 0);
  }
  if (path === "/api/v1/runs/preflight") {
    if (runPreflightPosts >= 2 || !same(body, payload)) return false;
    runPreflightPosts += 1; return true;
  }
  if (path === "/api/v1/runs") {
    if (runPosts >= 2 || !same(body, payload)) return false;
    runPosts += 1; return true;
  }
  if (path === "/api/v1/comparisons") {
    if (comparisonPosts || !exactKeys(body, ["run_ids"]) || !same(body.run_ids, runIds) || runIds.length !== 2) return false;
    comparisonPosts += 1; return true;
  }
  if (path === `/api/v1/resources/model-providers/${providerId}`) {
    const provider = body?.document;
    const allowed = !providerPosts && exactKeys(body, ["document", "status"]) && body.status === "draft"
      && exactKeys(provider, ["id", "kind", "model", "endpoint", "api_key", "timeout_seconds", "max_retries", "max_output_tokens", "redaction"])
      && provider.id === providerId && provider.kind === "openai_responses" && provider.model === model
      && provider.endpoint === `${fixtureOrigin}/v1/responses` && provider.api_key === null
      && provider.timeout_seconds === 30 && provider.max_retries === 0 && provider.max_output_tokens === 64
      && exactKeys(provider.redaction, ["enabled", "redact_keys", "max_string_chars", "include_evidence_content"])
      && provider.redaction.enabled === true && provider.redaction.include_evidence_content === false
      && Array.isArray(provider.redaction.redact_keys)
      && ["api_key", "authorization", "cookie", "credential", "password", "secret", "token"].every(key => provider.redaction.redact_keys.includes(key));
    if (allowed) { providerPosts += 1; providerConfig = structuredClone(provider); }
    return allowed;
  }
  if (path === `/api/v1/resources/model-providers/${providerId}/activate`) {
    if (activationPosts || !exactKeys(body, [])) return false;
    activationPosts += 1; return true;
  }
  if (path === "/api/v1/ai/authorizations") {
    const allowed = authorizationPosts === (phaseOne ? 1 : 0)
      && exactKeys(body, ["provider", "purposes", "data_scope", "limits", "expires_in_seconds", "approved_by", "usage_authorized", "local_endpoint_authorized"])
      && same(body.provider, providerConfig) && same(body.purposes, ["bluefire_experiment_assistance"])
      && body.data_scope === "reviewed_lab_context"
      && exactKeys(body.limits, ["max_requests", "max_request_bytes", "max_reserved_output_tokens"])
      && body.limits.max_requests === 1
      && body.limits?.max_request_bytes === 524288 && body.limits?.max_reserved_output_tokens === 64
      && body.expires_in_seconds === 300 && body.approved_by === "installed-comparison-replacement-reviewer"
      && body.usage_authorized === true && body.local_endpoint_authorized === true;
    if (allowed) authorizationPosts += 1;
    return allowed;
  }
  if (path === "/api/v1/assistance/turns") {
    const allowed = turnPosts < 2 && authorizationPosts === turnPosts + 1 && expectedContext
      && exactKeys(body, ["submission_id", "selection", "context_digest", "message", "autonomy", "provider_id"])
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id)
      && same(body.selection, expectedContext.selected) && body.context_digest === expectedContext.context_digest
      && body.message === prompt && body.autonomy === "assist" && body.provider_id === providerId
      && (!phaseOne || body.submission_id.replaceAll("-", "") !== originalId?.slice(4));
    if (allowed) {
      turnPosts += 1;
      turnJobIds.add(`job-${body.submission_id.replaceAll("-", "")}`);
    }
    return allowed;
  }
  return false;
}

async function api(path, body) {
  return page.evaluate(async ({ path, body }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!token) throw new Error("Installed browser session is missing");
    const response = await fetch(`/api/v1${path}`, {
      method: body === undefined ? "GET" : "POST", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": token, Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw new Error(`Installed API ${response.status}`);
    return response.json();
  }, { path, body });
}

async function fixtureState() {
  const response = await fetch(`${fixtureOrigin}/__fixture/state`, { signal: AbortSignal.timeout(5000) });
  assert.equal(response.status, 200);
  return response.json();
}

async function captureAssistantView(name) {
  assert.match(new URL(page.url()).hash, /^#\/compare\?/, "Capture must stay on the saved comparison view");
  assert.deepEqual(page.viewportSize(), { width: 1440, height: 900 });
  await page.evaluate(async () => {
    await Promise.race([
      document.fonts.ready,
      new Promise((_, reject) => setTimeout(() => reject(new Error("Fonts did not settle")), 2000)),
    ]);
  });
  const screenshot = await page.screenshot({
    fullPage: false, animations: "disabled",
    mask: [page.locator('input[type="password"]'), page.getByLabel("One-time connection code", { exact: false })],
  });
  assert.ok(screenshot.byteLength > 0 && screenshot.byteLength <= 4 * 1024 * 1024);
  assert.equal(screenshot.subarray(0, 8).toString("hex"), "89504e470d0a1a0a"); // pragma: allowlist secret - Public PNG signature.
  assert.equal(screenshot.readUInt32BE(16), 1440);
  assert.equal(screenshot.readUInt32BE(20), 900);
  const file = `${name}-1440x900.png`;
  writeFileSync(join(output, file), screenshot, { flag: "wx", mode: 0o600 });
  report.screenshots.push({ file, sha256: createHash("sha256").update(screenshot).digest("hex"), bytes: screenshot.byteLength });
}

async function poll(fn, wanted, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await fn();
    if (wanted(value)) return value;
    await new Promise(resolve => setTimeout(resolve, 120));
  }
  throw new Error("Bounded installed state did not arrive");
}

async function connect(capability) {
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.waitForFunction(() => /^[A-Za-z0-9_-]{64}$/.test(sessionStorage.getItem("bluefire.browser-session.v1") ?? ""));
}

async function createComparison() {
  const catalog = await api("/scenarios");
  const source = catalog.scenarios?.find(item => item.id === "scenario.endpoint.lab-collection-methods.v1");
  assert.ok(source?.steps?.length > 0);
  scenario = { ...source, id: scenarioId, title: "Synthetic comparison restart fixture",
    purpose: "Compare two generated simulations for restart explanation review." };
  payload = { scenario, layout: { schema_version: "bluefire.layout.v1", nodes: [] },
    mode: "simulate", autonomy: "off", ai_provider_id: "deterministic-offline.v1",
    runner_profile_id: "sandbox-simulate.v1", target_scope: { scope_refs: ["sandbox.workspace"] } };
  for (let index = 0; index < 2; index += 1) {
    const preflight = await api("/runs/preflight", payload);
    assert.equal(preflight.ready, true);
    assert.equal(preflight.plan?.mode, "simulate");
    const submitted = await api("/runs", payload);
    assert.match(submitted.job?.job_id ?? "", jobPattern);
    setupJobIds.add(submitted.job.job_id);
    const settled = await poll(() => api(`/jobs/${submitted.job.job_id}`), value => ["completed", "failed", "interrupted"].includes(value.state), 90000);
    assert.equal(settled.state, "completed");
    assert.match(settled.result_ref ?? "", runPattern);
    setupRunIds.add(settled.result_ref);
    const run = await api(`/runs/${settled.result_ref}`);
    assert.equal(run.mode, "simulate");
    assert.equal(run.scenario_id, scenarioId);
    runIds.push(run.run_id);
  }
  assert.notEqual(runIds[0], runIds[1]);
  comparison = await api("/comparisons", { run_ids: runIds });
  assert.deepEqual(comparison.run_ids, runIds);
  assert.deepEqual(comparison.summaries?.map(item => item.run_id), runIds);
  assert.match(comparison.saved_snapshot?.snapshot_id ?? "", /^run-comparison-[0-9a-f]{64}$/);
  report.snapshot_id = comparison.saved_snapshot.snapshot_id;
  const saved = await api(`/comparison-snapshots/${report.snapshot_id}`);
  assert.equal(saved.snapshot_id, report.snapshot_id);
  assert.match(saved.digest, digestPattern);
  assert.deepEqual(saved.comparison.run_ids, runIds);
  assert.equal(saved.source_integrity?.status, "verified");
  report.snapshot_digest = saved.digest;
  report.run_ids = [...runIds];
  report.saved_snapshot_hash = sha(saved);
  report.checks.push("two_real_service_synthetic_simulations_and_immutable_comparison");
}

async function authorizeProvider() {
  await page.goto(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Model connection", exact: true }).waitFor();
  await page.locator("label.field").filter({ has: page.locator(".field-label").getByText("API style", { exact: true }) }).locator("select").selectOption("openai_responses");
  await page.getByLabel("Model ID", { exact: false }).fill(model);
  await page.getByLabel("Request endpoint", { exact: false }).fill(`${fixtureOrigin}/v1/responses`);
  await page.getByLabel("Secret environment reference", { exact: false }).fill("");
  await page.locator("details.provider-request-limits > summary").click();
  await page.getByLabel("Timeout seconds", { exact: true }).fill("30");
  await page.getByLabel("Output token limit", { exact: false }).fill("64");
  await page.getByLabel("Transport retries", { exact: true }).fill("0");
  await page.locator(".provider-connection-fields > details.provider-field-wide:not(.provider-request-limits) > summary").click();
  await page.getByLabel("Provider ID", { exact: false }).fill(providerId);
  await page.getByRole("button", { name: "Save secret-free draft", exact: true }).click();
  await page.getByText(`Responses API · ${model} saved. Activation and model usage authorization remain separate.`, { exact: true }).waitFor();
  firstGrant = await authorizeUsage();
  assert.equal(providerPosts, 1); assert.equal(activationPosts, 1); assert.equal(authorizationPosts, 1);
  report.checks.push("labeled_loopback_provider_authorized_for_one_bounded_explanation");
}

async function authorizeUsage() {
  await page.getByRole("checkbox", { name: "Plan work in the Assistant", exact: true }).check();
  await page.getByLabel("Total request attempts", { exact: false }).fill("1");
  await page.getByLabel("Total request bytes", { exact: false }).fill("524288");
  await page.getByLabel("Total reserved output tokens", { exact: false }).fill("64");
  await page.getByLabel("Authorization duration in seconds", { exact: false }).fill("300");
  await page.getByLabel("Operator identity for model usage", { exact: true }).fill("installed-comparison-replacement-reviewer");
  await page.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint.", exact: true }).check();
  await page.getByRole("checkbox", { name: "I authorize the selected model work, reviewed lab data and these usage limits.", exact: true }).check();
  const response = page.waitForResponse(value => new URL(value.url()).pathname === "/api/v1/ai/authorizations" && value.request().method() === "POST");
  await page.getByRole("button", { name: "Authorize reviewed model usage", exact: true }).click();
  const saved = await response;
  assert.equal(saved.status(), 200);
  const grant = (await saved.json()).authorization;
  assert.match(grant?.authorization_id ?? "", /^ai-authorization-[0-9a-f]{32}$/);
  assert.equal(grant.status, "active");
  assert.equal(grant.limits.max_requests, 1);
  assert.equal(grant.limits.max_request_bytes, 524288);
  assert.equal(grant.limits.max_reserved_output_tokens, 64);
  assert.equal(grant.usage.requests, 0);
  assert.ok(grant.expires_at_ms > Date.now() && grant.expires_at_ms <= Date.now() + 300000);
  await page.getByText("Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.", { exact: true }).waitFor();
  return grant;
}

async function reauthorizeSavedProvider() {
  await page.goto(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Model connection", exact: true }).waitFor();
  const saved = page.locator(".provider-saved-connections article").filter({ hasText: model });
  await saved.waitFor({ state: "visible" });
  assert.equal(await saved.count(), 1);
  await saved.getByRole("button", { name: /^Edit / }).click();
  assert.equal(await page.getByLabel("Model ID", { exact: false }).inputValue(), model);
  assert.equal(await page.getByLabel("Request endpoint", { exact: false }).inputValue(), `${fixtureOrigin}/v1/responses`);
  secondGrant = await authorizeUsage();
  assert.notEqual(secondGrant.authorization_id, firstGrant.authorization_id);
  assert.equal(authorizationPosts, 2);
  assert.equal(providerPosts, 1); assert.equal(activationPosts, 1);
  report.checks.push("new_service_session_required_fresh_normal_settings_authorization");
}

async function openComparisonAndAssistant() {
  await page.goto(`${origin}/#/compare?snapshot=${encodeURIComponent(report.snapshot_id)}`, { waitUntil: "domcontentloaded" });
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  await page.getByRole("button", { name: "Explain comparison", exact: true }).click();
  const panel = page.locator("#experiment-assistant");
  await panel.waitFor({ state: "visible" });
  expectedContext = await api(`/comparison-snapshots/${report.snapshot_id}/assistant-context`);
  assert.equal(expectedContext.analysis_only, true);
  assert.deepEqual(expectedContext.capabilities, []);
  assert.deepEqual(expectedContext.selected, { kind: "comparison_snapshot", snapshot_id: report.snapshot_id, snapshot_digest: report.snapshot_digest });
  assert.match(expectedContext.context_digest, digestPattern);
  return panel;
}

async function selectAssistantProvider(panel) {
  await panel.getByRole("button", { name: "Assistant settings", exact: true }).click();
  await panel.getByRole("combobox", { name: /^(AI mode|Assistant mode)\b/ }).selectOption("assist");
  await panel.getByRole("combobox", { name: "Provider", exact: true }).selectOption(providerId);
  await panel.getByRole("button", { name: "Assistant settings", exact: true }).click();
}

function replacementFailureDiagnostic(substage, observed, httpStatus, error) {
  const stages = new Set([
    "provider_selection", "submission_fill", "submission_click", "submission_response",
    "submission_status", "submission_body", "submission_identity", "request_identity",
    "terminal_poll", "terminal_job", "terminal_turn", "completion_heading",
    "empty_plan", "empty_results", "provider_count", "retained_records",
    "authorization_usage", "capture", "write_counts",
  ]);
  const jobs = new Set(["queued", "awaiting_approval", "running", "cancelling", "cancelled", "completed", "failed", "interrupted"]);
  const turns = new Set(["planning", "working", "off", "awaiting_review", "awaiting_execute_approval", "ready_to_continue", "cancelling", "cancelled", "blocked", "completed"]);
  const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
  const arrayShape = value => value === undefined ? "missing"
    : Array.isArray(value) ? value.length === 0 ? "empty" : "nonempty" : "invalid";
  const job = object(observed) && object(observed.job) ? observed.job : null;
  const turn = object(observed) && object(observed.turn) ? observed.turn : null;
  return {
    substage: stages.has(substage) ? substage : "unknown",
    error_category: error?.name === "AssertionError" ? "assertion"
      : error?.name === "TimeoutError" ? "timeout"
      : error?.name === "TypeError" ? "type" : error?.name === "SyntaxError" ? "json" : "other",
    submission_status: httpStatus === undefined ? "unobserved" : httpStatus === 202 ? "accepted"
      : Number.isInteger(httpStatus) && httpStatus >= 400 && httpStatus <= 499 ? "client_error"
      : Number.isInteger(httpStatus) && httpStatus >= 500 && httpStatus <= 599 ? "server_error" : "other",
    job_state: jobs.has(job?.state) ? job.state : "unknown",
    turn_status: turns.has(turn?.status) ? turn.status : "unknown",
    job_error_shape: job === null ? "missing" : job.error == null ? "absent" : object(job.error) ? "object" : "invalid",
    result_ref_shape: job === null ? "missing" : job.result_ref == null ? "absent" : typeof job.result_ref === "string" ? "string" : "invalid",
    plan_shape: arrayShape(turn?.plan),
    results_shape: arrayShape(turn?.results),
  };
}

async function submitThroughUi(panel, observe = () => {}) {
  const response = page.waitForResponse(item => new URL(item.url()).pathname === "/api/v1/assistance/turns" && item.request().method() === "POST");
  observe("submission_fill");
  await panel.getByRole("textbox", { name: "What would you like to do?", exact: true }).fill(prompt);
  observe("submission_click");
  await panel.getByRole("button", { name: "Start work", exact: true }).click();
  observe("submission_response");
  const value = await response;
  observe("submission_status", value.status());
  assert.equal(value.status(), 202);
  observe("submission_body");
  const submitted = JSON.parse(value.request().postData());
  const envelope = await value.json();
  observe("submission_identity", undefined, envelope);
  assert.match(envelope.job?.job_id ?? "", jobPattern);
  return { jobId: envelope.job.job_id, submitted };
}

try {
  const firstCapability = await nextCapability();
  const { chromium } = await import(pathToFileURL(modulePath).href);
  browser = await chromium.launch({ headless: true, args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"] });
  context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 } });
  context.setDefaultTimeout(20000);
  await context.routeWebSocket("**/*", socket => socket.close());
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    let allowed = url.origin === origin && ["GET", "HEAD"].includes(method), reason;
    if (url.origin !== origin) reason = "outside_service_origin";
    else if (url.username || url.password) { allowed = false; reason = "url_credentials_not_allowlisted"; }
    else if (["GET", "HEAD"].includes(method) && !allowedRead(url, method)) { allowed = false; reason = "read_not_allowlisted"; }
    else if (method === "POST") {
      let body;
      try { body = request.postData() ? request.postDataJSON() : null; } catch { reason = "invalid_json"; }
      if (!reason) allowed = allowedWrite(url.pathname, body, request.postData() ?? "");
      if (!allowed) reason ??= "write_not_allowlisted";
    } else if (!["GET", "HEAD"].includes(method)) reason = "method_not_allowlisted";
    if (url.search && url.pathname.startsWith("/api/")) { allowed = false; reason = "api_query_not_allowlisted"; }
    if (!allowed) {
      report.blocked_requests.push({ method, path: url.origin === origin ? url.pathname : "outside_service_origin", reason });
      await route.abort();
    } else await route.continue();
  });
  page = await context.newPage();
  stage = "first-session";
  await connect(firstCapability);
  stage = "synthetic-comparison";
  await createComparison();
  stage = "provider-authorization";
  await authorizeProvider();
  stage = "first-explanation";
  const panel = await openComparisonAndAssistant();
  await selectAssistantProvider(panel);
  const first = await submitThroughUi(panel);
  originalId = first.jobId;
  const held = await poll(fixtureState, value => value.request_count === 1 || value.failed, 25000);
  assert.equal(held.failed, false);
  assert.equal(held.first_held, true);
  const original = await api(`/assistance/turns/${originalId}`);
  assert.equal(original.job.job_id, originalId);
  assert.equal(original.job.request.submitted_request.message, prompt);
  assert.equal(original.job.request.submitted_request.context_digest, expectedContext.context_digest);
  assert.deepEqual(original.turn.plan, []);
  report.observed_states.original_before_loss = {
    job: ["queued", "running"].includes(original.job.state) ? original.job.state : "other",
    turn: ["working", "off"].includes(original.turn.status) ? original.turn.status : "other",
  };
  const firstAuthorizations = await api("/ai/authorizations");
  firstAuthorizationContext = firstAuthorizations.context.binding_digest;
  const firstUsed = firstAuthorizations.authorizations.find(item => item.authorization_id === firstGrant.authorization_id);
  assert.equal(firstUsed.status, "active");
  assert.equal(firstUsed.usage.requests, 1);
  assert.equal(firstUsed.usage.reserved_output_tokens, 64);
  assert.ok(firstUsed.usage.request_bytes > 0 && firstUsed.usage.request_bytes <= 262144);
  assert.equal(firstUsed.limits.max_requests - firstUsed.usage.requests, 0);
  assert.equal(firstUsed.limits.max_request_bytes, 524288);
  assert.equal(firstUsed.limits.max_reserved_output_tokens - firstUsed.usage.reserved_output_tokens, 0);
  assert.ok(firstUsed.expires_at_ms > Date.now());
  phaseOne = {
    schema_version: "bluefire.assistant-replacement.phase-one.v1",
    snapshot_id: report.snapshot_id, snapshot_digest: report.snapshot_digest,
    run_ids: [...runIds], original_job_id: originalId,
    context_digest: expectedContext.context_digest,
    original_request_digest: sha(original.job.request.submitted_request),
    first_authorization: { authorization_id: firstUsed.authorization_id,
      expires_at_ms: firstUsed.expires_at_ms, requests: firstUsed.usage.requests,
      request_bytes: firstUsed.usage.request_bytes, reserved_output_tokens: firstUsed.usage.reserved_output_tokens,
      remaining_requests: 0, remaining_request_bytes: 524288 - firstUsed.usage.request_bytes,
      remaining_reserved_output_tokens: 0 },
  };
  writeFileSync(join(output, "phase-one.json"), `${JSON.stringify(phaseOne, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  report.checks.push("original_comparison_request_and_first_model_call_retained_before_process_loss");

  stage = "wait-for-restarted-cli";
  const secondCapability = await nextCapability();
  stage = "fresh-session";
  await connect(secondCapability);
  const afterRestartFixture = await fixtureState();
  assert.equal(afterRestartFixture.request_count, 1, "No provider request may replay on restart");
  const unavailable = await api("/ai/authorizations");
  assert.notEqual(unavailable.context.binding_digest, firstAuthorizationContext);
  const oldGrant = unavailable.authorizations.find(item => item.authorization_id === firstGrant.authorization_id);
  assert.equal(oldGrant.status, "context_unavailable");
  assert.equal(oldGrant.usage.requests, phaseOne.first_authorization.requests);
  assert.equal(oldGrant.usage.request_bytes, phaseOne.first_authorization.request_bytes);
  assert.equal(oldGrant.usage.reserved_output_tokens, phaseOne.first_authorization.reserved_output_tokens);
  assert.equal(oldGrant.expires_at_ms, phaseOne.first_authorization.expires_at_ms);
  assert.equal(unavailable.authorizations.filter(item => item.status === "active").length, 0);
  const originalAfter = await api(`/assistance/turns/${originalId}`);
  assert.equal(originalAfter.job.state, "interrupted");
  assert.equal(originalAfter.turn.status, "blocked");
  assert.equal(originalAfter.turn.next_action?.kind, "new_turn");
  report.observed_states.original_after_restart = { job: "interrupted", turn: "blocked" };
  assert.deepEqual(originalAfter.turn.plan, []);
  assert.equal(sha(originalAfter.job.request.submitted_request), phaseOne.original_request_digest);
  assert.equal(originalAfter.job.request.submitted_request.context_digest, phaseOne.context_digest);
  const snapshotAfter = await api(`/comparison-snapshots/${phaseOne.snapshot_id}`);
  assert.equal(sha(snapshotAfter), report.saved_snapshot_hash);
  assert.deepEqual(snapshotAfter.comparison.run_ids, phaseOne.run_ids);
  const runsAfter = await api("/runs");
  assert.deepEqual(runsAfter.runs?.map(item => item.run_id).sort(), [...runIds].sort());
  stage = "visible-blocked-original";
  const reopenedPanel = await openComparisonAndAssistant();
  await reopenedPanel.getByText("Start a new turn", { exact: false }).waitFor();
  await reopenedPanel.getByRole("heading", { name: "Work needs attention", exact: true }).waitFor();
  assert.equal(await reopenedPanel.getByRole("button", { name: /^(Recover next step|Recover retained operation|Resume saved turn|Continue saved work)$/ }).count(), 0);
  assert.equal((await fixtureState()).request_count, 1);
  await captureAssistantView("assistant-blocked-original");
  report.checks.push("restart_kept_original_blocked_without_provider_replay_or_continue_action");
  stage = "fresh-normal-authorization";
  await reauthorizeSavedProvider();
  const renewed = await api("/ai/authorizations");
  const newGrant = renewed.authorizations.find(item => item.authorization_id === secondGrant.authorization_id);
  assert.equal(newGrant.status, "active");
  assert.equal(newGrant.usage.requests, 0);
  assert.equal(newGrant.limits.max_requests, 1);
  assert.equal(newGrant.limits.max_reserved_output_tokens, 64);
  assert.ok(newGrant.expires_at_ms > Date.now());
  assert.equal((await fixtureState()).request_count, 1);
  const replacementPanel = await openComparisonAndAssistant();
  await replacementPanel.getByRole("button", { name: "Start another request", exact: true }).click();
  await replacementPanel.getByRole("textbox", { name: "What would you like to do?", exact: true }).waitFor();
  stage = "explicit-replacement";
  replacementSubstage = "provider_selection";
  await selectAssistantProvider(replacementPanel);
  const replacement = await submitThroughUi(replacementPanel, (substage, httpStatus, observed) => {
    replacementSubstage = substage;
    if (httpStatus !== undefined) replacementHttpStatus = httpStatus;
    if (observed !== undefined) replacementObserved = observed;
  });
  replacementId = replacement.jobId;
  replacementSubstage = "request_identity";
  assert.notEqual(replacementId, originalId);
  assert.equal(replacement.submitted.context_digest, phaseOne.context_digest);
  assert.equal(replacement.submitted.message, prompt);
  replacementSubstage = "terminal_poll";
  const completed = await poll(async () => {
    const value = await api(`/assistance/turns/${replacementId}`);
    replacementObserved = value;
    return value;
  }, value => ["completed", "blocked"].includes(value.turn?.status), 30000);
  replacementSubstage = "terminal_job";
  assert.equal(completed.job.state, "completed");
  replacementSubstage = "terminal_turn";
  assert.equal(completed.turn.status, "completed");
  replacementSubstage = "completion_heading";
  await replacementPanel.getByRole("heading", { name: "Work completed", exact: true }).waitFor();
  report.observed_states.replacement = { job: "completed", turn: "completed" };
  replacementSubstage = "empty_plan";
  assert.deepEqual(completed.turn.plan, []);
  replacementSubstage = "empty_results";
  assert.deepEqual(completed.turn.results, []);
  replacementSubstage = "provider_count";
  assert.equal((await fixtureState()).request_count, 2);
  replacementSubstage = "retained_records";
  const originalFinal = await api(`/assistance/turns/${originalId}`);
  assert.equal(originalFinal.job.state, "interrupted");
  assert.equal(originalFinal.turn.status, "blocked");
  assert.equal(sha(originalFinal.job.request.submitted_request), phaseOne.original_request_digest);
  assert.equal(sha(await api(`/comparison-snapshots/${phaseOne.snapshot_id}`)), report.saved_snapshot_hash);
  assert.deepEqual((await api("/runs")).runs?.map(item => item.run_id).sort(), [...runIds].sort());
  replacementSubstage = "authorization_usage";
  const finalGrants = await api("/ai/authorizations");
  const secondUsed = finalGrants.authorizations.find(item => item.authorization_id === secondGrant.authorization_id);
  assert.equal(secondUsed.status, "active");
  assert.equal(secondUsed.usage.requests, 1);
  assert.ok(secondUsed.usage.request_bytes > 0 && secondUsed.usage.request_bytes <= 262144);
  assert.equal(secondUsed.usage.reserved_output_tokens, 64);
  assert.equal(secondUsed.limits.max_requests - secondUsed.usage.requests, 0);
  assert.equal(secondUsed.limits.max_reserved_output_tokens - secondUsed.usage.reserved_output_tokens, 0);
  replacementSubstage = "capture";
  await captureAssistantView("assistant-completed-replacement");
  replacementSubstage = "write_counts";
  assert.equal(runPreflightPosts, 2); assert.equal(runPosts, 2); assert.equal(comparisonPosts, 1);
  assert.equal(turnPosts, 2); assert.equal(firstSessionPosts, 1); assert.equal(secondSessionPosts, 1);
  assert.equal(recoveryPhaseWriteAttempts, 0);
  assert.deepEqual(report.blocked_requests, []);
  report.phase_one = phaseOne;
  report.original = { job_id: originalId, state: originalFinal.job.state, status: originalFinal.turn.status };
  report.replacement = { job_id: replacementId, state: completed.job.state, status: completed.turn.status };
  report.authorization = { prior: { ...phaseOne.first_authorization, status_after_restart: oldGrant.status },
    replacement: { authorization_id: secondUsed.authorization_id, expires_at_ms: secondUsed.expires_at_ms,
      requests: secondUsed.usage.requests, request_bytes: secondUsed.usage.request_bytes,
      reserved_output_tokens: secondUsed.usage.reserved_output_tokens,
      remaining_requests: 0, remaining_request_bytes: 524288 - secondUsed.usage.request_bytes,
      remaining_reserved_output_tokens: 0 } };
  report.provider_request_count = 2;
  report.write_counts = { setup: { run_preflight: runPreflightPosts, run: runPosts, comparison: comparisonPosts,
    provider_save: providerPosts, provider_activate: activationPosts, authorization: 1,
    assistant_turn: 1, session: firstSessionPosts },
  recovery: { authorization: authorizationPosts - 1, assistant_turn: turnPosts - 1,
    session: secondSessionPosts, other_attempts: recoveryPhaseWriteAttempts } };
  report.checks.push("visible_explicit_new_request_created_distinct_completed_explanation");
  report.checks.push("snapshot_run_order_and_request_context_remained_unchanged_without_effectful_writes");
  report.status = "passed";
} catch (error) {
  report.errors.push({ stage, kind: "journey_failed" });
  if (stage === "explicit-replacement") {
    report.replacement_diagnostic = replacementFailureDiagnostic(
      replacementSubstage, replacementObserved, replacementHttpStatus, error,
    );
  }
  process.exitCode = 1;
} finally {
  capabilityInput.close();
  report.attempted_writes = {
    first_session: firstSessionPosts, second_session: secondSessionPosts,
    run_preflight: runPreflightPosts, run: runPosts, comparison: comparisonPosts,
    provider_save: providerPosts, provider_activate: activationPosts,
    authorization: authorizationPosts, assistant_turn: turnPosts,
    recovery_other_denied: recoveryPhaseWriteAttempts,
  };
  await context?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "context_close" }); process.exitCode = 1; });
  await browser?.close().catch(() => { report.errors.push({ stage: "cleanup", kind: "browser_close" }); process.exitCode = 1; });
  if (report.errors.length || report.blocked_requests.length || process.exitCode) report.status = "failed_or_incomplete";
  const raw = `${JSON.stringify(report, null, 2)}\n`;
  assert.ok(Buffer.byteLength(raw) <= 1024 * 1024);
  writeFileSync(join(output, "browser-report.json"), raw, { flag: "wx", mode: 0o600 });
}
