/* global process, URL, sessionStorage, fetch, setTimeout, structuredClone */
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [modulePath, output, port, fixturePort] = process.argv.slice(2);
const model = "bluefire-local-cancel-fixture-v1";
const providerId = "provider.installed-cancel-fixture.v1";
const purposes = ["bluefire_experiment_assistance"];
const report = {
  schema_version: "bluefire.installed-assistant-cancellation.v1",
  status: "failed_or_incomplete",
  installed_service: true,
  local_fixture_only: true,
  live_model_inference: false,
  native_execution: false,
  checks: [],
  blocked_requests: [],
};
let capability = "", origin, fixtureOrigin, chromium, browser, context, page, providerConfig;
let stage = "bootstrap";
let sessionPosts = 0, providerPosts = 0, activationPosts = 0, authorizationPosts = 0;
let graphContextPosts = 0, graphContextGets = 0, assistancePosts = 0, cancelPosts = 0;
let expectedContext, parentJobId, postedGraphSelection;
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const stableValue = value => Array.isArray(value) ? value.map(stableValue)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
    : value;
const same = (left, right) => JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
const validDigest = value => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);

async function api(path) {
  return page.evaluate(async path => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!token) throw new Error("Session missing");
    const response = await fetch(`/api/v1${path}`, {
      method: "GET", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": token, Accept: "application/json" },
    });
    if (!response.ok) throw new Error("Installed API request failed");
    return response.json();
  }, path);
}

async function fixtureState() {
  const response = await fetch(`${fixtureOrigin}/__fixture/state`, { redirect: "error" });
  assert.equal(response.status, 200);
  return response.json();
}

async function waitForCancelled(timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const envelope = await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`);
    const job = envelope?.job;
    const turn = envelope?.turn;
    if (job?.state === "cancelled" && turn?.status === "cancelled") return envelope;
    if (["failed", "completed", "interrupted"].includes(job?.state)) {
      throw new Error("Assistant operation reached an unexpected terminal state");
    }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  throw new Error("Assistant cancellation did not settle before the deadline");
}

async function main() {
  assert.match(port ?? "", /^\d{1,5}$/);
  assert.match(fixturePort ?? "", /^\d{1,5}$/);
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
    assert.ok(input.length <= 256);
  }
  ({ capability } = JSON.parse(input));
  input = "";
  assert.match(capability ?? "", /^[A-Za-z0-9_-]{64}$/);
  ({ chromium } = await import(pathToFileURL(modulePath).href));
  origin = `http://127.0.0.1:${port}`;
  fixtureOrigin = `http://127.0.0.1:${fixturePort}`;
  browser = await chromium.launch({ headless: true, args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"] });
  context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 } });
  context.setDefaultTimeout(20_000);
  await context.routeWebSocket("**/*", socket => socket.close());
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    let allowed = url.origin === origin && ["GET", "HEAD"].includes(method), reason;
    if (url.origin !== origin) reason = "non_loopback";
    else if (!["GET", "HEAD", "POST"].includes(method)) reason = "method_not_allowed";
    else if (method === "GET" && url.pathname === "/api/v1/assistance/graph-context") {
      allowed = graphContextGets === 0 && url.search === "";
      if (allowed) graphContextGets += 1; else reason = "graph_context_get_scope";
    } else if (method === "POST") {
      let body;
      try { body = request.postData() ? request.postDataJSON() : null; }
      catch { reason = "invalid_json"; }
      if (!reason) {
        allowed = false;
        if (url.pathname === "/api/v1/session") {
          allowed = sessionPosts === 0 && !request.postData();
          if (allowed) sessionPosts += 1; else reason = "session_scope";
        } else if (url.pathname === `/api/v1/resources/model-providers/${providerId}`) {
          const provider = body?.document;
          allowed = providerPosts === 0 && exactKeys(body, ["document", "status"]) && body.status === "draft"
            && exactKeys(provider, ["id", "kind", "model", "endpoint", "api_key", "timeout_seconds", "max_retries", "max_output_tokens", "redaction"])
            && provider.id === providerId && provider.kind === "openai_responses" && provider.model === model
            && provider.endpoint === `${fixtureOrigin}/v1/responses` && provider.api_key === null
            && provider.timeout_seconds === 30 && provider.max_retries === 0 && provider.max_output_tokens === 64
            && exactKeys(provider.redaction, ["enabled", "redact_keys", "max_string_chars", "include_evidence_content"])
            && provider.redaction.enabled === true && provider.redaction.include_evidence_content === false
            && ["api_key", "authorization", "cookie", "credential", "password", "secret", "token"].every(key => provider.redaction.redact_keys.includes(key));
          if (allowed) { providerPosts += 1; providerConfig = structuredClone(provider); } else reason = "provider_scope";
        } else if (url.pathname === `/api/v1/resources/model-providers/${providerId}/activate`) {
          allowed = activationPosts === 0 && exactKeys(body, []);
          if (allowed) activationPosts += 1; else reason = "activation_scope";
        } else if (url.pathname === "/api/v1/ai/authorizations") {
          allowed = authorizationPosts === 0 && exactKeys(body, ["provider", "purposes", "data_scope", "limits", "expires_in_seconds", "approved_by", "usage_authorized", "local_endpoint_authorized"])
            && same(body.provider, providerConfig) && Array.isArray(body.purposes) && same([...body.purposes].sort(), [...purposes].sort())
            && body.data_scope === "reviewed_lab_context" && body.limits?.max_requests === 1
            && body.limits?.max_request_bytes === 1_048_576 && body.limits?.max_reserved_output_tokens === 64
            && body.expires_in_seconds === 300 && body.approved_by === "installed-cancel-fixture-reviewer"
            && body.usage_authorized === true && body.local_endpoint_authorized === true;
          if (allowed) authorizationPosts += 1; else reason = "authorization_scope";
        } else if (url.pathname === "/api/v1/assistance/graph-context") {
          const keys = body && typeof body === "object" && !Array.isArray(body) ? Object.keys(body) : [];
          const selectionShape = exactKeys(body, ["kind", "base_scenario"])
            || exactKeys(body, ["kind", "base_scenario", "edit_step"]);
          const editStep = body?.edit_step;
          const editStepValid = editStep === undefined || (
            exactKeys(editStep, ["scenario", "step_id", "dirty"])
            && editStep.scenario && typeof editStep.scenario === "object" && !Array.isArray(editStep.scenario)
            && typeof editStep.step_id === "string" && editStep.step_id.length > 0 && editStep.step_id.length <= 200
            && typeof editStep.dirty === "boolean"
          );
          const bodySize = request.postDataBuffer()?.byteLength ?? 0;
          allowed = graphContextPosts === 0 && method === "POST" && selectionShape && body.kind === "graph"
            && body.base_scenario === null && editStepValid && bodySize > 0 && bodySize <= 1_048_576
            && keys.every(key => ["kind", "base_scenario", "edit_step"].includes(key));
          if (allowed) {
            graphContextPosts += 1;
            postedGraphSelection = structuredClone(body);
          } else reason = "graph_context_scope";
        } else if (url.pathname === "/api/v1/assistance/turns") {
          allowed = assistancePosts === 0 && expectedContext && exactKeys(body, ["submission_id", "selection", "context_digest", "message", "autonomy", "provider_id"])
            && /^[0-9a-f-]{36}$/.test(body.submission_id) && validDigest(body.context_digest)
            && body.context_digest === expectedContext.context_digest && same(body.selection, expectedContext.selected)
            && body.message === "Cancel the held local fixture request for recovery verification."
            && body.autonomy === "assist" && body.provider_id === providerId;
          if (allowed) assistancePosts += 1; else reason = "assistant_submit_scope";
        } else {
          const cancelPath = url.pathname.match(/^\/api\/v1\/jobs\/(job-[0-9a-f]{32})\/cancel$/);
          if (cancelPath && cancelPath[1] === parentJobId) {
            allowed = cancelPosts === 0 && exactKeys(body, []);
            if (allowed) cancelPosts += 1; else reason = "cancel_scope";
          } else reason = "write_not_allowlisted";
        }
      }
    }
    if (!allowed) {
      const blocked = { method, path: url.origin === origin ? url.pathname.replace(/job-[0-9a-f]{32}/g, "{job-id}") : "non-loopback", reason: reason ?? "request_not_allowed" };
      report.blocked_requests.push(blocked);
      await route.abort();
      return;
    }
    await route.continue();
  });

  page = await context.newPage();
  stage = "bootstrap-session";
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  capability = "";
  await page.waitForFunction(() => sessionStorage.getItem("bluefire.browser-session.v1") !== null);
  report.checks.push("ephemeral_browser_session_connected");

  stage = "normal-provider-authorization";
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
  await page.getByRole("checkbox", { name: "Plan work in the Assistant", exact: true }).check();
  await page.getByLabel("Total request attempts", { exact: false }).fill("1");
  await page.getByLabel("Total request bytes", { exact: false }).fill("1048576");
  await page.getByLabel("Total reserved output tokens", { exact: false }).fill("64");
  await page.getByLabel("Authorization duration in seconds", { exact: false }).fill("300");
  await page.getByLabel("Operator identity for model usage", { exact: true }).fill("installed-cancel-fixture-reviewer");
  await page.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint.", exact: true }).check();
  await page.getByRole("checkbox", { name: "I authorize the selected model work, reviewed lab data and these usage limits.", exact: true }).check();
  await page.getByRole("button", { name: "Authorize reviewed model usage", exact: true }).click();
  await page.getByText("Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.", { exact: true }).waitFor();
  assert.equal(providerPosts, 1); assert.equal(activationPosts, 1); assert.equal(authorizationPosts, 1);
  report.checks.push("provider_activation_and_one_request_usage_authorized_in_ui");

  stage = "normal-assistant-submit";
  const contextRead = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/graph-context" && response.request().method() === "POST");
  await page.goto(`${origin}/#/builder`, { waitUntil: "domcontentloaded" });
  const assistant = page.locator("#experiment-assistant");
  if (!(await assistant.isVisible())) await page.getByRole("button", { name: /^Assistant(?::|$)/ }).click();
  await assistant.waitFor({ state: "visible" });
  await page.getByRole("combobox", { name: /^(AI mode|Assistant mode)\b/ }).selectOption("assist");
  await page.getByRole("combobox", { name: "Provider", exact: true }).selectOption(providerId);
  const contextResponse = await contextRead;
  assert.equal(contextResponse.status(), 200);
  const contextGet = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/graph-context" && response.request().method() === "GET");
  await page.getByRole("combobox", { name: "Assistant operation", exact: true }).selectOption("new");
  const graphContextResponse = await contextGet;
  expectedContext = await graphContextResponse.json();
  assert.equal(postedGraphSelection?.kind, "graph");
  assert.equal(postedGraphSelection?.base_scenario, null);
  assert.deepEqual(expectedContext.selected, { kind: "graph", base_scenario: null });
  assert.equal(graphContextPosts, 1); assert.equal(graphContextGets, 1);
  const submitResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/turns" && response.request().method() === "POST");
  await page.getByRole("textbox", { name: "What would you like to do?", exact: true }).fill("Cancel the held local fixture request for recovery verification.");
  await page.getByRole("button", { name: "Start work", exact: true }).click();
  const parentResponse = await submitResponse;
  assert.equal(parentResponse.status(), 202);
  const parent = await parentResponse.json();
  parentJobId = parent.job?.job_id;
  assert.match(parentJobId ?? "", /^job-[0-9a-f]{32}$/);
  report.checks.push("assistant_job_started_from_current_graph_context");
  const fixtureDeadline = Date.now() + 20_000;
  let state;
  do {
    state = await fixtureState();
    if (state.failed) throw new Error("Local fixture rejected the bounded request");
    if (state.request_count === 1) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (Date.now() < fixtureDeadline);
  assert.equal(state.request_count, 1);
  report.checks.push("authorized_local_fixture_request_held_before_response");

  stage = "normal-assistant-stop";
  const stop = page.getByRole("button", { name: "Stop this operation", exact: true });
  await stop.waitFor({ state: "visible" });
  const cancelResponse = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/jobs/${parentJobId}/cancel` && response.request().method() === "POST");
  await stop.click();
  const requested = await cancelResponse;
  assert.equal(requested.status(), 202);
  const cancelled = await waitForCancelled();
  assert.equal(cancelled.turn.results.length, 0);
  report.cancelled_operation = {
    job_id: parentJobId,
    job_state: cancelled.job.state,
    turn_status: cancelled.turn.status,
    result_count: cancelled.turn.results.length,
  };
  report.checks.push("normal_assistant_stop_reached_durable_cancelled_terminal");

  stage = "reload-recovery";
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /^Assistant(?::|$)/ }).click();
  await assistant.waitFor({ state: "visible" });
  await page.getByRole("heading", { name: "Work stopped", exact: true }).waitFor();
  const reread = await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`);
  assert.equal(reread.job.state, "cancelled");
  assert.equal(reread.turn.status, "cancelled");
  assert.equal(reread.turn.results.length, 0);
  report.reloaded_operation = {
    job_id: reread.job.job_id,
    job_state: reread.job.state,
    turn_status: reread.turn.status,
    result_count: reread.turn.results.length,
  };
  assert.equal(assistancePosts, 1);
  assert.equal(cancelPosts, 1);
  assert.equal(report.blocked_requests.length, 0);
  report.checks.push("page_reload_recovered_same_saved_cancelled_operation_from_server");
  report.status = "passed";
}

try {
  await main();
} catch (error) {
  report.error = { stage, error_type: error instanceof Error ? error.name : "unknown" };
} finally {
  capability = "";
  if (context) {
    try { await context.close(); report.browser_context_closed = true; }
    catch { report.browser_context_closed = false; }
  } else report.browser_context_closed = true;
  if (browser) {
    try { await browser.close(); report.browser_closed = true; }
    catch { report.browser_closed = false; }
  } else report.browser_closed = true;
  report.counts = { session: sessionPosts, provider_save: providerPosts, activation: activationPosts, authorization: authorizationPosts, graph_context: graphContextPosts, graph_context_get: graphContextGets, assistance_submit: assistancePosts, cancel: cancelPosts };
  if (report.browser_context_closed && report.browser_closed && report.status === "passed") report.cleanup_passed = true;
  else { report.cleanup_passed = false; report.status = "failed_or_incomplete"; }
  writeFileSync(join(output, "installed-cancellation-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}
process.exit(report.status === "passed" ? 0 : 1);
