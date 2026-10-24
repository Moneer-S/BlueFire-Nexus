// The installed Assistant journey uses only a bounded loopback structured-output fixture.
/* global process, URL, sessionStorage, fetch, setTimeout, structuredClone, document, requestAnimationFrame */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [modulePath, output, port, fixturePort] = process.argv.slice(2);
const model = "bluefire-local-graph-fixture-v1";
const report = {
  schema_version: "bluefire.installed-assistant-fixture.v1",
  status: "failed_or_incomplete",
  installed_service: true,
  provider_kind: "local_loopback_structured_fixture",
  provider_model: model,
  live_provider_or_paid_model: false,
  native_execution: false,
  checks: [],
  blocked_requests: [],
  screenshots: [],
};
let stage = "bootstrap-input", capability = "", chromium, origin, fixtureOrigin;
try {
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
  stage = "playwright-import";
  ({ chromium } = await import(pathToFileURL(modulePath).href));
  origin = `http://127.0.0.1:${port}`;
  fixtureOrigin = `http://127.0.0.1:${fixturePort}`;
} catch (error) {
  capability = "";
  report.errors = [{ stage, kind: "bootstrap-failed", error_type: error instanceof Error ? error.name : "unknown" }];
  writeFileSync(join(output, "assistant-browser-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
  process.exit(1);
}
const providerId = "provider.installed-fixture.v1";
const providerEndpoint = `${fixtureOrigin}/v1/responses`;
const purposes = ["bluefire_experiment_assistance", "bluefire_ai_graph_draft"];
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const stableValue = value => Array.isArray(value) ? value.map(stableValue)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]))
    : value;
const sameStructure = (left, right) => JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
const digest = value => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const launchErrorCodes = new Set(["EACCES", "EINVAL", "ENOENT", "EPERM", "UNKNOWN", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"]);

function browserLaunchDiagnostic(error) {
  let message = "";
  let code = null;
  let errorType = "unknown";
  try {
    if (error instanceof Error && /^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(error.name)) errorType = error.name;
    const candidate = error?.code;
    if (typeof candidate === "string" && launchErrorCodes.has(candidate)) code = candidate;
  } catch { /* Keep diagnostics from affecting launch failure handling. */ }
  try {
    message = String(error?.message ?? "").slice(0, 8192);
    if (typeof capability === "string" && capability.length > 0) {
      message = message.split(capability).join("<redacted-capability>");
    }
    message = message
      .replace(/https?:\/\/[^\s"'<>]+/g, "<redacted-url>")
      .replace(/(?:[A-Za-z]:[\\/]|\\\\)[^\r\n"'<>]*/g, "<redacted-path>")
      .replace(/\/(?:[^\s"'<>]+\/)*[^\s"'<>]*/g, match => match.length > 1 ? "<redacted-path>" : match)
      .slice(0, 2048);
  } catch {
    message = "<launch-error-message-unavailable>";
  }
  return { error_type: errorType, error_code: code, message };
}

let browser, context, page;
let sessionPosts = 0, savePosts = 0, activatePosts = 0, authorizationPosts = 0, assistancePosts = 0;
let validatePosts = 0, reviewPosts = 0, continuationPosts = 0, expectedContext, parentJobId, graphJobId, proposal, validatedDigest;
let graphContextPosts = 0, graphContextGets = 0;
let providerConfig;
let reportBlockedWrite;
const blockedWrite = new Promise(resolve => { reportBlockedWrite = resolve; });

function failOnBlockedWrite(promise) {
  return Promise.race([
    promise,
    blockedWrite.then(blocked => {
      throw new Error(`Fixture blocked an expected write (${blocked.reason}).`);
    }),
  ]);
}

async function captureAssistantView(name) {
  assert.equal(new URL(page.url()).origin, origin);
  assert.ok(!new URL(page.url()).hash.startsWith("#/settings"), "Assistant evidence is captured after leaving Settings");
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
  const screenshot = await page.screenshot({
    fullPage: false,
    animations: "disabled",
    mask: [page.locator('input[type="password"]'), page.getByLabel("One-time connection code", { exact: false })],
  });
  writeFileSync(join(output, `${name}.png`), screenshot, { flag: "wx" });
  report.screenshots.push({
    name,
    sha256: createHash("sha256").update(screenshot).digest("hex"),
    bytes: screenshot.byteLength,
  });
}

async function api(path) {
  return page.evaluate(async ({ path }) => {
    const session = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!session) throw new Error("Session missing");
    const response = await fetch(`/api/v1${path}`, {
      method: "GET", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": session, Accept: "application/json" },
    });
    if (!response.ok) throw new Error("Installed API request failed");
    return response.json();
  }, { path });
}

function operationSummary(envelope) {
  const turn = envelope?.turn, child = turn?.active_child, continuation = turn?.continuation;
  const code = value => typeof value === "string" && /^[a-z][a-z0-9_]{0,79}$/.test(value) ? value : null;
  return {
    parent_job_id: /^job-[0-9a-f]{32}$/.test(envelope?.job?.job_id ?? "") ? envelope.job.job_id : null,
    job_state: typeof envelope?.job?.state === "string" ? envelope.job.state : null,
    turn_status: typeof turn?.status === "string" ? turn.status : null,
    plan_step_count: Array.isArray(turn?.plan) ? turn.plan.length : null,
    next_action_kind: typeof turn?.next_action?.kind === "string" ? turn.next_action.kind : null,
    next_action_label: typeof turn?.next_action?.label === "string" ? turn.next_action.label : null,
    recovery_present: Boolean(turn?.recovery),
    recovery_action_present: Boolean(turn?.recovery?.action),
    recovery_code: code(turn?.recovery?.code),
    active_child_kind: typeof child?.kind === "string" ? child.kind : null,
    active_child_job_id: /^job-[0-9a-f]{32}$/.test(child?.job_id ?? "") ? child.job_id : null,
    active_child_state: typeof child?.state === "string" ? child.state : null,
    active_child_error_code: code(child?.error?.code ?? child?.problem?.code),
    active_child_exception_type: code((child?.error?.exception_type ?? "").toLowerCase()),
    continuation_state: typeof continuation?.state === "string" ? continuation.state : null,
  };
}

function needsExplicitContinuation(operation) {
  return operation?.turn_status === "ready_to_continue"
    && operation.job_state === "completed"
    && operation.active_child_kind === null
    && operation.active_child_job_id === null
    && operation.continuation_state === null;
}

async function fixtureState() {
  const response = await fetch(`${fixtureOrigin}/__fixture/state`, { redirect: "error" });
  assert.equal(response.status, 200);
  return response.json();
}

async function waitForFixtureCount(count, timeoutMs = 20_000) {
  return failOnBlockedWrite((async () => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const state = await fixtureState();
      assert.equal(state.failed, false);
      if (state.request_count === count) return state;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error("Local fixture request deadline exceeded");
  })());
}

async function releaseFixture() {
  const response = await fetch(`${fixtureOrigin}/__fixture/release`, { method: "POST", redirect: "error" });
  assert.equal(response.status, 200);
}

async function ensureAssistantOpen() {
  const panel = page.locator("#experiment-assistant");
  if (!(await panel.isVisible())) await page.getByRole("button", { name: /^Assistant(?::|$)/ }).click();
  await failOnBlockedWrite(panel.waitFor({ state: "visible" }));
}

stage = "browser-launch";
try {
  try {
    browser = await chromium.launch({ headless: true, args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"] });
  } catch (error) {
    try {
      report.browser_launch_diagnostic = browserLaunchDiagnostic(error);
    } catch {
      report.browser_launch_diagnostic = {
        error_type: "unknown",
        error_code: null,
        message: "<launch-error-diagnostic-unavailable>",
      };
    }
    throw error;
  }
  stage = "browser-context-create";
  context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 } });
  context.setDefaultTimeout(20_000);
  stage = "browser-routing-setup";
  await context.routeWebSocket("**/*", socket => socket.close());
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    let allowed = url.origin === origin && ["GET", "HEAD"].includes(method), reason;
    if (url.origin !== origin) reason = "non_loopback";
    else if (!["GET", "HEAD", "POST"].includes(method)) reason = "method_not_allowed";
    else if (method === "GET" && url.pathname === "/api/v1/assistance/graph-context") {
      allowed = graphContextGets === 0 && url.search === "";
      if (allowed) graphContextGets += 1; else reason = "graph_context_get_out_of_scope";
    } else if (method === "POST") {
      let body;
      try { body = request.postData() ? request.postDataJSON() : null; }
      catch { reason = "invalid_json_body"; }
      if (!reason) {
        allowed = false;
        const path = url.pathname;
        const provider = body?.document;
        const providerExact = exactKeys(provider, ["id", "kind", "model", "endpoint", "api_key", "timeout_seconds", "max_retries", "max_output_tokens", "redaction"])
          && provider.id === providerId && provider.kind === "openai_responses" && provider.model === model
          && provider.endpoint === providerEndpoint && provider.api_key === null
          && provider.timeout_seconds === 30 && provider.max_retries === 0 && provider.max_output_tokens === 64
          && exactKeys(provider.redaction, ["enabled", "redact_keys", "max_string_chars", "include_evidence_content"])
          && provider.redaction.enabled === true && provider.redaction.include_evidence_content === false
          && ["api_key", "authorization", "cookie", "credential", "password", "secret", "token"].every(key => provider.redaction.redact_keys.includes(key));
        if (path === `/api/v1/resources/model-providers/${providerId}`) {
          allowed = savePosts === 0 && exactKeys(body, ["document", "status"]) && body.status === "draft" && providerExact;
          if (allowed) { savePosts += 1; providerConfig = structuredClone(provider); } else reason = "provider_draft_out_of_scope";
        } else if (path === `/api/v1/resources/model-providers/${providerId}/activate`) {
          allowed = activatePosts === 0 && exactKeys(body, []);
          if (allowed) activatePosts += 1; else reason = "provider_activation_out_of_scope";
        } else if (path === "/api/v1/ai/authorizations") {
          const authorizedPurposes = body?.purposes;
          allowed = authorizationPosts === 0 && exactKeys(body, ["provider", "purposes", "data_scope", "limits", "expires_in_seconds", "approved_by", "usage_authorized", "local_endpoint_authorized"])
            && sameStructure(body.provider, providerConfig)
            && Array.isArray(authorizedPurposes) && sameStructure([...authorizedPurposes].sort(), [...purposes].sort())
            && body.data_scope === "reviewed_lab_context"
            && exactKeys(body.limits, ["max_requests", "max_request_bytes", "max_reserved_output_tokens"])
            && body.limits.max_requests === 2 && body.limits.max_request_bytes === 2_097_152
            && body.limits.max_reserved_output_tokens === 128 && body.expires_in_seconds === 300
            && body.approved_by === "installed-fixture-reviewer" && body.usage_authorized === true
            && body.local_endpoint_authorized === true;
          if (allowed) authorizationPosts += 1; else reason = "authorization_out_of_scope";
        } else if (path === "/api/v1/session") {
          allowed = sessionPosts === 0 && !request.postData();
          if (allowed) sessionPosts += 1; else reason = "session_cap_or_body";
        } else if (path === "/api/v1/assistance/graph-context" && method === "POST") {
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
          allowed = graphContextPosts === 0 && selectionShape && body.kind === "graph"
            && body.base_scenario === null && editStepValid && bodySize > 0 && bodySize <= 1_048_576
            && keys.every(key => ["kind", "base_scenario", "edit_step"].includes(key));
          if (allowed) {
            graphContextPosts += 1;
          } else reason = "graph_context_out_of_scope";
        } else if (path === "/api/v1/assistance/turns") {
          allowed = assistancePosts === 0 && exactKeys(body, ["submission_id", "selection", "context_digest", "message", "autonomy", "provider_id"])
            && /^[0-9a-f-]{36}$/.test(body.submission_id) && digest(body.context_digest)
            && sameStructure(body.selection, expectedContext?.selected)
            && body.message === "Build a two-step fixture experiment for review."
            && body.autonomy === "assist" && body.provider_id === providerId;
          if (allowed) assistancePosts += 1; else reason = "assistant_request_out_of_scope";
        } else if (path === `/api/v1/assistance/turns/${parentJobId}/continue`) {
          allowed = continuationPosts === 0 && /^job-[0-9a-f]{32}$/.test(parentJobId ?? "")
            && exactKeys(body, ["submission_id", "context_digest"])
            && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(body.submission_id)
            && body.context_digest === expectedContext?.context_digest;
          if (allowed) continuationPosts += 1; else reason = "assistant_continuation_out_of_scope";
        } else {
          const graphPath = path.match(/^\/api\/v1\/ai\/graph-jobs\/(job-[0-9a-f]{32})\/(validate|review)$/);
          if (graphPath && graphJobId === graphPath[1] && graphPath[2] === "validate") {
            allowed = validatePosts === 0 && proposal && exactKeys(body, ["proposal_digest", "scenario"])
              && body.proposal_digest === proposal.proposal_digest && sameStructure(body.scenario, proposal.scenario);
            if (allowed) validatePosts += 1; else reason = "graph_validation_out_of_scope";
          } else if (graphPath && graphJobId === graphPath[1] && graphPath[2] === "review") {
            allowed = reviewPosts === 0 && proposal && exactKeys(body, ["decision", "proposal_digest", "reviewed_digest", "scenario"])
              && body.decision === "accept" && body.proposal_digest === proposal.proposal_digest
              && digest(body.reviewed_digest) && body.reviewed_digest === validatedDigest
              && sameStructure(body.scenario, proposal.scenario);
            if (allowed) reviewPosts += 1; else {
              reason = "graph_review_out_of_scope";
              report.blocked_graph_review_shape = {
                keys: body && typeof body === "object" && !Array.isArray(body)
                  ? Object.keys(body).filter(key => /^[a-z_]{1,40}$/.test(key)).sort().slice(0, 8) : [],
                decision: body?.decision === "accept" || body?.decision === "reject" ? body.decision : typeof body?.decision,
                exact_accept_keys: exactKeys(body, ["decision", "proposal_digest", "reviewed_digest", "scenario"]),
                proposal_digest_matches: body?.proposal_digest === proposal?.proposal_digest,
                reviewed_digest_valid: digest(body?.reviewed_digest),
                validation_digest_available: digest(validatedDigest),
                reviewed_digest_matches_validation: digest(validatedDigest) ? body?.reviewed_digest === validatedDigest : null,
                scenario_matches_proposal: Boolean(proposal && sameStructure(body?.scenario, proposal.scenario)),
              };
            }
          } else reason = "write_not_allowlisted";
        }
      }
    }
    if (!allowed) {
      const blocked = { method, path: url.origin === origin ? url.pathname : "non_loopback", reason: reason ?? "request_not_allowed" };
      report.blocked_requests.push(blocked);
      if (method === "POST") reportBlockedWrite(blocked);
      await route.abort();
      return;
    }
    if (method === "POST" && url.pathname === `/api/v1/ai/graph-jobs/${graphJobId}/validate`) {
      const response = await route.fetch();
      let validation;
      try { validation = await response.json(); } catch { validation = null; }
      if (response.status() === 200 && exactKeys(validation, ["proposal_digest", "reviewed_digest", "scenario", "validation"])
        && validation.proposal_digest === proposal?.proposal_digest && digest(validation.reviewed_digest)
        && exactKeys(validation.validation, ["valid"]) && validation.validation.valid === true
        && sameStructure(validation.scenario, proposal?.scenario)) {
        validatedDigest = validation.reviewed_digest;
      }
      await route.fulfill({ response });
      return;
    }
    await route.continue();
  });

  stage = "browser-new-page";
  page = await context.newPage();
  const assistanceResponses = [];
  page.on("response", response => {
    try {
      const url = new URL(response.url());
      const method = response.request().method();
      if (url.origin !== origin || !["GET", "POST"].includes(method)) return;
      const path = url.pathname
        .replace(/\/assistance\/turns\/job-[0-9a-f]{32}(?:\/continue)?$/, "/assistance/turns/{job-id}")
        .replace(/\/ai\/graph-jobs\/job-[0-9a-f]{32}(?:\/(?:validate|review))?$/, "/ai/graph-jobs/{job-id}");
      if (!new Set([
        "/api/v1/assistance/turns",
        "/api/v1/assistance/turns/{job-id}",
        "/api/v1/assistance/graph-context",
        "/api/v1/ai/graph-jobs/{job-id}",
      ]).has(path)) return;
      assistanceResponses.push({ method, path, status: response.status() });
      if (assistanceResponses.length > 24) assistanceResponses.shift();
    } catch { /* Browser diagnostics must not affect the journey. */ }
  });
  stage = "browser-initial-navigation";
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  stage = "browser-capability-entry";
  await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
  stage = "browser-capability-connect";
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  capability = "";
  stage = "browser-session-wait";
  await page.waitForFunction(() => sessionStorage.getItem("bluefire.browser-session.v1") !== null);
  report.checks.push("normal_ephemeral_browser_session");

  stage = "provider-configuration";
  await page.goto(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await failOnBlockedWrite(page.getByRole("heading", { name: "Model connection", exact: true }).waitFor());
  stage = "provider-api-style";
  await page.locator("label.field").filter({ has: page.locator(".field-label").getByText("API style", { exact: true }) }).locator("select").selectOption("openai_responses");
  stage = "provider-model";
  await page.getByLabel("Model ID", { exact: false }).fill(model);
  stage = "provider-endpoint";
  await page.getByLabel("Request endpoint", { exact: false }).fill(providerEndpoint);
  stage = "provider-credential-reference";
  await page.getByLabel("Secret environment reference", { exact: false }).fill("");
  stage = "provider-request-limits";
  await page.locator("details.provider-request-limits > summary").click();
  await page.getByLabel("Timeout seconds", { exact: true }).fill("30");
  await page.getByLabel("Output token limit", { exact: false }).fill("64");
  await page.getByLabel("Transport retries", { exact: true }).fill("0");
  stage = "provider-identity";
  await page.locator(".provider-connection-fields > details.provider-field-wide:not(.provider-request-limits) > summary").click();
  await page.getByLabel("Provider ID", { exact: false }).fill(providerId);
  stage = "provider-save";
  await page.getByRole("button", { name: "Save secret-free draft", exact: true }).click();
  await failOnBlockedWrite(page.getByText(`Responses API · ${model} saved. Activation and model usage authorization remain separate.`, { exact: true }).waitFor());
  report.checks.push("provider_saved_through_settings_ui");

  stage = "model-usage-authorization";
  await page.getByRole("checkbox", { name: "Plan work in the Assistant", exact: true }).check();
  await page.getByRole("checkbox", { name: "Create an experiment graph", exact: true }).check();
  await page.getByLabel("Total request attempts", { exact: false }).fill("2");
  await page.getByLabel("Total request bytes", { exact: false }).fill("2097152");
  await page.getByLabel("Total reserved output tokens", { exact: false }).fill("128");
  await page.getByLabel("Authorization duration in seconds", { exact: false }).fill("300");
  await page.getByLabel("Operator identity for model usage", { exact: true }).fill("installed-fixture-reviewer");
  await page.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint.", exact: true }).check();
  await page.getByRole("checkbox", { name: "I authorize the selected model work, reviewed lab data and these usage limits.", exact: true }).check();
  await page.getByRole("button", { name: "Authorize reviewed model usage", exact: true }).click();
  await failOnBlockedWrite(page.getByText("Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.", { exact: true }).waitFor());
  assert.equal(activatePosts, 1);
  assert.equal(authorizationPosts, 1);
  report.checks.push("provider_activated_and_usage_authorized_in_ui");

  stage = "captured-graph-context";
  const graphContextResponse = failOnBlockedWrite(page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/graph-context" && response.request().method() === "POST")
    .then(response => ({ response }), () => ({ timedOut: true })));
  await page.goto(`${origin}/#/builder`, { waitUntil: "domcontentloaded" });
  await ensureAssistantOpen();
  await page.getByRole("button", { name: "Assistant settings", exact: true }).click();
  const mode = page.getByRole("combobox", { name: /^(AI mode|Assistant mode)\b/ });
  await mode.selectOption("assist");
  await page.getByRole("combobox", { name: "Provider", exact: true }).selectOption(providerId);
  const initialGraphContextResult = await graphContextResponse;
  if (initialGraphContextResult.timedOut) {
    stage = "graph-context-response-timeout";
    throw new Error("Installed initial graph context response was not observed.");
  }
  assert.equal(graphContextPosts, 1);

  stage = "graph-level-new-experiment-context";
  const newExperimentContextResponse = failOnBlockedWrite(page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/graph-context" && response.request().method() === "GET")
    .then(response => ({ response }), () => ({ timedOut: true })));
  const newExperimentContextRequest = page.waitForRequest(request => new URL(request.url()).pathname === "/api/v1/assistance/graph-context" && request.method() === "GET")
    .then(request => ({ request }), () => ({ timedOut: true }));
  await page.getByRole("combobox", { name: "Assistant operation", exact: true }).selectOption("new");
  const [newContextRequestResult, newContextResponseResult] = await Promise.all([newExperimentContextRequest, newExperimentContextResponse]);
  if (newContextRequestResult.timedOut || newContextResponseResult.timedOut) {
    stage = "graph-level-context-response-timeout";
    throw new Error("New experiment graph context was not observed.");
  }
  assert.equal(newContextRequestResult.request.url(), `${origin}/api/v1/assistance/graph-context`);
  assert.equal(graphContextGets, 1);
  expectedContext = await newContextResponseResult.response.json();
  assert.deepEqual(expectedContext.selected, { kind: "graph", base_scenario: null });
  assert.equal(expectedContext.selected?.kind, "graph");
  assert.equal(expectedContext.selected?.base_scenario, null);
  assert.equal(Object.hasOwn(expectedContext.selected, "edit_step"), false);
  const graphCapability = expectedContext.capabilities?.find(item => item.id === "graph.propose_and_validate");
  assert.ok(graphCapability?.available);
  assert.equal(graphCapability.title, "Propose and validate a separate graph");
  assert.deepEqual(expectedContext.bounds, { max_nodes: 8, max_edges: 16 });
  assert.ok(digest(expectedContext.context_digest));
  report.checks.push("graph_level_new_experiment_context_selected_without_step_edit");
  await page.getByRole("button", { name: "Assistant settings", exact: true }).click();
  stage = "provider-configured-screenshot";
  await captureAssistantView("assistant-provider-configured");
  await page.getByRole("textbox", { name: "What would you like to do?", exact: true }).fill("Build a two-step fixture experiment for review.");
  stage = "assistant-submit-events";
  const submitResponse = failOnBlockedWrite(page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/turns" && response.request().method() === "POST")
    .then(response => ({ response }), () => ({ timedOut: true })));
  const submitRequest = page.waitForRequest(request => new URL(request.url()).pathname === "/api/v1/assistance/turns" && request.method() === "POST")
    .then(request => ({ request }), () => ({ timedOut: true }));
  const submitClick = page.getByRole("button", { name: "Start work", exact: true }).click()
    .then(() => ({ clicked: true }), () => ({ clicked: false }));
  const [clickResult, requestResult, responseResult] = await Promise.all([submitClick, submitRequest, submitResponse]);
  if (!clickResult.clicked) {
    stage = "assistant-submit-click-failed";
    throw new Error("Assistant submit control could not be activated.");
  }
  if (requestResult.timedOut) {
    stage = "assistant-submit-request-timeout";
    throw new Error("Assistant submission request was not observed.");
  }
  if (responseResult.timedOut) {
    stage = "assistant-submit-response-timeout";
    throw new Error("Assistant submission response was not observed.");
  }
  const request = JSON.parse(requestResult.request.postData());
  assert.equal(request.context_digest, expectedContext.context_digest);
  assert.ok(sameStructure(request.selection, expectedContext.selected));
  const parent = await responseResult.response.json();
  parentJobId = parent.job?.job_id;
  assert.match(parentJobId ?? "", /^job-[0-9a-f]{32}$/);
  await waitForFixtureCount(1);
  const operationDeadline = Date.now() + 20_000;
  let stableContinuationReads = 0;
  while (Date.now() < operationDeadline) {
    const current = operationSummary(await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`));
    report.assistant_operation = current;
    if (current.active_child_kind === "graph.ai.propose"
      || ["awaiting_review", "completed"].includes(current.turn_status)) break;
    stableContinuationReads = needsExplicitContinuation(current) ? stableContinuationReads + 1 : 0;
    if (stableContinuationReads >= 2) break;
    if (["failed", "cancelled", "interrupted"].includes(current.turn_status)) throw new Error("Assistant fixture operation stopped before proposal work.");
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  assert.ok(report.assistant_operation);
  assert.ok(report.assistant_operation.active_child_kind === "graph.ai.propose"
    || (needsExplicitContinuation(report.assistant_operation) && stableContinuationReads >= 2)
    || ["awaiting_review", "completed"].includes(report.assistant_operation.turn_status));
  assert.equal(report.assistant_operation.plan_step_count, 1);
  report.checks.push("assistant_submission_carries_captured_selection_and_digest");
  let continuedThroughUi = false;
  if (needsExplicitContinuation(report.assistant_operation)) {
    assert.equal(report.assistant_operation.next_action_kind, "continue");
    stage = "assistant-normal-continuation";
    const returnToActiveWork = page.getByRole("button", { name: /^(Return to active work|Recent operation)$/ });
    if (await returnToActiveWork.count()) await returnToActiveWork.click();
    const continuationLabel = report.assistant_operation.recovery_action_present ? "Resume saved turn" : report.assistant_operation.next_action_label;
    assert.ok(["Recover next step", "Resume saved turn"].includes(continuationLabel));
    const continuationButton = page.getByRole("button", { name: continuationLabel, exact: true });
    let continuationVisible = true;
    try {
      await failOnBlockedWrite(continuationButton.waitFor({ state: "visible", timeout: 5_000 }));
    } catch {
      if (report.blocked_requests.length) throw new Error("A fixture request was blocked while waiting for continuation.");
      continuationVisible = false;
    }
    const beforeContinuationClick = operationSummary(await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`));
    report.assistant_operation = beforeContinuationClick;
    if (needsExplicitContinuation(beforeContinuationClick)) {
      if (!continuationVisible) {
        report.assistant_visible_buttons = await page.locator("#experiment-assistant button").evaluateAll(buttons =>
          buttons.slice(0, 16).map(button => ({
            text: (button.innerText || "").trim().slice(0, 80),
            label: (button.getAttribute("aria-label") || "").slice(0, 80),
            disabled: button.disabled,
          })));
        report.assistant_visible_headings = (await page.locator("#experiment-assistant h2, #experiment-assistant h3, #experiment-assistant h4").allTextContents())
          .slice(0, 12).map(label => label.trim().slice(0, 100));
        report.assistant_visible_statuses = (await page.locator("#experiment-assistant [role=status]").allTextContents())
          .slice(0, 12).map(label => label.trim().slice(0, 120));
        report.assistant_http_responses = assistanceResponses.slice(-24);
        await page.screenshot({ path: join(output, "assistant-continuation-diagnostic.png"), animations: "disabled" });
        throw new Error("The saved continuation action remained unavailable while the parent had no child.");
      }
      const continueResponse = failOnBlockedWrite(page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/assistance/turns/${parentJobId}/continue` && response.request().method() === "POST")
        .then(response => ({ response }), () => ({ timedOut: true })));
      const continueClick = continuationButton.click()
        .then(() => ({ clicked: true }), () => ({ clicked: false }));
      const [continueClickResult, continueResult] = await Promise.all([continueClick, continueResponse]);
      if (!continueClickResult.clicked) {
        stage = "assistant-continuation-click-failed";
        throw new Error("The saved-turn recovery control could not be activated.");
      }
      if (continueResult.timedOut) {
        stage = "assistant-continuation-response-timeout";
        throw new Error("The normal saved-turn continuation was not observed.");
      }
      const continuationRequest = JSON.parse(continueResult.response.request().postData());
      assert.ok(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(continuationRequest.submission_id));
      assert.equal(continuationRequest.context_digest, expectedContext.context_digest);
      assert.equal(continueResult.response.status(), 202);
      continuedThroughUi = true;
      report.checks.push("saved_turn_continued_through_normal_ui_recovery");
    }
  }
  if (!continuedThroughUi) {
    assert.ok(report.assistant_operation.active_child_kind === "graph.ai.propose"
      || ["awaiting_review", "completed"].includes(report.assistant_operation.turn_status));
  }

  stage = "captured-context-navigation";
  let pendingFixture;
  try {
    pendingFixture = await waitForFixtureCount(2, 40_000);
  } catch {
    report.assistant_operation = operationSummary(await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`));
    const childId = report.assistant_operation.active_child_job_id;
    if (childId) {
      try {
        const childEnvelope = await api(`/ai/graph-jobs/${encodeURIComponent(childId)}`);
        const child = childEnvelope.job;
        const errorCode = child?.error?.code ?? child?.problem?.code;
        report.assistant_child_diagnostic = {
          job_state: typeof child?.state === "string" ? child.state : null,
          error_code: typeof errorCode === "string" && /^[a-z][a-z0-9_]{0,79}$/.test(errorCode) ? errorCode : null,
          exception_type: typeof child?.error?.exception_type === "string"
            && /^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(child.error.exception_type) ? child.error.exception_type : null,
          proposal_present: Boolean(childEnvelope.proposal),
          review_ready: childEnvelope.review_ready === true,
        };
      } catch (error) {
        report.assistant_child_diagnostic = { read_error_type: error instanceof Error ? error.name : "unknown" };
      }
    }
    throw new Error("The graph proposal fixture request did not arrive before its bounded deadline.");
  }
  assert.deepEqual(pendingFixture.purposes, purposes);
  report.checks.push("graph_level_proposal_dispatched");
  await page.goto(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await failOnBlockedWrite(page.getByRole("heading", { name: "Model connection", exact: true }).waitFor());
  await page.goto(`${origin}/#/builder`, { waitUntil: "domcontentloaded" });
  await ensureAssistantOpen();
  const returnToActiveWork = page.getByRole("button", { name: /^(Return to active work|Recent operation)$/ });
  if (await returnToActiveWork.count()) await returnToActiveWork.click();
  await failOnBlockedWrite(page.getByRole("region", { name: "Saved assistant work", exact: true }).waitFor());
  const retained = await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`);
  assert.equal(retained.job.job_id, parentJobId);
  assert.equal(retained.job.request.submitted_request.context_digest, expectedContext.context_digest);
  assert.ok(sameStructure(retained.job.request.submitted_request.selection, expectedContext.selected));
  report.checks.push("captured_assistant_request_retained_across_view_navigation");
  stage = "retained-assistant-screenshot";
  await captureAssistantView("assistant-retained-work");
  await releaseFixture();

  stage = "proposal-review-and-save";
  const deadline = Date.now() + 30_000;
  let envelope;
  while (Date.now() < deadline) {
    envelope = await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`);
    if (["awaiting_review", "completed"].includes(envelope.turn?.status)) break;
    if (["failed", "cancelled", "interrupted"].includes(envelope.turn?.status)) throw new Error("Assistant fixture operation did not complete.");
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  assert.ok(envelope);
  const childId = envelope.job?.progress?.children?.["step-1"]?.job_id;
  assert.match(childId ?? "", /^job-[0-9a-f]{32}$/);
  graphJobId = childId;
  const graphEnvelope = await api(`/ai/graph-jobs/${encodeURIComponent(childId)}`);
  proposal = graphEnvelope.proposal;
  assert.equal(proposal?.proposal_job_id, childId);
  assert.equal(proposal?.provider?.effective_provider_id, providerId);
  assert.equal(proposal?.provider?.model, model);
  assert.equal(proposal?.scenario?.steps?.length, 2);
  await page.goto(`${origin}/#/builder?graph_job=${encodeURIComponent(childId)}`, { waitUntil: "domcontentloaded" });
  await failOnBlockedWrite(page.getByRole("button", { name: "Save experiment", exact: true }).waitFor());
  stage = "proposal-review-screenshot";
  await captureAssistantView("assistant-proposal-review");
  const validationResponse = failOnBlockedWrite(page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/ai/graph-jobs/${childId}/validate` && response.request().method() === "POST")
    .then(response => ({ response }), () => ({ timedOut: true })));
  const validationClick = page.getByRole("button", { name: "Save experiment", exact: true }).click()
    .then(() => ({ clicked: true }), () => ({ clicked: false }));
  const [validationClickResult, validationResult] = await Promise.all([validationClick, validationResponse]);
  if (!validationClickResult.clicked) {
    stage = "proposal-save-click-failed";
    throw new Error("Save control could not be activated.");
  }
  if (validationResult.timedOut) {
    stage = "proposal-validation-response-timeout";
    throw new Error("Proposal validation response was not observed.");
  }
  const validation = await validationResult.response.json();
  assert.equal(validation.validation?.valid, true);
  validatedDigest = validation.reviewed_digest;
  assert.ok(digest(validatedDigest));
  await failOnBlockedWrite(page.getByRole("heading", { name: "Experiment saved", exact: true }).waitFor());
  const savedEnvelope = await api(`/ai/graph-jobs/${encodeURIComponent(childId)}`);
  assert.ok(savedEnvelope.application);
  assert.equal(savedEnvelope.application.proposal_job_id, childId);
  const immutable = await api(`/scenario-versions/${encodeURIComponent(savedEnvelope.application.scenario_id)}/versions/${savedEnvelope.application.version}`);
  assert.equal(immutable.scenario.digest, savedEnvelope.application.digest);
  assert.equal(immutable.scenario.document.id, savedEnvelope.application.scenario_id);
  stage = "saved-graph-screenshot";
  await page.getByRole("button", { name: "Open saved experiment", exact: true }).click();
  await failOnBlockedWrite(page.waitForURL(url => url.origin === origin && url.hash === "#/builder", { timeout: 10_000 }));
  await failOnBlockedWrite(page.locator(".builder-header h1").waitFor({ state: "visible" }));
  assert.equal(await page.locator(".builder-header h1").getAttribute("aria-label"), immutable.scenario.document.title);
  await captureAssistantView("assistant-saved-graph-reopened");
  const finalOperation = await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`);
  report.assistant_operation = operationSummary(finalOperation);
  const fixture = await fixtureState();
  assert.equal(fixture.request_count, 2);
  assert.deepEqual(fixture.purposes, purposes);
  assert.ok(fixture.request_bytes > 0 && fixture.request_bytes <= 2_097_152);
  assert.equal(fixture.failed, false);
  report.route_counts = {
    session: sessionPosts,
    provider_save: savePosts,
    provider_activate: activatePosts,
    authorization: authorizationPosts,
    assistance_submit: assistancePosts,
    assistance_continue: continuationPosts,
    graph_validate: validatePosts,
    graph_review: reviewPosts,
  };
  assert.equal(savePosts, 1, "exactly one provider save must pass the browser route");
  assert.equal(activatePosts, 1, "exactly one provider activation must pass the browser route");
  assert.equal(authorizationPosts, 1, "exactly one bounded authorization must pass the browser route");
  assert.equal(assistancePosts, 1, "exactly one captured-context submission must pass the browser route");
  assert.equal(continuationPosts, continuedThroughUi ? 1 : 0, "continuation count must match the UI recovery action actually used");
  assert.equal(validatePosts, 1, "the normal UI must validate the graph proposal exactly once");
  assert.equal(reviewPosts, 1, "the normal UI must save the reviewed graph exactly once");
  assert.equal(sessionPosts, 1, "exactly one browser session exchange must pass the browser route");
  report.provider_requests = { count: fixture.request_count, purposes: fixture.purposes, request_bytes: fixture.request_bytes };
  report.assistant_selection = { kind: expectedContext.selected.kind, step_edit: false, bounds: expectedContext.bounds };
  report.saved_graph = { scenario_id: savedEnvelope.application.scenario_id, version: savedEnvelope.application.version, digest: savedEnvelope.application.digest };
  report.checks.push("validated_proposal_saved_reopened_as_separate_immutable_graph_without_execution");
  assert.equal(report.blocked_requests.length, 0);
  report.status = "passed";
} catch (error) {
  report.errors = [{ stage, kind: "journey-failed", error_type: error instanceof Error ? error.name : "unknown" }];
  report.status = "failed_or_incomplete";
  try {
    report.journey_error_diagnostic = { stage, ...browserLaunchDiagnostic(error) };
  } catch {
    report.journey_error_diagnostic = {
      stage,
      error_type: "unknown",
      error_code: null,
      message: "<journey-error-diagnostic-unavailable>",
    };
  }
  process.exitCode = 1;
} finally {
  capability = "";
  await context?.close().catch(() => { report.errors = [{ stage: "cleanup", kind: "context-close" }]; process.exitCode = 1; });
  await browser?.close().catch(() => { report.errors = [{ stage: "cleanup", kind: "browser-close" }]; process.exitCode = 1; });
  if (process.exitCode) report.status = "failed_or_incomplete";
  writeFileSync(join(output, "assistant-browser-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}
