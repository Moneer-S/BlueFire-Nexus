// The installed Assistant journey uses only a bounded loopback structured-output fixture.
/* global process, URL, sessionStorage, fetch, setTimeout, clearTimeout, AbortController, AbortSignal, structuredClone, document, location */
import assert from "node:assert/strict";
import { readCanonicalRunIdentity } from "./run-result-identity.mjs";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { preflightDiagnostic } from "./preflight-diagnostics.mjs";
import { waitForRunApproval as pollForRunApproval } from "./run-job-state.mjs";

const [modulePath, output, port, fixturePort, outerDeadlineArg] = process.argv.slice(2);
const outerDeadlineMs = Number(outerDeadlineArg);
const model = "bluefire-local-graph-fixture-v1";
const report = {
  schema_version: "bluefire.installed-assistant-fixture.v2",
  status: "failed_or_incomplete",
  installed_service: true,
  provider_kind: "local_loopback_structured_fixture",
  provider_model: model,
  live_provider_or_paid_model: false,
  evidence_scope: "Generated fixture observations are normalized metadata, not target telemetry or held-out detection evidence.",
  graph_simulation_native_execution: false,
  generated_fixture_execute: { status: "not_started", native_execution: false },
  checks: [],
  blocked_requests: [],
  screenshots: [],
  errors: [],
};
let stage = "bootstrap-input", capability = "", chromium, origin, fixtureOrigin;
try {
  assert.match(port ?? "", /^\d{1,5}$/);
  assert.match(fixturePort ?? "", /^\d{1,5}$/);
  assert.ok(Number.isSafeInteger(outerDeadlineMs) && outerDeadlineMs > Date.now() + 55_000 && outerDeadlineMs <= Date.now() + 240_000);
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
const purposes = ["bluefire_experiment_assistance", "bluefire_ai_graph_draft", "bluefire_experiment_assistance", "bluefire_detection_source_creation"];
const authorizedPurposes = [...new Set(purposes)].sort();
const compositionPurposes = [
  { purpose: "bluefire_linux_file_access_composition_proposal", label: "Propose a Linux file-access verification graph" },
  { purpose: "bluefire_macos_file_access_composition_proposal", label: "Propose a macOS file-access verification graph" },
];
const receiverPurposeLabel = "Propose a bounded composition graph";
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
let compositionAuthorizationPosts = 0, authorizationRevokePosts = 0;
let purposeProofStarted = false, expectedCompositionPurpose, expectedRevokeAuthorizationId;
const revokeAttemptsById = new Map();
let validatePosts = 0, reviewPosts = 0, continuationPosts = 0, expectedContext, parentJobId, graphJobId, proposal, validatedDigest;
let runPreflightPosts = 0, runSubmitPosts = 0, approvalPosts = 0, runnerBootstrapPosts = 0, runnerStartPosts = 0, runnerStopPosts = 0;
let detectionSourcePosts = 0, detectionContextPosts = 0, detectionValidatePosts = 0, detectionReviewPosts = 0;
let runPayload, runJobId, runId, savedScenarioId, savedScenarioDocument;
let detectionJobId, detectionProposalDigest, detectionValidatedDigest, expectedDetectionContext, runnerStarted = false;
let graphContextPosts = 0, graphContextGets = 0;
const cleanupDeadline = outerDeadlineMs - 2_000;
const journeyDeadline = cleanupDeadline - 55_000;
let providerConfig;
let reportBlockedWrite;
const blockedWrite = new Promise(resolve => { reportBlockedWrite = resolve; });

function exactRunPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !exactKeys(value, ["scenario", "layout", "mode", "autonomy", "ai_provider_id", "runner_profile_id", "target_scope", "collectors"])) return false;
  const scenario = value.scenario;
  if (!scenario || typeof scenario !== "object" || Array.isArray(scenario)) return false;
  const savedScenario = { ...savedScenarioDocument };
  delete savedScenario.layout;
  return sameStructure(scenario, savedScenario)
    && scenario.id === savedScenarioId && scenario.start === "create_fixture"
    && Array.isArray(scenario.steps) && scenario.steps.length === 3
    && scenario.steps[0].id === "create_fixture" && scenario.steps[0].behavior_id === "sandbox.fixture.create.v1"
    && sameStructure(scenario.steps[0].parameters, { record_count: 4 })
    && scenario.steps[1].id === "transform_fixture" && scenario.steps[1].behavior_id === "sandbox.fixture.transform.v1"
    && sameStructure(scenario.steps[1].parameters, { redact_values: true })
    && sameStructure(scenario.steps[1].inputs, { workspace: { from_step: "create_fixture", artifact: "workspace" } })
    && scenario.steps[2].id === "cleanup_workspace" && scenario.steps[2].behavior_id === "sandbox.cleanup.v1"
    && sameStructure(scenario.steps[2].parameters, { verify_removal: true })
    && sameStructure(scenario.steps[2].inputs, { workspace: { from_step: "create_fixture", artifact: "workspace" } })
    && sameStructure(scenario.edges, [
      { from_step: "create_fixture", outcome: "success", to_step: "transform_fixture" },
      { from_step: "transform_fixture", outcome: "success", to_step: "cleanup_workspace" },
    ])
    && value.mode === "execute" && value.autonomy === "off"
    && value.ai_provider_id === "deterministic-offline.v1"
    && value.runner_profile_id === "sandbox-execute.v1"
    && sameStructure(value.target_scope, { scope_refs: ["sandbox.workspace"] })
    && sameStructure(value.collectors, ["collector.filesystem.sandbox.v1"])
    && exactKeys(value.layout, ["schema_version", "nodes"]) && value.layout.schema_version === "bluefire.layout.v1"
    && Array.isArray(value.layout.nodes) && value.layout.nodes.length <= 8;
}

function remainingJourneyMs(maximum) {
  const remaining = journeyDeadline - Date.now();
  if (remaining <= 0) throw new Error("The bounded Assistant journey budget is exhausted.");
  return Math.min(maximum, remaining);
}

function remainingCleanupMs(maximum) {
  const remaining = cleanupDeadline - Date.now();
  if (remaining <= 0) throw new Error("The reserved owned-process cleanup budget is exhausted.");
  return Math.min(maximum, remaining);
}

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
  const fontDeadline = Date.now() + remainingJourneyMs(2_000);
  page.setDefaultTimeout(remainingJourneyMs(10_000));
  await page.evaluate(async ({ deadline }) => {
    while (document.fonts.status !== "loaded" && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    if (document.fonts.status !== "loaded") throw new Error("Fonts did not settle before the bounded capture deadline.");
  }, { deadline: fontDeadline });
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

async function api(path, maximumMs = 10_000) {
  const timeoutMs = remainingJourneyMs(maximumMs);
  page.setDefaultTimeout(timeoutMs);
  return page.evaluate(async ({ path, timeoutMs }) => {
    const session = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!session) throw new Error("Session missing");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(`/api/v1${path}`, {
        method: "GET", redirect: "error", credentials: "omit", signal: controller.signal,
        headers: { "X-BlueFire-Session": session, Accept: "application/json" },
      });
      if (!response.ok) throw new Error("Installed API request failed");
      return await response.json();
    } finally { clearTimeout(timer); }
  }, { path, timeoutMs });
}

async function cleanupApi(path) {
  const timeoutMs = remainingCleanupMs(8_000);
  page.setDefaultTimeout(timeoutMs);
  return page.evaluate(async ({ path, timeoutMs }) => {
    const session = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!session) throw new Error("Session missing");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(`/api/v1${path}`, {
        method: "GET", redirect: "error", credentials: "omit", signal: controller.signal,
        headers: { "X-BlueFire-Session": session, Accept: "application/json" },
      });
      if (!response.ok) throw new Error("Installed cleanup API request failed");
      return await response.json();
    } finally { clearTimeout(timer); }
  }, { path, timeoutMs });
}

function ownedModelAuthorization(row) {
  if (!row || typeof row !== "object" || row.provider?.id !== providerId
    || !sameStructure(row.provider, providerConfig)
    || !Array.isArray(row.purposes)
    || !/^ai-authorization-[0-9a-f]{32}$/.test(row.authorization_id ?? "")) return false;
  const original = row.approved_by === "installed-fixture-reviewer"
    && sameStructure([...row.purposes].sort(), authorizedPurposes);
  const purposeOnly = row.approved_by === "installed-purpose-reviewer"
    && compositionPurposes.some(item => sameStructure(row.purposes, [item.purpose]));
  return original || purposeOnly;
}

async function revokeOwnedModelAuthorization(authorizationId, cleanup = false) {
  const read = cleanup ? cleanupApi : api;
  const deadline = Math.min(cleanup ? cleanupDeadline : journeyDeadline, Date.now() + 10_000);
  const readOwned = async () => {
    const current = (await read("/ai/authorizations")).authorizations;
    const row = Array.isArray(current) ? current.find(item => item.authorization_id === authorizationId) : null;
    assert.ok(ownedModelAuthorization(row), "Only the exact installed provider authorization may be revoked");
    return row;
  };
  try {
    for (let attempt = 0; attempt < 2 && Date.now() < deadline; attempt += 1) {
      const row = await readOwned();
      if (row.status === "revoked") return;
      assert.equal(row.status, "active");
      assert.ok((revokeAttemptsById.get(authorizationId) ?? 0) < 2);
      expectedRevokeAuthorizationId = authorizationId;
      const timeout = cleanup ? remainingCleanupMs(10_000) : remainingJourneyMs(10_000);
      await page.goto(`${origin}/#/settings`, { waitUntil: "domcontentloaded", timeout });
      const button = page.getByRole("button", { name: `Revoke model usage for ${model}`, exact: true });
      await button.waitFor({ state: "visible", timeout: cleanup ? remainingCleanupMs(8_000) : remainingJourneyMs(8_000) });
      assert.equal(await button.count(), 1, "Exactly one installed authorization may be active during revocation");
      try {
        await failOnBlockedWrite(button.click({ timeout: cleanup ? remainingCleanupMs(8_000) : remainingJourneyMs(8_000) }));
      } catch { /* A lost revoke response is reconciled with the exact saved authorization. */ }
      const settleUntil = Math.min(deadline, Date.now() + (attempt === 0 ? 1_500 : 8_000));
      while (Date.now() < settleUntil) {
        try {
          const updated = await readOwned();
          if (updated.status === "revoked") return;
          assert.equal(updated.status, "active");
        } catch { /* Missing or unavailable proof never establishes revocation. */ }
        await new Promise(resolve => setTimeout(resolve, 150));
      }
    }
  } finally {
    expectedRevokeAuthorizationId = undefined;
  }
  throw new Error("Installed model authorization revocation was not confirmed.");
}

async function cleanupOwnedModelAuthorizations() {
  if (authorizationPosts + compositionAuthorizationPosts === 0) return;
  if (!page || page.isClosed()) {
    report.cleanup = { ...(report.cleanup ?? {}), model_authorizations_revoked: false };
    process.exitCode = 1;
    return;
  }
  try {
    const current = (await cleanupApi("/ai/authorizations")).authorizations;
    assert.ok(Array.isArray(current));
    const active = current.filter(row => ownedModelAuthorization(row) && row.status === "active");
    assert.ok(active.length <= 3);
    for (const row of active) await revokeOwnedModelAuthorization(row.authorization_id, true);
    const final = (await cleanupApi("/ai/authorizations")).authorizations;
    assert.ok(Array.isArray(final));
    const owned = final.filter(row => ownedModelAuthorization(row));
    report.cleanup = { ...(report.cleanup ?? {}), model_authorizations_revoked:
      owned.length === authorizationPosts + compositionAuthorizationPosts
        && owned.every(row => row.status === "revoked") };
  } catch {
    report.cleanup = { ...(report.cleanup ?? {}), model_authorizations_revoked: false };
  }
  if (report.cleanup.model_authorizations_revoked !== true) process.exitCode = 1;
}

async function proveCompositionPurposeAuthorizations() {
  stage = "composition-purpose-fixture-budget-before";
  const before = await fixtureState();
  assert.equal(before.request_count, 4);
  purposeProofStarted = true;
  const initial = (await api("/ai/authorizations")).authorizations;
  assert.ok(Array.isArray(initial));
  const original = initial.filter(row => ownedModelAuthorization(row)
    && row.approved_by === "installed-fixture-reviewer");
  assert.equal(original.length, 1);
  assert.equal(original[0].status, "active");
  assert.deepEqual([...original[0].purposes].sort(), authorizedPurposes);
  stage = "composition-purpose-original-revoke";
  await revokeOwnedModelAuthorization(original[0].authorization_id);

  const recorded = [];
  for (const item of compositionPurposes) {
    stage = `composition-purpose-${item.purpose}-settings`;
    await gotoJourney(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
    const savedConnection = page.locator("section.provider-saved-connections article.provider-saved-connection")
      .filter({ hasText: providerId });
    await savedConnection.waitFor({ state: "visible" });
    assert.equal(await savedConnection.count(), 1);
    assert.equal((await savedConnection.locator("details code").textContent())?.trim(), providerId);
    assert.equal((await savedConnection.locator("strong").textContent())?.trim(), `Responses API · ${model}`);
    await savedConnection.getByText("Active", { exact: true }).waitFor();
    await savedConnection.getByRole("button", { name: `Edit Responses API · ${model}`, exact: true }).click();
    await page.getByRole("region", { name: "Selected connection summary", exact: true })
      .getByRole("heading", { name: model, exact: true }).waitFor();
    assert.equal(await page.getByRole("combobox", { name: "API style", exact: true }).inputValue(), "openai_responses");
    assert.equal(await page.getByLabel("Model ID", { exact: false }).inputValue(), model);
    assert.equal(await page.getByLabel("Request endpoint", { exact: false }).inputValue(), providerEndpoint);
    assert.equal(await page.getByLabel("Secret environment reference", { exact: false }).inputValue(), "");
    assert.equal(await page.getByLabel("Provider ID", { exact: false }).inputValue(), providerId);
    assert.equal(await page.getByLabel("Timeout seconds", { exact: true }).inputValue(), "30");
    assert.equal(await page.getByLabel("Output token limit", { exact: false }).inputValue(), "64");
    assert.equal(await page.getByLabel("Transport retries", { exact: true }).inputValue(), "0");
    const linux = page.getByRole("checkbox", { name: compositionPurposes[0].label, exact: true });
    const macos = page.getByRole("checkbox", { name: compositionPurposes[1].label, exact: true });
    const receiver = page.getByRole("checkbox", { name: receiverPurposeLabel, exact: true });
    await linux.waitFor({ state: "visible" });
    await macos.waitFor({ state: "visible" });
    await receiver.waitFor({ state: "visible" });
    assert.equal(await linux.count(), 1);
    assert.equal(await macos.count(), 1);
    assert.equal(await receiver.count(), 1);
    assert.equal(await linux.isEnabled(), true);
    assert.equal(await macos.isEnabled(), true);
    assert.equal(await receiver.isEnabled(), true);
    report.model_purpose_selection_resets ??= [];
    report.model_purpose_selection_resets.push({
      purpose: item.purpose,
      before: { linux: await linux.isChecked(), macos: await macos.isChecked(), receiver: await receiver.isChecked() },
    });
    await linux.uncheck();
    await macos.uncheck();
    await receiver.uncheck();
    assert.equal(await linux.isChecked(), false);
    assert.equal(await macos.isChecked(), false);
    assert.equal(await receiver.isChecked(), false);
    stage = `composition-purpose-${item.purpose}-selection`;
    await page.getByRole("checkbox", { name: item.label, exact: true }).check();
    assert.equal(await page.getByRole("checkbox", { name: item.label, exact: true }).isChecked(), true);
    assert.equal(await page.getByRole("checkbox", { name: compositionPurposes.find(other => other.purpose !== item.purpose).label, exact: true }).isChecked(), false);
    assert.equal(await receiver.isChecked(), false);
    report.checks.push(`composition_purpose_${item.purpose}_separate_from_receiver_in_settings`);

    stage = `composition-purpose-${item.purpose}-authorization`;
    await page.getByLabel("Total request attempts", { exact: false }).fill("1");
    await page.getByLabel("Total request bytes", { exact: false }).fill("1024");
    await page.getByLabel("Total reserved output tokens", { exact: false }).fill("64");
    await page.getByLabel("Authorization duration in seconds", { exact: false }).fill("120");
    await page.getByLabel("Operator identity for model usage", { exact: true }).fill("installed-purpose-reviewer");
    await page.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint.", exact: true }).check();
    await page.getByRole("checkbox", { name: "I authorize the selected model work, reviewed lab data and these usage limits.", exact: true }).check();
    expectedCompositionPurpose = item.purpose;
    await page.getByRole("button", { name: "Authorize reviewed model usage", exact: true }).click();
    await failOnBlockedWrite(page.getByText("Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.", { exact: true }).waitFor());
    const current = (await api("/ai/authorizations")).authorizations;
    assert.ok(Array.isArray(current));
    const selected = current.filter(row => ownedModelAuthorization(row)
      && row.approved_by === "installed-purpose-reviewer"
      && sameStructure(row.purposes, [item.purpose]));
    assert.equal(selected.length, 1);
    assert.equal(selected[0].status, "active");
    assert.equal(selected[0].usage?.requests, 0);
    const selectedCard = page.getByRole("article", { name: `Model authorization for ${model}` })
      .filter({ hasText: item.label });
    await selectedCard.waitFor({ state: "visible" });
    assert.equal(await selectedCard.count(), 1);
    stage = `composition-purpose-${item.purpose}-revoke`;
    await revokeOwnedModelAuthorization(selected[0].authorization_id);
    const revoked = (await api("/ai/authorizations")).authorizations;
    const result = Array.isArray(revoked)
      ? revoked.find(row => row.authorization_id === selected[0].authorization_id) : null;
    assert.ok(ownedModelAuthorization(result));
    assert.equal(result.status, "revoked");
    assert.deepEqual(result.purposes, [item.purpose]);
    assert.equal(result.usage?.requests, 0);
    expectedCompositionPurpose = undefined;
    recorded.push({ purpose: item.purpose, status: "revoked", model_requests: 0 });
    report.checks.push(`composition_purpose_${item.purpose}_persisted_and_revoked_without_request`);
  }
  stage = "composition-purpose-fixture-budget-after";
  const after = await fixtureState();
  assert.equal(after.request_count, 4);
  assert.deepEqual(after.purposes, purposes);
  assert.equal(compositionAuthorizationPosts, 2);
  assert.equal(authorizationRevokePosts, 3);
  report.model_purpose_authorizations = {
    original_authorization: "revoked",
    selected_purposes: recorded,
    receiver_purpose_selected: false,
    model_requests_before: before.request_count,
    model_requests_after: after.request_count,
  };
  report.cleanup = { ...(report.cleanup ?? {}), model_authorizations_revoked: true };
}

function waitForJourneyResponse(predicate, maximumMs = 12_000) {
  const timeout = remainingJourneyMs(maximumMs);
  page.setDefaultTimeout(timeout);
  return page.waitForResponse(predicate, { timeout });
}

function waitForJourneyRequest(predicate, maximumMs = 12_000) {
  const timeout = remainingJourneyMs(maximumMs);
  page.setDefaultTimeout(timeout);
  return page.waitForRequest(predicate, { timeout });
}

function fetchJourneyRoute(route) {
  return route.fetch({ timeout: remainingJourneyMs(12_000) });
}

function setJourneyActionTimeout(maximumMs = 12_000) {
  page.setDefaultTimeout(remainingJourneyMs(maximumMs));
}

function gotoJourney(url, options = {}) {
  const timeout = remainingJourneyMs(options.timeout ?? 12_000);
  page.setDefaultTimeout(timeout);
  return page.goto(url, { ...options, timeout });
}

function fetchFixture(url, options = {}) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(remainingJourneyMs(8_000)) });
}

async function waitForRunnerState(expected, timeoutMs = 45_000) {
  const deadline = Date.now() + remainingJourneyMs(timeoutMs);
  while (Date.now() < deadline) {
    const status = await api("/runner?profile_id=sandbox-execute.v1");
    if (status.state === expected) return status;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error("The owned Execute runner did not reach its expected state.");
}

async function waitForRunJob(jobId, timeoutMs = 120_000) {
  const deadline = Date.now() + remainingJourneyMs(timeoutMs);
  while (Date.now() < deadline) {
    const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
    if (["completed", "failed", "cancelled", "interrupted"].includes(job.state)) return job;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error("The reviewed generated-fixture run did not reach a terminal state.");
}

async function waitForRunApproval(jobId, timeoutMs = 20_000) {
  const deadline = Date.now() + remainingJourneyMs(timeoutMs);
  return pollForRunApproval({
    jobId,
    deadline,
    readJob: (identifier, remainingMs) => api(
      `/jobs/${encodeURIComponent(identifier)}`,
      Math.min(10_000, remainingMs),
    ),
    sleep: milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)),
  });
}

async function stopRunnerThroughUi() {
  if (!runnerStarted) return;
  const deadline = cleanupDeadline;
  while (Date.now() < deadline) {
    const status = await cleanupApi("/runner?profile_id=sandbox-execute.v1");
    if (status.state === "stopped") {
      runnerStarted = false;
      report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: true };
      return;
    }
    const stopLabel = status.state === "stale" ? "Reconcile stale host"
      : status.state === "unavailable" ? "Retry safe stop"
        : status.state === "ready" ? "Stop safely" : null;
    if (runnerStopPosts === 0 && stopLabel && (status.state !== "unavailable" || status.process === "authenticated")) {
      await page.goto(`${origin}/#/runners?profile=sandbox-execute.v1`, { waitUntil: "domcontentloaded", timeout: remainingCleanupMs(10_000) });
      await page.getByRole("button", { name: stopLabel, exact: true }).click({ timeout: remainingCleanupMs(8_000) });
    }
    await new Promise(resolve => setTimeout(resolve, Math.min(200, Math.max(1, deadline - Date.now()))));
  }
  throw new Error("Owned Execute runner did not reach stopped state inside the reserved cleanup budget.");
}

async function cancelOwnedRunThroughUi() {
  if (!runJobId) return;
  try {
    let job = await cleanupApi(`/jobs/${encodeURIComponent(runJobId)}`);
    if (!["completed", "failed", "cancelled", "interrupted"].includes(job.state)) {
      await page.goto(`${origin}/#/runs?job=${encodeURIComponent(runJobId)}`, { waitUntil: "domcontentloaded", timeout: remainingCleanupMs(10_000) });
      await page.getByRole("button", { name: "Cancel", exact: true }).click({ timeout: remainingCleanupMs(5_000) });
      const deadline = Math.min(cleanupDeadline, Date.now() + 25_000);
      while (Date.now() < deadline) {
        job = await cleanupApi(`/jobs/${encodeURIComponent(runJobId)}`);
        if (["completed", "failed", "cancelled", "interrupted"].includes(job.state)) break;
        await new Promise(resolve => setTimeout(resolve, 250));
      }
    }
    const terminal = ["completed", "failed", "cancelled", "interrupted"].includes(job.state);
    report.cleanup = { ...(report.cleanup ?? {}), execute_job_terminal: terminal, execute_job_final_state: terminal ? job.state : "nonterminal" };
    if (!terminal) throw new Error("Owned Execute job did not stop.");
  } catch {
    report.cleanup = { ...(report.cleanup ?? {}), execute_job_terminal: false };
  }
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
  const response = await fetchFixture(`${fixtureOrigin}/__fixture/state`, { redirect: "error" });
  assert.equal(response.status, 200);
  return response.json();
}

async function waitForFixtureCount(count, timeoutMs = 20_000) {
  return failOnBlockedWrite((async () => {
    const deadline = Date.now() + remainingJourneyMs(timeoutMs);
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
  const response = await fetchFixture(`${fixtureOrigin}/__fixture/release`, { method: "POST", redirect: "error" });
  assert.equal(response.status, 200);
}

async function ensureAssistantOpen() {
  const panel = page.locator("#experiment-assistant");
  if (!(await panel.isVisible())) await page.getByRole("button", { name: /^Assistant(?::|$)/ }).click();
  await failOnBlockedWrite(panel.waitFor({ state: "visible" }));
}

async function runExecuteSetupAction(actionStage, action) {
  stage = actionStage;
  setJourneyActionTimeout();
  await action();
}

async function executeGeneratedFixtureJourney(savedEnvelope, immutable) {
  remainingJourneyMs(1);
  savedScenarioId = savedEnvelope.application.scenario_id;
  savedScenarioDocument = immutable.scenario.document;
  await runExecuteSetupAction("execute-run-setup-review-run-link", () => page.getByRole("link", { name: "Review run", exact: true }).click());
  await runExecuteSetupAction("execute-run-setup-runs-route", () => page.waitForFunction(() => location.hash.startsWith("#/runs"), null, { timeout: remainingJourneyMs(10_000) }));
  await runExecuteSetupAction("execute-run-setup-execute-mode", () => page.getByRole("radio", { name: /Execute/ }).check());
  await runExecuteSetupAction("execute-run-setup-ai-off", () => page.getByRole("radio", { name: /Off\s+Deterministic/ }).check());
  await runExecuteSetupAction("execute-run-setup-environment-profile", () => page.getByRole("combobox", { name: "Environment profile", exact: true }).selectOption("sandbox-execute.v1"));
  await runExecuteSetupAction("execute-run-setup-provider-details", () => page.getByText("AI provider & environment details", { exact: true }).click());
  await runExecuteSetupAction("execute-run-setup-deterministic-provider", () => page.getByRole("combobox", { name: "Provider", exact: true }).selectOption("deterministic-offline.v1"));
  await runExecuteSetupAction("execute-run-setup-scope-details", () => page.getByText("Environment and scope references", { exact: true }).click());
  await runExecuteSetupAction("execute-run-setup-target-scope", () => page.getByRole("textbox", { name: /^Target scope\b/ }).fill("sandbox.workspace"));
  stage = "execute-run-setup-complete";
  report.checks.push("execute_graph_selected_with_ai_off_and_exact_sandbox_scope");

  stage = "execute-runner-enrollment";
  await gotoJourney(`${origin}/#/runners?profile=sandbox-execute.v1`, { waitUntil: "domcontentloaded" });
  await page.getByRole("combobox", { name: "Experiment runner profile", exact: true }).selectOption("sandbox-execute.v1");
  const initialRunner = await api("/runner?profile_id=sandbox-execute.v1");
  assert.equal(initialRunner.state, "unbootstrapped", "Refuse to reuse a runner that predates this owned run store");
  await page.getByRole("button", { name: "Verify & enroll", exact: true }).click();
  const enrolled = await waitForRunnerState("stopped", 120_000);
  assert.equal(enrolled.enrollment, "active");
  await page.getByRole("button", { name: "Start authenticated host", exact: true }).click();
  runnerStarted = true;
  const ready = await waitForRunnerState("ready");
  assert.equal(ready.process, "authenticated");
  report.runner = { profile_id: "sandbox-execute.v1", enrollment: "active", process: "authenticated", state: "ready" };
  report.checks.push("owned_execute_runner_enrolled_and_authenticated_through_ui");

  stage = "execute-run-preflight";
  await gotoJourney(`${origin}/#/runs?prepare=1`, { waitUntil: "domcontentloaded" });
  const preflight = waitForJourneyResponse(response => new URL(response.url()).pathname === "/api/v1/runs/preflight" && response.request().method() === "POST", 25_000);
  await page.getByRole("button", { name: "Check run", exact: true }).click();
  const preflightResponse = await preflight;
  assert.equal(preflightResponse.status(), 200);
  const reviewed = await preflightResponse.json();
  report.execute_preflight_diagnostic = preflightDiagnostic(reviewed, {
    profileId: "sandbox-execute.v1",
    actionIds: ["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1", "sandbox.cleanup.v1"],
  });
  assert.equal(reviewed.status, "approval_required");
  assert.equal(reviewed.plan?.mode, "execute");
  assert.equal(reviewed.plan?.runner_profile_id, "sandbox-execute.v1");
  assert.equal(reviewed.autonomy, "off");
  assert.equal(reviewed.ai_enabled, false);
  assert.equal(reviewed.plan?.autonomy, "off");
  assert.equal(reviewed.plan?.ai_enabled, false);
  assert.deepEqual(reviewed.actions, ["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1", "sandbox.cleanup.v1"]);
  assert.deepEqual(reviewed.plan?.steps?.map(step => ({
    step_id: step.step_id,
    behavior_id: step.behavior_id,
    action_id: step.action_id,
    parameters: step.parameters,
  })), [
    { step_id: "create_fixture", behavior_id: "sandbox.fixture.create.v1", action_id: "sandbox.fixture.create.v1", parameters: { record_count: 4 } },
    { step_id: "transform_fixture", behavior_id: "sandbox.fixture.transform.v1", action_id: "sandbox.fixture.transform.v1", parameters: { redact_values: true } },
    { step_id: "cleanup_workspace", behavior_id: "sandbox.cleanup.v1", action_id: "sandbox.cleanup.v1", parameters: { verify_removal: true } },
  ]);
  assert.ok(digest(reviewed.approval_binding?.plan_digest));
  report.execute_preflight = { status: reviewed.status, mode: reviewed.plan.mode, autonomy: reviewed.autonomy, ai_enabled: reviewed.ai_enabled, ai_provider_id: reviewed.plan.ai_provider?.provider_id, runner_profile_id: reviewed.plan.runner_profile_id, actions: reviewed.actions, plan_digest: reviewed.approval_binding.plan_digest };
  const submittedResponsePromise = waitForJourneyResponse(response => new URL(response.url()).pathname === "/api/v1/runs" && response.request().method() === "POST", 25_000);
  await page.getByRole("button", { name: "Create approval-gated job", exact: true }).click();
  const submittedResponse = await submittedResponsePromise;
  assert.equal(submittedResponse.status(), 202);
  const submitted = await submittedResponse.json();
  runJobId = submitted.job?.job_id;
  assert.match(runJobId ?? "", /^job-[0-9a-f]{32}$/);
  assert.equal(submitted.job.job_id, runJobId);
  assert.ok(["queued", "planning", "awaiting_approval"].includes(submitted.job.state));
  stage = "execute-run-approval-state";
  const approvalJob = await waitForRunApproval(runJobId, remainingJourneyMs(20_000));
  assert.equal(approvalJob.job_id, runJobId);
  assert.equal(approvalJob.state, "awaiting_approval");
  page.setDefaultTimeout(remainingJourneyMs(10_000));
  stage = "execute-run-approval";
  const terminalJobPromise = waitForRunJob(runJobId, remainingJourneyMs(110_000));
  await page.getByRole("checkbox", { name: /I approve this exact immutable job envelope once/ }).check();
  await page.getByLabel("Operator identity for this job", { exact: true }).fill("installed-fixture-execute-reviewer");
  await page.getByRole("button", { name: "Approve and release job", exact: true }).click();
  const completedJob = await terminalJobPromise;
  assert.equal(completedJob.state, "completed");
  runId = completedJob.result_ref;
  assert.match(runId ?? "", /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/);
  const run = await api(`/runs/${encodeURIComponent(runId)}`);
  assert.notEqual(run.is_demo, true);
  assert.equal(run.mode, "execute");
  const runAutonomy = run.autonomy ?? run.autonomy_level ?? run.plan?.autonomy;
  assert.equal(runAutonomy, "off");
  assert.equal(run.scenario_id, savedScenarioId);
  assert.equal(run.runner_profile_id, "sandbox-execute.v1");
  assert.equal(run.steps?.length, 3);
  assert.deepEqual(run.steps.map(step => step.step_id), ["create_fixture", "transform_fixture", "cleanup_workspace"]);
  assert.deepEqual(run.steps.map(step => step.behavior_id), ["sandbox.fixture.create.v1", "sandbox.fixture.transform.v1", "sandbox.cleanup.v1"]);
  const observed = (run.evidence?.records ?? []).filter(record => record.provenance === "observed");
  const actionByStep = { create_fixture: "sandbox.fixture.create.v1", transform_fixture: "sandbox.fixture.transform.v1" };
  assert.ok(observed.length >= 1 && observed.length <= 2, "Require real collector observations from this exact generated run");
  assert.equal(run.run_id, runId);
  assert.equal(new Set(observed.map(record => record.evidence_id)).size, observed.length);
  assert.ok(observed.every(record => record.run_id === runId
    && record.producer === "collector.filesystem.sandbox.v1"
    && Object.hasOwn(actionByStep, record.step_id)
    && record.behavior_id === actionByStep[record.step_id]
    && record.action_id === actionByStep[record.step_id]
    && /^evidence-[0-9a-f]{20}$/.test(record.evidence_id)));
  assert.equal(run.cleanup?.attempted, true);
  assert.equal(run.cleanup?.success, true);
  report.generated_fixture_execute = {
    status: "completed",
    native_execution: true,
    mode: run.mode,
    autonomy: runAutonomy,
    scenario_id: run.scenario_id,
    runner_profile_id: run.runner_profile_id,
    run_id: run.run_id,
    job_id: runJobId,
    step_count: run.steps.length,
    observed_metadata_record_count: observed.length,
    observed_evidence_ids: observed.map(record => record.evidence_id),
    observed_records: observed.map(record => ({ evidence_id: record.evidence_id, run_id: record.run_id, step_id: record.step_id, behavior_id: record.behavior_id, action_id: record.action_id, producer: record.producer })),
    cleanup: { attempted: run.cleanup.attempted, success: run.cleanup.success },
  };
  report.checks.push("approved_fixture_execute_run_completed_with_explicit_cleanup_and_observed_generated_fixture_metadata");

  stage = "execute-run-result-review";
  const reviewRun = page.locator(".live-console").getByRole("button", { name: "Review", exact: true });
  await reviewRun.waitFor({ state: "visible", timeout: remainingJourneyMs(20_000) });
  assert.equal(await reviewRun.isEnabled(), true, "The live console must expose a usable Review control for its loaded result.");
  await reviewRun.click();
  await page.waitForURL(url => url.origin === origin && url.hash === `#/runs/${encodeURIComponent(runId)}`, { timeout: remainingJourneyMs(12_000) });
  const selectedRun = page.getByRole("region", { name: "Selected run", exact: true });
  await selectedRun.waitFor({ state: "visible", timeout: remainingJourneyMs(12_000) });
  await selectedRun.getByText("Completed", { exact: true }).waitFor({ state: "visible", timeout: remainingJourneyMs(5_000) });
  const runIdentityPanel = page.locator(".historical-run-page details.run-review-details")
    .filter({ has: page.getByText("Run identity, environment and technical record", { exact: true }) });
  assert.equal(await runIdentityPanel.count(), 1, "The canonical run identity disclosure must be unique.");
  const runIdentity = runIdentityPanel.getByText("Run identity, environment and technical record", { exact: true });
  await runIdentity.click();
  const canonicalIdentity = await page.evaluate(readCanonicalRunIdentity);
  assert.deepEqual(canonicalIdentity, { identity_sections: 1, run_id_rows: 1, run_id_values: 1, run_id: runId },
    "The canonical labeled Run ID field must match the completed run.");
  await runIdentity.click();
  const runHistoryLink = page.locator(".historical-run-page").getByRole("link", { name: "Run history", exact: true });
  await runHistoryLink.scrollIntoViewIfNeeded({ timeout: remainingJourneyMs(5_000) });
  report.checks.push("completed_generated_fixture_run_opened_from_live_console_review_and_verified_in_canonical_run_view");
  await captureAssistantView("assistant-generated-fixture-execute-result");

  stage = "execute-runner-cleanup";
  await stopRunnerThroughUi();
  assert.equal(report.cleanup.runner_stopped, true);
  report.checks.push("execute_runner_stopped_through_ui_and_authenticated_status");

  stage = "detection-source-selection";
  const assistantPanel = page.locator("#experiment-assistant");
  if (await assistantPanel.isVisible()) {
    await page.getByRole("button", { name: "Close assistant", exact: true }).click();
  }
  await gotoJourney(`${origin}/#/detection-lab?run=${encodeURIComponent(runId)}&create=1`, { waitUntil: "domcontentloaded" });
  await page.getByRole("region", { name: "Create detection from run", exact: true }).waitFor();
  await page.getByRole("combobox", { name: /^Behavior to detect\b/ }).selectOption("sandbox.fixture.create.v1");
  await page.getByRole("combobox", { name: "Rule language", exact: true }).selectOption("sqlite");
  await page.getByRole("combobox", { name: /^Development case\b/ }).selectOption("benign");
  const detectionContextResponse = waitForJourneyResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/detection-context" && response.request().method() === "POST");
  await page.getByRole("button", { name: "Draft rule with Assistant", exact: true }).click();
  await ensureAssistantOpen();
  const currentSelection = page.getByRole("button", { name: "Current selection", exact: true });
  if (await currentSelection.isVisible()) await currentSelection.click();
  expectedDetectionContext = await (await detectionContextResponse).json();
  assert.equal(expectedDetectionContext.selected?.run_id, runId);
  assert.equal(expectedDetectionContext.selected?.behavior_id, "sandbox.fixture.create.v1");
  assert.equal(expectedDetectionContext.selected?.target_language, "sqlite");
  assert.equal(expectedDetectionContext.selected?.case_role, "benign");
  assert.ok(digest(expectedDetectionContext.context_digest));
  await page.getByRole("button", { name: "Assistant settings", exact: true }).click();
  await page.getByRole("combobox", { name: /^(AI mode|Assistant mode)\b/ }).selectOption("assist");
  await page.getByRole("combobox", { name: "Provider", exact: true }).selectOption(providerId);
  await page.getByRole("button", { name: "Assistant settings", exact: true }).click();
  await page.getByRole("textbox", { name: "What would you like to do?", exact: true }).fill("Draft a SQLite rule for the generated fixture observations.");
  stage = "detection-assistant-submit";
  const detectionSubmit = waitForJourneyResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/turns" && response.request().method() === "POST", 25_000);
  await page.getByRole("button", { name: "Start work", exact: true }).click();
  const detectionParent = await detectionSubmit;
  assert.equal(detectionParent.status(), 202);
  const detectionParentEnvelope = await detectionParent.json();
  const detectionParentId = detectionParentEnvelope.job?.job_id;
  assert.match(detectionParentId ?? "", /^job-[0-9a-f]{32}$/);
  const finalFixture = await waitForFixtureCount(4, 40_000);
  assert.deepEqual(finalFixture.purposes, purposes);
  let detectionOperation, detectionChildId;
  const childDeadline = Date.now() + remainingJourneyMs(20_000);
  while (Date.now() < childDeadline) {
    detectionOperation = await api(`/assistance/turns/${encodeURIComponent(detectionParentId)}`);
    detectionChildId = detectionOperation.turn?.active_child?.job_id;
    if (detectionChildId) break;
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  assert.match(detectionChildId ?? "", /^job-[0-9a-f]{32}$/);
  detectionJobId = detectionChildId;
  let sourceEnvelope;
  const proposalDeadline = Date.now() + remainingJourneyMs(30_000);
  while (Date.now() < proposalDeadline) {
    sourceEnvelope = await api(`/ai/detection-create-jobs/${encodeURIComponent(detectionJobId)}`);
    if (sourceEnvelope.review_ready) break;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  assert.equal(sourceEnvelope.job?.kind, "detection.ai.create");
  assert.equal(sourceEnvelope.review_ready, true);
  assert.equal(sourceEnvelope.proposal?.selected?.run_id, runId);
  assert.equal(sourceEnvelope.proposal?.selected?.behavior_id, "sandbox.fixture.create.v1");
  assert.equal(sourceEnvelope.proposal?.selected?.target_language, "sqlite");
  assert.equal(sourceEnvelope.proposal?.selected?.case_role, "benign");
  assert.equal(sourceEnvelope.proposal?.selected?.source_binding_digest, expectedDetectionContext.selected?.source_binding_digest);
  assert.deepEqual(sourceEnvelope.proposal?.evidence_refs, [observed[0].evidence_id]);
  detectionProposalDigest = sourceEnvelope.proposal.proposal_digest;
  assert.ok(digest(detectionProposalDigest));
  report.detection_proposal = {
    job_id: detectionJobId,
    proposal_digest: detectionProposalDigest,
    run_id: runId,
    behavior_id: sourceEnvelope.proposal.selected.behavior_id,
    target_language: sourceEnvelope.proposal.selected.target_language,
    development_case: sourceEnvelope.proposal.selected.case_role,
    cited_observed_evidence_ids: sourceEnvelope.proposal.evidence_refs,
    fixture_limitations_count: sourceEnvelope.proposal.limitations.length,
  };
  await gotoJourney(`${origin}/#/detection-lab?run=${encodeURIComponent(runId)}&create=1&create_job=${encodeURIComponent(detectionJobId)}`, { waitUntil: "domcontentloaded" });
  const reviewRegion = page.getByRole("region", { name: "Review new detection", exact: true });
  await reviewRegion.getByRole("heading", { name: "Review the proposed rule", exact: true }).waitFor();
  stage = "detection-source-review-and-evaluate";
  await reviewRegion.getByLabel("Reviewed by", { exact: true }).fill("Installed generated fixture reviewer");
  await reviewRegion.getByRole("button", { name: "Save and evaluate this rule", exact: true }).click();
  await reviewRegion.getByRole("heading", { name: "Rule saved and evaluated", exact: true }).waitFor({ timeout: remainingJourneyMs(25_000) });
  const savedDetection = await api(`/ai/detection-create-jobs/${encodeURIComponent(detectionJobId)}`);
  assert.equal(savedDetection.decision?.decision, "accept");
  assert.ok(savedDetection.application?.candidate_id);
  assert.ok(savedDetection.application?.evaluation_id);
  assert.equal(savedDetection.application?.run_id, runId);
  assert.equal(savedDetection.application?.development_case, true);
  assert.ok(savedDetection.evaluation?.result);
  const evaluationResult = savedDetection.evaluation.result;
  assert.equal(typeof evaluationResult.state, "string");
  assert.ok(Number.isSafeInteger(evaluationResult.match_count) && evaluationResult.match_count >= 0);
  assert.ok(Array.isArray(evaluationResult.evaluated_evidence_ids));
  assert.ok(Array.isArray(evaluationResult.matched_evidence_ids));
  assert.equal(evaluationResult.match_count, evaluationResult.matched_evidence_ids.length);
  assert.ok(evaluationResult.matched_evidence_ids.every(id => evaluationResult.evaluated_evidence_ids.includes(id)));
  assert.equal(savedDetection.evaluation.case_role, "benign");
  assert.equal(savedDetection.evaluation.classification?.activity_label, "benign");
  assert.equal(savedDetection.evaluation.classification?.evaluation_use, "development");
  assert.equal(savedDetection.evaluation.development_case, true);
  report.detection_application = {
    candidate_id: savedDetection.application.candidate_id,
    evaluation_id: savedDetection.application.evaluation_id,
    run_id: savedDetection.application.run_id,
    development_case: savedDetection.application.development_case,
    backend_executed: savedDetection.evaluation.backend.executed,
    result_state: evaluationResult.state,
    observed_match_count: evaluationResult.match_count,
  };
  const candidateId = savedDetection.application.candidate_id;
  const evaluationId = savedDetection.application.evaluation_id;
  const candidateRoute = `${origin}/#/detection-lab?candidate=${encodeURIComponent(candidateId)}&candidate_scope=registry&run=${encodeURIComponent(runId)}`;
  stage = "detection-saved-candidate-reopen";
  await gotoJourney(candidateRoute, { waitUntil: "domcontentloaded", timeout: 15_000 });
  const reopenedCandidateButton = page.locator(".candidate-list-items button[aria-pressed='true']");
  await reopenedCandidateButton.waitFor({ state: "visible", timeout: remainingJourneyMs(10_000) });
  const reopenedCandidateEnvelope = await api(`/detections/${encodeURIComponent(candidateId)}`);
  const reopenedCandidateResource = reopenedCandidateEnvelope.candidate;
  assert.equal(reopenedCandidateResource?.id, candidateId);
  const reopenedDocument = reopenedCandidateResource?.document;
  assert.equal(reopenedDocument?.candidate_id, candidateId);
  assert.equal(reopenedDocument?.target_language, "sqlite");
  assert.equal(reopenedDocument?.rule_source, sourceEnvelope.proposal.source);
  assert.equal(reopenedDocument?.definition_digest, savedDetection.evaluation.candidate?.definition_digest);
  assert.equal(reopenedDocument?.revision, savedDetection.evaluation.candidate?.revision);
  await page.getByRole("heading", { name: reopenedDocument.title, exact: true }).waitFor({ timeout: remainingJourneyMs(10_000) });
  assert.ok((await reopenedCandidateButton.innerText()).includes(reopenedDocument.title));
  const reopenedEvaluations = await api(`/detections/${encodeURIComponent(candidateId)}/evaluations`);
  const reopenedEvaluation = reopenedEvaluations.evaluations?.find(item => item.evaluation_id === evaluationId);
  assert.ok(reopenedEvaluation, "Saved development evaluation must be retrievable by its receipt ID");
  assert.equal(reopenedEvaluation.candidate?.candidate_id, candidateId);
  assert.equal(reopenedEvaluation.candidate?.definition_digest, reopenedDocument.definition_digest);
  assert.equal(reopenedEvaluation.candidate?.revision, reopenedDocument.revision);
  assert.equal(reopenedEvaluation.source?.run_id, runId);
  assert.equal(reopenedEvaluation.case_role, "benign");
  assert.equal(reopenedEvaluation.development_case, true);
  assert.equal(reopenedEvaluation.classification?.evaluation_use, "development");
  assert.equal(reopenedEvaluation.backend?.executed, true);
  await page.reload({ waitUntil: "domcontentloaded", timeout: remainingJourneyMs(15_000) });
  await reopenedCandidateButton.waitFor({ state: "visible", timeout: remainingJourneyMs(10_000) });
  const reopenedAgain = await api(`/detections/${encodeURIComponent(candidateId)}`);
  const evaluationsAgain = await api(`/detections/${encodeURIComponent(candidateId)}/evaluations`);
  assert.equal(reopenedAgain.candidate?.document?.definition_digest, reopenedDocument.definition_digest);
  assert.ok(evaluationsAgain.evaluations?.some(item => item.evaluation_id === evaluationId && item.source?.run_id === runId && item.development_case === true));
  stage = "detection-saved-evaluation-rendered-reopen";
  await page.getByRole("tab", { name: "Run evaluations", exact: true }).click();
  const retainedEvaluationCard = page.locator("article.detection-evaluation-report").filter({ hasText: evaluationId });
  await retainedEvaluationCard.waitFor({ state: "visible", timeout: remainingJourneyMs(10_000) });
  assert.equal(await retainedEvaluationCard.count(), 1, "The exact retained evaluation must appear once in the rendered history.");
  const developmentEvidence = retainedEvaluationCard.getByText("Development evidence", { exact: true });
  await developmentEvidence.waitFor({ state: "visible", timeout: remainingJourneyMs(5_000) });
  assert.equal(await retainedEvaluationCard.getByText("Development data", { exact: true }).isVisible(), true);
  const immutableRecordSummary = retainedEvaluationCard.getByText("Inspect immutable evaluation record", { exact: true });
  await immutableRecordSummary.click();
  const immutableRecord = retainedEvaluationCard.locator("pre").filter({ hasText: evaluationId });
  await immutableRecord.waitFor({ state: "visible", timeout: remainingJourneyMs(5_000) });
  const renderedEvaluation = JSON.parse(await immutableRecord.innerText());
  assert.equal(renderedEvaluation.evaluation_id, evaluationId);
  assert.equal(renderedEvaluation.candidate?.candidate_id, candidateId);
  assert.equal(renderedEvaluation.source?.run_id, runId);
  assert.equal(renderedEvaluation.development_case, true);
  await immutableRecordSummary.click();
  report.detection_reopened = {
    candidate_id: candidateId,
    revision: reopenedDocument.revision,
    definition_digest: reopenedDocument.definition_digest,
    evaluation_id: evaluationId,
    run_id: reopenedEvaluation.source.run_id,
    development_case: reopenedEvaluation.development_case,
    evaluation_use: reopenedEvaluation.classification.evaluation_use,
  };
  const resultHeading = retainedEvaluationCard.locator(".evaluation-result-title");
  assert.equal(await resultHeading.innerText(), `${evaluationResult.match_count} matched ${evaluationResult.match_count === 1 ? "record" : "records"}`);
  report.detection_reopened_layout = [];
  const originalViewport = page.viewportSize();
  try {
    for (const viewport of [{ width: 1440, height: 900 }, { width: 1366, height: 768 }]) {
      stage = `detection-evaluation-layout-${viewport.width}x${viewport.height}`;
      await page.setViewportSize(viewport);
      await resultHeading.evaluate(element => element.scrollIntoView({ block: "start", inline: "nearest", behavior: "instant" }));
      const layout = await retainedEvaluationCard.evaluate(card => {
        const heading = card.querySelector(".evaluation-result-title");
        const facts = card.querySelector(":scope > .data-list");
        if (!heading || !facts) return null;
        const cardRect = card.getBoundingClientRect(), titleRect = heading.getBoundingClientRect();
        const factsRect = facts.getBoundingClientRect();
        const hit = document.elementFromPoint(titleRect.left + titleRect.width / 2, titleRect.top + titleRect.height / 2);
        return {
          card_width: cardRect.width,
          facts_width: factsRect.width,
          facts_span_card: factsRect.width >= card.clientWidth - 32,
          facts_contained: factsRect.left >= cardRect.left && factsRect.right <= cardRect.right + 1,
          heading_in_view: titleRect.top >= 0 && titleRect.bottom <= document.documentElement.clientHeight,
          heading_unobscured: hit === heading || heading.contains(hit),
        };
      });
      report.detection_reopened_layout.push({ viewport, ...(layout ?? { measurement_available: false }) });
      await captureAssistantView(viewport.width === 1440 ? "assistant-generated-fixture-detection-result-reopened" : "assistant-generated-fixture-detection-result-reopened-1366x768");
      assert.ok(layout?.facts_span_card && layout.facts_contained, "Evaluation facts must use the report width, not collapse into a nested grid column.");
      assert.ok(layout.heading_in_view, "The measured conclusion must be inside the viewport.");
      assert.ok(layout.heading_unobscured, "The measured conclusion must not be covered by another surface.");
    }
  } finally {
    await page.setViewportSize(originalViewport);
  }
  report.checks.push("saved_detection_candidate_and_development_evaluation_reopened_by_exact_ids");
  report.checks.push("reviewed_fixture_detection_saved_and_evaluated_against_its_development_run");
}

stage = "browser-launch";
report.deadline_controls = {
  outer_budget_remaining_at_browser_launch_ms: Math.max(0, outerDeadlineMs - Date.now()),
  work_deadline_enforced: true,
  cleanup_reserve_ms: 55_000,
  outer_margin_ms: 2_000,
};
try {
  try {
    browser = await chromium.launch({ timeout: remainingJourneyMs(25_000), headless: true, args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"] });
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
  context.setDefaultTimeout(Math.min(12_000, remainingJourneyMs(12_000)));
  stage = "browser-routing-setup";
  await context.routeWebSocket("**/*", socket => socket.close());
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    let allowed = url.origin === origin && ["GET", "HEAD"].includes(method), reason;
    if (url.origin !== origin) reason = "non_loopback";
    else if (!["GET", "HEAD", "POST"].includes(method)) reason = "method_not_allowed";
    else if (method === "POST" && Date.now() >= journeyDeadline
      && url.pathname !== "/api/v1/runner/stop"
      && !(runJobId && url.pathname === `/api/v1/jobs/${runJobId}/cancel`)
      && !((authorizationPosts + compositionAuthorizationPosts > 0) && Date.now() < cleanupDeadline
        && /^\/api\/v1\/ai\/authorizations\/ai-authorization-[0-9a-f]{32}\/revoke$/.test(url.pathname))) reason = "work_deadline_expired";
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
          const initial = authorizationPosts === 0 && !purposeProofStarted && exactKeys(body, ["provider", "purposes", "data_scope", "limits", "expires_in_seconds", "approved_by", "usage_authorized", "local_endpoint_authorized"])
            && sameStructure(body.provider, providerConfig)
            && Array.isArray(body.purposes) && sameStructure([...body.purposes].sort(), authorizedPurposes)
            && body.data_scope === "reviewed_lab_context"
            && exactKeys(body.limits, ["max_requests", "max_request_bytes", "max_reserved_output_tokens"])
            && body.limits.max_requests === 4 && body.limits.max_request_bytes === 2_097_152
            && body.limits.max_reserved_output_tokens === 256 && body.expires_in_seconds === 300
            && body.approved_by === "installed-fixture-reviewer" && body.usage_authorized === true
            && body.local_endpoint_authorized === true;
          const nextPurpose = compositionPurposes[compositionAuthorizationPosts]?.purpose;
          const singlePurpose = purposeProofStarted && authorizationPosts === 1 && compositionAuthorizationPosts < 2
            && expectedCompositionPurpose === nextPurpose
            && exactKeys(body, ["provider", "purposes", "data_scope", "limits", "expires_in_seconds", "approved_by", "usage_authorized", "local_endpoint_authorized"])
            && sameStructure(body.provider, providerConfig)
            && sameStructure(body.purposes, [nextPurpose])
            && body.data_scope === "reviewed_lab_context"
            && exactKeys(body.limits, ["max_requests", "max_request_bytes", "max_reserved_output_tokens"])
            && body.limits.max_requests === 1 && body.limits.max_request_bytes === 1024
            && body.limits.max_reserved_output_tokens === 64 && body.expires_in_seconds === 120
            && body.approved_by === "installed-purpose-reviewer" && body.usage_authorized === true
            && body.local_endpoint_authorized === true;
          allowed = initial || singlePurpose;
          if (initial) authorizationPosts += 1;
          else if (singlePurpose) compositionAuthorizationPosts += 1;
          else reason = "authorization_out_of_scope";
        } else if (/^\/api\/v1\/ai\/authorizations\/ai-authorization-[0-9a-f]{32}\/revoke$/.test(path)) {
          const authorizationId = path.slice("/api/v1/ai/authorizations/".length, -"/revoke".length);
          const priorAttempts = revokeAttemptsById.get(authorizationId) ?? 0;
          allowed = authorizationPosts + compositionAuthorizationPosts > 0 && authorizationRevokePosts < 6
            && authorizationId === expectedRevokeAuthorizationId
            && priorAttempts < 2 && exactKeys(body, []);
          if (allowed) {
            authorizationRevokePosts += 1;
            revokeAttemptsById.set(authorizationId, priorAttempts + 1);
          } else reason = "authorization_revoke_out_of_scope";
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
          const graphTurn = assistancePosts === 0 && sameStructure(body?.selection, expectedContext?.selected)
            && body?.message === "Build a two-step fixture experiment for review.";
          const detectionTurn = assistancePosts === 1 && sameStructure(body?.selection, expectedDetectionContext?.selected)
            && body?.message === "Draft a SQLite rule for the generated fixture observations.";
          allowed = assistancePosts < 2 && exactKeys(body, ["submission_id", "selection", "context_digest", "message", "autonomy", "provider_id"])
            && /^[0-9a-f-]{36}$/.test(body.submission_id) && digest(body.context_digest)
            && (graphTurn || detectionTurn)
            && body.context_digest === (graphTurn ? expectedContext?.context_digest : expectedDetectionContext?.context_digest)
            && body.autonomy === "assist" && body.provider_id === providerId;
          if (allowed) assistancePosts += 1; else reason = "assistant_request_out_of_scope";
        } else if (path === "/api/v1/assistance/detection-source") {
          allowed = detectionSourcePosts === 0 && exactKeys(body, ["run_id"])
            && body.run_id === runId;
          if (allowed) detectionSourcePosts += 1; else reason = "detection_source_read_scope";
        } else if (path === "/api/v1/assistance/detection-context") {
          const keys = ["run_id", "source_binding_digest", "behavior_id", "target_language", "case_role"];
          allowed = detectionContextPosts === 0 && exactKeys(body, keys) && body.run_id === runId
            && body.behavior_id === "sandbox.fixture.create.v1" && body.target_language === "sqlite"
            && body.case_role === "benign" && digest(body.source_binding_digest);
          if (allowed) detectionContextPosts += 1; else reason = "detection_context_out_of_scope";
        } else if (path === "/api/v1/runs/preflight") {
          allowed = runPreflightPosts === 0 && exactRunPayload(body);
          if (allowed) { runPreflightPosts += 1; runPayload = structuredClone(body); } else reason = "execute_preflight_out_of_scope";
        } else if (path === "/api/v1/runs") {
          allowed = runSubmitPosts === 0 && runPayload && sameStructure(body, runPayload);
          if (allowed) runSubmitPosts += 1; else reason = "execute_submission_out_of_scope";
        } else if (path === "/api/v1/runner/bootstrap") {
          allowed = runnerBootstrapPosts === 0 && exactKeys(body, ["profile_id"]) && body.profile_id === "sandbox-execute.v1";
          if (allowed) runnerBootstrapPosts += 1; else reason = "runner_bootstrap_out_of_scope";
        } else if (path === "/api/v1/runner/start") {
          allowed = runnerStartPosts === 0 && exactKeys(body, ["profile_id"]) && body.profile_id === "sandbox-execute.v1";
          if (allowed) { runnerStartPosts += 1; runnerStarted = true; } else reason = "runner_start_out_of_scope";
        } else if (path === "/api/v1/runner/stop") {
          allowed = runnerStarted && runnerStopPosts === 0 && exactKeys(body, ["profile_id"]) && body.profile_id === "sandbox-execute.v1";
          if (allowed) runnerStopPosts += 1; else reason = "runner_stop_out_of_scope";
        } else if (path.match(/^\/api\/v1\/jobs\/(job-[0-9a-f]{32})\/approval$/)) {
          const id = path.match(/^\/api\/v1\/jobs\/(job-[0-9a-f]{32})\/approval$/)?.[1];
          allowed = Boolean(runJobId && id === runJobId) && approvalPosts === 0
            && exactKeys(body, ["approved_by"]) && body.approved_by === "installed-fixture-execute-reviewer";
          if (allowed) approvalPosts += 1; else reason = "execute_approval_out_of_scope";
        } else if (path.match(/^\/api\/v1\/jobs\/(job-[0-9a-f]{32})\/cancel$/)) {
          const id = path.match(/^\/api\/v1\/jobs\/(job-[0-9a-f]{32})\/cancel$/)?.[1];
          allowed = Boolean(runJobId && id === runJobId) && exactKeys(body, []);
          if (!allowed) reason = "execute_cancellation_out_of_scope";
        } else if (path.match(/^\/api\/v1\/ai\/detection-create-jobs\/(job-[0-9a-f]{32})\/validate$/)) {
          const id = path.match(/^\/api\/v1\/ai\/detection-create-jobs\/(job-[0-9a-f]{32})\/validate$/)?.[1];
          allowed = Boolean(detectionJobId && id === detectionJobId) && detectionValidatePosts === 0
            && exactKeys(body, ["proposal_digest", "title", "source"])
            && body.proposal_digest === detectionProposalDigest
            && body.title === "Generated fixture collection rule"
            && body.source === "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'";
          if (allowed) detectionValidatePosts += 1; else reason = "detection_source_validation_out_of_scope";
        } else if (path.match(/^\/api\/v1\/ai\/detection-create-jobs\/(job-[0-9a-f]{32})\/review$/)) {
          const id = path.match(/^\/api\/v1\/ai\/detection-create-jobs\/(job-[0-9a-f]{32})\/review$/)?.[1];
          allowed = Boolean(detectionJobId && id === detectionJobId) && detectionReviewPosts === 0
            && exactKeys(body, ["decision", "proposal_digest", "reviewed_digest", "title", "source", "reviewed_by"])
            && body.decision === "accept" && body.proposal_digest === detectionProposalDigest
            && body.reviewed_digest === detectionValidatedDigest
            && body.title === "Generated fixture collection rule"
            && body.source === "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'"
            && body.reviewed_by === "Installed generated fixture reviewer";
          if (allowed) detectionReviewPosts += 1; else reason = "detection_source_review_out_of_scope";
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
      const response = await fetchJourneyRoute(route);
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
    if (method === "POST" && detectionJobId
      && url.pathname === `/api/v1/ai/detection-create-jobs/${detectionJobId}/validate`) {
      const response = await fetchJourneyRoute(route);
      let validation;
      try { validation = await response.json(); } catch { validation = null; }
      if (response.status() === 200 && exactKeys(validation, ["proposal_digest", "reviewed_digest", "title", "source", "validation"])
        && validation.proposal_digest === detectionProposalDigest && digest(validation.reviewed_digest)
        && validation.title === "Generated fixture collection rule"
        && validation.source === "SELECT fixture_id FROM logs WHERE artifact_type = 'collector_observation'"
        && validation.validation?.valid === true && validation.validation?.target_language === "sqlite") {
        detectionValidatedDigest = validation.reviewed_digest;
      }
      await route.fulfill({ response });
      return;
    }
    if (method === "POST" && url.pathname === "/api/v1/runs") {
      const response = await fetchJourneyRoute(route);
      let submission;
      try { submission = await response.json(); } catch { submission = null; }
      const jobId = submission?.job?.job_id;
      if (response.status() === 202 && typeof jobId === "string" && /^job-[0-9a-f]{32}$/.test(jobId)) runJobId = jobId;
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
  await gotoJourney(origin, { waitUntil: "domcontentloaded", timeout: 15_000 });
  stage = "browser-capability-entry";
  await page.getByLabel("One-time connection code", { exact: false }).fill(capability);
  stage = "browser-capability-connect";
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  capability = "";
  stage = "browser-session-wait";
  await page.waitForFunction(() => sessionStorage.getItem("bluefire.browser-session.v1") !== null, null, { timeout: remainingJourneyMs(10_000) });
  report.checks.push("normal_ephemeral_browser_session");

  stage = "provider-configuration";
  await gotoJourney(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await failOnBlockedWrite(page.getByRole("heading", { name: "Model connection", exact: true }).waitFor());
  stage = "provider-api-style";
  await page.getByRole("combobox", { name: "API style", exact: true }).selectOption("openai_responses");
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
  await page.getByRole("checkbox", { name: "Create a detection from observations", exact: true }).check();
  await page.getByLabel("Total request attempts", { exact: false }).fill("4");
  await page.getByLabel("Total request bytes", { exact: false }).fill("2097152");
  await page.getByLabel("Total reserved output tokens", { exact: false }).fill("256");
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
  const graphContextResponse = failOnBlockedWrite(waitForJourneyResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/graph-context" && response.request().method() === "POST")
    .then(response => ({ response }), () => ({ timedOut: true })));
  await gotoJourney(`${origin}/#/builder`, { waitUntil: "domcontentloaded" });
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
  const newExperimentContextResponse = failOnBlockedWrite(waitForJourneyResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/graph-context" && response.request().method() === "GET")
    .then(response => ({ response }), () => ({ timedOut: true })));
  const newExperimentContextRequest = waitForJourneyRequest(request => new URL(request.url()).pathname === "/api/v1/assistance/graph-context" && request.method() === "GET")
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
  const submitResponse = failOnBlockedWrite(waitForJourneyResponse(response => new URL(response.url()).pathname === "/api/v1/assistance/turns" && response.request().method() === "POST")
    .then(response => ({ response }), () => ({ timedOut: true })));
  const submitRequest = waitForJourneyRequest(request => new URL(request.url()).pathname === "/api/v1/assistance/turns" && request.method() === "POST")
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
  const operationDeadline = Date.now() + remainingJourneyMs(20_000);
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
      const continueResponse = failOnBlockedWrite(waitForJourneyResponse(response => new URL(response.url()).pathname === `/api/v1/assistance/turns/${parentJobId}/continue` && response.request().method() === "POST")
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
  assert.deepEqual(pendingFixture.purposes, purposes.slice(0, 2));
  report.checks.push("graph_level_proposal_dispatched");
  await gotoJourney(`${origin}/#/settings`, { waitUntil: "domcontentloaded" });
  await failOnBlockedWrite(page.getByRole("heading", { name: "Model connection", exact: true }).waitFor());
  await gotoJourney(`${origin}/#/builder`, { waitUntil: "domcontentloaded" });
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
  const deadline = Date.now() + remainingJourneyMs(30_000);
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
  assert.equal(proposal?.scenario?.steps?.length, 3);
  await gotoJourney(`${origin}/#/builder?graph_job=${encodeURIComponent(childId)}`, { waitUntil: "domcontentloaded" });
  await failOnBlockedWrite(page.getByRole("button", { name: "Save experiment", exact: true }).waitFor());
  stage = "proposal-review-screenshot";
  await captureAssistantView("assistant-proposal-review");
  const validationResponse = failOnBlockedWrite(waitForJourneyResponse(response => new URL(response.url()).pathname === `/api/v1/ai/graph-jobs/${childId}/validate` && response.request().method() === "POST")
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
  await failOnBlockedWrite(page.waitForURL(url => url.origin === origin && url.hash === "#/builder", { timeout: remainingJourneyMs(10_000) }));
  await failOnBlockedWrite(page.locator(".builder-header h1").waitFor({ state: "visible" }));
  assert.equal(await page.locator(".builder-header h1").getAttribute("aria-label"), immutable.scenario.document.title);
  await captureAssistantView("assistant-saved-graph-reopened");
  await executeGeneratedFixtureJourney(savedEnvelope, immutable);
  const finalOperation = await api(`/assistance/turns/${encodeURIComponent(parentJobId)}`);
  report.assistant_operation = operationSummary(finalOperation);
  const fixture = await fixtureState();
  assert.equal(fixture.request_count, 4);
  assert.deepEqual(fixture.purposes, purposes);
  assert.ok(fixture.request_bytes > 0 && fixture.request_bytes <= 2_097_152);
  assert.equal(fixture.failed, false);
  await proveCompositionPurposeAuthorizations();
  report.route_counts = {
    session: sessionPosts,
    provider_save: savePosts,
    provider_activate: activatePosts,
    authorization: authorizationPosts,
    assistance_submit: assistancePosts,
    assistance_continue: continuationPosts,
    graph_validate: validatePosts,
    graph_review: reviewPosts,
    composition_purpose_authorization: compositionAuthorizationPosts,
    authorization_revoke: authorizationRevokePosts,
  };
  assert.equal(savePosts, 1, "exactly one provider save must pass the browser route");
  assert.equal(activatePosts, 1, "exactly one provider activation must pass the browser route");
  assert.equal(authorizationPosts, 1, "exactly one bounded authorization must pass the browser route");
  assert.equal(compositionAuthorizationPosts, 2, "exactly two single-purpose composition authorizations must pass the browser route");
  assert.equal(authorizationRevokePosts, 3, "the original and two single-purpose authorizations must each be revoked once");
  assert.equal(assistancePosts, 2, "exactly the graph and detection plans must pass the browser route");
  assert.equal(continuationPosts, continuedThroughUi ? 1 : 0, "continuation count must match the UI recovery action actually used");
  assert.equal(validatePosts, 1, "the normal UI must validate the graph proposal exactly once");
  assert.equal(reviewPosts, 1, "the normal UI must save the reviewed graph exactly once");
  assert.equal(sessionPosts, 1, "exactly one browser session exchange must pass the browser route");
  assert.equal(runPreflightPosts, 1);
  assert.equal(runSubmitPosts, 1);
  assert.equal(approvalPosts, 1);
  assert.equal(runnerBootstrapPosts, 1);
  assert.equal(runnerStartPosts, 1);
  assert.equal(runnerStopPosts, 1);
  assert.equal(detectionSourcePosts, 1);
  assert.equal(detectionContextPosts, 1);
  assert.equal(detectionValidatePosts, 1);
  assert.equal(detectionReviewPosts, 1);
  report.provider_requests = { count: fixture.request_count, purposes: fixture.purposes, request_bytes: fixture.request_bytes };
  report.assistant_selection = { kind: expectedContext.selected.kind, step_edit: false, bounds: expectedContext.bounds };
  report.saved_graph = { scenario_id: savedEnvelope.application.scenario_id, version: savedEnvelope.application.version, digest: savedEnvelope.application.digest };
  report.checks.push("validated_proposal_saved_reopened_as_separate_immutable_graph_before_execute");
  report.graph_simulation = { native_execution: false, saved_scenario_id: savedScenarioId };
  report.request_counts = {
    assistant_turns: assistancePosts, model_requests: fixture.request_count,
    run_preflight: runPreflightPosts, run_submission: runSubmitPosts, execute_approval: approvalPosts,
    runner_bootstrap: runnerBootstrapPosts, runner_start: runnerStartPosts, runner_stop: runnerStopPosts,
    detection_source: detectionSourcePosts, detection_context: detectionContextPosts,
    detection_validate: detectionValidatePosts, detection_review: detectionReviewPosts,
  };
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
  if (runJobId && page && !page.isClosed()) await cancelOwnedRunThroughUi();
  const executeTerminalConfirmed = !runJobId || report.cleanup?.execute_job_terminal === true;
  if (runnerStarted && page && !page.isClosed() && executeTerminalConfirmed) {
    try { await stopRunnerThroughUi(); }
    catch { report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: false }; }
  } else if (runnerStarted && !executeTerminalConfirmed) {
    report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: false, runner_stop_skipped_until_execute_terminal: true };
  }
  await cleanupOwnedModelAuthorizations();
  if (report.cleanup?.execute_job_terminal === false || report.cleanup?.runner_stopped === false) process.exitCode = 1;
  await context?.close().catch(() => { report.errors = [{ stage: "cleanup", kind: "context-close" }]; process.exitCode = 1; });
  await browser?.close().catch(() => { report.errors = [{ stage: "cleanup", kind: "browser-close" }]; process.exitCode = 1; });
  if (process.exitCode) report.status = "failed_or_incomplete";
  writeFileSync(join(output, "assistant-browser-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}
