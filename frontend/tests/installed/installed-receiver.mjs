// Installed-wheel retained-redaction original and linked retest through the ordinary UI.
/* global process, URL, URLSearchParams, document, fetch, sessionStorage, localStorage, location, structuredClone, AbortSignal, getComputedStyle, CSS, innerWidth, innerHeight, requestAnimationFrame, window */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import {
  handleReceiverRoute,
  createReceiverSettingsReadPolicy,
  createReceiverReloadContextCorrelation,
  closeReceiverWebSocket,
  observeReceiverEvent,
  observeReceiverWait,
  settleReceiverObservers,
  consumeRequestBudget,
  receiverContextRequestAllowed,
  receiverContextRequestIsFinal,
  receiverContextResponseMatchesRequest,
  receiverOwnerAdmissionState,
  receiverCompletedPhase,
  receiverRunIsNotDemo,
  receiverOwnerContextMatches,
  receiverApprovalAcknowledgementName,
  receiverCompositionCleanupState,
  sameJson as same,
} from "./receiver-guards.mjs";
import { boundedLocalTimeout, createDeadlineBudget } from "./receiver-deadline.mjs";
import { receiverPostDenialDiagnostic } from "./receiver-diagnostics.mjs";
import {
  receiverPreparationDiagnostic,
  receiverPrepareHttpDiagnostic,
  readReceiverCompositionUi,
  receiverCompositionInteractionDiagnostic,
} from "./receiver-diagnostics.mjs";

const [modulePath, output, port] = process.argv.slice(2);
assert.match(port ?? "", /^\d{1,5}$/);
const inputChunks = [];
let inputBytes = 0;
for await (const chunk of process.stdin) {
  inputBytes += chunk.length;
  assert.ok(inputBytes <= 256, "Capability input exceeded its limit");
  inputChunks.push(chunk);
}
let { capability, fixture_port: fixturePort } = JSON.parse(Buffer.concat(inputChunks).toString("utf8"));
inputChunks.length = 0;
assert.match(capability ?? "", /^[A-Za-z0-9_-]{64}$/);
assert.match(String(fixturePort ?? ""), /^\d{1,5}$/);
assert.ok(Number(fixturePort) > 0 && Number(fixturePort) <= 65535);

const JOURNEY_BUDGET_MS = 295_000;
const CLEANUP_BUDGET_MS = 60_000;
const deadlineBudget = createDeadlineBudget(Date.now(), JOURNEY_BUDGET_MS, CLEANUP_BUDGET_MS);

const PROFILE = "sandbox-endpoint-deep-lab.v1";
const STARTER = "scenario.receiver-defense.redaction-validation.v1";
const STARTER_TITLE = "Validate receiver redaction and legitimate use";
const FILESYSTEM_COLLECTOR = "collector.filesystem.sandbox.v1";
const COMPOSITION_QUESTION = "Can the retained receiver policy accept all eight generated records after redaction?";
const COMPOSITION_REVIEWER = "Installed receiver composition verifier";
const MODEL = "bluefire-local-graph-fixture-v1";
const PROVIDER_ID = "provider.installed-receiver-composition.v1";
const MODEL_REVIEWER = "Installed receiver composition fixture reviewer";
const MODEL_PURPOSE = "bluefire_composition_proposal";
const MODEL_PURPOSE_LABEL = "Propose a bounded composition graph";
const PROVIDER_ENDPOINT = `http://127.0.0.1:${fixturePort}/v1/responses`;
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
  owner: 2,
  prepare: 5,
  review: 5,
  approval: 5,
  cancel: 1,
  composition_list: 6, // Initial open/reopen plus grant, proposal, attempt, and revoke refreshes.
  composition_context: 1,
  composition_grant: 1,
  composition_proposal_context: 3,
  composition_proposal: 1,
  composition_attempt: 1,
  composition_revoke: 2,
  comparison: 1,
  provider_save: 1,
  provider_activate: 1,
  model_authorization: 1,
  model_authorization_revoke: 2,
};
const counts = Object.fromEntries(Object.keys(ROUTE_LIMITS).map((key) => [key, 0]));
const report = {
  schema_version: "bluefire.installed-receiver-retained-redaction.v1",
  status: "failed_or_incomplete",
  installed_wheel_service: true,
  native_execution_required: true,
  workflow: "retained_redaction_original_and_linked_retest",
  external_credentials: false,
  live_model_inference: false,
  generated_record_count: 8,
  target_scope: ["sandbox.workspace", "network.loopback"],
  runner_profile: PROFILE,
  checks: [],
  screenshots: [],
  blocked_requests: [],
  errors: [],
};
const callbackFailureKinds = new Set();
const pendingObservers = new Set();
const pageWaitFailureKinds = new Set();
function recordCallbackFailure(kind) {
  if (callbackFailureKinds.has(kind)) return;
  callbackFailureKinds.add(kind);
  report.errors.push({ stage: "browser_callback", kind });
}

const exactKeys = (value, names) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...names].sort());
const boundedString = (value, max = 128) => typeof value === "string" && value.trim().length > 0 && value.length <= max;
const safeStatus = (value, allowed) => allowed.includes(value) ? value : value == null ? "missing" : "other";
const PHASE_ERROR_CODES = new Set([
  "receiver_publication_uncertain", "receiver_result_insufficient", "receiver_session_unavailable",
]);
const EXECUTION_ERROR_CODES = new Set([
  "run_record_incomplete", "replay_record_incomplete", "run_cleanup_deferred", "replay_cleanup_deferred",
  "execution_callback_failed",
]);
const safePublicErrorCode = (value, allowed) => allowed.has(value) ? value : "unknown";
assert.equal(safePublicErrorCode("receiver_result_insufficient", PHASE_ERROR_CODES), "receiver_result_insufficient");
assert.equal(safePublicErrorCode("unrecognized-test-code", EXECUTION_ERROR_CODES), "unknown");
let lastPostBudgetDenial;
const count = (key) => {
  const allowed = consumeRequestBudget(counts, ROUTE_LIMITS, key);
  if (!allowed && Object.hasOwn(ROUTE_LIMITS, key)) {
    lastPostBudgetDenial = { key, count: counts[key], limit: ROUTE_LIMITS[key] };
  }
  return allowed;
};
let browser, context, page;
let connected = false;
let stage = "launch";
let expected401 = 0;
let receiverJobId;
let originalOwnerId;
let linkedOwnerId;
let executionJobId;
let currentPhase;
let baselineRunId;
let receiverStarted = false;
let runnerStarted = false;
let cleanupCancelAllowed = false;
let savedSelection;
let packagedStarter;
let expectedScenarioCopy;
let latestContext;
let latestFinalContextRequest;
let latestOwner;
let latestPreparationDigest;
let originalControlDigest;
let originalEnvelope;
let linkedEnvelope;
let compositionOwnerId;
let compositionAttemptJobId;
let latestCompositionReview;
let latestCompositionContext;
let latestCompositionObjective;
let compositionSnapshotId;
let compositionProposalJobId;
let latestCompositionProposal;
let providerConfig;
let modelAuthorizationId;
let expectedModelRevokeId;
let proposalReadCount = 0;
let modelAuthorizationReadCount = 0;
let modelProviderReadCount = 0;
let comparisonDiagnostic;
let comparisonSubmitted = false;
let phaseBindingDiagnostic;
let prepareHttpDiagnostic;
let pendingPreparationFailure;
let compositionInteractionStep = "reconcile";
let compositionInteractionUi;
const settingsReadAllowed = createReceiverSettingsReadPolicy();
let activeOwnerRole = "original";
const phaseOrders = { original: ["baseline", "protected", "legitimate"], linked: ["protected", "legitimate"] };
const phaseIndexes = { original: 0, linked: 0 };
const owners = new Map();
const executions = new Map();
const phaseEvidence = [];
const receiverSessionIds = new Set();

function remainingMs() {
  const remaining = deadlineBudget.remaining(Date.now());
  if (remaining <= 0) throw new Error("Installed receiver deadline exceeded");
  return remaining;
}

function recordPhaseBindingDiagnostic(assertionId, phaseName, phase) {
  const result = phase?.result;
  const executionJob = phase?.execution_job;
  const runId = result?.run_id;
  const resultRef = executionJob?.result_ref;
  phaseBindingDiagnostic = {
    assertion_id: assertionId,
    expected: {
      phase: phaseName,
      phase_status: "completed",
      result_present: true,
      execution_job_present: true,
      execution_job_kind: phaseName === "baseline" ? "scenario.run" : "scenario.replay",
      execution_job_state: "completed",
      decision: phaseName === "protected" ? "policy_refused" : "accepted",
      result_phase: phaseName,
      preparation_digest_present: true,
      cleanup_receiver: "verified_closed",
      cleanup_run: "complete",
      result_ref_present: true,
      run_id_present: true,
      run_id_matches_result_ref: true,
      run_id_valid: true,
    },
    observed: {
      phase_present: phase !== null && phase !== undefined,
      phase_name: safeStatus(phase?.phase, ["baseline", "protected", "legitimate"]),
      phase_status: safeStatus(phase?.status,
        ["not_started", "preparing", "review_ready", "awaiting_approval", "running", "stopping", "completed", "failed", "declined", "stopped", "interrupted"]),
      result_present: result !== null && result !== undefined,
      execution_job_present: executionJob !== null && executionJob !== undefined,
      execution_job_kind: safeStatus(executionJob?.kind, ["scenario.run", "scenario.replay"]),
      execution_job_state: safeStatus(executionJob?.state,
        ["queued", "planning", "awaiting_approval", "running", "paused", "cancelling", "cancelled", "completed", "failed", "interrupted"]),
      decision: safeStatus(result?.decision, ["accepted", "policy_refused", "rejected"]),
      result_phase: safeStatus(result?.phase, ["baseline", "protected", "legitimate"]),
      preparation_digest_present: typeof phase?.preparation?.preparation_digest === "string"
        && phase.preparation.preparation_digest.length > 0,
      cleanup_present: phase?.cleanup !== null && phase?.cleanup !== undefined,
      cleanup_receiver: safeStatus(phase?.cleanup?.receiver,
        ["not_started", "active", "uncertain", "verified_closed"]),
      cleanup_run: safeStatus(phase?.cleanup?.run, ["not_started", "pending", "complete"]),
      result_ref_present: typeof resultRef === "string" && resultRef.length > 0,
      run_id_present: typeof runId === "string" && runId.length > 0,
      run_id_valid: typeof runId === "string" && RUN_ID.test(runId),
      run_id_matches_result_ref: typeof runId === "string" && typeof resultRef === "string" && runId === resultRef,
    },
    phase_error_code: safePublicErrorCode(phase?.problem?.code, PHASE_ERROR_CODES),
    execution_error_code: safePublicErrorCode(executionJob?.error?.code, EXECUTION_ERROR_CODES),
  };
}

async function waitCompletedPhase(phaseName) {
  const pendingExecutionStates = ["queued", "planning", "awaiting_approval", "running", "paused", "cancelling"];
  const terminalFailureStates = ["failed", "cancelled", "interrupted"];
  phaseBindingDiagnostic = undefined;
  await waitOwner((owner) => {
    const phase = owner.phases?.find((item) => item?.phase === phaseName);
    const completed = receiverCompletedPhase(owner, phaseName);
    recordPhaseBindingDiagnostic("completed_phase_wait", phaseName, phase);
    if (completed) return true;
    if (["failed", "declined", "stopped", "interrupted"].includes(phase?.status)) return true;
    if (terminalFailureStates.includes(phase?.execution_job?.state)) return true;
    return phase?.status === "completed" && !pendingExecutionStates.includes(phase.execution_job?.state);
  });
  const phase = latestOwner.phases?.find((item) => item?.phase === phaseName);
  const completed = receiverCompletedPhase(latestOwner, phaseName);
  recordPhaseBindingDiagnostic(completed ? "completed_phase_binding" : "completed_phase_binding_failed", phaseName, phase);
  assert.ok(completed, `${phaseName} must retain a completed execution, preparation, result, and cleanup`);
  return completed;
}

function boundedTimeout(requested) {
  const timeout = deadlineBudget.bounded(requested, Date.now());
  if (timeout <= 0) throw new Error("Installed receiver deadline exceeded");
  return timeout;
}

function setPlaywrightBudget() {
  const timeout = remainingMs();
  context?.setDefaultTimeout(timeout);
  context?.setDefaultNavigationTimeout(timeout);
  return timeout;
}

async function compositionUiSnapshot(observation) {
  const diagnosticMs = deadlineBudget.bounded(250, Date.now());
  if (!page || diagnosticMs <= 0) return compositionInteractionUi;
  try {
    return await Promise.race([
      page.evaluate(readReceiverCompositionUi, {
        origin: ORIGIN, owner: compositionOwnerId, control: originalOwnerId, proposal: compositionProposalJobId,
      }).then(value => ({ ...value, observation })),
      delay(diagnosticMs, compositionInteractionUi, { ref: false }),
    ]);
  } catch { return compositionInteractionUi; }
}

async function visibleControlsDiagnostic() {
  if (!page) return undefined;
  const timeoutMs = deadlineBudget.bounded(250, Date.now());
  if (timeoutMs <= 0) return { unavailable: true };
  try {
    return await Promise.race([page.locator("button, input, select, [role='radio'], [role='checkbox']").evaluateAll((elements) => {
      const visible = elements.filter((element) => {
        const style = getComputedStyle(element);
        const bounds = element.getBoundingClientRect();
        return style.visibility !== "hidden" && style.display !== "none" && bounds.width > 0 && bounds.height > 0;
      });
      return {
        visible_count: visible.length,
        controls: visible.slice(0, 24).map((element) => ({
          tag: element.tagName.toLowerCase(),
          role: element.getAttribute("role") ?? "native",
          type: element.getAttribute("type") ?? "",
          disabled: Boolean(element.disabled),
          has_aria_label: Boolean(element.getAttribute("aria-label")),
          has_label: Boolean(element.closest("label") || (element.id && document.querySelector(`label[for="${CSS.escape(element.id)}"]`))),
        })),
      };
    }), delay(timeoutMs, { unavailable: true }, { ref: false })]);
  } catch {
    return { unavailable: true };
  }
}

const LOCATOR_FACTORIES = new Set(["getByRole", "getByLabel", "getByText", "getByPlaceholder", "getByTestId", "locator"]);
const LOCATOR_CHAINS = new Set(["getByRole", "getByLabel", "getByText", "getByPlaceholder", "getByTestId", "locator", "filter", "first", "last", "nth"]);
const LOCATOR_ACTIONS = new Map([
  ["click", 0], ["dblclick", 0], ["fill", 1], ["clear", 0], ["check", 0], ["uncheck", 0],
  ["selectOption", 1], ["press", 1], ["hover", 0], ["focus", 0], ["waitFor", 0], ["isChecked", 0],
  ["isVisible", 0], ["isEnabled", 0], ["isDisabled", 0], ["selectText", 0], ["setInputFiles", 1],
]);

function wrapLocator(locator) {
  return new Proxy(locator, {
    get(target, property) {
      const value = Reflect.get(target, property, target);
      if (typeof value !== "function") return value;
      return (...args) => {
        const timeout = setPlaywrightBudget();
        if (LOCATOR_ACTIONS.has(property)) {
          const optionIndex = LOCATOR_ACTIONS.get(property);
          args[optionIndex] = withTimeout(args[optionIndex], timeout);
        }
        const result = value.apply(target, args);
        return LOCATOR_CHAINS.has(property) ? wrapLocator(result) : result;
      };
    },
  });
}

function withTimeout(options, timeout) {
  return { ...(options && typeof options === "object" ? options : {}), timeout: boundedTimeout(options?.timeout ?? timeout) };
}

function wrapPage(target) {
  return new Proxy(target, {
    get(pageTarget, property) {
      const value = Reflect.get(pageTarget, property, pageTarget);
      if (typeof value !== "function") return value;
      return (...args) => {
        if (property === "isClosed") return value.apply(pageTarget, args);
        const timeout = setPlaywrightBudget();
        if (property === "goto" || property === "waitForResponse" || property === "waitForRequest" || property === "waitForEvent") {
          args[1] = withTimeout(args[1], timeout);
        } else if (property === "waitForFunction") {
          const optionIndex = args.length > 2 ? 2 : -1;
          if (optionIndex >= 0) args[optionIndex] = withTimeout(args[optionIndex], timeout);
        }
        const result = value.apply(pageTarget, args);
        if (property === "waitForResponse" || property === "waitForRequest" || property === "waitForEvent") {
          const waitStage = stage;
          return observeReceiverWait(result, () => {
            if (pageWaitFailureKinds.has(property)) return;
            pageWaitFailureKinds.add(property);
            report.errors.push({ stage: waitStage, kind: "page_wait_failed", method: property });
          }, pendingObservers);
        }
        return LOCATOR_FACTORIES.has(property) ? wrapLocator(result) : result;
      };
    },
  });
}

function allowedRead(url, method) {
  const path = url.pathname;
  if (["/api/v1/settings", "/api/v1/build-info"].includes(path)) return settingsReadAllowed(url, method);
  if ([
    "/",
    "/index.html",
    "/ui/app.js",
    "/ui/styles.css",
    "/ui/fonts/InterVariable.woff2",
  ].includes(path)) return !url.search;
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
    "/api/v1/detections",
    "/api/v1/comparison-snapshots",
  ].includes(path)) return !url.search;
  if (path === "/api/v1/resources/model-providers") {
    modelProviderReadCount += 1;
    return !url.search && modelProviderReadCount <= 20;
  }
  if (path === "/api/v1/ai/authorizations") {
    modelAuthorizationReadCount += 1;
    return !url.search && modelAuthorizationReadCount <= 240;
  }
  if (path === "/api/v1/runner") return url.search === `?profile_id=${PROFILE}`;
  if (/^\/api\/v1\/receiver-defense\/jobs\/job-[0-9a-f]{32}$/.test(path)) return !url.search;
  if (/^\/api\/v1\/jobs\/job-[0-9a-f]{32}$/.test(path)) return !url.search;
  if (/^\/api\/v1\/runs\/run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/.test(path)) return !url.search;
  if (/^\/api\/v1\/runs\/run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\/events$/.test(path)) {
    return /^\?after_sequence=\d+&limit=\d+$/.test(url.search);
  }
  if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}`) return !url.search;
  if (compositionProposalJobId && path === `/api/v1/composition/proposals/${compositionProposalJobId}`) {
    proposalReadCount += 1;
    return !url.search && proposalReadCount <= 64;
  }
  if (comparisonSubmitted && /^\/api\/v1\/comparison-snapshots\/run-comparison-[0-9a-f]{64}$/.test(path)) {
    return !url.search && (!compositionSnapshotId || path.endsWith(`/${compositionSnapshotId}`));
  }
  return false;
}

function contextExpectation(body) {
  const linked = body?.source_control !== undefined;
  return {
    selection: savedSelection,
    workflow: "retained_redaction",
    sourceControl: linked ? { job_id: originalOwnerId, control_digest: originalControlDigest } : null,
    profileIdsByMode: {
      simulate: ["sandbox-simulate.v1"],
      execute: ["sandbox-execute.v1", PROFILE],
    },
    scopeRefs: ["sandbox.workspace", "network.loopback"],
    collectors: [FILESYSTEM_COLLECTOR],
    finalRunIntent: {
      mode: "execute",
      autonomy: "off",
      ai_provider_id: null,
      runner_profile_id: PROFILE,
      target_scope: { scope_refs: ["sandbox.workspace", "network.loopback"] },
      collectors: [FILESYSTEM_COLLECTOR],
    },
  };
}

function validateFinalContext(body) {
  return receiverContextRequestIsFinal(body, contextExpectation(body));
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
  lastPostBudgetDenial = undefined;
  const path = url.pathname;
  if (path === "/api/v1/session") return count("session") && body === null;
  const provider = body?.document;
  const providerExact = exactKeys(provider, ["id", "kind", "model", "endpoint", "api_key", "timeout_seconds", "max_retries", "max_output_tokens", "redaction"])
    && provider.id === PROVIDER_ID && provider.kind === "openai_responses" && provider.model === MODEL
    && provider.endpoint === PROVIDER_ENDPOINT && provider.api_key === null
    && provider.timeout_seconds === 30 && provider.max_retries === 0 && provider.max_output_tokens === 1024
    && exactKeys(provider.redaction, ["enabled", "redact_keys", "max_string_chars", "include_evidence_content"])
    && provider.redaction.enabled === true && provider.redaction.include_evidence_content === false
    && ["api_key", "authorization", "cookie", "credential", "password", "secret", "token"].every(key => provider.redaction.redact_keys.includes(key));
  if (path === `/api/v1/resources/model-providers/${PROVIDER_ID}`) {
    const ok = count("provider_save") && exactKeys(body, ["document", "status"]) && body.status === "draft" && providerExact;
    if (ok) providerConfig = structuredClone(provider);
    return Boolean(ok);
  }
  if (path === `/api/v1/resources/model-providers/${PROVIDER_ID}/activate`) {
    return count("provider_activate") && exactKeys(body, []);
  }
  if (path === "/api/v1/ai/authorizations") {
    return count("model_authorization") && providerConfig && exactKeys(body, ["provider", "purposes", "data_scope", "limits", "expires_in_seconds", "approved_by", "usage_authorized", "local_endpoint_authorized"])
      && same(body.provider, providerConfig) && same(body.purposes, [MODEL_PURPOSE])
      && body.data_scope === "reviewed_lab_context"
      && exactKeys(body.limits, ["max_requests", "max_request_bytes", "max_reserved_output_tokens"])
      && body.limits.max_requests === 1 && body.limits.max_request_bytes === 262_144
      && body.limits.max_reserved_output_tokens === 1024 && body.expires_in_seconds === 300
      && body.approved_by === MODEL_REVIEWER && body.usage_authorized === true
      && body.local_endpoint_authorized === true;
  }
  if (/^\/api\/v1\/ai\/authorizations\/ai-authorization-[0-9a-f]{32}\/revoke$/.test(path)) {
    const id = path.slice("/api/v1/ai/authorizations/".length, -"/revoke".length);
    return count("model_authorization_revoke") && id === expectedModelRevokeId && exactKeys(body, []);
  }
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
  if (path === "/api/v1/composition/objective-list") {
    return count("composition_list") && exactKeys(body, ["control_owner_id"])
      && body.control_owner_id === originalOwnerId && phaseIndexes.original === 3;
  }
  if (path === "/api/v1/composition/context") {
    return count("composition_context") && exactKeys(body, ["control_owner_id", "question", "limits"])
      && body.control_owner_id === originalOwnerId && body.question === COMPOSITION_QUESTION
      && body.limits === null && originalEnvelope?.status === "completed"
      && originalEnvelope.control?.status === "retained" && phaseIndexes.original === 3;
  }
  if (path === "/api/v1/composition/objectives") {
    const ok = count("composition_grant") && exactKeys(body, ["submission_id", "review", "reviewed_by", "review_digest"])
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id)
      && same(body.review, { control_owner_id: originalOwnerId, question: COMPOSITION_QUESTION, limits: null })
      && body.reviewed_by === COMPOSITION_REVIEWER
      && body.review_digest === latestCompositionReview?.review_digest;
    if (ok) compositionOwnerId = `job-${body.submission_id.replaceAll("-", "")}`;
    return ok;
  }
  if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}/proposal-context`) {
    return count("composition_proposal_context") && exactKeys(body, ["prior_attempt_id"])
      && body.prior_attempt_id === null;
  }
  if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}/proposals`) {
    const ok = count("composition_proposal") && exactKeys(body, ["submission_id", "provider_id", "context_digest", "prior_attempt_id"])
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id)
      && body.provider_id === PROVIDER_ID && body.context_digest === latestCompositionContext?.context_digest
      && body.prior_attempt_id === null && counts.model_authorization === 1;
    if (ok) compositionProposalJobId = `job-${body.submission_id.replaceAll("-", "")}`;
    return Boolean(ok);
  }
  if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}/attempts`) {
    const ok = count("composition_attempt") && exactKeys(body, ["submission_id", "proposal", "prior_attempt_id"])
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id)
      && body.prior_attempt_id === null && latestCompositionContext?.grant_id === latestCompositionObjective?.grant?.document?.grant_id
      && latestCompositionProposal?.candidate_ready === true
      && same(body.proposal, latestCompositionProposal?.proposal?.candidate)
      && same(body.proposal, latestCompositionContext?.initial_proposal);
    if (ok) compositionAttemptJobId = `job-${body.submission_id.replaceAll("-", "")}`;
    return ok;
  }
  if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}/revoke`) {
    return count("composition_revoke") && exactKeys(body, []);
  }
  if (path === "/api/v1/comparisons") {
    const ok = count("comparison") && compositionAttemptJobId && exactKeys(body, ["run_ids"])
      && same(body.run_ids, [baselineRunId, report.composition?.run_id]);
    if (ok) comparisonSubmitted = true;
    return Boolean(ok);
  }
  if (path === "/api/v1/receiver-defense/context") {
    latestContext = undefined;
    latestFinalContextRequest = undefined;
    const expected = contextExpectation(body);
    const ok = count("context") && receiverContextRequestAllowed(body, expected);
    if (ok && receiverContextRequestIsFinal(body, expected)) latestFinalContextRequest = structuredClone(body);
    return ok;
  }
  if (path === "/api/v1/receiver-defense/jobs") {
    const linked = body?.source_control !== undefined;
    const keys = linked
      ? ["selection", "run_intent", "workflow", "source_control", "submission_id", "context_digest"]
      : ["selection", "run_intent", "workflow", "submission_id", "context_digest"];
    const roleReady = linked
      ? Boolean(originalEnvelope?.status === "completed" && originalEnvelope?.control?.status === "retained"
        && originalEnvelope.control.receiver_state === "stopped" && phaseIndexes.original === 3
        && same(body.source_control, { job_id: originalOwnerId, control_digest: originalControlDigest }))
      : !originalOwnerId && latestFinalContextRequest?.source_control === undefined;
    const ok = count("owner") && roleReady && exactKeys(body, keys)
      && validateFinalContext({ selection: body.selection, run_intent: body.run_intent, workflow: body.workflow,
        ...(linked ? { source_control: body.source_control } : {}) })
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id)
      && receiverOwnerContextMatches(body, latestFinalContextRequest, latestContext);
    return ok;
  }
  const currentPhases = phaseOrders[activeOwnerRole];
  const expectedPhase = currentPhases?.[phaseIndexes[activeOwnerRole]];
  const preparePath = receiverJobId && `/api/v1/receiver-defense/jobs/${receiverJobId}/prepare`;
  if (path === preparePath) {
    const ok = count("prepare") && exactKeys(body, ["submission_id", "phase", "reviewed_by"])
      && body.phase === expectedPhase && boundedString(body.reviewed_by)
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id);
    if (ok) currentPhase = body.phase;
    return ok;
  }
  const reviewPath = receiverJobId && `/api/v1/receiver-defense/jobs/${receiverJobId}/review`;
  if (path === reviewPath) {
    return count("review") && exactKeys(body, ["submission_id", "phase", "preparation_digest", "decision", "reviewed_by"])
      && body.phase === currentPhase && body.phase === expectedPhase && body.preparation_digest === latestPreparationDigest
      && body.decision === "accept" && boundedString(body.reviewed_by)
      && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.submission_id);
  }
  const approvalPath = executionJobId && `/api/v1/jobs/${executionJobId}/approval`;
  if (path === approvalPath) {
    return count("approval") && exactKeys(body, ["approved_by"]) && boundedString(body.approved_by);
  }
  const cancelPath = receiverJobId && `/api/v1/jobs/${receiverJobId}/cancel`;
  if (path === cancelPath) return cleanupCancelAllowed && count("cancel") && exactKeys(body, []);
  return false;
}

async function appApi(path, requestedTimeout = remainingMs()) {
  const timeout = boundedTimeout(requestedTimeout);
  return page.evaluate(async ({ apiPath, timeout }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    if (!token) throw new Error("Session unavailable");
    const response = await fetch(`/api/v1${apiPath}`, {
      method: "GET", redirect: "error", credentials: "omit",
      headers: { "X-BlueFire-Session": token, Accept: "application/json" },
      signal: AbortSignal.timeout(timeout),
    });
    if (!response.ok) throw new Error("Owned status read failed");
    return response.json();
  }, { apiPath: path, timeout });
}

function ownedModelAuthorization(row) {
  return row && typeof row === "object" && /^ai-authorization-[0-9a-f]{32}$/.test(row.authorization_id ?? "")
    && row.provider?.id === PROVIDER_ID && same(row.provider, providerConfig)
    && same(row.purposes, [MODEL_PURPOSE]) && row.approved_by === MODEL_REVIEWER;
}

async function readOwnedModelAuthorization(requestedTimeout = remainingMs()) {
  const value = await appApi("/ai/authorizations", requestedTimeout);
  assert.ok(Array.isArray(value.authorizations));
  const owned = value.authorizations.filter(ownedModelAuthorization);
  assert.equal(owned.length, 1, "Only one exact receiver model authorization may be owned");
  if (modelAuthorizationId) assert.equal(owned[0].authorization_id, modelAuthorizationId);
  modelAuthorizationId = owned[0].authorization_id;
  return owned[0];
}

async function revokeModelAuthorizationNormally() {
  if (counts.model_authorization === 0) {
    report.cleanup = { ...(report.cleanup ?? {}), model_authorization_revoked: false, model_authorization_not_issued: true };
    return;
  }
  if (!connected || !page || page.isClosed()) {
    report.cleanup = { ...(report.cleanup ?? {}), model_authorization_revoked: false };
    return;
  }
  try {
    const until = Date.now() + Math.min(15_000, remainingMs());
    const localTimeout = (deadline = until) => {
      const timeout = boundedLocalTimeout(deadline, Date.now(), remainingMs());
      if (timeout <= 0) throw new Error("Model authorization cleanup deadline exceeded");
      return timeout;
    };
    for (let attempt = 0; attempt < 2 && Date.now() < until && deadlineBudget.remaining(Date.now()) > 0; attempt += 1) {
      const row = await readOwnedModelAuthorization(localTimeout());
      if (row.status === "revoked") {
        report.cleanup = { ...(report.cleanup ?? {}), model_authorization_revoked: true };
        return;
      }
      assert.equal(row.status, "active");
      assert.ok(counts.model_authorization_revoke < ROUTE_LIMITS.model_authorization_revoke);
      expectedModelRevokeId = row.authorization_id;
      await page.goto(`${ORIGIN}/#/settings`, { waitUntil: "domcontentloaded", timeout: localTimeout() });
      const button = page.getByRole("button", { name: `Revoke model usage for ${MODEL}`, exact: true });
      await button.waitFor({ state: "visible", timeout: localTimeout() });
      assert.equal(await Promise.race([
        button.count(),
        delay(localTimeout(), undefined, { ref: false }).then(() => { throw new Error("Model revoke control count timed out"); }),
      ]), 1);
      try { await button.click({ timeout: localTimeout() }); }
      catch { /* A lost response is reconciled against this exact owned authorization. */ }
      const settleUntil = Math.min(until, Date.now() + (attempt === 0 ? 1500 : 8000));
      while (Date.now() < settleUntil && deadlineBudget.remaining(Date.now()) > 0) {
        try {
          const current = await readOwnedModelAuthorization(localTimeout(settleUntil));
          if (current.status === "revoked") {
            report.cleanup = { ...(report.cleanup ?? {}), model_authorization_revoked: true };
            return;
          }
          assert.equal(current.status, "active");
        } catch { /* Missing or unavailable status cannot establish revocation. */ }
        const pause = boundedLocalTimeout(settleUntil, Date.now(), deadlineBudget.remaining(Date.now()));
        if (pause <= 0) break;
        await delay(Math.min(150, pause));
      }
    }
  } catch { /* Unknown authorization status remains an incomplete cleanup. */ }
  finally { expectedModelRevokeId = undefined; }
  report.cleanup = { ...(report.cleanup ?? {}), model_authorization_revoked: false };
}

const ACTIVE_WORK_KEY = "bluefire.local.active-defensive-work.v1";
const HOME_PHASE_LABELS = { baseline: "Baseline", protected: "Redaction required", legitimate: "Legitimate redacted use" };
const HOME_DECISION_LABELS = { accepted: "Accepted by the receiver", policy_refused: "Prevented by the receiver" };

function homeObjectiveLabel(reached, mode) {
  return reached === true ? (mode === "simulate" ? "Achieved (synthetic)" : "Achieved")
    : reached === false ? "Not achieved" : "Not established";
}

function homeRunStatusLabel(status) {
  return status.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

// Retain only bounded result fields, never the preparation/session-bearing owner document.
function homeRecordProjection(value, ownerId) {
  assert.equal(value.job?.job_id, ownerId);
  assert.equal(value.status, "completed");
  assert.equal(value.control?.status, "retained");
  assert.equal(value.control?.desired_policy_id, "receiver.redacted-only.v1");
  assert.deepEqual(value.phases.map(item => item.phase), ["baseline", "protected", "legitimate"]);
  const phases = value.phases.map(item => {
    assert.equal(item.status, "completed");
    assert.equal(item.result?.receiver_observation.schema_version, "bluefire.owned-receiver-observation.v1");
    assert.equal(item.result?.receiver_observation.state, "verified");
    assert.ok(Object.hasOwn(HOME_DECISION_LABELS, item.result?.decision));
    assert.equal(item.result.run?.run_id, item.result.run_id);
    assert.equal(typeof item.result.run?.status, "string");
    return { phase: item.phase, decision: item.result.decision, run_id: item.result.run_id,
      objective_reached: item.result.run.objective_reached, mode: item.result.run.mode, run_status: item.result.run.status };
  });
  return { owner_job_id: ownerId, status: value.status, desired_policy_id: value.control.desired_policy_id,
    control_status: value.control.status, phases };
}

async function assertRecentOutcomeContexts(projection) {
  const recentRows = page.locator(".recent-work-table tbody tr");
  await recentRows.first().waitFor({ state: "visible" });
  const rows = await recentRows.evaluateAll(elements => elements.map(element => {
    const runHref = element.querySelector(".recent-work-name a")?.getAttribute("href");
    const runPath = runHref?.startsWith("#") ? runHref.slice(1) : runHref;
    return {
      runId: runPath?.startsWith("/runs/") ? decodeURIComponent(runPath.slice("/runs/".length)) : undefined,
      phase: element.querySelector(".recent-work-phase")?.textContent?.trim() ?? null,
      decision: element.querySelector(".recent-work-decision")?.textContent?.trim() ?? null,
      objective: element.querySelector(".recent-work-outcome > strong")?.textContent?.trim(),
      status: element.querySelector(".recent-work-outcome > small")?.textContent?.trim(),
    };
  }));
  assert.ok(rows.length > 0, "Home must retain its existing recent run rows");
  const expected = new Map(projection.phases.map(item => [item.run_id, item]));
  let matchedOwnerRows = 0;
  for (const row of rows) {
    assert.ok(row.runId, "Every recent outcome row must keep its saved run identity");
    const phase = expected.get(row.runId);
    if (!phase) {
      assert.equal(row.phase, null, "An unrelated run must not inherit this receiver workflow's phase");
      assert.equal(row.decision, null, "An unrelated run must not inherit this receiver's decision");
      assert.ok(row.objective, "An unrelated run must keep its objective outcome");
      assert.ok(row.status?.startsWith("Run status: "), "An unrelated run must keep its separate run status");
      continue;
    }
    matchedOwnerRows += 1;
    assert.equal(row.phase, HOME_PHASE_LABELS[phase.phase]);
    assert.equal(row.decision, HOME_DECISION_LABELS[phase.decision]);
    assert.equal(row.objective, homeObjectiveLabel(phase.objective_reached, phase.mode),
      "Receiver context must not replace the saved objective outcome");
    assert.equal(row.status, `Run status: ${homeRunStatusLabel(phase.run_status)}`,
      "Receiver context must leave the saved run status unchanged");
  }
  assert.ok(matchedOwnerRows > 0, "At least one recent row must belong to the selected verified receiver workflow");
}

async function waitRememberedWork(ownerId) {
  await page.waitForFunction(({ key, id }) => {
    const value = JSON.parse(localStorage.getItem(key) ?? "null");
    return value?.family === "handoff" && value?.id === id && Object.keys(value).sort().join(",") === "family,id";
  }, { key: ACTIVE_WORK_KEY, id: ownerId });
}

async function assertHomeRecord(projection, recordTitle) {
  const card = page.getByRole("region", { name: "Active objective", exact: true });
  await card.waitFor({ state: "visible" });
  await page.waitForFunction(title => document.querySelector(".active-objective .active-work-heading h3")?.textContent === title
    && document.querySelector(".active-objective button[aria-label='Refresh active objective']")?.disabled === false,
  `Controlled data handoff · ${recordTitle}`);
  assert.equal(await card.locator(".error-state, .loading-state").count(), 0, "Home must show a successfully checked record");
  assert.equal(await card.getByText("Previously loaded evidence. Its current state could not be checked.", { exact: true }).count(), 0,
    "Cached evidence must not pass as a successful fresh read");
  assert.equal(await card.getByRole("status").count(), 0, "The saved-state check must be settled");
  const title = card.locator(".active-work-heading h3");
  await title.waitFor({ state: "visible" });
  assert.equal(await title.textContent(), `Controlled data handoff · ${recordTitle}`);
  assert.equal(await card.locator(".active-work-purpose").textContent(),
    "Can a redaction requirement stop unredacted records while allowing legitimate redacted use?");
  assert.deepEqual(await card.locator(".active-objective-context > div").evaluateAll(elements => elements.map(element => ({
    label: element.querySelector("dt")?.textContent, value: element.querySelector("dd")?.textContent,
  }))), [{ label: "Environment", value: "Loopback receiver" }, { label: "Current stage", value: "Legitimate redacted use" }]);
  assert.equal(await card.locator(".active-objective-change p").textContent(), "Desired policy: Require redacted records · Retained");
  const rows = await card.locator(".active-objective-evidence > dl > div").evaluateAll(elements => elements.map(element => ({
    label: element.querySelector("dt")?.textContent, value: element.querySelector("dd")?.textContent,
  })));
  assert.deepEqual(rows, projection.phases.map(item => ({ label: HOME_PHASE_LABELS[item.phase], value: HOME_DECISION_LABELS[item.decision] })));
  const sourceDisclosure = card.locator(".active-objective-sources");
  assert.equal(await sourceDisclosure.count(), 1);
  assert.equal(await sourceDisclosure.locator("summary").textContent(), "Evidence sources");
  assert.equal(await sourceDisclosure.getAttribute("open"), null);
  await sourceDisclosure.locator("summary").click();
  const source = await sourceDisclosure.locator("dl > div").evaluate(element => ({
    label: element.querySelector("dt")?.textContent, value: element.querySelector("dd")?.textContent,
  }));
  assert.equal(source.label, "Evidence source");
  assert.ok(source.value.startsWith("Owned loopback receiver decision"));
  assert.ok(source.value.includes("Run evidence:"));
  await sourceDisclosure.locator("summary").click();
  assert.equal(await sourceDisclosure.getAttribute("open"), null);
  assert.equal(await card.locator(".active-objective-state > span").textContent(), "Recorded state: Completed");
  assert.equal(await card.getByRole("link", { name: "Continue objective", exact: true }).getAttribute("href"),
    `#/compare?receiver=1&goal=data-handoff&receiver_job=${projection.owner_job_id}`);
  await assertRecentOutcomeContexts(projection);
  return card;
}

async function captureActiveHome(card, viewport, projection) {
  stage = `home-active-capture-${viewport.width}x${viewport.height}`;
  assert.ok(connected, "Never capture connection credentials");
  await page.setViewportSize(viewport);
  await page.evaluate(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    document.getElementById("main-content")?.scrollTo({ top: 0, left: 0, behavior: "instant" });
  });
  await page.evaluate(async () => { await document.fonts.ready; await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); });
  // Retain the real frame before assertions so a geometry failure is reviewable.
  // A saved frame is evidence, not a passing visual qualification.
  const documentGeometry = await page.evaluate(() => ({ width: innerWidth, height: innerHeight,
    document_width: document.documentElement.clientWidth, scroll_width: document.documentElement.scrollWidth }));
  const name = `receiver-home-active-${viewport.width}x${viewport.height}`;
  const image = await page.screenshot({ fullPage: false, animations: "disabled", mask: [page.locator('input[type="password"]')] });
  writeFileSync(join(output, `${name}.png`), image, { flag: "wx", mode: 0o600 });
  const capture = { name, sha256: createHash("sha256").update(image).digest("hex"), viewport_kind: "responsive_viewport",
    geometry: documentGeometry, elements: [], owner_job_id: projection.owner_job_id, layout_verified: false };
  report.screenshots.push(capture);
  const targets = [
    ["heading", card.getByRole("heading", { name: "Active objective", exact: true })],
    ["title", card.locator(".active-work-heading h3")],
    ["objective", card.locator(".active-work-purpose")],
    ["environment_and_stage", card.locator(".active-objective-context")],
    ["policy", card.locator(".active-objective-change p")],
    ["recorded_state", card.locator(".active-objective-state > span")],
    ["continue_objective", card.getByRole("link", { name: "Continue objective", exact: true })],
    ["show_working_draft", card.getByRole("button", { name: "Show working draft", exact: true })],
    ["refresh", card.getByRole("button", { name: "Refresh active objective", exact: true })],
    ...projection.phases.map((item, index) => [item.phase, card.locator(".active-objective-evidence > dl > div").nth(index)]),
    ["evidence_sources", card.locator(".active-objective-sources > summary")],
  ];
  const elements = [];
  capture.elements = elements;
  for (const [label, locator] of targets) {
    assert.equal(await locator.count(), 1);
    await locator.waitFor({ state: "visible" });
    const geometry = await locator.evaluate(element => {
      const box = element.getBoundingClientRect();
      let left = 0, top = 0, right = innerWidth, bottom = innerHeight;
      for (let parent = element.parentElement; parent; parent = parent.parentElement) {
        const style = getComputedStyle(parent), bounds = parent.getBoundingClientRect();
        const borderLeft = parseFloat(style.borderLeftWidth) || 0, borderRight = parseFloat(style.borderRightWidth) || 0;
        const borderTop = parseFloat(style.borderTopWidth) || 0, borderBottom = parseFloat(style.borderBottomWidth) || 0;
        if (/auto|scroll|hidden|clip/.test(style.overflowX)) {
          const scrollbar = Math.max(0, parent.offsetWidth - parent.clientWidth - borderLeft - borderRight);
          left = Math.max(left, bounds.left + borderLeft); right = Math.min(right, bounds.right - borderRight - scrollbar);
        }
        if (/auto|scroll|hidden|clip/.test(style.overflowY)) {
          const scrollbar = Math.max(0, parent.offsetHeight - parent.clientHeight - borderTop - borderBottom);
          top = Math.max(top, bounds.top + borderTop); bottom = Math.min(bottom, bounds.bottom - borderBottom - scrollbar);
        }
      }
      // Rounded corners are outside the element's hit surface. Check its
      // painted interior, while retaining the complete clipping/text checks.
      const style = getComputedStyle(element);
      const radius = Math.max(...[style.borderTopLeftRadius, style.borderTopRightRadius,
        style.borderBottomLeftRadius, style.borderBottomRightRadius].map(value => parseFloat(value) || 0));
      const insetX = Math.min(box.width / 2, Math.max(2, radius + 1));
      const insetY = Math.min(box.height / 2, Math.max(2, radius + 1));
      const samples = [[box.left + insetX, box.top + insetY], [box.right - insetX, box.top + insetY],
        [box.left + insetX, box.bottom - insetY], [box.right - insetX, box.bottom - insetY],
        [box.left + box.width / 2, box.top + box.height / 2]];
      return { left: box.left, right: box.right, top: box.top, bottom: box.bottom, width: box.width, height: box.height,
        clip: { left, right, top, bottom }, text_fits: element.scrollWidth <= element.clientWidth + 1 && element.scrollHeight <= element.clientHeight + 1,
        hit_samples: samples, corner_radius: radius,
        owned_hits: samples.map(([x, y]) => { const hit = document.elementFromPoint(x, y); return Boolean(hit && (hit === element || element.contains(hit))); }) };
    });
    report.home_layout_probe = { viewport, element: label, geometry };
    assert.ok(geometry.width > 0 && geometry.height > 0 && geometry.text_fits, "Active objective text must remain readable");
    assert.ok(geometry.left >= geometry.clip.left - 1 && geometry.right <= geometry.clip.right + 1
      && geometry.top >= geometry.clip.top - 1 && geometry.bottom <= geometry.clip.bottom + 1, "Active objective content must fit its visible viewport");
    assert.ok(geometry.owned_hits.every(Boolean), "Active objective content must be unobscured");
    elements.push({ label, ...geometry });
  }
  assert.ok(documentGeometry.scroll_width <= documentGeometry.document_width + 1, "Home must not overflow horizontally");
  capture.layout_verified = true;
  report.checks.push(`active_objective_readable_at_${viewport.width}x${viewport.height}`);
  delete report.home_layout_probe;
}

async function waitOwner(predicate, timeout = 120_000, ownerId = receiverJobId, deadline) {
  const until = deadline ?? Date.now() + Math.min(remainingMs(), timeout);
  while (Date.now() < until) {
    const requestTimeout = boundedLocalTimeout(until, Date.now(), remainingMs());
    if (requestTimeout <= 0) break;
    latestOwner = await appApi(`/receiver-defense/jobs/${ownerId}`, requestTimeout);
    if (Date.now() >= until) break;
    const role = owners.get(ownerId);
    if (role === "original") originalEnvelope = latestOwner;
    else if (role === "linked") linkedEnvelope = latestOwner;
    const current = latestOwner.phases?.find((item) => item.phase === currentPhase);
    if (current?.preparation?.preparation_digest) latestPreparationDigest = current.preparation.preparation_digest;
    if (current?.execution_job?.job_id) executionJobId = current.execution_job.job_id;
    if (predicate(latestOwner)) return latestOwner;
    await delay(Math.min(500, Math.max(1, until - Date.now())));
  }
  remainingMs();
  throw new Error("Receiver phase did not reach the expected saved state");
}

async function waitComposition(predicate, timeout = 110_000) {
  const until = Date.now() + Math.min(remainingMs(), timeout);
  while (Date.now() < until) {
    const requestTimeout = boundedLocalTimeout(until, Date.now(), remainingMs());
    if (requestTimeout <= 0) break;
    latestCompositionObjective = await appApi(`/composition/objectives/${compositionOwnerId}`, requestTimeout);
    assert.equal(latestCompositionObjective.owner?.job_id, compositionOwnerId);
    if (predicate(latestCompositionObjective)) return latestCompositionObjective;
    await delay(Math.min(500, Math.max(1, until - Date.now())));
  }
  remainingMs();
  throw new Error("Composed attempt did not reach the expected saved state");
}

async function waitForState(predicate, label, timeout = 10_000, deadline) {
  const until = deadline ?? Date.now() + Math.min(remainingMs(), timeout);
  while (Date.now() < until) {
    remainingMs();
    if (predicate()) return;
    await delay(Math.min(50, Math.max(1, until - Date.now())));
  }
  remainingMs();
  throw new Error(`${label} was not recorded`);
}

async function readRunnerStatus() {
  return appApi(`/runner?profile_id=${PROFILE}`);
}

async function stopOwnerNormally() {
  if (!receiverJobId || !connected || !page || page.isClosed()) {
    if (receiverStarted) report.cleanup = { ...(report.cleanup ?? {}), receiver_control_stopped: false };
    return;
  }
  try {
    latestOwner = await appApi(`/receiver-defense/jobs/${receiverJobId}`);
    if (["completed", "stopped"].includes(latestOwner.status)) return;
    const response = await page.evaluate(async ({ jobId, timeout }) => {
      const token = sessionStorage.getItem("bluefire.browser-session.v1");
      return fetch(`/api/v1/jobs/${encodeURIComponent(jobId)}/cancel`, {
        method: "POST", redirect: "error", credentials: "omit",
        headers: { "X-BlueFire-Session": token, "Content-Type": "application/json", Accept: "application/json" },
        body: "{}",
        signal: AbortSignal.timeout(timeout),
      }).then((result) => result.ok);
    }, { jobId: receiverJobId, timeout: remainingMs() });
    if (!response) throw new Error("Receiver test cancellation was refused");
    latestOwner = await waitOwner((value) => value.status === "stopped", 30_000);
    report.cleanup = { ...(report.cleanup ?? {}), receiver_control_stopped: true };
  } catch {
    report.cleanup = { ...(report.cleanup ?? {}), receiver_control_stopped: false };
  }
}

async function revokeCompositionNormally() {
  if (!compositionOwnerId || !connected || !page || page.isClosed()) return;
  try {
    const until = Date.now() + Math.min(30_000, remainingMs());
    let revokeRequested = false;
    while (Date.now() < until) {
      const timeout = boundedLocalTimeout(until, Date.now(), remainingMs());
      if (timeout <= 0) break;
      let current;
      try { current = await appApi(`/composition/objectives/${compositionOwnerId}`, timeout); }
      catch {
        await delay(Math.min(500, Math.max(1, until - Date.now())));
        continue;
      }
      assert.equal(current.owner?.job_id, compositionOwnerId);
      const cleanupState = receiverCompositionCleanupState(current);
      if (cleanupState === "settled") {
        report.cleanup = { ...(report.cleanup ?? {}), composition_grant_revoked: true };
        return;
      }
      if (cleanupState === "no_grant") {
        report.cleanup = { ...(report.cleanup ?? {}), composition_grant_revoked: false, composition_no_grant_issued: true };
        return;
      }
      if (current.grant && current.grant.status !== "revoked" && !revokeRequested) {
        revokeRequested = true;
        const postTimeout = boundedLocalTimeout(until, Date.now(), remainingMs());
        if (postTimeout <= 0) break;
        try {
          await page.evaluate(async ({ owner, timeout }) => {
            const token = sessionStorage.getItem("bluefire.browser-session.v1");
            const response = await fetch(`/api/v1/composition/objectives/${encodeURIComponent(owner)}/revoke`, {
              method: "POST", redirect: "error", credentials: "omit",
              headers: { "X-BlueFire-Session": token, "Content-Type": "application/json", Accept: "application/json" },
              body: "{}", signal: AbortSignal.timeout(timeout),
            });
            return response.ok;
          }, { owner: compositionOwnerId, timeout: postTimeout });
        } catch { /* A lost response is reconciled by exact saved status reads below. */ }
      }
      await delay(Math.min(500, Math.max(1, until - Date.now())));
    }
    report.cleanup = { ...(report.cleanup ?? {}), composition_grant_revoked: false };
  } catch {
    report.cleanup = { ...(report.cleanup ?? {}), composition_grant_revoked: false };
  }
}

async function stopRunnerNormally() {
  if (!runnerStarted) return;
  if (!connected || !page || page.isClosed()) {
    report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: false };
    return;
  }
  try {
    const status = await readRunnerStatus();
    if (status.state === "ready") {
      const stopped = await page.evaluate(async ({ profileId, timeout }) => {
        const token = sessionStorage.getItem("bluefire.browser-session.v1");
        const response = await fetch("/api/v1/runner/stop", {
          method: "POST", redirect: "error", credentials: "omit",
          headers: { "X-BlueFire-Session": token, "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ profile_id: profileId }),
          signal: AbortSignal.timeout(timeout),
        });
        return response.ok ? response.json() : null;
      }, { profileId: PROFILE, timeout: remainingMs() });
      if (!stopped || stopped.state !== "stopped") throw new Error("Runner stop was not confirmed");
    }
    await page.waitForFunction(async ({ origin, profile, timeout }) => {
      const token = sessionStorage.getItem("bluefire.browser-session.v1");
      const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, {
        headers: { "X-BlueFire-Session": token }, signal: AbortSignal.timeout(timeout),
      });
      return response.ok && (await response.json()).state === "stopped";
    }, { origin: ORIGIN, profile: PROFILE, timeout: remainingMs() }, { timeout: 45_000 });
    assert.equal((await readRunnerStatus()).state, "stopped");
    report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: true };
  } catch {
    report.cleanup = { ...(report.cleanup ?? {}), runner_stopped: false };
  }
}

async function executePhase(phaseName, role) {
  const phaseButton = `Prepare ${phaseName} receiver`;
  currentPhase = phaseName;
  stage = `${role}-${phaseName}-preparation`;
  await page.getByRole("button", { name: phaseButton, exact: true }).waitFor({ state: "visible" });
  await page.getByLabel("Prepared by", { exact: true }).fill(`Installed receiver ${role} verifier`);
  await page.getByRole("button", { name: phaseButton, exact: true }).click();
  await waitOwner((owner) => owner.next_action?.kind === "review_replay"
    && owner.phases?.find((item) => item.phase === phaseName)?.review_ready === true);
  const before = latestOwner.phases.find((item) => item.phase === phaseName);
  assert.ok(before?.preparation?.preparation_digest);
  const preparationDigest = before.preparation.preparation_digest;
  const sessionId = before.preparation.session?.receiver_session_id;
  if (typeof sessionId !== "string" || !/^[0-9a-f]{64}$/.test(sessionId) || receiverSessionIds.has(sessionId)) {
    throw new Error("Receiver session identity was invalid or reused");
  }
  receiverSessionIds.add(sessionId);
  latestPreparationDigest = preparationDigest;

  stage = `${role}-${phaseName}-review`;
  executionJobId = undefined;
  await page.getByRole("checkbox", { name: "I reviewed this receiver policy and the complete run plan.", exact: true }).check();
  await page.getByLabel("Reviewed by", { exact: true }).fill(`Installed receiver ${role} verifier`);
  await page.getByRole("button", { name: "Accept and review run approval", exact: true }).click();
  await page.getByRole("button", { name: "Approve and release job", exact: true }).waitFor({ state: "visible" });
  await waitForState(() => Boolean(executionJobId), `${role}/${phaseName} reviewed execution identity`);
  assert.match(executionJobId ?? "", ID, `${role}/${phaseName} must create the reviewed execution job`);
  const phaseExecutionId = executionJobId;

  stage = `${role}-${phaseName}-execute-approval`;
  await page.getByRole("checkbox", { name: receiverApprovalAcknowledgementName }).check();
  await page.getByLabel("Operator identity for this job", { exact: true }).fill(`Installed receiver ${role} verifier`);
  await page.getByRole("button", { name: "Approve and release job", exact: true }).click();
  stage = `${role}-${phaseName}-result-binding`;
  const completed = await waitCompletedPhase(phaseName);
  const result = completed?.result;
  recordPhaseBindingDiagnostic("phase_result_present", phaseName, completed);
  assert.ok(result, `${role}/${phaseName} must retain its result`);
  recordPhaseBindingDiagnostic("execution_job_kind", phaseName, completed);
  assert.equal(completed.execution_job.kind, phaseName === "baseline" ? "scenario.run" : "scenario.replay");
  recordPhaseBindingDiagnostic("execution_job_state", phaseName, completed);
  assert.equal(completed.execution_job.state, "completed");
  recordPhaseBindingDiagnostic("result_phase", phaseName, completed);
  assert.equal(result.phase, phaseName);
  recordPhaseBindingDiagnostic("run_id_matches_result_ref", phaseName, completed);
  assert.equal(result.run_id, completed.execution_job.result_ref);
  recordPhaseBindingDiagnostic("run_id_format", phaseName, completed);
  assert.match(result.run_id, RUN_ID);
  recordPhaseBindingDiagnostic("receiver_observation_state", phaseName, completed);
  assert.equal(result.receiver_observation?.state, "verified");
  recordPhaseBindingDiagnostic("result_cleanup_receiver", phaseName, completed);
  assert.equal(result.cleanup?.receiver, "verified_closed");
  recordPhaseBindingDiagnostic("result_cleanup_run", phaseName, completed);
  assert.equal(result.cleanup?.run, "complete");
  recordPhaseBindingDiagnostic("phase_cleanup_receiver", phaseName, completed);
  assert.equal(completed.cleanup?.receiver, "verified_closed");
  recordPhaseBindingDiagnostic("phase_cleanup_run", phaseName, completed);
  assert.equal(completed.cleanup?.run, "complete");
  const terminal = result.receiver_observation.terminal?.decision;
  assert.equal(terminal?.decision, phaseName === "protected" ? "policy_refused" : "accepted");
  assert.equal(terminal?.semantics?.record_count, 8);
  if (phaseName === "baseline") {
    assert.equal(result.decision, "accepted");
    assert.ok(result.artifact);
    assert.equal(terminal.semantics.redacted_record_count, 0);
    assert.equal(terminal.semantics.retained_record_count, 8);
  } else if (phaseName === "protected") {
    assert.equal(result.decision, "policy_refused");
    assert.deepEqual(result.artifact, originalEnvelope.phases.find((item) => item.phase === "baseline")?.result?.artifact);
  } else {
    assert.equal(result.decision, "accepted");
    assert.notDeepEqual(result.artifact, originalEnvelope.phases.find((item) => item.phase === "baseline")?.result?.artifact);
    assert.deepEqual(result.legitimate_use, {
      baseline_run_id: originalEnvelope.phases.find((item) => item.phase === "baseline")?.result?.run_id,
      established: true,
    });
    assert.equal(terminal.semantics.redacted_record_count, 8);
    assert.equal(terminal.semantics.retained_record_count, 0);
  }
  phaseEvidence.push({
    owner_role: role,
    owner_job_id: receiverJobId,
    phase: phaseName,
    status: completed.status,
    execution_state: completed.execution_job.state,
    execution_job_id: phaseExecutionId,
    preparation_digest: preparationDigest,
    run_id: result.run_id,
    artifact: result.artifact,
    decision: result.decision,
    observation_state: result.receiver_observation.state,
    terminal_decision: terminal.decision,
    terminal_authenticated: terminal.authenticated,
    terminal_record_count: terminal.semantics.record_count,
    terminal_redacted_record_count: terminal.semantics.redacted_record_count,
    terminal_retained_record_count: terminal.semantics.retained_record_count,
    legitimate_use: result.legitimate_use ?? null,
    cleanup: { receiver: result.cleanup.receiver, run: result.cleanup.run },
  });
  report.phase_evidence = phaseEvidence;
  report.unique_receiver_session_count = receiverSessionIds.size;
  phaseIndexes[role] += 1;
  executions.set(`${receiverJobId}:${phaseName}`, phaseExecutionId);
  if (role === "original") originalEnvelope = latestOwner;
  else linkedEnvelope = latestOwner;
  return completed;
}

try {
  const { chromium } = await import(pathToFileURL(modulePath).href);
  browser = await chromium.launch({
    headless: true,
    timeout: boundedTimeout(30_000),
    args: ["--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1", "--no-proxy-server", "--disable-background-networking"],
  });
  report.browser_version = browser.version();
  context = await browser.newContext({ serviceWorkers: "block", viewport: { width: 1440, height: 900 } });
  context.setDefaultTimeout(remainingMs());
  context.setDefaultNavigationTimeout(remainingMs());
  await context.routeWebSocket("**/*", (socket) => closeReceiverWebSocket(socket, {
    onBlocked: () => report.blocked_requests.push({ kind: "websocket", destination: "blocked" }),
    onFailure: recordCallbackFailure,
  }));
  await context.route("**/*", (route) => handleReceiverRoute(route, {
    expectedOrigin: ORIGIN,
    allowedRead,
    authorizePost,
    describeBlockedPost: (url, reason) => receiverPostDenialDiagnostic(url.pathname, reason, lastPostBudgetDenial),
    onBlocked: (entry) => report.blocked_requests.push(entry),
    onFailure: recordCallbackFailure,
  }));
  page = wrapPage(await context.newPage());
  page.on("response", observeReceiverEvent(async (response) => {
    const request = response.request();
    if (new URL(response.url()).origin !== ORIGIN) return;
    const path = new URL(response.url()).pathname;
    if (request.method() === "GET" && path === "/api/v1/session" && response.status() === 401) expected401 += 1;
    if (request.method() !== "POST") return;
    const preparePath = receiverJobId
      ? `/api/v1/receiver-defense/jobs/${receiverJobId}/prepare`
      : undefined;
    const failedPrepareResponse = path === preparePath && !response.ok();
    const prepareStatus = failedPrepareResponse ? response.status() : null;
    if (failedPrepareResponse) {
      prepareHttpDiagnostic = receiverPrepareHttpDiagnostic(prepareStatus, null);
      if (pendingPreparationFailure?.prepare_http) {
        Object.assign(pendingPreparationFailure.prepare_http, prepareHttpDiagnostic);
      }
    }
    try {
      const contextRequestBody = path === "/api/v1/receiver-defense/context"
        ? request.postDataJSON()
        : undefined;
      const data = await response.json();
      if (failedPrepareResponse) {
        prepareHttpDiagnostic = receiverPrepareHttpDiagnostic(prepareStatus, data);
        if (pendingPreparationFailure?.prepare_http) {
          Object.assign(pendingPreparationFailure.prepare_http, prepareHttpDiagnostic);
        }
      }
      if (path === "/api/v1/receiver-defense/context" && response.ok()
        && receiverContextResponseMatchesRequest(contextRequestBody, latestFinalContextRequest, data)) latestContext = data;
      else if (path === "/api/v1/composition/context" && response.ok()) latestCompositionReview = data;
      else if (path === "/api/v1/composition/objectives" && response.ok()) latestCompositionObjective = data;
      else if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}/proposal-context` && response.ok()) latestCompositionContext = data;
      else if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}/attempts` && response.ok()) latestCompositionObjective = data;
      else if (compositionOwnerId && path === `/api/v1/composition/objectives/${compositionOwnerId}/revoke` && response.ok()) latestCompositionObjective = data;
      else if (path === "/api/v1/comparisons" && response.ok()) compositionSnapshotId = data.saved_snapshot?.snapshot_id;
      else if (path === "/api/v1/receiver-defense/jobs" && response.ok()) {
        const createdId = data.job?.job_id;
        const role = data.context?.source_control ? "linked" : "original";
        if (role === "original") originalOwnerId = createdId;
        else linkedOwnerId = createdId;
        receiverJobId = createdId;
        activeOwnerRole = role;
        owners.set(createdId, role);
        latestOwner = data;
        receiverStarted = Boolean(receiverJobId);
        if (role === "original") originalEnvelope = data;
        else linkedEnvelope = data;
      } else if (receiverJobId && path === `/api/v1/receiver-defense/jobs/${receiverJobId}/prepare` && response.ok()) {
        latestOwner = data;
        const phase = data.phases?.find((item) => item.phase === currentPhase);
        if (phase?.preparation?.preparation_digest) latestPreparationDigest = phase.preparation.preparation_digest;
      } else if (receiverJobId && path === `/api/v1/receiver-defense/jobs/${receiverJobId}/review` && response.ok()) {
        latestOwner = data;
        const phase = data.phases?.find((item) => item.phase === currentPhase);
        executionJobId = phase?.execution_job?.job_id;
        if (executionJobId) executions.set(`${receiverJobId}:${currentPhase}`, executionJobId);
        if (activeOwnerRole === "original") originalEnvelope = data;
        else linkedEnvelope = data;
      }
    } catch { /* Error details stay out of the retained report. */ }
  }, () => recordCallbackFailure("response_observer_failed"), pendingObservers));
  page.on("pageerror", observeReceiverEvent(() => report.errors.push({ stage, kind: "page_error" }),
    () => recordCallbackFailure("pageerror_observer_failed"), pendingObservers));
  page.on("console", observeReceiverEvent((message) => {
    if (message.type() !== "error") return;
    if (!connected && stage === "connect" && expected401 > 0 && message.location().url === `${ORIGIN}/api/v1/session`
      && /^Failed to load resource: the server responded with a status of 401\b/.test(message.text())) {
      expected401 -= 1;
      return;
    }
    report.errors.push({ stage, kind: "console_error" });
  }, () => recordCallbackFailure("console_observer_failed"), pendingObservers));

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
  await page.waitForFunction(async ({ origin, profile, timeout }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, {
      headers: { "X-BlueFire-Session": token }, signal: AbortSignal.timeout(timeout),
    });
    return response.ok && (await response.json()).state === "stopped";
  }, { origin: ORIGIN, profile: PROFILE, timeout: remainingMs() }, { timeout: 120_000 });
  const afterBootstrap = await readRunnerStatus();
  if (afterBootstrap.state !== "ready") {
    assert.equal(afterBootstrap.state, "stopped", "Only the exact newly enrolled runner can be started");
    await page.getByRole("button", { name: "Start authenticated host", exact: true }).click();
  }
  await page.waitForFunction(async ({ origin, profile, timeout }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, {
      headers: { "X-BlueFire-Session": token }, signal: AbortSignal.timeout(timeout),
    });
    return response.ok && (await response.json()).state === "ready";
  }, { origin: ORIGIN, profile: PROFILE, timeout: remainingMs() }, { timeout: 45_000 });
  const ready = await readRunnerStatus();
  report.runner_status_diagnostic = {
    state: safeStatus(ready.state, ["ready", "stopped", "unbootstrapped", "unavailable"]),
    enrollment: safeStatus(ready.enrollment, ["active", "required", "revoked", "unavailable"]),
    process: safeStatus(ready.process, ["authenticated", "absent", "stale", "unavailable"]),
    profile_matches: ready.profile_id === PROFILE,
  };
  assert.equal(ready.state, "ready");
  assert.equal(ready.profile_id, PROFILE);
  assert.equal(ready.enrollment, "active");
  assert.equal(ready.process, "authenticated");
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

  stage = "baseline-save-version";
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
  stage = "baseline-read-saved-version";
  const persistedCopies = (await appApi("/scenario-versions")).scenarios.filter((item) => item.scenario_id === saved.scenario_id);
  assert.equal(persistedCopies.length, 1, "Exactly one saved copy must be retained");
  assert.equal(persistedCopies[0].version, 1);
  assert.equal(persistedCopies[0].digest, saved.digest);
  assert.ok(same(persistedCopies[0].document, expectedScenarioCopy));
  savedSelection = { kind: "saved_scenario", scenario_id: saved.scenario_id, version: saved.version, digest: saved.digest };
  report.source_starter_scenario_id = STARTER;
  report.saved_scenario_copy = { scenario_id: saved.scenario_id, version: saved.version, digest: saved.digest };
  report.checks.push("packaged_starter_duplicated_and_saved_through_ui");

  stage = "baseline-control-open";
  await page.goto(`${ORIGIN}/#/compare?receiver=1`);
  stage = "baseline-control-workflow";
  await page.getByRole("radio", { name: "Retain redaction and verify legitimate use", exact: true }).check();
  stage = "baseline-control-saved-experiment";
  await page.getByLabel("Saved experiment", { exact: false }).selectOption(`${saved.scenario_id}:${saved.version}:${saved.digest}`);
  stage = "baseline-control-execution-mode";
  await page.getByRole("radio", { name: /^Execute / }).check();
  stage = "baseline-control-environment-profile";
  await page.getByRole("combobox", { name: "Environment profile", exact: true }).selectOption(PROFILE);
  stage = "baseline-control-target-scopes";
  for (const label of ["Files in the selected workspace", "Connections to the local lab receiver"]) {
    const scope = page.getByRole("checkbox", { name: label, exact: true });
    if (!(await scope.isChecked())) await scope.check();
  }
  stage = "baseline-control-save-availability";
  const saveControl = page.getByRole("button", { name: "Save control test", exact: true });
  await saveControl.waitFor({ state: "visible" });
  await page.waitForFunction(() => {
    const button = [...document.querySelectorAll("button")].find((item) => item.textContent?.trim() === "Save control test");
    return Boolean(button && !button.disabled);
  }, undefined, { timeout: 30_000 });
  stage = "baseline-control-submit";
  await saveControl.click();
  stage = "baseline-control-job-navigation";
  await page.waitForFunction(() => location.hash.includes("receiver_job=job-"));
  stage = "baseline-control-owner-response";
  const ownerResponseDeadline = Date.now() + Math.min(remainingMs(), 10_000);
  await waitForState(() => Boolean(receiverJobId && latestOwner?.context && latestFinalContextRequest && latestContext), "original receiver owner response", 10_000, ownerResponseDeadline);
  assert.match(receiverJobId ?? "", ID);
  const baselineOwnerId = receiverJobId;
  const originalFinalRequest = structuredClone(latestFinalContextRequest);
  const originalFinalContext = structuredClone(latestContext);
  assert.notEqual(receiverOwnerAdmissionState(latestOwner, baselineOwnerId, originalFinalRequest, originalFinalContext), "invalid");
  const admittedOwner = await waitOwner((value) => {
    const state = receiverOwnerAdmissionState(value, baselineOwnerId, originalFinalRequest, originalFinalContext);
    assert.notEqual(state, "invalid", "The saved owner response changed identity, source, context, or admission shape");
    return state === "accepted";
  }, 10_000, baselineOwnerId, ownerResponseDeadline);
  assert.equal(admittedOwner.context.workflow, "retained_redaction");
  assert.equal(admittedOwner.admission.accepted, true);
  report.receiver_job_id = baselineOwnerId;
  report.checks.push("saved_scenario_context_and_receiver_admission");

  stage = "original-baseline-preparation";
  activeOwnerRole = "original";
  currentPhase = "baseline";
  await page.getByRole("button", { name: "Prepare baseline receiver", exact: true }).waitFor({ state: "visible" });
  await page.getByLabel("Prepared by", { exact: true }).fill("Installed receiver baseline verifier");
  await page.getByRole("button", { name: "Prepare baseline receiver", exact: true }).click();
  await waitOwner((owner) => owner.next_action?.kind === "review_replay" && owner.phases?.[0]?.review_ready === true);
  const preparedBaseline = latestOwner.phases.find((item) => item.phase === "baseline");
  latestPreparationDigest = preparedBaseline.preparation.preparation_digest;
  receiverStarted = true;
  report.receiver_preparation = {
    phase: preparedBaseline.phase,
    policy_id: preparedBaseline.policy_id,
    preparation_digest: latestPreparationDigest,
    preflight_ready: preparedBaseline.preparation.preflight?.status === "approval_required",
    target_effects_started_before_review: preparedBaseline.preparation.target_effects_started,
  };
  assert.equal(report.receiver_preparation.preflight_ready, true);
  assert.equal(report.receiver_preparation.target_effects_started_before_review, false);

  stage = "baseline-review";
  executionJobId = undefined;
  await page.getByRole("checkbox", { name: "I reviewed this receiver policy and the complete run plan.", exact: true }).check();
  await page.getByLabel("Reviewed by", { exact: true }).fill("Installed receiver baseline verifier");
  await page.getByRole("button", { name: "Accept and review run approval", exact: true }).click();
  await page.getByRole("button", { name: "Approve and release job", exact: true }).waitFor({ state: "visible" });
  await waitForState(() => Boolean(executionJobId), "original/baseline reviewed execution identity");
  assert.match(executionJobId ?? "", ID);
  report.execution_job_id = executionJobId;

  stage = "execute-approval";
  await page.getByRole("checkbox", { name: receiverApprovalAcknowledgementName }).check();
  await page.getByLabel("Operator identity for this job", { exact: true }).fill("Installed receiver baseline verifier");
  await page.getByRole("button", { name: "Approve and release job", exact: true }).click();
  stage = "baseline-result-binding";
  const baseline = await waitCompletedPhase("baseline");
  const result = baseline.result;
  recordPhaseBindingDiagnostic("baseline_result_present", "baseline", baseline);
  assert.ok(result);
  recordPhaseBindingDiagnostic("execution_job_kind_scenario_run", "baseline", baseline);
  assert.equal(baseline.execution_job.kind, "scenario.run");
  recordPhaseBindingDiagnostic("execution_job_state_completed", "baseline", baseline);
  assert.equal(baseline.execution_job.state, "completed");
  recordPhaseBindingDiagnostic("baseline_decision_accepted", "baseline", baseline);
  assert.equal(result.decision, "accepted");
  recordPhaseBindingDiagnostic("baseline_result_phase", "baseline", baseline);
  assert.equal(result.phase, "baseline");
  recordPhaseBindingDiagnostic("run_id_matches_execution_result_ref", "baseline", baseline);
  assert.equal(result.run_id, baseline.execution_job.result_ref);
  recordPhaseBindingDiagnostic("run_id_matches_required_format", "baseline", baseline);
  assert.match(result.run_id, RUN_ID);
  stage = "baseline-run-source";
  assert.equal(result.run?.mode, "execute");
  assert.equal(receiverRunIsNotDemo(result.run), true, "The finalized run must not be marked as a demo");
  assert.equal(result.run?.runner_profile_id, PROFILE);
  assert.equal(result.run?.plan?.autonomy, "off");
  stage = "baseline-authenticated-observation";
  assert.equal(result.receiver_observation?.state, "verified");
  assert.equal(result.receiver_observation?.terminal?.decision?.decision, "accepted");
  assert.equal(result.receiver_observation?.terminal?.decision?.semantics?.record_count, 8);
  stage = "baseline-cleanup";
  assert.equal(result.cleanup?.receiver, "verified_closed");
  assert.equal(result.cleanup?.run, "complete");
  assert.equal(baseline.cleanup?.receiver, "verified_closed");
  assert.equal(baseline.cleanup?.run, "complete");
  baselineRunId = result.run_id;
  report.run_id = baselineRunId;
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
  stage = "baseline-retained-source-proof";
  assert.equal(report.baseline.scenario_id, savedSelection.scenario_id);
  assert.equal(report.baseline.receiver_terminal.authenticated, true);
  report.checks.push("native_execute_baseline_and_authenticated_receiver_terminal");
  originalEnvelope = latestOwner;
  phaseIndexes.original = 1;
  phaseEvidence.push({
    owner_role: "original", owner_job_id: originalOwnerId, phase: "baseline", status: baseline.status,
    execution_state: baseline.execution_job.state, observation_state: result.receiver_observation.state,
    execution_job_id: executionJobId, preparation_digest: baseline.preparation.preparation_digest,
    run_id: result.run_id,
    artifact: result.artifact, decision: result.decision, terminal_decision: result.receiver_observation.terminal.decision.decision,
    terminal_authenticated: result.receiver_observation.terminal.decision.authenticated,
    terminal_record_count: result.receiver_observation.terminal.decision.semantics.record_count,
    terminal_redacted_record_count: result.receiver_observation.terminal.decision.semantics.redacted_record_count,
    terminal_retained_record_count: result.receiver_observation.terminal.decision.semantics.retained_record_count,
    legitimate_use: null, cleanup: { receiver: result.cleanup.receiver, run: result.cleanup.run },
  });
  report.phase_evidence = phaseEvidence;
  const baselineSessionId = baseline.preparation.session?.receiver_session_id;
  if (typeof baselineSessionId !== "string" || !/^[0-9a-f]{64}$/.test(baselineSessionId)) {
    throw new Error("Original baseline receiver session identity was invalid");
  }
  receiverSessionIds.add(baselineSessionId);
  report.unique_receiver_session_count = receiverSessionIds.size;

  activeOwnerRole = "original";
  await executePhase("protected", "original");
  await executePhase("legitimate", "original");
  assert.equal(phaseIndexes.original, 3);
  assert.equal(originalEnvelope.status, "completed");
  assert.equal(originalEnvelope.control?.status, "retained");
  assert.equal(originalEnvelope.control?.receiver_state, "stopped");
  originalControlDigest = originalEnvelope.control.control_digest;
  assert.match(originalControlDigest ?? "", /^sha256:[0-9a-f]{64}$/);
  report.original_owner_job_id = originalOwnerId;
  report.original_control = {
    status: originalEnvelope.control.status,
    receiver_state: originalEnvelope.control.receiver_state,
    control_digest: originalControlDigest,
    source_baseline_run_id: originalEnvelope.phases.find((item) => item.phase === "baseline")?.result?.run_id,
  };
  report.checks.push("original_baseline_protected_and_legitimate_use_completed_with_retained_policy");

  stage = "composition-model-settings";
  const retainedControlUrl = page.url();
  await page.goto(`${ORIGIN}/#/settings`, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Model connection", exact: true }).waitFor();
  await page.getByRole("combobox", { name: "API style", exact: true }).selectOption("openai_responses");
  await page.getByLabel("Model ID", { exact: false }).fill(MODEL);
  await page.getByLabel("Request endpoint", { exact: false }).fill(PROVIDER_ENDPOINT);
  await page.getByLabel("Secret environment reference", { exact: false }).fill("");
  await page.locator("details.provider-request-limits > summary").click();
  await page.getByLabel("Timeout seconds", { exact: true }).fill("30");
  await page.getByLabel("Output token limit", { exact: false }).fill("1024");
  await page.getByLabel("Transport retries", { exact: true }).fill("0");
  await page.locator(".provider-connection-fields > details.provider-field-wide:not(.provider-request-limits) > summary").click();
  await page.getByLabel("Provider ID", { exact: false }).fill(PROVIDER_ID);
  stage = "composition-model-save";
  await page.getByRole("button", { name: "Save secret-free draft", exact: true }).click();
  await page.getByText(`Responses API · ${MODEL} saved. Activation and model usage authorization remain separate.`, { exact: true }).waitFor();
  assert.equal(counts.provider_save, 1);
  stage = "composition-model-consent";
  const receiverPurpose = page.getByRole("checkbox", { name: MODEL_PURPOSE_LABEL, exact: true });
  await receiverPurpose.waitFor({ state: "visible" });
  assert.equal(await receiverPurpose.isChecked(), false);
  await receiverPurpose.check();
  await page.getByLabel("Total request attempts", { exact: false }).fill("1");
  await page.getByLabel("Total request bytes", { exact: false }).fill("262144");
  await page.getByLabel("Total reserved output tokens", { exact: false }).fill("1024");
  await page.getByLabel("Authorization duration in seconds", { exact: false }).fill("300");
  await page.getByLabel("Operator identity for model usage", { exact: true }).fill(MODEL_REVIEWER);
  await page.getByRole("checkbox", { name: "I authorize requests to this loopback endpoint.", exact: true }).check();
  await page.getByRole("checkbox", { name: "I authorize the selected model work, reviewed lab data and these usage limits.", exact: true }).check();
  await page.getByRole("button", { name: "Authorize reviewed model usage", exact: true }).click();
  await page.getByText("Authorization saved. No model request was sent. Select this provider in Assistant or run setup when ready.", { exact: true }).waitFor();
  assert.equal(counts.provider_activate, 1);
  assert.equal(counts.model_authorization, 1);
  const authorized = await readOwnedModelAuthorization();
  assert.equal(authorized.status, "active");
  assert.equal(authorized.usage?.requests, 0);
  report.checks.push("receiver_composition_loopback_provider_saved_and_exact_purpose_authorized_without_request");
  await page.goto(retainedControlUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("link", { name: "Open composition workspace", exact: true }).waitFor();

  stage = "composition-review";
  await page.getByRole("link", { name: "Open composition workspace", exact: true }).click();
  await page.getByLabel("Objective question", { exact: true }).fill(COMPOSITION_QUESTION);
  const reviewResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/composition/context"
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Review finite delegation", exact: true }).click();
  latestCompositionReview = await (await reviewResponse).json();
  assert.equal(latestCompositionReview.environment?.control_owner_id, originalOwnerId);
  assert.equal(latestCompositionReview.objective?.predicate?.record_count, 8);
  assert.equal(latestCompositionReview.objective?.predicate?.kind, "redacted_delivery_preserves_records");
  assert.match(latestCompositionReview.review_digest ?? "", /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(latestCompositionReview.snapshot?.methods?.map(method => method.action_id), [
    "sandbox.fixture.create.v1", "sandbox.fixture.transform.v1", "sandbox.discovery.list.v1",
    "sandbox.discovery.metadata.v1", "sandbox.collection.stage.v1", "sandbox.peer.handoff.v1",
    "sandbox.cleanup.v1",
  ]);
  assert.equal(latestCompositionReview.limits?.per_attempt_wall_ms, 90_000);
  stage = "composition-grant";
  await page.getByLabel("Delegation reviewed by", { exact: true }).fill(COMPOSITION_REVIEWER);
  await page.getByRole("checkbox", { name: "I authorize the reviewed finite capabilities, data effects, cleanup reserve and cumulative budgets for this objective.", exact: true }).check();
  const grantResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/composition/objectives"
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Issue capability grant", exact: true }).click();
  latestCompositionObjective = await (await grantResponse).json();
  assert.equal(latestCompositionObjective.owner?.job_id, compositionOwnerId);
  assert.equal(latestCompositionObjective.grant?.status, "active");
  assert.equal(latestCompositionObjective.grant?.document?.environment?.control_owner_id, originalOwnerId);
  assert.equal(latestCompositionObjective.grant?.document?.objective?.predicate?.record_count, 8);
  assert.equal(latestCompositionObjective.attempts?.length, 0);
  const grantId = latestCompositionObjective.grant.document.grant_id;
  assert.match(grantId ?? "", /^grant-[0-9a-f]{32}$/);
  await waitForState(() => latestCompositionContext?.grant_id === grantId,
    "current established composition graph", 20_000);
  const initial = latestCompositionContext.initial_proposal;
  assert.equal(initial?.schema_version, "bluefire.composition-proposal.v1");
  assert.equal(initial.steps?.find(step => step.behavior_id === "sandbox.fixture.transform.v1")?.parameters?.redact_values, false);
  assert.ok(initial.steps?.some(step => step.behavior_id === "sandbox.peer.handoff.v1"));
  stage = "composition-model-proposal";
  await page.getByRole("combobox", { name: "Configured model provider", exact: true }).selectOption(PROVIDER_ID);
  const proposalResponse = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/composition/objectives/${compositionOwnerId}/proposals`
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Request AI graph", exact: true }).click();
  latestCompositionProposal = await (await proposalResponse).json();
  assert.equal(latestCompositionProposal.job?.job_id, compositionProposalJobId);
  assert.equal(latestCompositionProposal.job?.kind, "composition.proposal");
  const proposalUntil = Date.now() + Math.min(20_000, remainingMs());
  while (Date.now() < proposalUntil && latestCompositionProposal?.job?.state !== "completed") {
    await delay(Math.min(750, Math.max(1, proposalUntil - Date.now())));
    latestCompositionProposal = await appApi(`/composition/proposals/${compositionProposalJobId}`);
  }
  stage = "composition-model-proposal-binding";
  assert.equal(latestCompositionProposal.job?.state, "completed");
  assert.equal(latestCompositionProposal.job?.request?.owner_id, compositionOwnerId);
  assert.equal(latestCompositionProposal.job?.request?.submitted_request?.provider_id, PROVIDER_ID);
  assert.equal(latestCompositionProposal.job?.request?.submitted_request?.context_digest, latestCompositionContext.context_digest);
  assert.equal(latestCompositionProposal.job?.request?.submitted_request?.prior_attempt_id, null);
  assert.equal(latestCompositionProposal.provider_outcome, "candidate");
  assert.equal(latestCompositionProposal.candidate_ready, true);
  assert.equal(latestCompositionProposal.proposal?.proposal_job_id, compositionProposalJobId);
  assert.equal(latestCompositionProposal.proposal?.owner_id, compositionOwnerId);
  assert.equal(latestCompositionProposal.proposal?.context_digest, latestCompositionContext.context_digest);
  assert.match(latestCompositionProposal.proposal?.proposal_digest ?? "", /^sha256:[0-9a-f]{64}$/);
  assert.match(latestCompositionProposal.proposal?.model_context_digest ?? "", /^sha256:[0-9a-f]{64}$/);
  assert.equal(latestCompositionProposal.proposal?.provider?.provider_id, PROVIDER_ID);
  assert.equal(latestCompositionProposal.proposal?.provider?.model, MODEL);
  assert.equal(latestCompositionProposal.proposal?.provider?.attempts, 1);
  assert.equal(latestCompositionProposal.proposal?.provider?.used_fallback, false);
  assert.deepEqual(latestCompositionProposal.proposal?.candidate, initial);
  assert.deepEqual(latestCompositionProposal.proposal?.scenario, latestCompositionContext.initial_scenario);
  assert.equal((await readOwnedModelAuthorization()).usage?.requests, 1);
  stage = "composition-model-proposal-inspect";
  await page.getByRole("button", { name: "Start fresh attempt within grant", exact: true }).waitFor();
  await page.getByRole("button", { name: "Inspect graph", exact: true }).click();
  await page.locator(".composition-graph").getByText("Compiler-validated projection", { exact: true }).waitFor();
  stage = "composition-model-proposal-reopen";
  const proposalDigest = latestCompositionProposal.proposal.proposal_digest;
  // Retire the previous document before installing correlation: even a request
  // initiated by it during navigation must not acknowledge the saved reopening.
  await page.goto("about:blank", { waitUntil: "domcontentloaded" });
  const reopenedContext = createReceiverReloadContextCorrelation(
    request => request.isNavigationRequest() && request.frame() === page.mainFrame()
      && new URL(request.url()).origin === ORIGIN,
    request => request.method() === "POST" && new URL(request.url()).origin === ORIGIN
      && new URL(request.url()).pathname === `/api/v1/composition/objectives/${compositionOwnerId}/proposal-context`,
  );
  const reopenedRequest = page.waitForRequest(reopenedContext.request, { timeout: 20_000 });
  const reopenedResponse = page.waitForResponse(reopenedContext.response, { timeout: 20_000 });
  await page.goto(`${ORIGIN}/#/composition?${new URLSearchParams({ control: originalOwnerId, objective: compositionOwnerId, proposal: compositionProposalJobId })}`, { waitUntil: "domcontentloaded" });
  await reopenedRequest;
  const freshContextResponse = await reopenedResponse;
  assert.equal(freshContextResponse.ok(), true);
  latestCompositionContext = await freshContextResponse.json();
  assert.equal(latestCompositionContext?.grant_id, grantId);
  await page.getByRole("button", { name: "Start fresh attempt within grant", exact: true }).waitFor();
  latestCompositionProposal = await appApi(`/composition/proposals/${compositionProposalJobId}`);
  assert.equal(latestCompositionProposal.job?.job_id, compositionProposalJobId);
  assert.equal(latestCompositionProposal.proposal?.proposal_digest, proposalDigest);
  assert.deepEqual(latestCompositionProposal.proposal?.candidate, initial);
  assert.equal(latestCompositionProposal.candidate_ready, true);
  assert.equal(latestCompositionContext?.context_digest, latestCompositionProposal.proposal?.context_digest);
  const modelProposalProof = {
    job_id: compositionProposalJobId, proposal_digest: proposalDigest,
    context_digest: latestCompositionContext.context_digest, provider_id: PROVIDER_ID,
    candidate_ready: true, reopened: true, same_initial_graph: true,
    model_authorization_requests: 1,
  };
  report.checks.push("single_loopback_composition_proposal_reopened_and_applied_to_existing_attempt");
  stage = "composition-attempt";
  compositionInteractionUi = await compositionUiSnapshot("before_click");
  const attemptResponse = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/composition/objectives/${compositionOwnerId}/attempts`
    && response.request().method() === "POST");
  compositionInteractionStep = "click";
  await page.getByRole("button", { name: "Start fresh attempt within grant", exact: true }).click();
  compositionInteractionStep = "response";
  latestCompositionObjective = await (await attemptResponse).json();
  compositionInteractionStep = "settlement";
  assert.equal(latestCompositionObjective.owner?.job_id, compositionOwnerId);
  const settledComposition = await waitComposition(value => value.attempts?.some(attempt =>
    attempt.job_id === compositionAttemptJobId && attempt.progress?.settlement === "settled"
      && attempt.progress?.verified_result));
  const composedAttempt = settledComposition.attempts.find(attempt => attempt.job_id === compositionAttemptJobId);
  const binding = composedAttempt?.request?.composition_attempt;
  const verified = composedAttempt?.progress?.verified_result;
  assert.equal(composedAttempt?.state, "completed");
  assert.equal(binding?.parent_job_id, compositionOwnerId);
  assert.equal(binding?.grant_id, grantId);
  assert.equal(binding?.grant_digest, settledComposition.grant.document.grant_digest);
  assert.match(binding?.attempt_id ?? "", /^attempt-[0-9a-f]{32}$/);
  assert.match(binding?.run_id ?? "", RUN_ID);
  assert.equal(verified?.run_id, binding.run_id);
  assert.equal(verified?.source_binding?.run_id, binding.run_id);
  assert.match(composedAttempt.progress.verified_result_digest ?? "", /^sha256:[0-9a-f]{64}$/);
  const receiverObservation = composedAttempt.progress.receiver_observation;
  assert.equal(receiverObservation?.state, "verified");
  assert.equal(receiverObservation?.terminal?.decision?.authenticated, true);
  assert.equal(receiverObservation?.terminal?.decision?.decision, "policy_refused");
  assert.equal(receiverObservation?.process_exit?.returncode, 0);
  assert.equal(composedAttempt.progress.receiver_closed, true);
  assert.deepEqual(verified.receiver_result && {
    decision: verified.receiver_result.decision,
    record_count: verified.receiver_result.record_count,
    redacted_record_count: verified.receiver_result.redacted_record_count,
    retained_record_count: verified.receiver_result.retained_record_count,
    empty_record_count: verified.receiver_result.empty_record_count,
  }, { decision: "policy_refused", record_count: 8, redacted_record_count: 0, retained_record_count: 8, empty_record_count: 0 });
  assert.deepEqual(verified.cleanup, { run: "complete", receiver: "verified_closed" });
  assert.equal(verified.objective?.established, false);
  assert.deepEqual(verified.objective?.checks, {
    receiver_verified: true, policy_unchanged: true, data_class_preserved: true,
    record_count_preserved: true, all_records_redacted: false, accepted: false,
    run_cleaned: true, receiver_closed: true,
  });
  stage = "composition-finalized-run-read";
  const finalizedComposedRun = await appApi(`/runs/${encodeURIComponent(binding.run_id)}`);
  stage = "composition-finalized-run-binding";
  assert.equal(finalizedComposedRun.schema_version, "bluefire.run-result.v1");
  assert.equal(finalizedComposedRun.run_id, binding.run_id);
  assert.equal(finalizedComposedRun.mode, "execute");
  assert.ok(["completed", "incomplete"].includes(finalizedComposedRun.status));
  assert.equal(receiverRunIsNotDemo(finalizedComposedRun), true);
  assert.ok(typeof finalizedComposedRun.finalized_at === "string" && finalizedComposedRun.finalized_at.length > 0);
  assert.equal(finalizedComposedRun.manifest?.schema_version, "1.0");
  assert.equal(finalizedComposedRun.manifest?.run_id, binding.run_id);
  assert.match(finalizedComposedRun.manifest?.bundle_hash ?? "", /^sha256:[0-9a-f]{64}$/);
  assert.equal(typeof finalizedComposedRun.objective_reached, "boolean");
  const finalizedGraphObjectiveReached = finalizedComposedRun.objective_reached;
  report.composition = {
    control_owner_job_id: originalOwnerId, objective_owner_job_id: compositionOwnerId,
    grant_id: grantId, grant_status: "active", attempt_job_id: compositionAttemptJobId,
    attempt_id: binding.attempt_id, settlement: composedAttempt.progress.settlement,
    run_id: binding.run_id, verified_result_digest: composedAttempt.progress.verified_result_digest,
    receiver_decision: verified.receiver_result.decision, receiver_authenticated: true,
    record_count: verified.receiver_result.record_count,
    redacted_record_count: verified.receiver_result.redacted_record_count,
    retained_record_count: verified.receiver_result.retained_record_count,
    empty_record_count: verified.receiver_result.empty_record_count,
    cleanup: verified.cleanup, objective_established: verified.objective.established,
    finalized_run_objective_reached: finalizedGraphObjectiveReached,
    model_proposal: modelProposalProof,
  };
  report.checks.push("finite_composed_attempt_settled_with_authenticated_policy_refusal_and_objective_false");
  stage = "composition-revoke";
  const revokeResponse = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/composition/objectives/${compositionOwnerId}/revoke`
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  latestCompositionObjective = await (await revokeResponse).json();
  assert.equal(latestCompositionObjective.grant?.status, "revoked");
  assert.equal(latestCompositionObjective.grant?.cleanup_state, "settled");
  assert.equal(latestCompositionObjective.attempts?.find(attempt => attempt.job_id === compositionAttemptJobId)?.progress?.settlement, "settled");
  report.composition.grant_status = "revoked";
  report.cleanup = { ...(report.cleanup ?? {}), composition_grant_revoked: true };
  report.checks.push("composed_attempt_grant_revoked_after_verified_cleanup");

  stage = "linked-retest-setup";
  await page.goto(`${ORIGIN}/#/compare?receiver=1&receiver_job=${originalOwnerId}`);
  await waitRememberedWork(originalOwnerId);
  await page.getByRole("button", { name: "Review fresh retest", exact: true }).click();
  const retestAcknowledgement = page.getByRole("checkbox", { name: "I reviewed the retained policy, original baseline lineage, and this retest's scope.", exact: true });
  await retestAcknowledgement.waitFor({ state: "visible" });
  await page.waitForFunction(() => {
    const label = [...document.querySelectorAll("label")].find((item) => item.textContent?.includes("I reviewed the retained policy, original baseline lineage, and this retest's scope."));
    return Boolean(label && !label.querySelector("input")?.disabled);
  });
  await retestAcknowledgement.check();
  const saveRetest = page.getByRole("button", { name: "Save fresh retest", exact: true });
  await page.waitForFunction(() => [...document.querySelectorAll("button")].some((item) => item.textContent?.trim() === "Save fresh retest" && !item.disabled));
  await saveRetest.click();
  await page.waitForFunction(() => location.hash.includes("receiver_job=job-"));
  await page.waitForFunction(() => new URLSearchParams(location.hash.split("?")[1] ?? "").get("receiver_job") !== null);
  await waitForState(() => Boolean(linkedOwnerId && linkedEnvelope?.context), "linked receiver owner response");
  assert.match(linkedOwnerId ?? "", ID, "The normal retained-control UI must create a linked owner");
  assert.notEqual(linkedOwnerId, originalOwnerId);
  assert.deepEqual(linkedEnvelope?.context?.source_control, { job_id: originalOwnerId, control_digest: originalControlDigest });
  assert.equal(linkedEnvelope?.context?.source_baseline?.run_id, baselineRunId);
  report.linked_owner_job_id = linkedOwnerId;
  report.checks.push("fresh_retest_created_through_retained_control_ui_with_original_lineage");

  activeOwnerRole = "linked";
  await executePhase("protected", "linked");
  await executePhase("legitimate", "linked");
  assert.equal(phaseIndexes.linked, 2);
  assert.equal(linkedEnvelope.status, "completed");
  assert.equal(linkedEnvelope.control?.status, "retained");
  assert.equal(linkedEnvelope.control?.receiver_state, "stopped");
  assert.equal(linkedEnvelope.context.source_control.job_id, originalOwnerId);
  assert.equal(linkedEnvelope.context.source_baseline.run_id, baselineRunId);
  assert.deepEqual(linkedEnvelope.phases.find((item) => item.phase === "protected")?.result?.artifact,
    originalEnvelope.phases.find((item) => item.phase === "baseline")?.result?.artifact);
  report.linked_retest = {
    status: linkedEnvelope.status,
    phases: linkedEnvelope.phases.map((item) => ({ phase: item.phase, status: item.status, run_id: item.result?.run_id, decision: item.result?.decision })),
    source_control_job_id: linkedEnvelope.context.source_control.job_id,
    source_control_digest: linkedEnvelope.context.source_control.control_digest,
    source_baseline_run_id: linkedEnvelope.context.source_baseline.run_id,
    retained_control_status: linkedEnvelope.control.status,
    receiver_state: linkedEnvelope.control.receiver_state,
  };
  report.phase_evidence = phaseEvidence;
  report.unique_receiver_session_count = receiverSessionIds.size;
  report.checks.push("linked_fresh_protected_refusal_and_legitimate_use_completed_under_retained_policy");
  report.cleanup = { ...(report.cleanup ?? {}), original_owner_completed_retained: true, linked_owner_completed_retained: true };

  stage = "runner-cleanup";
  await page.goto(`${ORIGIN}/#/runners?profile=${encodeURIComponent(PROFILE)}`);
  await page.getByRole("button", { name: "Stop safely", exact: true }).waitFor({ state: "visible" });
  await page.getByRole("button", { name: "Stop safely", exact: true }).click();
  await page.waitForFunction(async ({ origin, profile, timeout }) => {
    const token = sessionStorage.getItem("bluefire.browser-session.v1");
    const response = await fetch(`${origin}/api/v1/runner?profile_id=${encodeURIComponent(profile)}`, {
      headers: { "X-BlueFire-Session": token }, signal: AbortSignal.timeout(timeout),
    });
    return response.ok && (await response.json()).state === "stopped";
  }, { origin: ORIGIN, profile: PROFILE, timeout: remainingMs() }, { timeout: 45_000 });
  runnerStarted = false;
  report.cleanup.runner_stopped = true;
  report.runner_final_state = { state: "stopped", source: "authenticated_status_poll_after_stop" };
  report.checks.push("managed_runner_stopped_through_ui");

  stage = "composition-saved-comparison-page";
  const comparisonParams = new URLSearchParams({ compare_context: "1" });
  comparisonParams.append("compare_run", baselineRunId);
  comparisonParams.append("compare_run", report.composition.run_id);
  await page.goto(`${ORIGIN}/#/compare?${comparisonParams}`);
  await page.getByRole("button", { name: "Compare selected", exact: true }).waitFor();
  stage = "composition-saved-comparison-response";
  const comparisonResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/comparisons"
    && response.request().method() === "POST");
  await page.getByRole("button", { name: "Compare selected", exact: true }).click();
  const response = await comparisonResponse;
  comparisonDiagnostic = { http_status: response.status() };
  stage = "composition-saved-comparison-response-json";
  const comparison = await response.json();
  stage = "composition-saved-comparison-response-run-ids";
  assert.deepEqual(comparison.run_ids, [baselineRunId, report.composition.run_id]);
  stage = "composition-saved-comparison-response-baseline-id";
  assert.equal(comparison.baseline_run_id, baselineRunId);
  stage = "composition-saved-comparison-response-summary-ids";
  assert.deepEqual(comparison.summaries?.map(item => item.run_id), comparison.run_ids);
  stage = "composition-saved-comparison-projection-read";
  const composedSummary = comparison.summaries[1];
  comparisonDiagnostic.projection = {
    state: ["verified", "unverified"].includes(composedSummary?.capability_objective?.state)
      ? composedSummary.capability_objective.state : "unreported",
    established: typeof composedSummary?.capability_objective?.established === "boolean"
      ? composedSummary.capability_objective.established : "unreported",
    effective_objective: typeof composedSummary?.objective_reached === "boolean"
      ? composedSummary.objective_reached : "unreported",
    graph_objective: typeof composedSummary?.graph_objective_reached === "boolean"
      ? composedSummary.graph_objective_reached : "unreported",
    cleanup_success: typeof composedSummary?.cleanup_success === "boolean"
      ? composedSummary.cleanup_success : "unreported",
  };
  stage = "composition-saved-comparison-projection-state";
  assert.equal(composedSummary.capability_objective?.state, "verified");
  stage = "composition-saved-comparison-projection-run-id";
  assert.equal(composedSummary.capability_objective?.run_id, report.composition.run_id);
  stage = "composition-saved-comparison-projection-attempt-id";
  assert.equal(composedSummary.capability_objective?.attempt_id, report.composition.attempt_id);
  stage = "composition-saved-comparison-projection-established";
  assert.equal(composedSummary.capability_objective?.established, false);
  stage = "composition-saved-comparison-projection-result-digest";
  assert.equal(composedSummary.capability_objective?.result_digest, report.composition.verified_result_digest);
  stage = "composition-saved-comparison-effective-objective";
  assert.equal(composedSummary.objective_reached, false);
  stage = "composition-saved-comparison-graph-objective";
  assert.equal(composedSummary.graph_objective_reached, finalizedGraphObjectiveReached);
  stage = "composition-saved-comparison-cleanup-success";
  assert.equal(composedSummary.cleanup_success, true);
  stage = "composition-saved-comparison-baseline-unscoped";
  assert.equal(comparison.summaries[0].capability_objective, null);
  stage = "composition-saved-comparison-delta-read";
  const composedDelta = comparison.deltas?.find(item => item.from_run_id === baselineRunId
    && item.to_run_id === report.composition.run_id);
  comparisonDiagnostic.delta = {
    comparability: ["comparable", "different_objectives", "unverified"].includes(composedDelta?.objective_comparability)
      ? composedDelta.objective_comparability : "unreported",
    objective_changed: typeof composedDelta?.objective_changed === "boolean"
      ? composedDelta.objective_changed : "unreported",
    recovery_signal: Array.isArray(composedDelta?.signals)
      ? composedDelta.signals.includes("objective_recovered") : "unreported",
    regression_signal: Array.isArray(composedDelta?.signals)
      ? composedDelta.signals.includes("objective_regressed") : "unreported",
  };
  stage = "composition-saved-comparison-delta-comparability";
  assert.equal(composedDelta?.objective_comparability, "different_objectives");
  stage = "composition-saved-comparison-delta-unchanged";
  assert.equal(composedDelta?.objective_changed, false);
  stage = "composition-saved-comparison-delta-no-recovery";
  assert.ok(!composedDelta?.signals?.includes("objective_recovered"));
  stage = "composition-saved-comparison-delta-no-regression";
  assert.ok(!composedDelta?.signals?.includes("objective_regressed"));
  stage = "composition-saved-comparison-save-snapshot-id";
  assert.match(comparison.saved_snapshot?.snapshot_id ?? "", /^run-comparison-[0-9a-f]{64}$/);
  compositionSnapshotId = comparison.saved_snapshot.snapshot_id;
  stage = "composition-saved-comparison-save-read";
  const savedComparison = await appApi(`/comparison-snapshots/${compositionSnapshotId}`);
  comparisonDiagnostic.saved_source_integrity = ["verified", "unavailable"].includes(savedComparison?.source_integrity?.status)
    ? savedComparison.source_integrity.status : "unreported";
  stage = "composition-saved-comparison-save-identity";
  assert.equal(savedComparison.snapshot_id, compositionSnapshotId);
  stage = "composition-saved-comparison-save-run-ids";
  assert.deepEqual(savedComparison.comparison.run_ids, comparison.run_ids);
  stage = "composition-saved-comparison-save-source-integrity";
  assert.equal(savedComparison.source_integrity?.status, "verified");
  stage = "composition-saved-comparison-save-source-ids";
  assert.deepEqual(savedComparison.source_bindings?.map(binding => binding.run_id), comparison.run_ids);
  stage = "composition-saved-comparison-save-objective-digest";
  assert.match(savedComparison.source_bindings[1]?.capability_objective_digest ?? "", /^sha256:[0-9a-f]{64}$/);
  stage = "composition-saved-comparison-render-results";
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  stage = "composition-saved-comparison-render-conclusion";
  await page.getByRole("region", { name: "Comparison conclusion", exact: true })
    .getByText("Objective checks differ", { exact: true }).waitFor();
  stage = "composition-saved-comparison-render-objective";
  await page.getByRole("region", { name: "Compared run outcomes", exact: true })
    .getByText("Not achieved", { exact: true }).waitFor();
  stage = "composition-saved-comparison-render-proof";
  await page.getByRole("region", { name: "Compared run outcomes", exact: true })
    .getByText("Verified", { exact: true }).waitFor();
  stage = "composition-saved-comparison-render-graph";
  const graphRow = page.getByRole("region", { name: "Compared run outcomes", exact: true })
    .getByRole("row").filter({ has: page.getByRole("rowheader", { name: "Run-level completion", exact: true }) });
  await graphRow.waitFor();
  assert.equal(await graphRow.getByRole("cell").count(), 2);
  assert.equal(await graphRow.getByRole("cell").nth(0).innerText(), "Not applicable");
  assert.equal(await graphRow.getByRole("cell").nth(1).innerText(), finalizedGraphObjectiveReached ? "Met" : "Not met");
  stage = "composition-saved-comparison-reopen-page";
  await page.goto(`${ORIGIN}/#/compare`);
  const history = page.locator("details.saved-comparisons-browser");
  const historySummary = history.locator(":scope > summary");
  stage = "composition-saved-comparison-reopen-history";
  await historySummary.waitFor();
  if (!await history.evaluate(element => element.open)) await historySummary.click();
  stage = "composition-saved-comparison-reopen-select";
  await page.locator(`button[data-snapshot-id=${JSON.stringify(compositionSnapshotId)}]`).click();
  stage = "composition-saved-comparison-reopen-results";
  await page.getByRole("region", { name: "Comparison results", exact: true }).waitFor();
  stage = "composition-saved-comparison-reopen-route";
  assert.match(new URL(page.url()).hash, new RegExp(`snapshot=${compositionSnapshotId}`));
  stage = "composition-saved-comparison-reopen-read";
  const reopenedComparison = await appApi(`/comparison-snapshots/${compositionSnapshotId}`);
  comparisonDiagnostic.reopened_source_integrity = ["verified", "unavailable"].includes(reopenedComparison?.source_integrity?.status)
    ? reopenedComparison.source_integrity.status : "unreported";
  stage = "composition-saved-comparison-reopen-identity";
  assert.equal(reopenedComparison.snapshot_id, savedComparison.snapshot_id);
  stage = "composition-saved-comparison-reopen-digest";
  assert.equal(reopenedComparison.digest, savedComparison.digest);
  stage = "composition-saved-comparison-reopen-run-ids";
  assert.deepEqual(reopenedComparison.comparison.run_ids, comparison.run_ids);
  stage = "composition-saved-comparison-reopen-objective";
  assert.equal(reopenedComparison.comparison.summaries[1].capability_objective?.established, false);
  stage = "composition-saved-comparison-reopen-result-digest";
  assert.equal(reopenedComparison.comparison.summaries[1].capability_objective?.result_digest, report.composition.verified_result_digest);
  stage = "composition-saved-comparison-reopen-graph";
  assert.equal(reopenedComparison.comparison.summaries[1].graph_objective_reached, finalizedGraphObjectiveReached);
  stage = "composition-saved-comparison-reopen-comparability";
  assert.equal(reopenedComparison.comparison.deltas[0].objective_comparability, "different_objectives");
  stage = "composition-saved-comparison-reopen-source-integrity";
  assert.equal(reopenedComparison.source_integrity?.status, "verified");
  stage = "composition-saved-comparison-reopen-render-conclusion";
  await page.getByRole("region", { name: "Comparison conclusion", exact: true })
    .getByText("Objective checks differ", { exact: true }).waitFor();
  report.composition.graph_objective_reached = composedSummary.graph_objective_reached;
  report.composition.comparison = {
    baseline_run_id: baselineRunId, snapshot_id: compositionSnapshotId,
    snapshot_digest: savedComparison.digest, source_integrity: reopenedComparison.source_integrity.status,
    objective_comparability: reopenedComparison.comparison.deltas[0].objective_comparability,
    objective_changed: reopenedComparison.comparison.deltas[0].objective_changed,
    objective_recovered: reopenedComparison.comparison.deltas[0].signals?.includes("objective_recovered") === true,
    reopened: true,
  };
  report.checks.push("saved_composed_comparison_reopened_with_false_capability_objective_and_recorded_graph_result");

  const finalOwner = await appApi(`/receiver-defense/jobs/${receiverJobId}`);
  assert.equal(finalOwner.status, "completed");
  assert.equal(finalOwner.control?.status, "retained");
  assert.equal(finalOwner.control?.receiver_state, "stopped");
  assert.deepEqual(finalOwner.phases.map((item) => item.phase), ["protected", "legitimate"]);
  assert.ok(finalOwner.phases.every((item) => item.status === "completed"
    && item.cleanup.receiver === "verified_closed" && item.cleanup.run === "complete"));
  const finalOriginal = await appApi(`/receiver-defense/jobs/${originalOwnerId}`);
  assert.equal(finalOriginal.status, "completed");
  assert.equal(finalOriginal.control?.status, "retained");
  assert.equal(finalOriginal.control?.receiver_state, "stopped");
  assert.ok(finalOriginal.phases.every((item) => item.status === "completed"
    && item.cleanup.receiver === "verified_closed" && item.cleanup.run === "complete"));
  // Keep completed execution and shutdown evidence even if later UI checks fail.
  report.owner_status = finalOwner.status;

  stage = "home-linked-reference";
  await waitRememberedWork(linkedOwnerId);
  const draftBeforeHome = await page.evaluate(() => ({ draft: localStorage.getItem("bluefire.local.scenario.v1"),
    saved: localStorage.getItem("bluefire.local.scenario-saved.v1") }));
  assert.ok(typeof draftBeforeHome.draft === "string" && draftBeforeHome.draft.length > 0, "The journey must retain its working draft");
  const homeProjection = homeRecordProjection(finalOriginal, originalOwnerId);
  assert.ok(boundedString(finalOriginal.context?.scenario_title, 512));
  const homeTitle = finalOriginal.context.scenario_title;
  report.checks.push("latest_validated_linked_receiver_reference_retained");

  // The linked retest has two phases. Reopen its real original through the normal
  // record route to inspect all three saved outcomes without inventing a baseline.
  stage = "home-original-record-selection";
  await page.goto(`${ORIGIN}/#/compare?receiver=1&receiver_job=${originalOwnerId}`);
  await waitRememberedWork(originalOwnerId);
  await page.getByRole("link", { name: "Overview", exact: true }).click();
  let homeCard = await assertHomeRecord(homeProjection, homeTitle);
  report.checks.push("active_objective_matches_original_record_outcomes_and_retained_policy");

  stage = "home-continue-objective";
  await homeCard.getByRole("link", { name: "Continue objective", exact: true }).click();
  await page.waitForFunction(id => location.hash === `#/compare?receiver=1&goal=data-handoff&receiver_job=${id}`, originalOwnerId);
  await page.getByRole("list", { name: "Recorded phase outcomes", exact: true }).waitFor({ state: "visible" });
  await waitRememberedWork(originalOwnerId);
  await page.getByRole("link", { name: "Overview", exact: true }).click();
  await assertHomeRecord(homeProjection, homeTitle);
  report.checks.push("active_objective_continues_exact_saved_receiver_route");

  stage = "home-reload-restoration";
  await page.reload();
  await waitRememberedWork(originalOwnerId);
  homeCard = await assertHomeRecord(homeProjection, homeTitle);
  report.checks.push("active_objective_reference_and_recorded_summary_restored_after_reload");

  stage = "home-direct-read-refresh";
  const [refreshed] = await Promise.all([
    page.waitForResponse(response => response.request().method() === "GET"
      && response.url() === `${ORIGIN}/api/v1/receiver-defense/jobs/${originalOwnerId}`),
    homeCard.getByRole("button", { name: "Refresh active objective", exact: true }).click(),
  ]);
  assert.ok(refreshed.ok());
  assert.deepEqual(homeRecordProjection(await refreshed.json(), originalOwnerId), homeProjection);
  homeCard = await assertHomeRecord(homeProjection, homeTitle);
  report.home_resume = { selected_owner_job_id: originalOwnerId, previous_linked_owner_job_id: linkedOwnerId,
    recorded_result: homeProjection, direct_refresh_verified: true, reload_restored: true,
    continuation_route: `/compare?receiver=1&goal=data-handoff&receiver_job=${originalOwnerId}` };
  report.checks.push("active_objective_refresh_reads_exact_owned_receiver_record");
  for (const viewport of [{ width: 1440, height: 900 }, { width: 1366, height: 768 }]) {
    await captureActiveHome(homeCard, viewport, homeProjection);
  }

  stage = "home-show-working-draft";
  await homeCard.getByRole("button", { name: "Show working draft", exact: true }).click();
  await page.locator("#working-copy-heading").waitFor({ state: "visible" });
  assert.equal(await page.locator(".active-objective").count(), 0);
  assert.equal(await page.evaluate(key => localStorage.getItem(key), ACTIVE_WORK_KEY), null);
  const draftAfterHome = await page.evaluate(() => ({ draft: localStorage.getItem("bluefire.local.scenario.v1"),
    saved: localStorage.getItem("bluefire.local.scenario-saved.v1") }));
  assert.deepEqual(draftAfterHome, draftBeforeHome);
  report.home_resume.working_draft_unchanged = true;
  report.home_resume.working_draft_sha256 = createHash("sha256").update(draftBeforeHome.draft).digest("hex");
  report.checks.push("show_working_draft_clears_navigation_preference_without_changing_draft");

  stage = "composition-model-authorization-revoke";
  await revokeModelAuthorizationNormally();
  assert.equal(report.cleanup.model_authorization_revoked, true);
  assert.equal(counts.model_authorization_revoke, 1);
  report.checks.push("receiver_composition_model_authorization_revoked_after_one_proposal");

  report.request_counts = counts;
  assert.equal(report.blocked_requests.length, 0);
  assert.equal(report.errors.length, 0);
  assert.equal(counts.owner, 2);
  assert.equal(counts.save_scenario, 1);
  assert.equal(counts.prepare, 5);
  assert.equal(counts.review, 5);
  assert.equal(counts.approval, 5);
  assert.equal(counts.cancel, 0);
  assert.ok(counts.composition_list >= 1 && counts.composition_list <= ROUTE_LIMITS.composition_list);
  for (const name of ["composition_context", "composition_grant", "composition_proposal", "composition_attempt", "composition_revoke", "comparison", "provider_save", "provider_activate", "model_authorization", "model_authorization_revoke"]) {
    assert.equal(counts[name], 1);
  }
  assert.ok(counts.composition_proposal_context >= 2 && counts.composition_proposal_context <= ROUTE_LIMITS.composition_proposal_context);
  assert.equal(report.cleanup.composition_grant_revoked, true);
  assert.equal(report.cleanup.model_authorization_revoked, true);
  assert.equal(new Set(phaseEvidence.map((item) => item.run_id)).size, 5);
  assert.equal(receiverSessionIds.size, 5);
  report.unique_receiver_session_count = receiverSessionIds.size;
  report.status = "passed";
} catch (error) {
  const errorType = ["AssertionError", "TimeoutError", "TypeError", "Error"].includes(error?.name) ? error.name : "other";
  const failure = { stage, kind: "journey_failed", error_type: errorType };
  if (stage === "composition-attempt" || stage === "composition-model-proposal-reopen") {
    // A spent journey budget must not delay the cleanup reserve for diagnostics.
    compositionInteractionUi = await compositionUiSnapshot("failure");
    failure.composition_interaction = receiverCompositionInteractionDiagnostic(
      compositionInteractionStep, compositionInteractionUi, latestCompositionObjective,
      latestCompositionContext, latestCompositionProposal, Date.now(),
    );
  }
  if (stage.endsWith("-preparation") && currentPhase && receiverJobId) {
    failure.receiver_preparation = receiverPreparationDiagnostic(
      latestOwner,
      currentPhase,
      prepareHttpDiagnostic,
    );
    pendingPreparationFailure = failure.receiver_preparation;
  }
  if (phaseBindingDiagnostic && (stage === "baseline-result-binding" || stage.endsWith("-result-binding"))) {
    if (stage === "baseline-result-binding") failure.baseline_binding = phaseBindingDiagnostic;
    else failure.phase_binding = phaseBindingDiagnostic;
  }
  if (stage.startsWith("baseline-control-")) failure.visible_controls = await visibleControlsDiagnostic();
  if (stage.startsWith("composition-saved-comparison") && comparisonDiagnostic) {
    failure.comparison_diagnostic = comparisonDiagnostic;
  }
  report.errors.push(failure);
  report.request_counts = counts;
} finally {
  capability = "";
  deadlineBudget.beginCleanup(Date.now());
  try { setPlaywrightBudget(); } catch { /* Cleanup still closes browser resources when the total budget is spent. */ }
  await revokeCompositionNormally();
  if (counts.model_authorization > 0 && report.cleanup?.model_authorization_revoked !== true) {
    await revokeModelAuthorizationNormally();
  }
  if (receiverStarted) {
    cleanupCancelAllowed = true;
    await stopOwnerNormally();
  }
  if (runnerStarted) await stopRunnerNormally();
  try { await context?.close(); }
  catch { report.errors.push({ stage: "cleanup", kind: "browser_context_close" }); }
  try { await browser?.close(); }
  catch { report.errors.push({ stage: "cleanup", kind: "browser_close" }); }
  if (!await settleReceiverObservers(pendingObservers, deadlineBudget.bounded(1000, Date.now()))) {
    recordCallbackFailure("observer_unsettled");
  }
  if (report.cleanup?.receiver_control_stopped === false || report.cleanup?.runner_stopped === false
    || (counts.model_authorization > 0 && report.cleanup?.model_authorization_revoked !== true)) {
    report.status = "failed_or_incomplete";
  }
  if (report.errors.length || report.blocked_requests.length) report.status = "failed_or_incomplete";
  writeFileSync(join(output, "installed-receiver-report.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}
