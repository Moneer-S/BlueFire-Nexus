import { preflightDiagnostic } from "./preflight-diagnostics.mjs";
/* global document, localStorage, location, getComputedStyle, URL, innerWidth, innerHeight */

// Serialized by Playwright: return only fixed labels and booleans, never UI text,
// saved request bodies, URLs, model configuration or storage contents.
export function readReceiverCompositionUi(expected) {
  const route = new URL(location.href);
  const hash = new URL(route.hash.slice(1), route.origin);
  if (route.origin !== expected.origin || hash.pathname !== "/composition"
    || hash.searchParams.get("objective") !== expected.owner
    || hash.searchParams.get("control") !== expected.control
    || hash.searchParams.get("proposal") !== expected.proposal) return { route_matches: false };
  const buttons = [...document.querySelectorAll("button")].filter(button => button.textContent.trim() === "Start fresh attempt within grant");
  const button = buttons.length === 1 ? buttons[0] : undefined;
  const bounds = button?.getBoundingClientRect();
  const style = button && getComputedStyle(button);
  const centerX = bounds ? bounds.left + bounds.width / 2 : -1;
  const centerY = bounds ? bounds.top + bounds.height / 2 : -1;
  const inView = Boolean(bounds?.width && bounds?.height && centerX >= 0 && centerX < innerWidth && centerY >= 0 && centerY < innerHeight);
  const hit = inView ? document.elementFromPoint(centerX, centerY) : null;
  const textPresent = text => [...document.querySelectorAll(".composition-page .callout strong, .composition-page .loading-state strong")].some(element => element.textContent === text);
  let pendingKind = "none";
  try {
    const raw = localStorage.getItem("bluefire.composition.pending.v1");
    if (raw) {
      const saved = raw.length <= 500_000 ? JSON.parse(raw) : null;
      pendingKind = ["grant", "proposal", "attempt"].includes(saved?.kind) ? saved.kind : "other";
    }
  } catch { pendingKind = "unavailable"; }
  return {
    route_matches: true,
    button_present: Boolean(button),
    button_visible: Boolean(bounds?.width && bounds?.height && style?.display !== "none" && style?.visibility !== "hidden"),
    button_enabled: button ? !button.disabled : null,
    center_hit: !inView ? "out_of_view" : hit === button ? "self" : hit && button.contains(hit) ? "descendant" : "other",
    dispatch_unavailable: textPresent("New dispatch unavailable"),
    context_fetching: textPresent("Verifying current facts and capabilities"),
    candidate_mismatch: textPresent("Candidate no longer matches current evidence"),
    confirmation_pending: textPresent("Request confirmation pending") || textPresent("Saving exact request"),
    pending_kind: pendingKind,
  };
}

export function receiverCompositionInteractionDiagnostic(step, ui, objective, context, proposal, now) {
  const remaining = objective?.grant?.document?.expires_at_ms - now;
  return {
    schema_version: "bluefire.installed-receiver-composition-interaction.v1",
    step: ["reconcile", "click", "response", "settlement"].includes(step) ? step : "other",
    observation: enumValue(ui?.observation, ["before_click", "failure"]),
    center_hit: enumValue(ui?.center_hit, ["self", "descendant", "other", "out_of_view"]),
    route_matches: ui?.route_matches === true,
    button_present: booleanValue(ui?.button_present),
    button_visible: booleanValue(ui?.button_visible),
    button_enabled: booleanValue(ui?.button_enabled),
    dispatch_unavailable: booleanValue(ui?.dispatch_unavailable),
    context_fetching: booleanValue(ui?.context_fetching),
    candidate_mismatch: booleanValue(ui?.candidate_mismatch),
    confirmation_pending: booleanValue(ui?.confirmation_pending),
    pending_kind: enumValue(ui?.pending_kind, ["none", "grant", "proposal", "attempt", "other", "unavailable"]),
    grant_status: enumValue(objective?.grant?.status, ["active", "paused", "revoked", "expired"]),
    grant_time: Number.isFinite(remaining) ? remaining <= 0 ? "expired" : remaining <= 30_000 ? "under_30_seconds" : "over_30_seconds" : "unknown",
    context_present: Boolean(context),
    context_grant_matches: Boolean(context && context.grant_id === objective?.grant?.document?.grant_id),
    candidate_ready: proposal?.candidate_ready === true,
    context_digest_matches: Boolean(context && proposal?.proposal?.context_digest === context.context_digest),
  };
}

const OWNER_STATUSES = ["active", "blocked", "completed", "stopped", "stopping"];
const OWNER_ACTIONS = [
  "approve_execute", "cleanup_required", "completed", "prepare_receiver", "review_replay", "stopped", "wait",
];
const PHASE_NAMES = ["baseline", "protected", "legitimate"];
const PHASE_STATUSES = [
  "awaiting_approval", "completed", "declined", "failed", "interrupted", "not_started",
  "preparing", "review_ready", "running", "stopped", "stopping",
];
const RECEIVER_CLEANUP = ["active", "not_started", "uncertain", "verified_closed"];
const RUN_CLEANUP = ["complete", "not_started", "pending"];
const JOB_STATES = [
  "awaiting_approval", "cancelled", "cancelling", "completed", "failed", "interrupted",
  "paused", "planning", "queued", "running",
];
const PHASE_ERROR_CODES = new Set([
  "receiver_publication_uncertain", "receiver_result_insufficient", "receiver_session_unavailable",
]);
const JOB_ERROR_CODES = new Set([
  "execution_callback_failed", "replay_cleanup_deferred", "replay_record_incomplete",
  "run_cleanup_deferred", "run_record_incomplete",
]);
const JOB_ERROR_TYPES = new Set([
  "APIError", "FileNotFoundError", "JobCancelled", "JobRuntimeError", "OSError",
  "PermissionError", "ProductStoreError", "ReceiverSessionError", "RunnerTransportError",
  "TimeoutError", "TypeError", "ValueError",
]);
const PREPARATION_STAGES = [
  "armed_read", "armed_validate", "attempt_sink", "containment_register", "deadline_check",
  "generation_frame", "monitor_start", "pipe_check", "platform_containment", "prepared_write",
  "process_identity", "ready_read", "ready_validate", "worker_enrollment",
  "worker_listener_startup", "worker_prepare_validation", "worker_ready_frame", "worker_spawn",
];
const PREPARE_HTTP_ERROR_CODES = new Set([
  "browser_session_required", "invalid_service_response", "receiver_defense_refused", "service_error",
]);

const isRecord = value => value !== null && typeof value === "object" && !Array.isArray(value);
const enumValue = (value, allowed) => allowed.includes(value) ? value : value == null ? "missing" : "other";
const errorCode = (value, allowed) => typeof value === "string" && allowed.has(value) ? value : "unknown";
const errorType = value => typeof value === "string" && JOB_ERROR_TYPES.has(value) ? value : "other";
const booleanValue = value => typeof value === "boolean" ? value : null;

export function receiverPrepareHttpDiagnostic(status, body) {
  return {
    schema_version: "bluefire.installed-receiver-prepare-http-diagnostic.v1",
    status: Number.isSafeInteger(status) && status >= 400 && status <= 599 ? status : null,
    error_code: errorCode(body?.error?.code, PREPARE_HTTP_ERROR_CODES),
  };
}

export function receiverPreparationDiagnostic(owner, phaseName, prepareHttp = null) {
  const validOwner = isRecord(owner) ? owner : {};
  const phase = PHASE_NAMES.includes(phaseName) && Array.isArray(validOwner.phases)
    ? validOwner.phases.find(item => isRecord(item) && item.phase === phaseName)
    : undefined;
  const validPhase = isRecord(phase) ? phase : {};
  const receiverJob = isRecord(validPhase.receiver_job) ? validPhase.receiver_job : {};
  const progress = isRecord(receiverJob.progress) ? receiverJob.progress : {};
  const executionJob = isRecord(validPhase.execution_job) ? validPhase.execution_job : {};
  const receiverCleanup = isRecord(validPhase.cleanup) ? validPhase.cleanup.receiver : undefined;
  const runCleanup = isRecord(validPhase.cleanup) ? validPhase.cleanup.run : undefined;
  const refusal = Object.hasOwn(progress, "preflight_refusal")
    ? preflightDiagnostic(progress.preflight_refusal)
    : null;
  const safePrepareHttp = isRecord(prepareHttp)
    && prepareHttp.schema_version === "bluefire.installed-receiver-prepare-http-diagnostic.v1"
    ? {
      schema_version: prepareHttp.schema_version,
      status: Number.isSafeInteger(prepareHttp.status) && prepareHttp.status >= 400 && prepareHttp.status <= 599
        ? prepareHttp.status
        : null,
      error_code: errorCode(prepareHttp.error_code, PREPARE_HTTP_ERROR_CODES),
    }
    : null;

  return {
    schema_version: "bluefire.installed-receiver-preparation-diagnostic.v1",
    owner_status: enumValue(validOwner.status, OWNER_STATUSES),
    owner_next_action: enumValue(validOwner.next_action?.kind, OWNER_ACTIONS),
    phase: PHASE_NAMES.includes(phaseName) ? phaseName : "unknown",
    phase_status: enumValue(validPhase.status, PHASE_STATUSES),
    phase_problem_code: errorCode(validPhase.problem?.code, PHASE_ERROR_CODES),
    receiver_cleanup: enumValue(receiverCleanup, RECEIVER_CLEANUP),
    run_cleanup: enumValue(runCleanup, RUN_CLEANUP),
    preparation_present: validPhase.preparation !== null && validPhase.preparation !== undefined,
    receiver_job_state: enumValue(receiverJob.state, JOB_STATES),
    receiver_job_error_code: errorCode(receiverJob.error?.code, JOB_ERROR_CODES),
    receiver_job_error_type: errorType(receiverJob.error?.exception_type),
    receiver_prepare_failure_stage: enumValue(progress.prepare_failure_stage, PREPARATION_STAGES),
    execution_job_state: enumValue(executionJob.state, JOB_STATES),
    execution_job_error_code: errorCode(executionJob.error?.code, JOB_ERROR_CODES),
    prepare_started: booleanValue(progress.prepare_started),
    execution_started: booleanValue(progress.execution_started),
    receiver_closed: booleanValue(progress.receiver_closed),
    prepare_http: safePrepareHttp,
    preflight_refusal: refusal,
  };
}
