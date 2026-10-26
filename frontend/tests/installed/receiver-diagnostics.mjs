import { preflightDiagnostic } from "./preflight-diagnostics.mjs";

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
    execution_job_state: enumValue(executionJob.state, JOB_STATES),
    execution_job_error_code: errorCode(executionJob.error?.code, JOB_ERROR_CODES),
    prepare_started: booleanValue(progress.prepare_started),
    execution_started: booleanValue(progress.execution_started),
    receiver_closed: booleanValue(progress.receiver_closed),
    prepare_http: safePrepareHttp,
    preflight_refusal: refusal,
  };
}
