const object = (value: unknown, fields: readonly string[], label: string): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is unavailable.`);
  const row = value as Record<string, unknown>;
  const actual = Object.keys(row).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) throw new Error(`${label} changed.`);
  return row;
};
const choice = <T extends string>(value: unknown, values: readonly T[], label: string): T => {
  if (typeof value !== "string" || !values.includes(value as T)) throw new Error(`${label} is unavailable.`);
  return value as T;
};
const text = (value: unknown, label: string, maximum = 512): string => {
  if (typeof value !== "string" || !value.trim() || value !== value.trim() || value.length > maximum || [...value].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) throw new Error(`${label} is unavailable.`);
  return value;
};
const nullableText = (value: unknown, label: string, maximum = 512): string | null => value === null ? null : text(value, label, maximum);
const integer = (value: unknown, label: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number => {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new Error(`${label} is unavailable.`);
  return Number(value);
};
const boolean = (value: unknown, label: string): boolean => {
  if (typeof value !== "boolean") throw new Error(`${label} is unavailable.`);
  return value;
};
const digest = (value: unknown, label: string): string => {
  const candidate = text(value, label, 71);
  if (!/^sha256:[0-9a-f]{64}$/.test(candidate)) throw new Error(`${label} is unavailable.`);
  return candidate;
};
const nullableDigest = (value: unknown, label: string): string | null => value === null ? null : digest(value, label);
const timestamp = (value: unknown, label: string): string => {
  const candidate = text(value, label, 40);
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?Z$/.exec(candidate);
  const parsed = Date.parse(candidate);
  const date = new Date(parsed);
  if (!parts || !Number.isFinite(parsed) || date.getUTCFullYear() !== Number(parts[1]) || date.getUTCMonth() + 1 !== Number(parts[2]) || date.getUTCDate() !== Number(parts[3]) || date.getUTCHours() !== Number(parts[4]) || date.getUTCMinutes() !== Number(parts[5]) || date.getUTCSeconds() !== Number(parts[6])) throw new Error(`${label} is unavailable.`);
  return candidate;
};
const nullableTimestamp = (value: unknown, label: string): string | null => value === null ? null : timestamp(value, label);
const identifier = (value: unknown, pattern: RegExp, label: string): string => {
  const candidate = text(value, label, 180);
  if (!pattern.test(candidate)) throw new Error(`${label} is unavailable.`);
  return candidate;
};
const strings = (value: unknown, label: string, maximum = 32, itemMaximum = 500): string[] => {
  if (!Array.isArray(value) || value.length > maximum) throw new Error(`${label} is unavailable.`);
  const result = value.map((entry, index) => text(entry, `${label} item ${index + 1}`, itemMaximum));
  if (new Set(result).size !== result.length) throw new Error(`${label} changed.`);
  return result;
};

const EXPERIMENT_ID = /^experiment-[0-9a-f]{32}$/;
const ATTEMPT_ID = /^engine-attempt-[0-9a-f]{32}$/;
const CHECK_ID = /^controller-check-[0-9a-f]{32}$/;
const JOB_ID = /^job-[0-9a-f]{32}$/;
const RUN_ID = /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/;
const ENGINE_EVIDENCE_ID = /^engine-evidence-[0-9a-f]{24}$/;
const OBSERVED_EVIDENCE_ID = /^evidence-[0-9a-f]{20}$/;
const FINDING_ID = /^engine-finding-[0-9a-f]{24}$/;
const ARTIFACT_ID = /^artifact-[0-9a-f]{32}$/;
const CHANGE_ID = /^defense-change-[0-9a-f]{32}$/;
const SOURCE_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const REVISION = /^[0-9a-f]{40}$/;

export const engineAttemptRoles = ["baseline", "adaptive_search"] as const;
export type EngineAttemptRole = typeof engineAttemptRoles[number];
export const engineAttemptStates = ["queued", "preflight", "running", "stopping", "completed", "partial", "failed", "cancelled", "budget_exhausted", "unknown"] as const;
export type EngineAttemptState = typeof engineAttemptStates[number];
export type EngineCompleteness = "complete" | "partial" | "unknown";
export type EngineCleanupState = "pending" | "verified_absent" | "residue" | "unknown";
export type EngineEvidenceCategory = "engine_assertion" | "tool_result" | "independent_target_effect" | "independent_security_outcome" | "legitimate_use";

export interface EngineFinding { finding_id: string; attempt_id: string; title: string; severity: "critical" | "high" | "medium" | "low" | "informational" | "unknown"; mechanism_digest: string; status: "reported" | "reproduced" | "not_reproduced" | "unknown"; summary: string; source_artifact_id: string; evidence_ids: string[] }
export interface EngineObservation { evidence_id: string; attempt_id: string; category: EngineEvidenceCategory; provenance: "engine_reported" | "runner_reported" | "observed" | "control_blocked"; summary: string; producer: string; timestamp: string; limitations: string[] }
export interface EngineArtifact { artifact_id: string; attempt_id: string; name: string; sha256: string; bytes: number; media_type: string; access: "private" | "reviewable" }
export interface EngineAttempt {
  attempt_id: string; role: EngineAttemptRole; job_id: string; run_id: string; upstream_session_id: string | null; state: EngineAttemptState; completeness: EngineCompleteness; exit_reason: string | null; started_at: string | null; finished_at: string | null;
  usage: { duration_ms: number; model_requests: number; input_tokens: number; output_tokens: number; tool_calls: number; cost_microusd: number | null };
  findings: EngineFinding[]; observations: EngineObservation[]; artifacts: EngineArtifact[]; cleanup: { state: EngineCleanupState; receipt_ref: string | null; finished_at: string | null; limitations: string[] }; resume_supported: false;
}

export const engineControllerCheckKinds = ["retained_reproducer", "legitimate_use"] as const;
export type EngineControllerCheckKind = typeof engineControllerCheckKinds[number];
export type EngineControllerCheckState = "reserved" | "completed" | "failed" | "unknown";
export interface EngineControllerObservation { evidence_id: string; check_id: string; category: "independent_target_effect" | "independent_security_outcome" | "legitimate_use"; provenance: "observed" | "control_blocked"; summary: string; producer: string; timestamp: string; limitations: string[] }
export interface EngineControllerCheck {
  check_id: string; role: EngineControllerCheckKind; job_id: string; run_id: string; performer: "bluefire.controller" | "bluefire.trusted-client"; mechanism_ref: string; target_snapshot_ref: string; input_digest: string; result_digest: string | null; state: EngineControllerCheckState; independent_evidence_refs: string[]; created_at: string; settled_at: string | null; observations: EngineControllerObservation[]; cleanup: { state: EngineCleanupState; receipt_ref: string | null; finished_at: string | null; limitations: string[] };
}

export interface EngineProjectionAttempt {
  role: EngineAttemptRole; attempt_id: string; job_id: string; run_id: string; state: EngineAttemptState; completeness: EngineCompleteness;
  engine: { id: "strix"; version: string; revision: string; package_digest: string }; model: { provider: string; id: string; data_destination: string };
  target_snapshot_ref: string; delegation_digest: string; execution_approval_digest: string; cleanup: { state: EngineCleanupState; receipt_ref: string | null }; engine_evidence_count: number; limitations: string[];
}
export interface EngineProjectionCheck {
  role: EngineControllerCheckKind; check_id: string; job_id: string; run_id: string; state: EngineControllerCheckState; performer: "bluefire.controller" | "bluefire.trusted-client"; mechanism_ref: string; target_snapshot_ref: string; input_digest: string; result_digest: string | null; independent_evidence_refs: string[]; cleanup: { state: EngineCleanupState; receipt_ref: string | null };
}
export interface EngineProjectionObservation {
  evidence_id: string; run_id: string; attempt_id: string | null; check_id: string | null; mechanism_ref: string; target_snapshot_ref: string; assessment: "unauthorized_disclosure" | "authorization_denied" | "legitimate_use_succeeded" | "no_protected_effect" | "unknown"; record_hash: string;
}
interface EngineConclusionBase { status: string; run_id: string | null; support_refs: string[] }
export interface EngineExperimentConclusion {
  headline: "inconclusive_original_mechanism" | "original_mechanism_still_succeeds" | "inconclusive_retest" | "original_blocked_legitimate_use_failed" | "original_blocked_legitimate_use_unknown" | "original_blocked_alternate_path_found" | "original_blocked_no_remaining_path_observed_within_limits" | "original_blocked_adaptive_result_unknown";
  original_mechanism: EngineConclusionBase & { status: "not_attempted" | "established" | "not_established" | "unknown" };
  retained_reproducer: EngineConclusionBase & { status: "not_attempted" | "still_succeeds" | "blocked" | "not_established" | "unknown" };
  adaptive_search: EngineConclusionBase & { status: "not_attempted" | "remaining_path_found" | "no_path_observed_within_limits" | "inconclusive" | "pending"; limit_qualified?: boolean };
  legitimate_use: EngineConclusionBase & { status: "not_attempted" | "passed" | "failed" | "unknown" };
  telemetry_health: { status: "not_started" | "complete" | "partial" | "unavailable"; expected_sources: string[]; verified_sources: string[]; missing_sources: string[] };
  cleanup: { status: "not_started" | EngineCleanupState; items: Array<{ kind: "engine_attempt" | "controller_check"; id: string; state: EngineCleanupState; receipt_ref: string | null }> };
  defense: { state: "not_reviewed" | "reviewed" | "applied" | "retained" | "rolled_back" | "unknown"; change_id: string | null; mechanism_ref: string | null; before_target_snapshot_ref: string; after_target_snapshot_ref: string | null; current_target_snapshot_ref: string | null; application_receipt_ref: string | null; reconciliation_receipt_ref: string | null; rollback_operation_ref: string | null; rollback_receipt_ref: string | null };
  unknowns: string[];
}
export type EngineWorkflowState = "ready_for_baseline" | "baseline_active" | "review_defense" | "apply_defense" | "reconcile_defense" | "run_retained_reproducer" | "retained_reproducer_active" | "run_adaptive_search" | "adaptive_search_active" | "run_legitimate_use" | "legitimate_use_active" | "choose_defense_disposition" | "complete";
export interface EngineExperimentProjection {
  schema_version: "bluefire.engine-experiment-projection.v1"; experiment_id: string; revision: number; experiment_digest: string; projection_digest: string; workflow_state: EngineWorkflowState; conclusion: EngineExperimentConclusion; attempts: EngineProjectionAttempt[]; checks: EngineProjectionCheck[]; observations: EngineProjectionObservation[]; run_integrity: Array<{ run_id: string; terminal: boolean; state: "verified" | "unavailable"; detail: string }>;
}
export interface EngineDefenseChange { change_id: string; state: "reviewed" | "applied" | "retained" | "rolled_back" | "unknown"; kind: "configuration" | "permission" | "identity" | "prevention" | "visibility" | "detection"; summary: string; mechanism_ref: string; before_target_snapshot_ref: string; after_target_snapshot_ref: string; rollback_digest: string; applied_at: string | null }
export type EngineWorkspaceActionKind = "start_baseline" | "review_evidence" | "review_defense" | "apply_defense" | "reconcile_defense" | "repeat_mechanism" | "start_adaptive_search" | "run_legitimate_use" | "choose_defense_disposition" | "open_comparison";
export interface EngineWorkspaceAction { kind: EngineWorkspaceActionKind; label: string; enabled: boolean; reason: string | null; primary: boolean }
export type EngineWorkspaceSelectedContext = { kind: "engine_attempt"; attempt: EngineAttempt } | { kind: "controller_check"; check: EngineControllerCheck } | null;
export interface EngineWorkspaceSelection { kind: "engine_attempt" | "controller_check"; id: string }
export interface EngineExperiment {
  schema_version: "bluefire.engine-experiment-workspace.v1"; workspace_digest: string; experiment_id: string; revision: number; experiment_digest: string;
  objective: { objective_ref: string; title: string; summary: string };
  environment: { environment_ref: string; environment_id: string; display_name: string; platform: "linux" | "windows" | "macos"; disposable: true };
  current_target: { snapshot_ref: string; display_name: string; captured_at: string };
  engine_setup: { engine: { id: "strix"; display_name: string; version: string; revision: string; package_digest: string; sandbox_image_digest: string }; model: { provider: string; id: string; data_destination: string; authorization_digest: string; test_provider: boolean } };
  authorization: { scope_ref: string; scope_version: "bluefire.engine-capability-delegation.v1"; wall_clock_seconds: number; action_limit: number; artifact_byte_limit: number; cost_limit_microunits: number };
  defensive_change: EngineDefenseChange | null; projection: EngineExperimentProjection; actions: EngineWorkspaceAction[]; selected_context: EngineWorkspaceSelectedContext; limitations: string[];
}

const parseFinding = (value: unknown, attemptId: string): EngineFinding => {
  const row = object(value, ["finding_id", "attempt_id", "title", "severity", "mechanism_digest", "status", "summary", "source_artifact_id", "evidence_ids"], "Engine finding");
  const finding: EngineFinding = { finding_id: identifier(row.finding_id, FINDING_ID, "Finding identity"), attempt_id: identifier(row.attempt_id, ATTEMPT_ID, "Finding attempt identity"), title: text(row.title, "Finding title", 200), severity: choice(row.severity, ["critical", "high", "medium", "low", "informational", "unknown"], "Finding severity"), mechanism_digest: digest(row.mechanism_digest, "Finding mechanism"), status: choice(row.status, ["reported", "reproduced", "not_reproduced", "unknown"], "Finding status"), summary: text(row.summary, "Finding summary", 1000), source_artifact_id: identifier(row.source_artifact_id, ARTIFACT_ID, "Finding source artifact"), evidence_ids: Array.isArray(row.evidence_ids) ? row.evidence_ids.map(item => identifier(item, ENGINE_EVIDENCE_ID, "Finding evidence identity")) : (() => { throw new Error("Finding evidence is unavailable."); })() };
  if (finding.attempt_id !== attemptId || new Set(finding.evidence_ids).size !== finding.evidence_ids.length) throw new Error("Finding identity changed.");
  return finding;
};
const parseObservation = (value: unknown, attemptId: string): EngineObservation => {
  const row = object(value, ["evidence_id", "attempt_id", "category", "provenance", "summary", "producer", "timestamp", "limitations"], "Engine observation");
  const category = choice(row.category, ["engine_assertion", "tool_result", "independent_target_effect", "independent_security_outcome", "legitimate_use"], "Evidence category");
  const observation: EngineObservation = { evidence_id: identifier(row.evidence_id, category === "engine_assertion" || category === "tool_result" ? ENGINE_EVIDENCE_ID : OBSERVED_EVIDENCE_ID, "Evidence identity"), attempt_id: identifier(row.attempt_id, ATTEMPT_ID, "Evidence attempt identity"), category, provenance: choice(row.provenance, ["engine_reported", "runner_reported", "observed", "control_blocked"], "Evidence provenance"), summary: text(row.summary, "Evidence summary", 1000), producer: text(row.producer, "Evidence producer", 200), timestamp: timestamp(row.timestamp, "Evidence time"), limitations: strings(row.limitations, "Evidence limitations", 16) };
  if (observation.attempt_id !== attemptId) throw new Error("Evidence identity changed.");
  if (observation.category === "engine_assertion" && observation.provenance !== "engine_reported") throw new Error("Engine assertion provenance changed.");
  if (observation.category === "tool_result" && observation.provenance !== "runner_reported") throw new Error("Tool-result provenance changed.");
  if (["independent_target_effect", "independent_security_outcome", "legitimate_use"].includes(observation.category) && !["observed", "control_blocked"].includes(observation.provenance)) throw new Error("Independent evidence provenance changed.");
  return observation;
};
const parseArtifact = (value: unknown, attemptId: string): EngineArtifact => {
  const row = object(value, ["artifact_id", "attempt_id", "name", "sha256", "bytes", "media_type", "access"], "Engine artifact");
  const artifact: EngineArtifact = { artifact_id: identifier(row.artifact_id, ARTIFACT_ID, "Artifact identity"), attempt_id: identifier(row.attempt_id, ATTEMPT_ID, "Artifact attempt identity"), name: text(row.name, "Artifact name", 240), sha256: digest(row.sha256, "Artifact digest"), bytes: integer(row.bytes, "Artifact size", 0, 64 * 1024 * 1024), media_type: text(row.media_type, "Artifact media type", 100), access: choice(row.access, ["private", "reviewable"], "Artifact access") };
  if (artifact.attempt_id !== attemptId || artifact.name.includes("/") || artifact.name.includes("\\") || artifact.name === "." || artifact.name === "..") throw new Error("Artifact identity changed.");
  return artifact;
};
const parseDetailedAttempt = (value: unknown): EngineAttempt => {
  const row = object(value, ["attempt_id", "role", "job_id", "run_id", "upstream_session_id", "state", "completeness", "exit_reason", "started_at", "finished_at", "usage", "findings", "observations", "artifacts", "cleanup", "resume_supported"], "Selected engine attempt");
  const attemptId = identifier(row.attempt_id, ATTEMPT_ID, "Attempt identity");
  const usage = object(row.usage, ["duration_ms", "model_requests", "input_tokens", "output_tokens", "tool_calls", "cost_microusd"], "Engine attempt usage");
  const cleanup = object(row.cleanup, ["state", "receipt_ref", "finished_at", "limitations"], "Engine attempt cleanup");
  const attempt: EngineAttempt = {
    attempt_id: attemptId, role: choice(row.role, engineAttemptRoles, "Attempt role"), job_id: identifier(row.job_id, JOB_ID, "Attempt job identity"), run_id: identifier(row.run_id, RUN_ID, "Attempt run identity"), upstream_session_id: nullableText(row.upstream_session_id, "Upstream session identity", 160), state: choice(row.state, engineAttemptStates, "Attempt state"), completeness: choice(row.completeness, ["complete", "partial", "unknown"], "Attempt completeness"), exit_reason: nullableText(row.exit_reason, "Attempt exit reason", 240), started_at: nullableTimestamp(row.started_at, "Attempt start time"), finished_at: nullableTimestamp(row.finished_at, "Attempt finish time"),
    usage: { duration_ms: integer(usage.duration_ms, "Attempt duration", 0, 7_200_000), model_requests: integer(usage.model_requests, "Model requests", 0, 10_000), input_tokens: integer(usage.input_tokens, "Input tokens", 0), output_tokens: integer(usage.output_tokens, "Output tokens", 0), tool_calls: integer(usage.tool_calls, "Tool calls", 0, 100_000), cost_microusd: usage.cost_microusd === null ? null : integer(usage.cost_microusd, "Model cost", 0) },
    findings: Array.isArray(row.findings) ? row.findings.map(item => parseFinding(item, attemptId)) : (() => { throw new Error("Attempt findings are unavailable."); })(), observations: Array.isArray(row.observations) ? row.observations.map(item => parseObservation(item, attemptId)) : (() => { throw new Error("Attempt observations are unavailable."); })(), artifacts: Array.isArray(row.artifacts) ? row.artifacts.map(item => parseArtifact(item, attemptId)) : (() => { throw new Error("Attempt artifacts are unavailable."); })(),
    cleanup: { state: choice(cleanup.state, ["pending", "verified_absent", "residue", "unknown"], "Cleanup state"), receipt_ref: nullableDigest(cleanup.receipt_ref, "Cleanup receipt"), finished_at: nullableTimestamp(cleanup.finished_at, "Cleanup finish time"), limitations: strings(cleanup.limitations, "Cleanup limitations", 16) }, resume_supported: boolean(row.resume_supported, "Resume support") as false,
  };
  if (attempt.resume_supported !== false) throw new Error("Engine resume is unsupported.");
  const active = ["queued", "preflight", "running", "stopping"].includes(attempt.state);
  if (active && attempt.finished_at !== null || !active && attempt.finished_at === null || attempt.started_at && attempt.finished_at && Date.parse(attempt.finished_at) < Date.parse(attempt.started_at)) throw new Error("Attempt timing changed.");
  if ((active && attempt.cleanup.state !== "pending") || (!active && attempt.cleanup.state === "pending") || (attempt.cleanup.state === "pending") !== (attempt.cleanup.finished_at === null) || (attempt.cleanup.state === "pending") !== (attempt.cleanup.receipt_ref === null)) throw new Error("Attempt cleanup changed.");
  for (const values of [attempt.findings.map(item => item.finding_id), attempt.observations.map(item => item.evidence_id), attempt.artifacts.map(item => item.artifact_id)]) if (new Set(values).size !== values.length) throw new Error("Attempt record identities changed.");
  const artifactIds = new Set(attempt.artifacts.map(item => item.artifact_id)); const evidenceIds = new Set(attempt.observations.map(item => item.evidence_id));
  if (attempt.findings.some(item => !artifactIds.has(item.source_artifact_id) || item.evidence_ids.some(id => !evidenceIds.has(id)))) throw new Error("Finding source identity changed.");
  return attempt;
};

const parseControllerObservation = (value: unknown, checkId: string): EngineControllerObservation => {
  const row = object(value, ["evidence_id", "check_id", "category", "provenance", "summary", "producer", "timestamp", "limitations"], "Controller observation");
  const observation: EngineControllerObservation = { evidence_id: identifier(row.evidence_id, OBSERVED_EVIDENCE_ID, "Controller evidence identity"), check_id: identifier(row.check_id, CHECK_ID, "Controller check identity"), category: choice(row.category, ["independent_target_effect", "independent_security_outcome", "legitimate_use"], "Controller evidence category"), provenance: choice(row.provenance, ["observed", "control_blocked"], "Controller evidence provenance"), summary: text(row.summary, "Controller evidence summary", 1000), producer: text(row.producer, "Controller evidence producer", 200), timestamp: timestamp(row.timestamp, "Controller evidence time"), limitations: strings(row.limitations, "Controller evidence limitations", 16) };
  if (observation.check_id !== checkId) throw new Error("Controller evidence identity changed.");
  return observation;
};
const parseDetailedCheck = (value: unknown): EngineControllerCheck => {
  const row = object(value, ["check_id", "role", "job_id", "run_id", "performer", "mechanism_ref", "target_snapshot_ref", "input_digest", "result_digest", "state", "independent_evidence_refs", "created_at", "settled_at", "observations", "cleanup"], "Selected controller check");
  const checkId = identifier(row.check_id, CHECK_ID, "Controller check identity"); const role = choice(row.role, engineControllerCheckKinds, "Controller check role"); const performer = choice(row.performer, ["bluefire.controller", "bluefire.trusted-client"], "Controller check performer"); const cleanup = object(row.cleanup, ["state", "receipt_ref", "finished_at", "limitations"], "Controller check cleanup");
  const check: EngineControllerCheck = { check_id: checkId, role, job_id: identifier(row.job_id, JOB_ID, "Controller check job identity"), run_id: identifier(row.run_id, RUN_ID, "Controller check run identity"), performer, mechanism_ref: digest(row.mechanism_ref, "Controller mechanism"), target_snapshot_ref: digest(row.target_snapshot_ref, "Controller target snapshot"), input_digest: digest(row.input_digest, "Controller check input"), result_digest: nullableDigest(row.result_digest, "Controller check result"), state: choice(row.state, ["reserved", "completed", "failed", "unknown"], "Controller check state"), independent_evidence_refs: Array.isArray(row.independent_evidence_refs) ? row.independent_evidence_refs.map(item => identifier(item, OBSERVED_EVIDENCE_ID, "Controller evidence reference")) : (() => { throw new Error("Controller evidence references are unavailable."); })(), created_at: timestamp(row.created_at, "Controller check creation time"), settled_at: nullableTimestamp(row.settled_at, "Controller check settlement time"), observations: Array.isArray(row.observations) ? row.observations.map(item => parseControllerObservation(item, checkId)) : (() => { throw new Error("Controller observations are unavailable."); })(), cleanup: { state: choice(cleanup.state, ["pending", "verified_absent", "residue", "unknown"], "Controller cleanup state"), receipt_ref: nullableDigest(cleanup.receipt_ref, "Controller cleanup receipt"), finished_at: nullableTimestamp(cleanup.finished_at, "Controller cleanup finish time"), limitations: strings(cleanup.limitations, "Controller cleanup limitations", 16) } };
  if (performer !== (role === "retained_reproducer" ? "bluefire.controller" : "bluefire.trusted-client")) throw new Error("Controller check performer changed.");
  const terminal = check.state !== "reserved";
  if (terminal !== (check.settled_at !== null) || terminal !== (check.result_digest !== null) || terminal !== (check.cleanup.state !== "pending") || terminal !== (check.cleanup.receipt_ref !== null) || terminal !== (check.cleanup.finished_at !== null)) throw new Error("Controller check settlement changed.");
  if (check.settled_at && Date.parse(check.settled_at) < Date.parse(check.created_at)) throw new Error("Controller check timing changed.");
  if (new Set(check.independent_evidence_refs).size !== check.independent_evidence_refs.length || new Set(check.observations.map(item => item.evidence_id)).size !== check.observations.length || check.observations.some(item => !check.independent_evidence_refs.includes(item.evidence_id))) throw new Error("Controller evidence identities changed.");
  return check;
};

const parseProjectionAttempt = (value: unknown): EngineProjectionAttempt => {
  const row = object(value, ["role", "attempt_id", "job_id", "run_id", "state", "completeness", "engine", "model", "target_snapshot_ref", "delegation_digest", "execution_approval_digest", "cleanup", "engine_evidence_count", "limitations"], "Projected engine attempt");
  const engine = object(row.engine, ["id", "version", "revision", "package_digest"], "Projected engine identity"); const model = object(row.model, ["provider", "id", "data_destination"], "Projected model identity"); const cleanup = object(row.cleanup, ["state", "receipt_ref"], "Projected attempt cleanup");
  const result: EngineProjectionAttempt = { role: choice(row.role, engineAttemptRoles, "Projected attempt role"), attempt_id: identifier(row.attempt_id, ATTEMPT_ID, "Projected attempt identity"), job_id: identifier(row.job_id, JOB_ID, "Projected attempt job"), run_id: identifier(row.run_id, RUN_ID, "Projected attempt run"), state: choice(row.state, engineAttemptStates, "Projected attempt state"), completeness: choice(row.completeness, ["complete", "partial", "unknown"], "Projected attempt completeness"), engine: { id: choice(engine.id, ["strix"], "Projected engine"), version: text(engine.version, "Projected engine version", 80), revision: identifier(engine.revision, REVISION, "Projected engine revision"), package_digest: digest(engine.package_digest, "Projected engine package") }, model: { provider: identifier(model.provider, SOURCE_ID, "Projected model provider"), id: text(model.id, "Projected model ID", 160), data_destination: text(model.data_destination, "Projected model destination", 200) }, target_snapshot_ref: digest(row.target_snapshot_ref, "Projected target snapshot"), delegation_digest: digest(row.delegation_digest, "Projected delegation"), execution_approval_digest: digest(row.execution_approval_digest, "Projected execution approval"), cleanup: { state: choice(cleanup.state, ["pending", "verified_absent", "residue", "unknown"], "Projected attempt cleanup state"), receipt_ref: nullableDigest(cleanup.receipt_ref, "Projected attempt cleanup receipt") }, engine_evidence_count: integer(row.engine_evidence_count, "Projected engine evidence count", 0, 512), limitations: strings(row.limitations, "Projected attempt limitations", 32, 300) };
  const terminal = ["completed", "partial", "failed", "cancelled", "budget_exhausted", "unknown"].includes(result.state);
  if (terminal === (result.cleanup.state === "pending") || (result.cleanup.state === "pending") !== (result.cleanup.receipt_ref === null)) throw new Error("Projected attempt cleanup changed.");
  return result;
};
const parseProjectionCheck = (value: unknown): EngineProjectionCheck => {
  const row = object(value, ["role", "check_id", "job_id", "run_id", "state", "performer", "mechanism_ref", "target_snapshot_ref", "input_digest", "result_digest", "independent_evidence_refs", "cleanup"], "Projected controller check"); const cleanup = object(row.cleanup, ["state", "receipt_ref"], "Projected check cleanup"); const role = choice(row.role, engineControllerCheckKinds, "Projected check role"); const performer = choice(row.performer, ["bluefire.controller", "bluefire.trusted-client"], "Projected check performer");
  const result: EngineProjectionCheck = { role, check_id: identifier(row.check_id, CHECK_ID, "Projected check identity"), job_id: identifier(row.job_id, JOB_ID, "Projected check job"), run_id: identifier(row.run_id, RUN_ID, "Projected check run"), state: choice(row.state, ["reserved", "completed", "failed", "unknown"], "Projected check state"), performer, mechanism_ref: digest(row.mechanism_ref, "Projected check mechanism"), target_snapshot_ref: digest(row.target_snapshot_ref, "Projected check target"), input_digest: digest(row.input_digest, "Projected check input"), result_digest: nullableDigest(row.result_digest, "Projected check result"), independent_evidence_refs: Array.isArray(row.independent_evidence_refs) ? row.independent_evidence_refs.map(item => identifier(item, OBSERVED_EVIDENCE_ID, "Projected check evidence")) : (() => { throw new Error("Projected check evidence is unavailable."); })(), cleanup: { state: choice(cleanup.state, ["pending", "verified_absent", "residue", "unknown"], "Projected check cleanup state"), receipt_ref: nullableDigest(cleanup.receipt_ref, "Projected check cleanup receipt") } };
  if (performer !== (role === "retained_reproducer" ? "bluefire.controller" : "bluefire.trusted-client")) throw new Error("Projected check performer changed.");
  const terminal = result.state !== "reserved";
  if (terminal !== (result.result_digest !== null) || terminal === (result.cleanup.state === "pending") || (result.cleanup.state === "pending") !== (result.cleanup.receipt_ref === null) || new Set(result.independent_evidence_refs).size !== result.independent_evidence_refs.length) throw new Error("Projected check settlement changed.");
  return result;
};

const parseConclusionBase = <T extends string>(value: unknown, statuses: readonly T[], label: string): EngineConclusionBase & { status: T } => {
  const row = object(value, ["status", "run_id", "support_refs"], label);
  return { status: choice(row.status, statuses, `${label} status`), run_id: row.run_id === null ? null : identifier(row.run_id, RUN_ID, `${label} run`), support_refs: Array.isArray(row.support_refs) ? row.support_refs.map(item => identifier(item, OBSERVED_EVIDENCE_ID, `${label} support`)) : (() => { throw new Error(`${label} support is unavailable.`); })() };
};
const parseConclusion = (value: unknown): EngineExperimentConclusion => {
  const row = object(value, ["headline", "original_mechanism", "retained_reproducer", "adaptive_search", "legitimate_use", "telemetry_health", "cleanup", "defense", "unknowns"], "Engine conclusion");
  const adaptiveRow = object(row.adaptive_search, ["status", "run_id", "support_refs", "limit_qualified"], "Adaptive search conclusion");
  const adaptiveBase = { status: choice(adaptiveRow.status, ["not_attempted", "remaining_path_found", "no_path_observed_within_limits", "inconclusive", "pending"], "Adaptive search status"), run_id: adaptiveRow.run_id === null ? null : identifier(adaptiveRow.run_id, RUN_ID, "Adaptive search run"), support_refs: Array.isArray(adaptiveRow.support_refs) ? adaptiveRow.support_refs.map(item => identifier(item, OBSERVED_EVIDENCE_ID, "Adaptive search support")) : (() => { throw new Error("Adaptive search support is unavailable."); })(), limit_qualified: boolean(adaptiveRow.limit_qualified, "Adaptive search qualification") };
  if ((adaptiveBase.status === "no_path_observed_within_limits") !== (adaptiveBase.limit_qualified === true)) throw new Error("Adaptive search qualification changed.");
  const telemetry = object(row.telemetry_health, ["status", "expected_sources", "verified_sources", "missing_sources"], "Telemetry health"); const cleanup = object(row.cleanup, ["status", "items"], "Conclusion cleanup");
  const defense = object(row.defense, ["state", "change_id", "mechanism_ref", "before_target_snapshot_ref", "after_target_snapshot_ref", "current_target_snapshot_ref", "application_receipt_ref", "reconciliation_receipt_ref", "rollback_operation_ref", "rollback_receipt_ref"], "Conclusion defense");
  const cleanupItems = Array.isArray(cleanup.items) ? cleanup.items.map(item => { const entry = object(item, ["kind", "id", "state", "receipt_ref"], "Conclusion cleanup item"); const kind = choice(entry.kind, ["engine_attempt", "controller_check"], "Cleanup item kind"); return { kind, id: identifier(entry.id, kind === "engine_attempt" ? ATTEMPT_ID : CHECK_ID, "Cleanup item identity"), state: choice(entry.state, ["pending", "verified_absent", "residue", "unknown"], "Cleanup item state"), receipt_ref: nullableDigest(entry.receipt_ref, "Cleanup item receipt") }; }) : (() => { throw new Error("Conclusion cleanup items are unavailable."); })();
  const result: EngineExperimentConclusion = {
    headline: choice(row.headline, ["inconclusive_original_mechanism", "original_mechanism_still_succeeds", "inconclusive_retest", "original_blocked_legitimate_use_failed", "original_blocked_legitimate_use_unknown", "original_blocked_alternate_path_found", "original_blocked_no_remaining_path_observed_within_limits", "original_blocked_adaptive_result_unknown"], "Conclusion headline"),
    original_mechanism: parseConclusionBase(row.original_mechanism, ["not_attempted", "established", "not_established", "unknown"], "Original mechanism conclusion"), retained_reproducer: parseConclusionBase(row.retained_reproducer, ["not_attempted", "still_succeeds", "blocked", "not_established", "unknown"], "Retained reproducer conclusion"), adaptive_search: adaptiveBase, legitimate_use: parseConclusionBase(row.legitimate_use, ["not_attempted", "passed", "failed", "unknown"], "Legitimate-use conclusion"),
    telemetry_health: { status: choice(telemetry.status, ["not_started", "complete", "partial", "unavailable"], "Telemetry status"), expected_sources: strings(telemetry.expected_sources, "Expected telemetry", 4, 80), verified_sources: strings(telemetry.verified_sources, "Verified telemetry", 4, 80), missing_sources: strings(telemetry.missing_sources, "Missing telemetry", 4, 80) }, cleanup: { status: choice(cleanup.status, ["not_started", "pending", "verified_absent", "residue", "unknown"], "Conclusion cleanup state"), items: cleanupItems },
    defense: { state: choice(defense.state, ["not_reviewed", "reviewed", "applied", "retained", "rolled_back", "unknown"], "Conclusion defense state"), change_id: defense.change_id === null ? null : identifier(defense.change_id, CHANGE_ID, "Conclusion defense identity"), mechanism_ref: nullableDigest(defense.mechanism_ref, "Conclusion defense mechanism"), before_target_snapshot_ref: digest(defense.before_target_snapshot_ref, "Conclusion defense preimage"), after_target_snapshot_ref: nullableDigest(defense.after_target_snapshot_ref, "Conclusion defense target"), current_target_snapshot_ref: nullableDigest(defense.current_target_snapshot_ref, "Conclusion current target"), application_receipt_ref: nullableDigest(defense.application_receipt_ref, "Conclusion application receipt"), reconciliation_receipt_ref: nullableDigest(defense.reconciliation_receipt_ref, "Conclusion reconciliation receipt"), rollback_operation_ref: nullableDigest(defense.rollback_operation_ref, "Conclusion rollback operation"), rollback_receipt_ref: nullableDigest(defense.rollback_receipt_ref, "Conclusion rollback receipt") }, unknowns: strings(row.unknowns, "Conclusion unknowns", 32),
  };
  const expectedHeadline = result.original_mechanism.status !== "established" ? "inconclusive_original_mechanism" : result.retained_reproducer.status !== "blocked" ? result.retained_reproducer.status === "still_succeeds" ? "original_mechanism_still_succeeds" : "inconclusive_retest" : result.legitimate_use.status === "failed" ? "original_blocked_legitimate_use_failed" : result.legitimate_use.status !== "passed" ? "original_blocked_legitimate_use_unknown" : result.adaptive_search.status === "remaining_path_found" ? "original_blocked_alternate_path_found" : result.adaptive_search.status === "no_path_observed_within_limits" ? "original_blocked_no_remaining_path_observed_within_limits" : "original_blocked_adaptive_result_unknown";
  if (result.headline !== expectedHeadline) throw new Error("Engine conclusion headline changed.");
  const expectedTelemetry = new Set(result.telemetry_health.expected_sources);
  const verifiedTelemetry = new Set(result.telemetry_health.verified_sources);
  const missingTelemetry = new Set(result.telemetry_health.missing_sources);
  if (expectedTelemetry.size !== result.telemetry_health.expected_sources.length
    || verifiedTelemetry.size !== result.telemetry_health.verified_sources.length
    || missingTelemetry.size !== result.telemetry_health.missing_sources.length
    || [...verifiedTelemetry].some(source => !expectedTelemetry.has(source) || missingTelemetry.has(source))
    || [...missingTelemetry].some(source => !expectedTelemetry.has(source))
    || expectedTelemetry.size !== verifiedTelemetry.size + missingTelemetry.size) throw new Error("Telemetry source identity changed.");
  const expectedTelemetryStatus = expectedTelemetry.size === 0 ? "not_started" : missingTelemetry.size === 0 ? "complete" : verifiedTelemetry.size ? "partial" : "unavailable";
  if (result.telemetry_health.status !== expectedTelemetryStatus) throw new Error("Telemetry status changed.");
  const cleanupStates = new Set(result.cleanup.items.map(item => item.state));
  const expectedCleanup = cleanupStates.has("residue") ? "residue" : cleanupStates.has("unknown") ? "unknown" : cleanupStates.has("pending") ? "pending" : result.cleanup.items.length ? "verified_absent" : "not_started";
  if (result.cleanup.status !== expectedCleanup) throw new Error("Conclusion cleanup state changed.");
  return result;
};

const parseProjection = (value: unknown): EngineExperimentProjection => {
  const row = object(value, ["schema_version", "experiment_id", "revision", "experiment_digest", "workflow_state", "conclusion", "attempts", "checks", "observations", "run_integrity", "projection_digest"], "Engine experiment projection");
  if (row.schema_version !== "bluefire.engine-experiment-projection.v1") throw new Error("Engine projection version is unsupported.");
  const attempts = Array.isArray(row.attempts) && row.attempts.length <= 2 ? row.attempts.map(parseProjectionAttempt) : (() => { throw new Error("Projected attempts are unavailable."); })(); const checks = Array.isArray(row.checks) && row.checks.length <= 2 ? row.checks.map(parseProjectionCheck) : (() => { throw new Error("Projected checks are unavailable."); })();
  const observations = Array.isArray(row.observations) && row.observations.length <= 256 ? row.observations.map(item => { const entry = object(item, ["evidence_id", "run_id", "attempt_id", "check_id", "mechanism_ref", "target_snapshot_ref", "assessment", "record_hash"], "Projected observation"); const attemptId = entry.attempt_id === null ? null : identifier(entry.attempt_id, ATTEMPT_ID, "Observation attempt"); const checkId = entry.check_id === null ? null : identifier(entry.check_id, CHECK_ID, "Observation check"); if ((attemptId === null) === (checkId === null)) throw new Error("Observation owner identity changed."); return { evidence_id: identifier(entry.evidence_id, OBSERVED_EVIDENCE_ID, "Observation identity"), run_id: identifier(entry.run_id, RUN_ID, "Observation run"), attempt_id: attemptId, check_id: checkId, mechanism_ref: digest(entry.mechanism_ref, "Observation mechanism"), target_snapshot_ref: digest(entry.target_snapshot_ref, "Observation target"), assessment: choice(entry.assessment, ["unauthorized_disclosure", "authorization_denied", "legitimate_use_succeeded", "no_protected_effect", "unknown"], "Observation assessment"), record_hash: digest(entry.record_hash, "Observation record") } satisfies EngineProjectionObservation; }) : (() => { throw new Error("Projected observations are unavailable."); })();
  const runIntegrity = Array.isArray(row.run_integrity) && row.run_integrity.length <= 4 ? row.run_integrity.map(item => { const entry = object(item, ["run_id", "terminal", "state", "detail"], "Run integrity"); return { run_id: identifier(entry.run_id, RUN_ID, "Integrity run"), terminal: boolean(entry.terminal, "Terminal run label"), state: choice(entry.state, ["verified", "unavailable"], "Run integrity state"), detail: text(entry.detail, "Run integrity detail", 500) }; }) : (() => { throw new Error("Run integrity is unavailable."); })();
  const result: EngineExperimentProjection = { schema_version: "bluefire.engine-experiment-projection.v1", experiment_id: identifier(row.experiment_id, EXPERIMENT_ID, "Projected experiment identity"), revision: integer(row.revision, "Projected revision", 1, 10_000), experiment_digest: digest(row.experiment_digest, "Projected experiment digest"), projection_digest: digest(row.projection_digest, "Projection digest"), workflow_state: choice(row.workflow_state, ["ready_for_baseline", "baseline_active", "review_defense", "apply_defense", "reconcile_defense", "run_retained_reproducer", "retained_reproducer_active", "run_adaptive_search", "adaptive_search_active", "run_legitimate_use", "legitimate_use_active", "choose_defense_disposition", "complete"], "Workflow state"), conclusion: parseConclusion(row.conclusion), attempts, checks, observations, run_integrity: runIntegrity };
  const attemptRoles = attempts.map(item => item.role); const checkRoles = checks.map(item => item.role);
  if (attemptRoles.some((role, index) => role !== engineAttemptRoles[index]) || checkRoles.some((role, index) => role !== engineControllerCheckKinds[index])) throw new Error("Projected workflow order changed.");
  const identityRows = [attempts.map(item => item.attempt_id), checks.map(item => item.check_id), [...attempts.map(item => item.job_id), ...checks.map(item => item.job_id)], [...attempts.map(item => item.run_id), ...checks.map(item => item.run_id)], observations.map(item => item.evidence_id), runIntegrity.map(item => item.run_id)]; if (identityRows.some(values => new Set(values).size !== values.length)) throw new Error("Projected workflow identities changed.");
  const workById = new Map<string, { run_id: string }>([...attempts.map(item => [item.attempt_id, item] as const), ...checks.map(item => [item.check_id, item] as const)]);
  if (observations.some(item => workById.get(item.attempt_id ?? item.check_id!)?.run_id !== item.run_id)) throw new Error("Projected observation owner changed.");
  const workRuns = new Set([...attempts.map(item => item.run_id), ...checks.map(item => item.run_id)]);
  if (runIntegrity.length !== workRuns.size || runIntegrity.some(item => !workRuns.has(item.run_id))) throw new Error("Run integrity identity changed.");
  const evidenceIds = new Set(observations.map(item => item.evidence_id)); for (const conclusion of [result.conclusion.original_mechanism, result.conclusion.retained_reproducer, result.conclusion.adaptive_search, result.conclusion.legitimate_use]) if (new Set(conclusion.support_refs).size !== conclusion.support_refs.length || conclusion.support_refs.some(id => !evidenceIds.has(id)) || conclusion.run_id !== null && !workRuns.has(conclusion.run_id)) throw new Error("Conclusion support identity changed.");
  const baseline = attempts.find(item => item.role === "baseline");
  const reproducer = checks.find(item => item.role === "retained_reproducer");
  const adaptive = attempts.find(item => item.role === "adaptive_search");
  const legitimate = checks.find(item => item.role === "legitimate_use");
  const attemptActive = (item: EngineProjectionAttempt) => ["queued", "preflight", "running", "stopping"].includes(item.state);
  const checkActive = (item: EngineProjectionCheck) => item.state === "reserved";
  const expectedWorkflow: EngineWorkflowState = !baseline ? "ready_for_baseline"
    : attemptActive(baseline) ? "baseline_active"
      : result.conclusion.defense.state === "not_reviewed" ? "review_defense"
        : result.conclusion.defense.state === "reviewed" ? "apply_defense"
          : result.conclusion.defense.state === "unknown" ? "reconcile_defense"
            : result.conclusion.defense.state === "rolled_back" ? "complete"
              : !reproducer ? "run_retained_reproducer"
                : checkActive(reproducer) ? "retained_reproducer_active"
                  : !adaptive ? "run_adaptive_search"
                    : attemptActive(adaptive) ? "adaptive_search_active"
                      : !legitimate ? "run_legitimate_use"
                        : checkActive(legitimate) ? "legitimate_use_active"
                          : result.conclusion.defense.state === "retained" ? "complete" : "choose_defense_disposition";
  if (result.workflow_state !== expectedWorkflow) throw new Error("Workflow state changed.");
  const baselineObservations = baseline ? observations.filter(item => item.attempt_id === baseline.attempt_id) : [];
  const reproducerObservations = reproducer ? observations.filter(item => item.check_id === reproducer.check_id) : [];
  const adaptiveObservations = adaptive ? observations.filter(item => item.attempt_id === adaptive.attempt_id) : [];
  const legitimateObservations = legitimate ? observations.filter(item => item.check_id === legitimate.check_id) : [];
  const assessments = (items: EngineProjectionObservation[]) => new Set(items.map(item => item.assessment));
  const baselineAssessments = assessments(baselineObservations);
  const reproducerAssessments = assessments(reproducerObservations);
  const adaptiveAssessments = assessments(adaptiveObservations);
  const legitimateAssessments = assessments(legitimateObservations);
  const expectedOriginalStatus = !baseline ? "not_attempted" : baselineAssessments.has("unauthorized_disclosure") ? "established" : baselineObservations.length ? "not_established" : "unknown";
  const expectedReproducerStatus = !reproducer ? "not_attempted" : reproducerAssessments.has("unauthorized_disclosure") ? "still_succeeds" : reproducerAssessments.has("authorization_denied") ? "blocked" : reproducerObservations.length ? "not_established" : "unknown";
  const adaptiveTerminal = adaptive ? ["completed", "partial", "failed", "cancelled", "budget_exhausted", "unknown"].includes(adaptive.state) : false;
  const adaptiveBounded = Boolean(adaptive && adaptiveObservations.length && [...adaptiveAssessments].every(item => item === "authorization_denied" || item === "no_protected_effect") && adaptive.state === "completed" && adaptive.completeness === "complete");
  const expectedAdaptiveStatus = !adaptive ? "not_attempted" : adaptiveAssessments.has("unauthorized_disclosure") ? "remaining_path_found" : adaptiveBounded ? "no_path_observed_within_limits" : adaptiveTerminal ? "inconclusive" : "pending";
  const expectedLegitimateStatus = !legitimate ? "not_attempted" : legitimateAssessments.has("legitimate_use_succeeded") ? "passed" : legitimateAssessments.has("authorization_denied") ? "failed" : "unknown";
  if (result.conclusion.original_mechanism.status !== expectedOriginalStatus || result.conclusion.retained_reproducer.status !== expectedReproducerStatus || result.conclusion.adaptive_search.status !== expectedAdaptiveStatus || result.conclusion.legitimate_use.status !== expectedLegitimateStatus) throw new Error("Conclusion status changed.");
  const conclusionOwners = [
    [result.conclusion.original_mechanism, baseline, baselineObservations],
    [result.conclusion.retained_reproducer, reproducer, reproducerObservations],
    [result.conclusion.adaptive_search, adaptive, adaptiveObservations],
    [result.conclusion.legitimate_use, legitimate, legitimateObservations],
  ] as const;
  for (const [conclusion, owner, ownerObservations] of conclusionOwners) {
    if (conclusion.run_id !== (owner?.run_id ?? null)) throw new Error("Conclusion run identity changed.");
    if (conclusion.support_refs.length !== ownerObservations.length || conclusion.support_refs.some((reference, index) => reference !== ownerObservations[index]?.evidence_id)) throw new Error("Conclusion evidence owner changed.");
  }
  const expectedTelemetry: Array<readonly [string, EngineProjectionObservation[]]> = [];
  if (baseline) expectedTelemetry.push(["baseline", baselineObservations]);
  if (reproducer) expectedTelemetry.push(["retained_reproducer", reproducerObservations]);
  if (adaptive) expectedTelemetry.push(["adaptive_search", adaptiveObservations]);
  if (legitimate) expectedTelemetry.push(["legitimate_use", legitimateObservations]);
  const expectedSources = expectedTelemetry.map(([source]) => source);
  const verifiedSources = expectedTelemetry.filter(([, items]) => items.length > 0).map(([source]) => source);
  const missingSources = expectedTelemetry.filter(([, items]) => items.length === 0).map(([source]) => source);
  if (result.conclusion.telemetry_health.expected_sources.join("\0") !== expectedSources.join("\0") || result.conclusion.telemetry_health.verified_sources.join("\0") !== verifiedSources.join("\0") || result.conclusion.telemetry_health.missing_sources.join("\0") !== missingSources.join("\0")) throw new Error("Telemetry projection changed.");
  const projectedWork = [
    ...attempts.map(item => ({ kind: "engine_attempt" as const, id: item.attempt_id, state: item.cleanup.state, receipt_ref: item.cleanup.receipt_ref, run_id: item.run_id, terminal: !["queued", "preflight", "running", "stopping"].includes(item.state) })),
    ...checks.map(item => ({ kind: "controller_check" as const, id: item.check_id, state: item.cleanup.state, receipt_ref: item.cleanup.receipt_ref, run_id: item.run_id, terminal: item.state !== "reserved" })),
  ];
  if (result.conclusion.cleanup.items.length !== projectedWork.length || result.conclusion.cleanup.items.some((item, index) => {
    const projected = projectedWork[index];
    return !projected || item.kind !== projected.kind || item.id !== projected.id || item.state !== projected.state || item.receipt_ref !== projected.receipt_ref;
  })) throw new Error("Conclusion cleanup identity changed.");
  if (runIntegrity.some(item => projectedWork.find(work => work.run_id === item.run_id)?.terminal !== item.terminal)) throw new Error("Run integrity terminal state changed.");
  const integrityByRun = new Map(runIntegrity.map(item => [item.run_id, item] as const));
  if (observations.some(item => integrityByRun.get(item.run_id)?.state !== "verified")) throw new Error("Unverified run supplied a projected observation.");
  return result;
};
const parseDefense = (value: unknown): EngineDefenseChange | null => {
  if (value === null) return null;
  const row = object(value, ["change_id", "state", "kind", "summary", "mechanism_ref", "before_target_snapshot_ref", "after_target_snapshot_ref", "rollback_digest", "applied_at"], "Defensive change");
  return { change_id: identifier(row.change_id, CHANGE_ID, "Defensive change identity"), state: choice(row.state, ["reviewed", "applied", "retained", "rolled_back", "unknown"], "Defensive change state"), kind: choice(row.kind, ["configuration", "permission", "identity", "prevention", "visibility", "detection"], "Defensive change kind"), summary: text(row.summary, "Defensive change summary", 1000), mechanism_ref: digest(row.mechanism_ref, "Defensive mechanism"), before_target_snapshot_ref: digest(row.before_target_snapshot_ref, "Defensive change preimage"), after_target_snapshot_ref: digest(row.after_target_snapshot_ref, "Defensive change result"), rollback_digest: digest(row.rollback_digest, "Defensive change rollback"), applied_at: nullableTimestamp(row.applied_at, "Defensive change time") };
};

export function checkedEngineExperiment(value: unknown, expectedExperimentId?: string, expectedSelection?: EngineWorkspaceSelection): EngineExperiment {
  const row = object(value, ["schema_version", "workspace_digest", "experiment_id", "revision", "experiment_digest", "objective", "environment", "current_target", "engine_setup", "authorization", "defensive_change", "projection", "actions", "selected_context", "limitations"], "Engine experiment workspace");
  if (row.schema_version !== "bluefire.engine-experiment-workspace.v1") throw new Error("Engine workspace version is unsupported.");
  const objective = object(row.objective, ["objective_ref", "title", "summary"], "Engine objective"); const environment = object(row.environment, ["environment_ref", "environment_id", "display_name", "platform", "disposable"], "Engine environment"); const target = object(row.current_target, ["snapshot_ref", "display_name", "captured_at"], "Current target"); const setup = object(row.engine_setup, ["engine", "model"], "Engine setup"); const engine = object(setup.engine, ["id", "display_name", "version", "revision", "package_digest", "sandbox_image_digest"], "Engine setup identity"); const model = object(setup.model, ["provider", "id", "data_destination", "authorization_digest", "test_provider"], "Model setup identity"); const authorization = object(row.authorization, ["scope_ref", "scope_version", "wall_clock_seconds", "action_limit", "artifact_byte_limit", "cost_limit_microunits"], "Engine authorization");
  const projection = parseProjection(row.projection); const experimentId = identifier(row.experiment_id, EXPERIMENT_ID, "Experiment identity"); const revision = integer(row.revision, "Experiment revision", 1, 10_000); const experimentDigest = digest(row.experiment_digest, "Experiment digest"); const defense = parseDefense(row.defensive_change);
  const actions = Array.isArray(row.actions) && row.actions.length <= 12 ? row.actions.map(item => { const action = object(item, ["kind", "label", "enabled", "reason", "primary"], "Workspace action"); return { kind: choice(action.kind, ["start_baseline", "review_evidence", "review_defense", "apply_defense", "reconcile_defense", "repeat_mechanism", "start_adaptive_search", "run_legitimate_use", "choose_defense_disposition", "open_comparison"], "Workspace action kind"), label: text(action.label, "Workspace action label", 120), enabled: boolean(action.enabled, "Workspace action availability"), reason: nullableText(action.reason, "Workspace action reason", 300), primary: boolean(action.primary, "Primary action label") } satisfies EngineWorkspaceAction; }) : (() => { throw new Error("Workspace actions are unavailable."); })();
  let selectedContext: EngineWorkspaceSelectedContext = null;
  if (row.selected_context !== null) { const contextValue = row.selected_context as Record<string, unknown>; if (contextValue.kind === "engine_attempt") { const context = object(row.selected_context, ["kind", "attempt"], "Selected engine context"); selectedContext = { kind: "engine_attempt", attempt: parseDetailedAttempt(context.attempt) }; } else if (contextValue.kind === "controller_check") { const context = object(row.selected_context, ["kind", "check"], "Selected controller context"); selectedContext = { kind: "controller_check", check: parseDetailedCheck(context.check) }; } else throw new Error("Selected workspace context is unavailable."); }
  const result: EngineExperiment = {
    schema_version: "bluefire.engine-experiment-workspace.v1", workspace_digest: digest(row.workspace_digest, "Workspace digest"), experiment_id: experimentId, revision, experiment_digest: experimentDigest,
    objective: { objective_ref: digest(objective.objective_ref, "Objective reference"), title: text(objective.title, "Objective title", 200), summary: text(objective.summary, "Objective summary", 1000) }, environment: { environment_ref: digest(environment.environment_ref, "Environment reference"), environment_id: text(environment.environment_id, "Environment identity", 180), display_name: text(environment.display_name, "Environment name", 200), platform: choice(environment.platform, ["linux", "windows", "macos"], "Environment platform"), disposable: boolean(environment.disposable, "Disposable environment") as true }, current_target: { snapshot_ref: digest(target.snapshot_ref, "Current target snapshot"), display_name: text(target.display_name, "Current target name", 200), captured_at: timestamp(target.captured_at, "Current target time") },
    engine_setup: { engine: { id: choice(engine.id, ["strix"], "Engine"), display_name: text(engine.display_name, "Engine name", 100), version: text(engine.version, "Engine version", 80), revision: identifier(engine.revision, REVISION, "Engine revision"), package_digest: digest(engine.package_digest, "Engine package"), sandbox_image_digest: digest(engine.sandbox_image_digest, "Engine sandbox image") }, model: { provider: identifier(model.provider, SOURCE_ID, "Model provider"), id: text(model.id, "Model identity", 160), data_destination: text(model.data_destination, "Model destination", 200), authorization_digest: digest(model.authorization_digest, "Model authorization"), test_provider: boolean(model.test_provider, "Test-provider label") } }, authorization: { scope_ref: digest(authorization.scope_ref, "Authorization scope"), scope_version: choice(authorization.scope_version, ["bluefire.engine-capability-delegation.v1"], "Authorization scope version"), wall_clock_seconds: integer(authorization.wall_clock_seconds, "Wall-clock limit", 1, 7_200), action_limit: integer(authorization.action_limit, "Action limit", 1, 512), artifact_byte_limit: integer(authorization.artifact_byte_limit, "Artifact limit", 1, 64 * 1024 * 1024), cost_limit_microunits: integer(authorization.cost_limit_microunits, "Cost limit", 0, 10_000_000_000) }, defensive_change: defense, projection, actions, selected_context: selectedContext, limitations: strings(row.limitations, "Workspace limitations", 32),
  };
  if (expectedExperimentId !== undefined && experimentId !== expectedExperimentId) throw new Error("Engine experiment identity changed.");
  if (result.environment.disposable !== true) throw new Error("External engine experiments require a disposable environment.");
  if (projection.experiment_id !== experimentId || projection.revision !== revision || projection.experiment_digest !== experimentDigest) throw new Error("Engine projection identity changed.");
  if (actions.filter(action => action.primary).length > 1 || new Set(actions.map(action => action.kind)).size !== actions.length) throw new Error("Workspace actions changed.");
  for (const attempt of projection.attempts) if (attempt.engine.id !== result.engine_setup.engine.id || attempt.engine.version !== result.engine_setup.engine.version || attempt.engine.revision !== result.engine_setup.engine.revision || attempt.engine.package_digest !== result.engine_setup.engine.package_digest || attempt.model.provider !== result.engine_setup.model.provider || attempt.model.id !== result.engine_setup.model.id || attempt.model.data_destination !== result.engine_setup.model.data_destination || attempt.delegation_digest !== result.authorization.scope_ref) throw new Error("Attempt setup identity changed.");
  if (defense === null
    ? projection.conclusion.defense.state !== "not_reviewed"
      || projection.conclusion.defense.change_id !== null
      || projection.conclusion.defense.mechanism_ref !== null
      || projection.conclusion.defense.after_target_snapshot_ref !== null
      || projection.conclusion.defense.application_receipt_ref !== null
      || projection.conclusion.defense.reconciliation_receipt_ref !== null
      || projection.conclusion.defense.rollback_operation_ref !== null
      || projection.conclusion.defense.rollback_receipt_ref !== null
    : projection.conclusion.defense.change_id !== defense.change_id
      || projection.conclusion.defense.state !== defense.state
      || projection.conclusion.defense.mechanism_ref !== defense.mechanism_ref
      || projection.conclusion.defense.before_target_snapshot_ref !== defense.before_target_snapshot_ref
      || projection.conclusion.defense.after_target_snapshot_ref !== defense.after_target_snapshot_ref) throw new Error("Defensive change projection changed.");
  if (projection.conclusion.defense.current_target_snapshot_ref !== result.current_target.snapshot_ref) throw new Error("Current target projection changed.");
  if (selectedContext?.kind === "engine_attempt") { const detail = selectedContext.attempt; const summary = projection.attempts.find(item => item.attempt_id === detail.attempt_id); const engineEvidenceCount = detail.observations.filter(item => item.category === "engine_assertion" || item.category === "tool_result").length; if (!summary || summary.role !== detail.role || summary.job_id !== detail.job_id || summary.run_id !== detail.run_id || summary.state !== detail.state || summary.completeness !== detail.completeness || summary.cleanup.state !== detail.cleanup.state || summary.cleanup.receipt_ref !== detail.cleanup.receipt_ref || summary.engine_evidence_count !== engineEvidenceCount) throw new Error("Selected attempt context changed."); if (detail.usage.duration_ms > result.authorization.wall_clock_seconds * 1000 || detail.usage.tool_calls > result.authorization.action_limit || detail.artifacts.reduce((total, artifact) => total + artifact.bytes, 0) > result.authorization.artifact_byte_limit) throw new Error("Selected attempt exceeded its recorded limits."); const projectedEvidence = new Set(projection.observations.filter(item => item.attempt_id === detail.attempt_id).map(item => item.evidence_id)); if (detail.observations.filter(item => !["engine_assertion", "tool_result"].includes(item.category)).some(item => !projectedEvidence.has(item.evidence_id))) throw new Error("Selected attempt observation changed."); }
  if (selectedContext?.kind === "controller_check") { const detail = selectedContext.check; const summary = projection.checks.find(item => item.check_id === detail.check_id); const sameEvidenceRefs = summary && summary.independent_evidence_refs.length === detail.independent_evidence_refs.length && summary.independent_evidence_refs.every((reference, index) => reference === detail.independent_evidence_refs[index]); const projectedEvidence = new Set(projection.observations.filter(item => item.check_id === detail.check_id && item.run_id === detail.run_id).map(item => item.evidence_id)); if (!summary || summary.role !== detail.role || summary.job_id !== detail.job_id || summary.run_id !== detail.run_id || summary.state !== detail.state || summary.performer !== detail.performer || summary.mechanism_ref !== detail.mechanism_ref || summary.target_snapshot_ref !== detail.target_snapshot_ref || summary.input_digest !== detail.input_digest || summary.result_digest !== detail.result_digest || !sameEvidenceRefs || summary.cleanup.state !== detail.cleanup.state || summary.cleanup.receipt_ref !== detail.cleanup.receipt_ref || detail.observations.some(item => !projectedEvidence.has(item.evidence_id))) throw new Error("Selected controller context changed."); }
  if (expectedSelection) { const selectedId = selectedContext?.kind === "engine_attempt" ? selectedContext.attempt.attempt_id : selectedContext?.kind === "controller_check" ? selectedContext.check.check_id : null; if (selectedContext?.kind !== expectedSelection.kind || selectedId !== expectedSelection.id) throw new Error("Selected workspace context changed."); }
  return result;
}

export const selectedEngineAttempt = (workspace: EngineExperiment, attemptId?: string | null): EngineAttempt | undefined => workspace.selected_context?.kind === "engine_attempt" && (!attemptId || workspace.selected_context.attempt.attempt_id === attemptId) ? workspace.selected_context.attempt : undefined;
export const selectedControllerCheck = (workspace: EngineExperiment, checkId?: string | null): EngineControllerCheck | undefined => workspace.selected_context?.kind === "controller_check" && (!checkId || workspace.selected_context.check.check_id === checkId) ? workspace.selected_context.check : undefined;
export const engineAttemptLabel = (role: EngineAttemptRole): string => ({ baseline: "Baseline exploration", adaptive_search: "Fresh adaptive search" })[role];
export const engineControllerCheckLabel = (role: EngineControllerCheckKind): string => ({ retained_reproducer: "Original mechanism retest", legitimate_use: "Legitimate-use check" })[role];
export const engineStateLabel = (attempt: Pick<EngineAttempt, "state" | "cleanup"> | Pick<EngineProjectionAttempt, "state" | "cleanup">): string => {
  if (attempt.cleanup.state === "unknown" || attempt.cleanup.state === "residue") return "Cleanup needs review";
  return ({ queued: "Queued", preflight: "Checking readiness", running: "Running", stopping: "Stopping", completed: "Completed", partial: "Partial evidence", failed: "Failed", cancelled: "Cancelled", budget_exhausted: "Search limit reached", unknown: "State unknown" } as const)[attempt.state];
};
export const engineControllerCheckStateLabel = (check: Pick<EngineControllerCheck, "state" | "cleanup"> | Pick<EngineProjectionCheck, "state" | "cleanup">): string => {
  if (check.cleanup.state === "unknown" || check.cleanup.state === "residue") return "Cleanup needs review";
  return ({ reserved: "Reserved", completed: "Completed", failed: "Failed", unknown: "State unknown" } as const)[check.state];
};
export const engineWorkflowLabel = (state: EngineWorkflowState): string => ({ ready_for_baseline: "Ready for baseline", baseline_active: "Baseline active", review_defense: "Review defense", apply_defense: "Apply defense", reconcile_defense: "Reconcile defense", run_retained_reproducer: "Run original mechanism retest", retained_reproducer_active: "Original mechanism retest active", run_adaptive_search: "Run adaptive search", adaptive_search_active: "Adaptive search active", run_legitimate_use: "Run legitimate-use check", legitimate_use_active: "Legitimate-use check active", choose_defense_disposition: "Choose defense disposition", complete: "Complete" })[state];
