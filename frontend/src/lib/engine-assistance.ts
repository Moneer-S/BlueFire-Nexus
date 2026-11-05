import { engineAttemptLabel, engineControllerCheckLabel, type EngineExperiment } from "./engine-experiment";
import { request } from "./api";
import type { AssistanceContext } from "./assistance";
import { sameJson } from "./replay-review";

export interface EngineExperimentAssistanceSelection {
  kind: "engine_experiment";
  experiment_id: string;
  workspace_digest: string;
  attempt_id: string | null;
  check_id: string | null;
}

type EngineAttemptRole = "baseline" | "adaptive_search";
type EngineCheckRole = "retained_reproducer" | "legitimate_use";
type CleanupState = "pending" | "verified_absent" | "residue" | "unknown";
type SelectedObservation = {
  evidence_id: string; category: "engine_assertion" | "tool_result" | "independent_target_effect" | "independent_security_outcome" | "legitimate_use";
  provenance: "engine_reported" | "runner_reported" | "observed" | "control_blocked";
  summary: string; producer: string; timestamp: string; limitations: string[];
};
type SelectedCleanup = { state: CleanupState; receipt_ref: string | null; limitations: string[] };
type SelectedRecord = null | {
  kind: "engine_attempt"; id: string; role: EngineAttemptRole; job_id: string; run_id: string;
  state: string; completeness: "complete" | "partial" | "unknown"; observations: SelectedObservation[];
  cleanup: SelectedCleanup;
} | {
  kind: "controller_check"; id: string; role: EngineCheckRole; job_id: string; run_id: string;
  state: string; performer: "bluefire.controller" | "bluefire.trusted-client"; observations: SelectedObservation[];
  cleanup: SelectedCleanup;
};

export interface EngineExperimentAssistanceSummary {
  schema_version: "bluefire.engine-experiment-assistance-summary.v1";
  proof_scope: "saved_engine_experiment_only";
  experiment_id: string;
  revision: number;
  workspace_digest: string;
  workflow_state: string;
  objective: { title: string; summary: string };
  environment: { display_name: string; platform: "linux" | "windows" | "macos"; disposable: true; current_target: "unknown" | "established" };
  provider: { engine_id: string; engine_version: string; model_provider: string; model_id: string; data_destination: string; test_provider: boolean; live_model_inference_proven: false };
  attempts: Array<{ role: EngineAttemptRole; attempt_id: string; run_id: string; state: string; completeness: "complete" | "partial" | "unknown"; engine_reported_evidence_count: number; cleanup_state: CleanupState }>;
  checks: Array<{ role: EngineCheckRole; check_id: string; run_id: string; state: string; performer: "bluefire.controller" | "bluefire.trusted-client"; cleanup_state: CleanupState }>;
  independent_observations: Array<{ evidence_id: string; run_id: string; attempt_id: string | null; check_id: string | null; assessment: string; record_hash: string }>;
  conclusion: Record<string, unknown>;
  selected_record: SelectedRecord;
}

export interface EngineExperimentAssistanceContext extends AssistanceContext {
  selected: EngineExperimentAssistanceSelection;
  analysis_only: true;
  capabilities: [];
  reference_summary: EngineExperimentAssistanceSummary;
}

const EXPERIMENT_ID = /^experiment-[0-9a-f]{32}$/;
const ATTEMPT_ID = /^engine-attempt-[0-9a-f]{32}$/;
const CHECK_ID = /^controller-check-[0-9a-f]{32}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RUN_ID = /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/;
const JOB_ID = /^job-[0-9a-f]{32}$/;
const EVIDENCE_ID = /^(?:engine-evidence-[0-9a-f]{24}|evidence-[0-9a-f]{20})$/;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,199}$/;
const LOCAL_PATH = /(?:(?:^|[^A-Za-z0-9])[a-z]:[\\/]|file:\/\/|\\\\[^\\\s]+\\|(?:^|\s)(?:\.\.?[\\/]|~[\\/])\S+|(?:^|[\s=:])\/(?!\/)(?:[^/\s]+\/)*[^/\s]*)/i;
const SECRET = /(?:-----BEGIN\s+.*(?:PRIVATE|SECRET)\s+KEY|\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?token|token|password|passwd|client[_-]?secret|secret|credential|authorization|cookie)\b\s*[:=]\s*\S+|\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[pousr]_|github_pat_|glpat-|sk-)[A-Za-z0-9_-]{12,})/i;
const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, fields: readonly string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
const oneOf = <T extends string>(value: unknown, choices: readonly T[]): value is T => typeof value === "string" && choices.includes(value as T);
const nullable = <T>(value: unknown, valid: (item: unknown) => item is T): value is T | null => value === null || valid(value);
const identifier = (value: unknown, expression = OPAQUE_ID): value is string => typeof value === "string" && expression.test(value);
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= 2_147_483_647;
const safeText = (value: unknown, maximum = 500): value is string => typeof value === "string" && value.length > 0 && value.length <= maximum && value.trim() === value
  && [...value].every(character => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127) && !LOCAL_PATH.test(value) && !SECRET.test(value);
const safeStrings = (value: unknown, maximum = 32): value is string[] => Array.isArray(value) && value.length <= maximum && value.every(item => safeText(item)) && new Set(value).size === value.length;
const cleanupStates = ["pending", "verified_absent", "residue", "unknown"] as const;
const attemptRoles = ["baseline", "adaptive_search"] as const;
const checkRoles = ["retained_reproducer", "legitimate_use"] as const;
const attemptStates = ["queued", "preflight", "running", "stopping", "completed", "partial", "failed", "cancelled", "budget_exhausted", "unknown"] as const;
const checkStates = ["reserved", "completed", "failed", "unknown"] as const;
const workflowStates = ["ready_for_baseline", "baseline_active", "review_defense", "apply_defense", "reconcile_defense", "run_retained_reproducer", "retained_reproducer_active", "run_adaptive_search", "adaptive_search_active", "run_legitimate_use", "legitimate_use_active", "choose_defense_disposition", "complete"] as const;
const assessments = ["unauthorized_disclosure", "authorization_denied", "legitimate_use_succeeded", "no_protected_effect", "unknown"] as const;
const evidenceCategories = ["engine_assertion", "tool_result", "independent_target_effect", "independent_security_outcome", "legitimate_use"] as const;
const evidenceProvenance = ["engine_reported", "runner_reported", "observed", "control_blocked"] as const;

export function validEngineExperimentSelection(value: unknown): value is EngineExperimentAssistanceSelection {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const row = value as Record<string, unknown>;
  const fields = ["attempt_id", "check_id", "experiment_id", "kind", "workspace_digest"];
  const actual = Object.keys(row).sort();
  return actual.length === fields.length && actual.every((field, index) => field === fields[index])
    && row.kind === "engine_experiment"
    && typeof row.experiment_id === "string" && EXPERIMENT_ID.test(row.experiment_id)
    && typeof row.workspace_digest === "string" && DIGEST.test(row.workspace_digest)
    && (row.attempt_id === null || typeof row.attempt_id === "string" && ATTEMPT_ID.test(row.attempt_id))
    && (row.check_id === null || typeof row.check_id === "string" && CHECK_ID.test(row.check_id))
    && !(row.attempt_id !== null && row.check_id !== null);
}

export function engineExperimentSelection(experiment: EngineExperiment, attemptId?: string | null, checkId?: string | null): EngineExperimentAssistanceSelection {
  const selectedAttempt = attemptId ?? null, selectedCheck = checkId ?? null;
  if (selectedAttempt !== null && selectedCheck !== null) throw new Error("Select either an engine attempt or a trusted check.");
  if (selectedAttempt !== null && !experiment.projection.attempts.some(attempt => attempt.attempt_id === selectedAttempt)) throw new Error("Selected engine attempt is unavailable.");
  if (selectedCheck !== null && !experiment.projection.checks.some(check => check.check_id === selectedCheck)) throw new Error("Selected controller check is unavailable.");
  return { kind: "engine_experiment", experiment_id: experiment.experiment_id, workspace_digest: experiment.workspace_digest, attempt_id: selectedAttempt, check_id: selectedCheck };
}

export function engineExperimentSelectionMatches(selection: EngineExperimentAssistanceSelection, experiment: EngineExperiment): boolean {
  return validEngineExperimentSelection(selection)
    && selection.experiment_id === experiment.experiment_id
    && selection.workspace_digest === experiment.workspace_digest
    && (selection.attempt_id === null || experiment.projection.attempts.some(attempt => attempt.attempt_id === selection.attempt_id))
    && (selection.check_id === null || experiment.projection.checks.some(check => check.check_id === selection.check_id));
}

function validObservation(value: unknown): value is SelectedObservation {
  if (!exact(value, ["evidence_id", "category", "provenance", "summary", "producer", "timestamp", "limitations"])
    || !identifier(value.evidence_id, EVIDENCE_ID) || !oneOf(value.category, evidenceCategories)
    || !oneOf(value.provenance, evidenceProvenance) || !safeText(value.summary, 1000)
    || !safeText(value.producer, 200) || !safeText(value.timestamp, 80) || !safeStrings(value.limitations, 16)) return false;
  if (value.category === "engine_assertion") return value.provenance === "engine_reported";
  if (value.category === "tool_result") return value.provenance === "runner_reported";
  return value.provenance === "observed" || value.provenance === "control_blocked";
}

function validCleanup(value: unknown): value is SelectedCleanup {
  return exact(value, ["state", "receipt_ref", "limitations"]) && oneOf(value.state, cleanupStates)
    && nullable(value.receipt_ref, (item): item is string => identifier(item, DIGEST)) && safeStrings(value.limitations, 16);
}

function validSelectedRecord(value: unknown, selected: EngineExperimentAssistanceSelection): value is SelectedRecord {
  if (value === null) return selected.attempt_id === null && selected.check_id === null;
  if (!object(value) || !Array.isArray(value.observations) || value.observations.length > 256 || !value.observations.every(validObservation)
    || !validCleanup(value.cleanup)) return false;
  if (value.kind === "engine_attempt") {
    return exact(value, ["kind", "id", "role", "job_id", "run_id", "state", "completeness", "observations", "cleanup"])
      && value.id === selected.attempt_id && selected.check_id === null && identifier(value.id, ATTEMPT_ID)
      && oneOf(value.role, attemptRoles) && identifier(value.job_id, JOB_ID) && identifier(value.run_id, RUN_ID)
      && oneOf(value.state, attemptStates) && oneOf(value.completeness, ["complete", "partial", "unknown"] as const);
  }
  if (value.kind === "controller_check") {
    return exact(value, ["kind", "id", "role", "job_id", "run_id", "state", "performer", "observations", "cleanup"])
      && value.id === selected.check_id && selected.attempt_id === null && identifier(value.id, CHECK_ID)
      && oneOf(value.role, checkRoles) && identifier(value.job_id, JOB_ID) && identifier(value.run_id, RUN_ID)
      && oneOf(value.state, checkStates) && oneOf(value.performer, ["bluefire.controller", "bluefire.trusted-client"] as const);
  }
  return false;
}

const validSupportResult = (value: unknown, statuses: readonly string[], adaptive = false): boolean => {
  const fields = adaptive ? ["status", "run_id", "support_refs", "limit_qualified"] : ["status", "run_id", "support_refs"];
  return exact(value, fields) && oneOf(value.status, statuses) && nullable(value.run_id, (item): item is string => identifier(item, RUN_ID))
    && safeStrings(value.support_refs, 256) && (!adaptive || typeof value.limit_qualified === "boolean");
};

function validConclusion(value: unknown): value is Record<string, unknown> {
  if (!exact(value, ["headline", "original_mechanism", "retained_reproducer", "adaptive_search", "legitimate_use", "telemetry_health", "cleanup", "defense", "unknowns"])
    || !oneOf(value.headline, ["inconclusive_original_mechanism", "original_mechanism_still_succeeds", "inconclusive_retest", "original_blocked_legitimate_use_failed", "original_blocked_legitimate_use_unknown", "original_blocked_alternate_path_found", "original_blocked_no_remaining_path_observed_within_limits", "original_blocked_adaptive_result_unknown"] as const)
    || !validSupportResult(value.original_mechanism, ["not_attempted", "established", "not_established", "unknown"])
    || !validSupportResult(value.retained_reproducer, ["not_attempted", "still_succeeds", "blocked", "not_established", "unknown"])
    || !validSupportResult(value.adaptive_search, ["not_attempted", "remaining_path_found", "no_path_observed_within_limits", "inconclusive", "pending"], true)
    || !validSupportResult(value.legitimate_use, ["not_attempted", "failed", "passed", "unknown"]) || !safeStrings(value.unknowns, 32)) return false;
  const telemetry = value.telemetry_health;
  if (!exact(telemetry, ["status", "expected_sources", "verified_sources", "missing_sources"])
    || !oneOf(telemetry.status, ["not_started", "complete", "partial", "unavailable"] as const)
    || ![telemetry.expected_sources, telemetry.verified_sources, telemetry.missing_sources].every(item => Array.isArray(item) && item.length <= 4 && item.every(role => oneOf(role, ["baseline", "retained_reproducer", "adaptive_search", "legitimate_use"] as const)))) return false;
  const expected = new Set(telemetry.expected_sources as string[]), verified = new Set(telemetry.verified_sources as string[]), missing = new Set(telemetry.missing_sources as string[]);
  if ([...verified].some(item => !expected.has(item) || missing.has(item)) || [...missing].some(item => !expected.has(item)) || new Set([...verified, ...missing]).size !== expected.size) return false;
  const cleanup = value.cleanup;
  if (!exact(cleanup, ["status", "items"]) || !oneOf(cleanup.status, ["not_started", ...cleanupStates] as const)
    || !Array.isArray(cleanup.items) || cleanup.items.length > 256 || !cleanup.items.every(item => exact(item, ["kind", "id", "state", "receipt_ref"])
      && oneOf(item.kind, ["engine_attempt", "controller_check"] as const) && identifier(item.id)
      && oneOf(item.state, cleanupStates) && nullable(item.receipt_ref, (receipt): receipt is string => identifier(receipt, DIGEST)))) return false;
  const defense = value.defense;
  return exact(defense, ["state", "change_id", "mechanism_ref", "before_target_snapshot_ref", "after_target_snapshot_ref", "current_target_snapshot_ref", "application_receipt_ref", "reconciliation_receipt_ref", "rollback_operation_ref", "rollback_receipt_ref"])
    && oneOf(defense.state, ["not_reviewed", "reviewed", "applied", "retained", "rolled_back", "unknown"] as const)
    && nullable(defense.change_id, (item): item is string => identifier(item))
    && [defense.mechanism_ref, defense.before_target_snapshot_ref, defense.after_target_snapshot_ref, defense.current_target_snapshot_ref, defense.application_receipt_ref, defense.reconciliation_receipt_ref, defense.rollback_operation_ref, defense.rollback_receipt_ref]
      .every(item => nullable(item, (digestValue): digestValue is string => identifier(digestValue, DIGEST)));
}

function validSummary(value: unknown, selected: EngineExperimentAssistanceSelection): value is EngineExperimentAssistanceSummary {
  if (!exact(value, ["schema_version", "proof_scope", "experiment_id", "revision", "workspace_digest", "workflow_state", "objective", "environment", "provider", "attempts", "checks", "independent_observations", "conclusion", "selected_record"])
    || value.schema_version !== "bluefire.engine-experiment-assistance-summary.v1" || value.proof_scope !== "saved_engine_experiment_only"
    || value.experiment_id !== selected.experiment_id || value.workspace_digest !== selected.workspace_digest
    || !Number.isSafeInteger(value.revision) || Number(value.revision) < 1 || !oneOf(value.workflow_state, workflowStates)
    || !exact(value.objective, ["title", "summary"]) || !safeText(value.objective.title, 200) || !safeText(value.objective.summary, 1000)
    || !exact(value.environment, ["display_name", "platform", "disposable", "current_target"]) || !safeText(value.environment.display_name, 200)
    || !oneOf(value.environment.platform, ["linux", "windows", "macos"] as const) || value.environment.disposable !== true || !oneOf(value.environment.current_target, ["unknown", "established"] as const)) return false;
  const provider = value.provider;
  if (!exact(provider, ["engine_id", "engine_version", "model_provider", "model_id", "data_destination", "test_provider", "live_model_inference_proven"])
    || !safeText(provider.engine_id, 200) || !safeText(provider.engine_version, 200) || !safeText(provider.model_provider, 200) || !safeText(provider.model_id, 200)
    || !safeText(provider.data_destination, 500) || typeof provider.test_provider !== "boolean" || provider.live_model_inference_proven !== false) return false;
  if (!Array.isArray(value.attempts) || value.attempts.length > 2 || !value.attempts.every(item => exact(item, ["role", "attempt_id", "run_id", "state", "completeness", "engine_reported_evidence_count", "cleanup_state"])
    && oneOf(item.role, attemptRoles) && identifier(item.attempt_id, ATTEMPT_ID) && identifier(item.run_id, RUN_ID) && oneOf(item.state, attemptStates)
    && oneOf(item.completeness, ["complete", "partial", "unknown"] as const) && count(item.engine_reported_evidence_count) && oneOf(item.cleanup_state, cleanupStates))) return false;
  if (!Array.isArray(value.checks) || value.checks.length > 2 || !value.checks.every(item => exact(item, ["role", "check_id", "run_id", "state", "performer", "cleanup_state"])
    && oneOf(item.role, checkRoles) && identifier(item.check_id, CHECK_ID) && identifier(item.run_id, RUN_ID) && oneOf(item.state, checkStates)
    && oneOf(item.performer, ["bluefire.controller", "bluefire.trusted-client"] as const) && oneOf(item.cleanup_state, cleanupStates))) return false;
  if (!Array.isArray(value.independent_observations) || value.independent_observations.length > 256 || !value.independent_observations.every(item => exact(item, ["evidence_id", "run_id", "attempt_id", "check_id", "assessment", "record_hash"])
    && identifier(item.evidence_id, EVIDENCE_ID) && identifier(item.run_id, RUN_ID)
    && nullable(item.attempt_id, (id): id is string => identifier(id, ATTEMPT_ID)) && nullable(item.check_id, (id): id is string => identifier(id, CHECK_ID))
    && (item.attempt_id === null) !== (item.check_id === null) && oneOf(item.assessment, assessments) && identifier(item.record_hash, DIGEST))) return false;
  return validConclusion(value.conclusion) && validSelectedRecord(value.selected_record, selected);
}

export function checkedEngineExperimentAssistanceContext(value: unknown, selected: EngineExperimentAssistanceSelection): EngineExperimentAssistanceContext {
  if (!validEngineExperimentSelection(selected) || !exact(value, ["schema_version", "selected", "analysis_only", "capabilities", "reference_summary", "limitations", "context_digest"])
    || value.schema_version !== "bluefire.assistance-context.v1" || !sameJson(value.selected, selected) || value.analysis_only !== true
    || !Array.isArray(value.capabilities) || value.capabilities.length !== 0 || !safeStrings(value.limitations, 40)
    || !identifier(value.context_digest, DIGEST) || !validSummary(value.reference_summary, selected)
    || new TextEncoder().encode(JSON.stringify(value)).length > 64 * 1024) throw new Error("The saved engine-experiment explanation context changed or is unavailable.");
  return value as unknown as EngineExperimentAssistanceContext;
}

export async function engineExperimentAssistanceContext(selected: EngineExperimentAssistanceSelection): Promise<EngineExperimentAssistanceContext> {
  if (!validEngineExperimentSelection(selected)) throw new Error("Select one exact saved engine-experiment context.");
  const response: unknown = await request(`/engine-experiments/${encodeURIComponent(selected.experiment_id)}/assistant-context`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(selected),
  });
  return checkedEngineExperimentAssistanceContext(response, selected);
}

export const engineAssistanceLabel = (selection: EngineExperimentAssistanceSelection, experiment: EngineExperiment): string => {
  if (!engineExperimentSelectionMatches(selection, experiment)) throw new Error("Engine Assistant context changed.");
  const attempt = selection.attempt_id === null ? undefined : experiment.projection.attempts.find(item => item.attempt_id === selection.attempt_id);
  const check = selection.check_id === null ? undefined : experiment.projection.checks.find(item => item.check_id === selection.check_id);
  return attempt ? `${experiment.objective.title}: ${engineAttemptLabel(attempt.role)}` : check ? `${experiment.objective.title}: ${engineControllerCheckLabel(check.role)}` : experiment.objective.title;
};
