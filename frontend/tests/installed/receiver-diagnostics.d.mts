import type { PreflightDiagnostic } from "./preflight-diagnostics.mjs";

export function readReceiverCompositionUi(expected: { origin: string; owner: string; control: string; proposal: string }): Record<string, unknown>;
export function receiverCompositionInteractionDiagnostic(step: unknown, ui: unknown, objective: unknown, context: unknown, proposal: unknown, now: number): Record<string, unknown>;

export type ReceiverPostRouteFamily =
  | "session"
  | "provider_save"
  | "provider_activate"
  | "model_authorization_create"
  | "model_authorization_revoke"
  | "runner_bootstrap"
  | "runner_start"
  | "runner_stop"
  | "scenario_version_save"
  | "composition_objective_list"
  | "composition_context"
  | "composition_objective_create"
  | "composition_proposal_context"
  | "composition_proposal"
  | "composition_attempt"
  | "composition_revoke"
  | "comparison_create"
  | "receiver_context"
  | "receiver_owner_create"
  | "receiver_prepare"
  | "receiver_review"
  | "execution_approval"
  | "receiver_cancel"
  | "other";

export type ReceiverPostDenialCategory =
  | "budget_exhausted"
  | "invalid_json_body"
  | "origin_rejected"
  | "route_guard_rejected"
  | "unknown_route";

export interface ReceiverPostDenialDiagnostic {
  route_family: ReceiverPostRouteFamily;
  denial_category: ReceiverPostDenialCategory;
  budget_count?: number;
  budget_limit?: number;
}

export function receiverPostDenialDiagnostic(
  pathname: string,
  reason: string,
  budget?: { key: string; count: number; limit: number } | null,
): ReceiverPostDenialDiagnostic;

export interface ReceiverPrepareHttpDiagnostic {
  schema_version: "bluefire.installed-receiver-prepare-http-diagnostic.v1";
  status: number | null;
  error_code: string;
}

export interface ReceiverPreparationDiagnostic {
  schema_version: "bluefire.installed-receiver-preparation-diagnostic.v1";
  owner_status: string;
  owner_next_action: string;
  phase: "baseline" | "protected" | "legitimate" | "unknown";
  phase_status: string;
  phase_problem_code: string;
  receiver_cleanup: string;
  run_cleanup: string;
  preparation_present: boolean;
  receiver_job_state: string;
  receiver_job_error_code: string;
  receiver_job_error_type: string;
  receiver_prepare_failure_stage: string;
  execution_job_state: string;
  execution_job_error_code: string;
  prepare_started: boolean | null;
  execution_started: boolean | null;
  receiver_closed: boolean | null;
  prepare_http: ReceiverPrepareHttpDiagnostic | null;
  preflight_refusal: PreflightDiagnostic | null;
}

export function receiverPrepareHttpDiagnostic(status: unknown, body: unknown): ReceiverPrepareHttpDiagnostic;
export function receiverPreparationDiagnostic(
  owner: unknown,
  phaseName: unknown,
  prepareHttp?: unknown,
): ReceiverPreparationDiagnostic;
