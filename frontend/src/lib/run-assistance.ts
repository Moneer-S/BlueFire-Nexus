import type { PreflightReport, RunConfiguration, RunJob, Scenario } from "../types";
import type { GraphApplication } from "./graph-assistance";
import { sameJson } from "./replay-review";

export interface RunIntent {
  mode: RunConfiguration["mode"];
  autonomy: RunConfiguration["autonomy"];
  ai_provider_id: string | null;
  runner_profile_id: string | null;
  target_scope: { scope_refs: string[] };
  collectors?: string[];
  action_implementations?: Record<string, string>;
}
export interface SavedGraphSelection { kind: "saved_graph"; proposal_job_id: string; application: GraphApplication; run_intent: RunIntent }
export interface RunPreparation {
  schema_version: "bluefire.assistance-run-preparation.v1";
  preparation_digest: string; context_digest: string; selection: SavedGraphSelection;
  scenario: Scenario; run_request: { scenario: Scenario } & RunIntent; preflight: PreflightReport;
  approval_created: false; effects_started: false;
}
export interface RunPreparationDecision { decision: "accept" | "reject" | "policy"; preparation_digest: string }
export interface RunInspection {
  schema_version: "bluefire.run-evidence-inspection.v1"; run_id: string; run_digest: string;
  summary: string; findings: Array<{ claim: string; evidence_refs: string[] }>; limitations: string[];
  observed_records: number; total_records: number; status: "supported" | "insufficient";
  provider: Record<string, unknown> | null; model_interpretation: boolean;
}
export interface RunInspectedResult {
  kind: "run_inspected"; step_id: string; run_id: string; run_job_id: string; inspection_job_id: string;
  scenario_id: string; version: number; digest: string; mode: RunIntent["mode"];
  objective_reached: boolean | null; cleanup_state: string; observed_records: number; total_records: number;
  inspection_status: "supported" | "insufficient"; native_path: string;
  runtime_modified: boolean; runtime_proposal_record_ids: string[]; actual_scenario_digest: string;
}
export interface AssistanceRunEnvelope {
  job: RunJob; preparation: RunPreparation | null; decision: RunPreparationDecision | null;
  run_job: RunJob | null; inspection_job: RunJob | null; inspection: RunInspection | null;
  result: Omit<RunInspectedResult, "step_id"> | null; review_ready: boolean;
}
export interface RunPreparationRefusal {
  code: string; message: string; preflight?: PreflightReport | null;
}
export function runPreparationRefusal(envelope?: AssistanceRunEnvelope): RunPreparationRefusal | undefined {
  const value = envelope?.job.progress.preflight_refusal;
  if (!value || typeof value !== "object" || !("code" in value) || !("message" in value)
    || typeof value.code !== "string" || typeof value.message !== "string") return;
  return value as RunPreparationRefusal;
}
export function runIntent(config: RunConfiguration): RunIntent {
  return { mode: config.mode, autonomy: config.autonomy, ai_provider_id: config.autonomy === "off" ? null : config.provider || null,
    runner_profile_id: config.profileId || null, target_scope: { scope_refs: [...config.scopeRefs] },
    ...(config.mode === "execute" ? { collectors: [...config.collectors] } : {}),
    ...(config.mode === "execute" && Object.keys(config.actionImplementations).length ? { action_implementations: { ...config.actionImplementations } } : {}) };
}
const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const bounded = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 200 && [...value].every((character) => character.charCodeAt(0) >= 32);
export function validSavedGraphSelection(value: unknown): value is SavedGraphSelection {
  if (!value || typeof value !== "object") return false;
  const selection = value as SavedGraphSelection;
  const app = selection.application, intent = selection.run_intent;
  return selection.kind === "saved_graph" && /^job-[0-9a-f]{32}$/.test(selection.proposal_job_id)
    && Boolean(app && app.proposal_job_id === selection.proposal_job_id && digest(app.proposal_digest) && digest(app.reviewed_digest)
      && bounded(app.scenario_id) && Number.isSafeInteger(app.version) && app.version > 0 && digest(app.digest) && typeof app.operator_modified === "boolean")
    && Boolean(intent && ["simulate", "execute"].includes(intent.mode) && ["off", "assist", "auto"].includes(intent.autonomy)
      && (intent.ai_provider_id === null || bounded(intent.ai_provider_id)) && (intent.runner_profile_id === null || bounded(intent.runner_profile_id))
      && Array.isArray(intent.target_scope?.scope_refs) && intent.target_scope.scope_refs.length <= 32 && intent.target_scope.scope_refs.every(bounded)
      && (intent.collectors === undefined || Array.isArray(intent.collectors) && intent.collectors.length <= 32 && intent.collectors.every(bounded))
      && (intent.action_implementations === undefined || intent.action_implementations && typeof intent.action_implementations === "object" && !Array.isArray(intent.action_implementations)
        && Object.entries(intent.action_implementations).length <= 256 && Object.entries(intent.action_implementations).every(([key, item]) => bounded(key) && bounded(item))));
}
export function checkedAssistanceRun(value: AssistanceRunEnvelope, jobId: string): AssistanceRunEnvelope {
  if (value.job?.job_id !== jobId || value.job.kind !== "run.assistance.prepare" || typeof value.review_ready !== "boolean") throw new Error("This saved work does not match the requested run preparation.");
  const preparation = value.preparation;
  if (preparation && (preparation.schema_version !== "bluefire.assistance-run-preparation.v1" || !digest(preparation.preparation_digest)
    || !validSavedGraphSelection(preparation.selection) || preparation.scenario?.id !== preparation.selection.application.scenario_id
    || preparation.approval_created !== false || preparation.effects_started !== false)) throw new Error("The saved run preparation could not be verified.");
  if (value.decision && (!preparation || value.decision.preparation_digest !== preparation.preparation_digest || !["accept", "reject", "policy"].includes(value.decision.decision))) throw new Error("The recorded decision does not match this preparation.");
  if (value.run_job && (value.run_job.kind !== "scenario.run" || !preparation || !sameJson(value.run_job.request?._run_submission_request, preparation.run_request) || !sameJson(value.run_job.request?.assistance_run, { operation_job_id: jobId, preparation_digest: preparation?.preparation_digest }))) throw new Error("The run does not match the reviewed experiment and settings.");
  const inspectionJob = value.inspection_job, inspection = value.inspection, result = value.result;
  if (inspectionJob && (inspectionJob.kind !== "run.evidence.inspect" || !value.run_job?.result_ref
    || inspectionJob.request?.run_id !== value.run_job.result_ref || !sameJson(inspectionJob.request?.assistance_run, { operation_job_id: jobId, preparation_digest: preparation?.preparation_digest }))) throw new Error("The evidence review does not belong to this recorded run.");
  if (inspection && (!inspectionJob || inspection.schema_version !== "bluefire.run-evidence-inspection.v1"
    || inspection.run_id !== inspectionJob.request?.run_id || inspection.run_digest !== inspectionJob.request?.run_digest
    || !["supported", "insufficient"].includes(inspection.status) || typeof inspection.model_interpretation !== "boolean")) throw new Error("The evidence summary does not match its saved inspection.");
  if (result && (!inspection || !preparation || result.run_id !== inspection.run_id || result.run_job_id !== value.run_job?.job_id
    || result.inspection_job_id !== inspectionJob?.job_id || result.inspection_status !== inspection.status
    || result.scenario_id !== preparation.selection.application.scenario_id || result.version !== preparation.selection.application.version
    || result.digest !== preparation.selection.application.digest)) throw new Error("The saved outcome belongs to another experiment or evidence review.");
  return value;
}

const decisionKey = (jobId: string) => `bluefire.assistance-run-review.${jobId}`;
export type OperatorRunDecision = RunPreparationDecision & { decision: "accept" | "reject" };
export function readRunDecision(jobId: string): OperatorRunDecision | undefined {
  const raw = sessionStorage.getItem(decisionKey(jobId));
  if (raw === null) return;
  if (raw.length > 500) throw new Error("The retained run decision is invalid. Check the saved operation before continuing.");
  const value = JSON.parse(raw) as OperatorRunDecision;
  if (!value || !["accept", "reject"].includes(value.decision) || !digest(value.preparation_digest)) throw new Error("The retained run decision is invalid. Check the saved operation before continuing.");
  return value;
}
export function storeRunDecision(jobId: string, value: OperatorRunDecision): boolean {
  try {
    const existing = readRunDecision(jobId);
    if (existing && !sameJson(existing, value)) return false;
    sessionStorage.setItem(decisionKey(jobId), JSON.stringify(value));
    return sameJson(readRunDecision(jobId), value);
  } catch { return false; }
}

export function assistanceRunLink(job?: RunJob | null): string | undefined {
  const binding = job?.request?.assistance_run;
  if (!binding || typeof binding !== "object" || !("operation_job_id" in binding) || typeof binding.operation_job_id !== "string" || !/^job-[0-9a-f]{32}$/.test(binding.operation_job_id)) return;
  return `/runs?assistance_job=${encodeURIComponent(binding.operation_job_id)}`;
}
