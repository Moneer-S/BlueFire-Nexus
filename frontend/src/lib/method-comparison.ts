import type { ReplayPreparation } from "./api";
import type { DetectionCaseRole, DetectionRunEvaluation, RunJob } from "../types";
import { sameJson } from "./replay-review";

export type MethodSource = DetectionRunEvaluation["source"] & { mode: string; finalized_at: string; observed_records_digest: string };
export interface MethodOption { option_id: string; step_id: string; behavior_from: string; behavior_to: string; title_from: string; title: string }
export interface MethodContext { schema_version: "bluefire.method-comparison-context.v1"; source_run: MethodSource; source_binding_digest: string; options: MethodOption[]; replay_extent: "full"; replay_autonomy: "off" }
export interface MethodRequest {
  submission_id: string; source_binding_digest: string; selected_step_id: string;
  candidate_id: string; candidate_resource_digest: string; question: string;
  source_case_role: DetectionCaseRole; provider_id: string; autonomy: "assist" | "auto";
}
export interface MethodPending { sourceId: string; request: MethodRequest }
export interface MethodDetector { candidate_id: string; definition_digest: string; resource_digest: string; target_language: string }
export interface MethodProposal {
  schema_version: "bluefire.method-comparison-proposal.v1"; proposal_digest: string;
  source_run: MethodSource; detector: MethodDetector; option_id: string; option: MethodOption;
  replay_preparation: ReplayPreparation; reason: string; evidence_refs: string[];
  limitations: string[]; comparison_limitations: string[];
  provider: { provider_id: string; kind: string; model: string; usage: Record<string, unknown> };
  scope: { scope_refs?: string[]; [key: string]: unknown }; profile: { id?: string; [key: string]: unknown };
  changes: { step_id: string; behavior: { from: string; to: string }; runtime_autonomy: { from: string; to: "off" } };
  replay_extent: "full"; replay_autonomy: "off";
}
export interface MethodDecision { proposal_digest: string; decision: "accept" | "reject"; reviewed_by: string }
export interface MethodResult {
  schema_version: "bluefire.method-comparison-result.v1"; proposal_job_id: string; proposal_digest: string;
  replay_job_id: string; source_run_id: string; child_run_id: string;
  candidate_id: string; candidate_definition_digest: string;
  baseline_evaluation_id: string; child_evaluation_id: string; comparison_id: string; comparison_digest: string;
}
const key = "bluefire.method-comparison.pending.v1";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
const text = (value: unknown, max = 200): value is string => typeof value === "string" && value.length > 0 && value.length <= max && [...value].every((character) => character.charCodeAt(0) >= 32);
export const methodJobId = (id: string) => `job-${id.replaceAll("-", "")}`;
export const jobSettled = (job?: RunJob) => Boolean(job && ["completed", "failed", "cancelled", "interrupted"].includes(job.state));
export function methodComparisonLink(job?: RunJob | null): string | undefined {
  const binding = job?.request?.method_comparison as { proposal_job_id?: unknown } | undefined;
  const parentId = binding?.proposal_job_id ?? (job?.kind === "replay.comparison.recover" ? job.request?.proposal_job_id : undefined);
  if (typeof parentId !== "string" || !/^job-[0-9a-f]{32}$/.test(parentId)) return undefined;
  const params = new URLSearchParams({ method_job: parentId });
  if (text(job?.request?.source_run_id)) params.set("source", job.request.source_run_id);
  return `/compare?${params}`;
}
export function readMethodPending(): MethodPending | undefined {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw || raw.length > 7000) return undefined;
    const value = JSON.parse(raw) as MethodPending, request = value?.request;
    if (!text(value?.sourceId) || !request || !uuid.test(request.submission_id) || !digest.test(request.source_binding_digest) || !digest.test(request.candidate_resource_digest) ||
      !text(request.selected_step_id) || !text(request.candidate_id) || !text(request.provider_id) || !text(request.question, 1000) || !["assist", "auto"].includes(request.autonomy) || !["attack", "benign", "replay", "heldout"].includes(request.source_case_role)) return undefined;
    return value;
  } catch { return undefined; }
}
export function storeMethodPending(value: MethodPending): boolean {
  try {
    if (sessionStorage.getItem(key) !== null && !sameJson(readMethodPending(), value)) return false;
    sessionStorage.setItem(key, JSON.stringify(value));
    return sameJson(readMethodPending(), value);
  } catch { return false; }
}
export function matchesMethodPending(job: RunJob, value: MethodPending): boolean {
  return job.kind === "replay.ai.propose" && job.job_id === methodJobId(value.request.submission_id) && job.request?.source_run_id === value.sourceId && sameJson(job.request.submitted_request, value.request);
}
export function settleMethodPending(job: RunJob): boolean {
  const value = readMethodPending();
  if (!value || !matchesMethodPending(job, value)) return false;
  try { sessionStorage.removeItem(key); return sessionStorage.getItem(key) === null; } catch { return false; }
}
export function methodProposal(job?: RunJob): MethodProposal | undefined {
  const proposal = job?.progress.proposal as MethodProposal | undefined;
  if (job?.kind !== "replay.ai.propose" || !proposal || proposal.schema_version !== "bluefire.method-comparison-proposal.v1" || !digest.test(proposal.proposal_digest) ||
    proposal.replay_extent !== "full" || proposal.replay_autonomy !== "off" || !sameJson(proposal.source_run, job.request?.source_run) || !sameJson(proposal.detector, job.request?.detector)) return undefined;
  const options = job.request?.options;
  const option = Array.isArray(options) ? options.find((item: Record<string, unknown>) => item.option_id === proposal.option_id) as Record<string, unknown> | undefined : undefined;
  if (!option || !sameJson(Object.fromEntries(Object.entries(option).filter(([field]) => field !== "replay_preparation")), proposal.option) || !sameJson(option.replay_preparation, proposal.replay_preparation) ||
    typeof proposal.reason !== "string" || !proposal.reason.trim() || proposal.reason.length > 1000 || proposal.reason.includes("\0") || !Array.isArray(proposal.evidence_refs) || !proposal.evidence_refs.every((id) => text(id)) || !Array.isArray(proposal.limitations) || !Array.isArray(proposal.comparison_limitations)) return undefined;
  return proposal;
}
export function methodResult(job: RunJob | undefined, parent: RunJob | undefined, proposal: MethodProposal | undefined): MethodResult | undefined {
  const result = job?.progress.comparison as MethodResult | undefined;
  if (!result || !parent || !proposal || result.schema_version !== "bluefire.method-comparison-result.v1" || result.proposal_job_id !== parent.job_id || result.proposal_digest !== proposal.proposal_digest ||
    result.source_run_id !== proposal.source_run.run_id || result.candidate_id !== proposal.detector.candidate_id || result.candidate_definition_digest !== proposal.detector.definition_digest ||
    result.replay_job_id !== methodJobId(String(parent.request?.replay_submission_id)) || !text(result.child_run_id) || !text(result.baseline_evaluation_id) || !text(result.child_evaluation_id) || !text(result.comparison_id) || !digest.test(result.comparison_digest)) return undefined;
  return result;
}
