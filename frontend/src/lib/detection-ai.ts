import type { DetectionCaseRole, DetectionResource, DetectionRunEvaluation, JobRetryResult, RunJob } from "../types";
import { sameJson } from "./replay-review";

export interface DetectionAIRequest {
  submission_id: string;
  run_id: string;
  parent_resource_digest: string;
  question: string;
  case_role: DetectionCaseRole;
  provider_id: string;
  autonomy: "assist";
}
export interface DetectionAIReceipt { candidateId: string; request: DetectionAIRequest }
export interface DetectionAIProposal {
  schema_version: "bluefire.detection-ai-proposal.v1";
  proposal_digest: string;
  parent: { candidate_id: string; resource_digest: string; definition_digest: string; target_language: string; source: string };
  source_run: DetectionRunEvaluation["source"];
  source: string;
  reason: string;
  evidence_refs: string[];
  limitations: string[];
  provider: { provider_id: string; kind: string; model: string; usage: Record<string, unknown> };
  provider_binding_digest: string;
  context_digest: string;
}
export interface DetectionAIDecision {
  proposal_digest: string;
  parent_resource_digest: string;
  decision: "accept" | "reject";
  reviewed_by: string;
}
export interface DetectionAIApplication {
  schema_version: "bluefire.detection-ai-application.v1";
  proposal_job_id: string;
  proposal_digest: string;
  candidate_id: string;
  evaluation_id: string;
  run_id: string;
  development_case: true;
  applied_at: string;
}

const key = "bluefire.detection-ai.pending.v1";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
export const detectionJobId = (submissionId: string) => `job-${submissionId.replaceAll("-", "")}`;
export const detectionJobActive = (job: RunJob) => !["completed", "failed", "cancelled", "interrupted"].includes(job.state);
export function matchesDetectionRetry(result: JobRetryResult, source: RunJob): boolean {
  const intent = (job: RunJob) => Object.fromEntries(Object.entries(job.request ?? {}).filter(([field]) => !["_submission", "retry_of_job_id"].includes(field)));
  return result.retry_of_job_id === source.job_id && result.source_job.job_id === source.job_id && result.job.job_id !== source.job_id && result.job.kind === source.kind && result.job.request?.retry_of_job_id === source.job_id && sameJson(intent(result.job), intent(source));
}
const text = (value: unknown, max = 200): value is string => typeof value === "string" && value.length > 0 && value.length <= max && [...value].every((character) => character.charCodeAt(0) >= 32);

export function readDetectionAIReceipt(): DetectionAIReceipt | undefined {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw || raw.length > 6000) return undefined;
    const value = JSON.parse(raw) as DetectionAIReceipt;
    const request = value?.request;
    if (!text(value?.candidateId) || !request || !uuid.test(request.submission_id) || !text(request.run_id) || !digest.test(request.parent_resource_digest) || !text(request.question, 1000) || !text(request.provider_id) || request.autonomy !== "assist" || !["attack", "benign", "replay", "heldout"].includes(request.case_role)) return undefined;
    return value;
  } catch { return undefined; }
}
export function storeDetectionAIReceipt(receipt: DetectionAIReceipt): boolean {
  try {
    if (sessionStorage.getItem(key) !== null && !sameJson(readDetectionAIReceipt(), receipt)) return false;
    sessionStorage.setItem(key, JSON.stringify(receipt));
    return sameJson(readDetectionAIReceipt(), receipt);
  } catch { return false; }
}
export function matchesDetectionAIReceipt(job: RunJob, receipt: DetectionAIReceipt): boolean {
  return job.kind === "detection.ai.propose" && job.job_id === detectionJobId(receipt.request.submission_id) && job.request?.candidate_id === receipt.candidateId && sameJson(job.request.submitted_request, receipt.request);
}
export function settleDetectionAIReceipt(job: RunJob): boolean {
  const receipt = readDetectionAIReceipt();
  if (!receipt || !matchesDetectionAIReceipt(job, receipt)) return false;
  try { sessionStorage.removeItem(key); return sessionStorage.getItem(key) === null; } catch { return false; }
}
export function detectionProposal(job?: RunJob): DetectionAIProposal | undefined {
  const proposal = job?.progress.proposal as DetectionAIProposal | undefined;
  if (job?.kind !== "detection.ai.propose" || job.state !== "completed" || proposal?.schema_version !== "bluefire.detection-ai-proposal.v1" || !digest.test(proposal.proposal_digest) ||
    !text(proposal.parent?.candidate_id) || !digest.test(proposal.parent.resource_digest) || typeof proposal.parent.source !== "string" || !text(proposal.source_run?.run_id) ||
    !sameJson(proposal.parent, job.request?.parent) || !sameJson(proposal.source_run, job.request?.source_run) || typeof proposal.source !== "string" || !proposal.source.trim() || proposal.source.length > 32768 || typeof proposal.reason !== "string" || !proposal.reason.trim() || proposal.reason.length > 1000 ||
    !Array.isArray(proposal.evidence_refs) || !proposal.evidence_refs.length || proposal.evidence_refs.length > 128 || new Set(proposal.evidence_refs).size !== proposal.evidence_refs.length || !proposal.evidence_refs.every((id) => text(id) && Array.isArray(job.request?.observed_ids) && job.request.observed_ids.includes(id)) ||
    !Array.isArray(proposal.limitations) || proposal.limitations.length > 16 || !proposal.limitations.every((item) => typeof item === "string" && item.length > 0 && item.length <= 1000) || !proposal.provider?.provider_id || !proposal.provider.model) return undefined;
  return proposal;
}
export function proposalIsCurrent(proposal: DetectionAIProposal, resource?: DetectionResource, runId?: string): boolean {
  return resource?.id === proposal.parent.candidate_id && resource.digest === proposal.parent.resource_digest && runId === proposal.source_run.run_id;
}
export function detectionApplication(job: RunJob | undefined, proposalJob: RunJob | undefined, proposal: DetectionAIProposal | undefined): DetectionAIApplication | undefined {
  const applied = job?.progress.application as DetectionAIApplication | undefined;
  if (!proposal || !proposalJob || !applied || applied.schema_version !== "bluefire.detection-ai-application.v1" || applied.proposal_job_id !== proposalJob.job_id || applied.proposal_digest !== proposal.proposal_digest || applied.run_id !== proposal.source_run.run_id || applied.development_case !== true || !text(applied.candidate_id) || !text(applied.evaluation_id)) return undefined;
  return applied;
}
