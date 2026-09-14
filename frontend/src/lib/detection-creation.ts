import type { DetectionRunEvaluation, RunJob } from "../types";
import { sameJson } from "./replay-review";

export type DetectionCreationLanguage = "sqlite" | "sigma";
export type DetectionCreationRole = "attack" | "benign" | "replay";
export interface RunDetectionSelection {
  kind: "run_detection";
  run_id: string;
  source_binding_digest: string;
  behavior_id: string;
  target_language: DetectionCreationLanguage;
  case_role: DetectionCreationRole;
}

export const creationJobId = (value: string) => /^job-[0-9a-f]{32}$/.test(value);
export const creationDigest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const identifier = (value: unknown): value is string => typeof value === "string" && /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(value) && value.length <= 200;
export function validRunDetectionSelection(value: unknown): value is RunDetectionSelection {
  if (!value || typeof value !== "object") return false;
  const selected = value as RunDetectionSelection;
  return selected.kind === "run_detection" && /^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/.test(selected.run_id)
    && creationDigest(selected.source_binding_digest) && identifier(selected.behavior_id)
    && ["sqlite", "sigma"].includes(selected.target_language) && ["attack", "benign", "replay"].includes(selected.case_role);
}

export const detectionCreationPath = (runId: string, jobId?: string) => `/detection-lab?${new URLSearchParams({ run: runId, create: "1", ...(jobId ? { create_job: jobId } : {}) })}`;

export interface DetectionCreationSource {
  schema_version: "bluefire.detection-creation-source.v1";
  run_id: string; run_title: string; mode: string;
  source_run: Record<string, unknown>; source_binding_digest: string;
  observed_count: number; evidence_count: number; available: boolean; reason: string | null;
  behaviors: Array<{ behavior_id: string; title: string; step_ids: string[]; observed_count: number }>;
  languages: Array<{ id: DetectionCreationLanguage; available: boolean; reason: string | null; backend: Record<string, unknown> }>;
  limitations: string[];
}
export interface DetectionCreationValidation {
  proposal_digest: string; reviewed_digest: string; title: string; source: string;
  validation: { valid: true; target_language: DetectionCreationLanguage; backend: Record<string, unknown> };
}
export type DetectionCreationDecision = { decision: "accept"; proposal_digest: string; reviewed_digest: string; title: string; source: string; reviewed_by: string }
  | { decision: "reject"; proposal_digest: string; reviewed_by: string };
export interface DetectionCreationProposal {
  schema_version: "bluefire.detection-source-creation-proposal.v1"; proposal_digest: string;
  selected: RunDetectionSelection; source_run: Record<string, unknown>;
  title: string; source: string; reason: string; evidence_refs: string[]; limitations: string[];
  provider: Record<string, unknown>;
  provider_binding_digest: string;
}
export interface DetectionCreationApplication {
  schema_version: "bluefire.detection-source-creation-application.v1";
  proposal_job_id: string;
  application_job_id: string;
  proposal_digest: string;
  reviewed_digest: string;
  candidate_id: string;
  resource_digest: string;
  definition_digest: string;
  actual_source_digest: string;
  evaluation_id: string;
  run_id: string;
  source_binding_digest: string;
  operator_modified: boolean;
  development_case: true;
}
export interface DetectionCreatedResult extends DetectionCreationApplication {
  kind: "detection_created";
  step_id: string;
  native_path: string;
  match_count: DetectionRunEvaluation["result"]["match_count"];
  observed_count: number;
  evidence_count: number;
  state: string;
  backend_executed: boolean;
}
export interface DetectionCreationEnvelope {
  job: RunJob; proposal: DetectionCreationProposal | null; review_ready: boolean;
  decision: DetectionCreationDecision | null; application_job: RunJob | null;
  application: DetectionCreationApplication | null; evaluation: DetectionRunEvaluation | null;
}

export function checkedCreationSource(value: DetectionCreationSource, runId: string): DetectionCreationSource {
  if (value.schema_version !== "bluefire.detection-creation-source.v1" || value.run_id !== runId || !creationDigest(value.source_binding_digest)
    || !Number.isSafeInteger(value.observed_count) || value.observed_count < 0 || !Number.isSafeInteger(value.evidence_count) || value.evidence_count < value.observed_count
    || typeof value.available !== "boolean" || !Array.isArray(value.behaviors) || !Array.isArray(value.languages)
    || value.behaviors.some((row) => !identifier(row.behavior_id) || typeof row.title !== "string")
    || value.languages.some((row) => !["sqlite", "sigma"].includes(row.id) || typeof row.available !== "boolean")) throw new Error("The source response does not match this run. Reload its evidence before drafting a rule.");
  return value;
}
export function checkedCreationEnvelope(value: DetectionCreationEnvelope, jobId: string): DetectionCreationEnvelope {
  if (!creationJobId(jobId) || value.job?.job_id !== jobId || value.job.kind !== "detection.ai.create" || typeof value.review_ready !== "boolean") throw new Error("This link does not identify the requested detection draft.");
  const proposal = value.proposal, decision = value.decision, application = value.application, evaluation = value.evaluation;
  const object = (item: unknown): Record<string, unknown> => item && typeof item === "object" && !Array.isArray(item) ? item as Record<string, unknown> : {};
  const request = value.job.request ?? {}, submitted = object(request.submitted_request), context = object(request.context), source = object(context.source);
  const owner = object(request.assistance_turn), applicationRequest = value.application_job?.request;
  if (proposal && (proposal.schema_version !== "bluefire.detection-source-creation-proposal.v1" || !creationDigest(proposal.proposal_digest) || !validRunDetectionSelection(proposal.selected)
    || !sameJson(proposal.selected, submitted.selection) || !sameJson(proposal.selected, context.selected) || !sameJson(proposal.source_run, source.source_run)
    || source.source_binding_digest !== proposal.selected.source_binding_digest || !creationDigest(proposal.provider_binding_digest) || proposal.provider_binding_digest !== request.provider_binding_digest
    || typeof owner.parent_job_id !== "string" || !creationJobId(owner.parent_job_id) || typeof owner.step_id !== "string"
    || !Array.isArray(request.observed_ids) || !Array.isArray(proposal.evidence_refs) || proposal.evidence_refs.some((id) => !(request.observed_ids as unknown[]).includes(id))
    || !validCreationText(proposal.title, proposal.source) || proposal.source_run.run_id !== proposal.selected.run_id)) throw new Error("The rule proposal could not be verified.");
  if (decision && (!proposal || !validCreationDecision(decision, proposal))) throw new Error("The saved decision does not match the rule proposal.");
  if (value.application_job && (value.application_job.kind !== "detection.ai.create.apply" || !creationJobId(value.application_job.job_id) || !decision
    || applicationRequest?.proposal_job_id !== jobId || !sameJson(applicationRequest.decision, decision) || !sameJson(applicationRequest.assistance_turn, request.assistance_turn))) throw new Error("The save operation could not be verified.");
  if (application && (!proposal || decision?.decision !== "accept" || application.schema_version !== "bluefire.detection-source-creation-application.v1"
    || application.proposal_job_id !== jobId || application.proposal_digest !== proposal.proposal_digest || application.reviewed_digest !== decision.reviewed_digest
    || application.application_job_id !== value.application_job?.job_id || application.run_id !== proposal.selected.run_id || application.source_binding_digest !== proposal.selected.source_binding_digest
    || !/^detection-[0-9a-f]{20}$/.test(application.candidate_id) || !creationDigest(application.definition_digest) || !creationDigest(application.resource_digest)
    || !creationDigest(application.actual_source_digest) || application.development_case !== true || typeof application.operator_modified !== "boolean")) throw new Error("The saved rule does not match this reviewed proposal.");
  if (evaluation && (!application || !proposal || evaluation.evaluation_id !== application.evaluation_id || !sameJson(evaluation.source, proposal.source_run)
    || evaluation.case_role !== proposal.selected.case_role || evaluation.candidate.target_language !== proposal.selected.target_language
    || evaluation.candidate.candidate_id !== application.candidate_id || evaluation.candidate.definition_digest !== application.definition_digest || evaluation.development_case !== true)) throw new Error("The evaluation does not match the saved rule and source run.");
  return value;
}
export const creationWorkActive = (job?: RunJob | null) => Boolean(job && !["completed", "failed", "cancelled", "interrupted"].includes(job.state));
export function validCreationText(title: string, source: string) {
  return typeof title === "string" && title.trim().length > 0 && title.length <= 200 && !/[\r\n\0]/.test(title)
    && typeof source === "string" && source.trim().length > 0 && !source.includes("\0") && new TextEncoder().encode(source).length <= 32768;
}
function validCreationDecision(value: DetectionCreationDecision, proposal: DetectionCreationProposal): boolean {
  return value.proposal_digest === proposal.proposal_digest && typeof value.reviewed_by === "string" && Boolean(value.reviewed_by.trim()) && value.reviewed_by.length <= 200
    && (value.decision === "reject" || (value.decision === "accept" && creationDigest(value.reviewed_digest) && validCreationText(value.title, value.source)));
}
export interface DetectionCreationDraft { proposal_digest: string; title: string; source: string; decision?: DetectionCreationDecision }
const draftKey = (jobId: string) => `bluefire.detection-create-review.${jobId}`;
export function readCreationDraft(jobId: string, proposal: DetectionCreationProposal): DetectionCreationDraft | undefined {
  const raw = sessionStorage.getItem(draftKey(jobId));
  if (raw === null) return;
  if (raw.length > 80000) throw new Error("The retained rule draft exceeds its size limit. Its original text has been preserved.");
  const value = JSON.parse(raw) as DetectionCreationDraft;
  if (!value || value.proposal_digest !== proposal.proposal_digest || typeof value.title !== "string" || typeof value.source !== "string"
    || (value.decision && (!validCreationDecision(value.decision, proposal) || (value.decision.decision === "accept" && (value.decision.title !== value.title || value.decision.source !== value.source))))) throw new Error("The retained rule draft could not be verified. It has not been replaced.");
  return value;
}
export function storeCreationDraft(jobId: string, proposal: DetectionCreationProposal, value: DetectionCreationDraft): boolean {
  try {
    const previous = readCreationDraft(jobId, proposal);
    if (value.proposal_digest !== proposal.proposal_digest || (previous?.decision && !sameJson(value, previous))) return false;
    const raw = JSON.stringify(value);
    if (raw.length > 80000) return false;
    sessionStorage.setItem(draftKey(jobId), raw);
    return sameJson(readCreationDraft(jobId, proposal), value);
  } catch { return false; }
}
