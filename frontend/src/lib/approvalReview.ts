import type { AIProposalReview, PreflightReport, RunJob } from "../types";

export const approvalBindingFields = ["state_digest", "plan_digest", "target_scope_digest", "profile_id", "maximum_tier"] as const;

export function approvalDeadline(expiresAt: unknown): number {
  return typeof expiresAt === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(expiresAt) ? Date.parse(expiresAt) : NaN;
}

export function hasUsableStoredApprovalReview(report?: PreflightReport): boolean {
  return Boolean(
    report?.status === "approval_required"
    && report.plan
    && report.approval_binding
    && approvalBindingFields.every((field) => typeof report.approval_binding?.[field] === "string" && report.approval_binding[field].length > 0)
    && report.approval_envelope
    && typeof report.approval_envelope.envelope_digest === "string"
    && report.approval_envelope.envelope_digest.length > 0
    && Array.isArray(report.approval_envelope.steps),
  );
}

/** Restore the review published with this ordinary job, never a new intent. */
export function storedRunApprovalPreflight(job: RunJob, options: { forDisplayOnly?: boolean } = {}): PreflightReport | undefined {
  const report = job.request?._run_submission_preflight as PreflightReport | undefined;
  const request = job.approval_request;
  const binding = report?.approval_binding;
  const approvalId = request?.approval_id;
  if (
    job.kind !== "scenario.run" || job.state !== "awaiting_approval"
    || ["ai_proposal", "ai_proposal_execute"].includes(String(job.progress.approval_kind ?? ""))
    || request?.status !== "pending" || typeof approvalId !== "string" || !approvalId
    || (!options.forDisplayOnly && !(approvalDeadline(request.expires_at) > Date.now()))
    || job.request?.approval_request_id !== approvalId
    || (job.progress.approval_request_id !== undefined && job.progress.approval_request_id !== approvalId)
    || !hasUsableStoredApprovalReview(report) || !binding
    || report?.plan?.mode !== "execute" || !Array.isArray(report.plan.steps) || !report.plan.steps.length
    || !report.approval_envelope?.steps.length
    || !approvalBindingFields.every((field) => request[field] === binding[field])
  ) return undefined;
  return report;
}

export function continuationApprovalPreflight(job: RunJob, review?: AIProposalReview, request?: Record<string, unknown> | null, options: { forDisplayOnly?: boolean } = {}): PreflightReport | undefined {
  const canonical = review?.execute_approval_review;
  const report = canonical?.preflight;
  const binding = report?.approval_binding;
  const approvalId = request?.approval_id;
  const originalId = job.request?.approval_request_id;
  const continuation = review?.resolution?.continuation;
  const audit = continuation && typeof continuation === "object" ? continuation as Record<string, unknown> : undefined;
  if (
    job.state !== "awaiting_approval" || job.progress.approval_kind !== "ai_proposal_execute"
    || review?.status !== "accepted" || review.job_id !== job.job_id
    || review.proposal_record_id !== job.progress.proposal_record_id
    || request?.status !== "pending" || typeof approvalId !== "string" || !approvalId
    || (!options.forDisplayOnly && !(approvalDeadline(request.expires_at) > Date.now()))
    || typeof originalId !== "string" || !originalId || originalId === approvalId
    || job.progress.approval_request_id !== approvalId || review.resolution?.approval_request_id !== approvalId
    || canonical?.schema_version !== "bluefire.continuation-approval-review.v1"
    || canonical.job_id !== job.job_id || canonical.proposal_record_id !== review.proposal_record_id
    || canonical.approval_request_id !== approvalId
    || !hasUsableStoredApprovalReview(report) || !binding
    || !Array.isArray(report?.plan?.steps) || !report.plan.steps.length || report.plan.mode !== "execute"
    || !report.approval_envelope?.steps.length
    || audit?.continuation_plan_digest !== binding.plan_digest
    || typeof audit?.execute_approval_binding_digest !== "string" || !audit.execute_approval_binding_digest
    || !approvalBindingFields.every((field) => request[field] === binding[field])
  ) return undefined;
  return report;
}
