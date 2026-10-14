import { request } from "./api";
import type { AssistanceContext } from "./assistance";
import { validS3Job } from "./s3-access";
import { sameJson } from "./replay-review";

export interface AuditAssistanceSelection { kind: "s3_audit_review"; workflow_job_id: string; review_id: string; review_digest: string }
const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
export function validAuditAssistanceSelection(value: unknown): value is AuditAssistanceSelection {
  return object(value) && Object.keys(value).length === 4 && value.kind === "s3_audit_review" && validS3Job(value.workflow_job_id) && validS3Job(value.review_id) && typeof value.review_digest === "string" && /^sha256:[0-9a-f]{64}$/.test(value.review_digest);
}
export function isAuditSelection(value: AssistanceContext["selected"]): value is AuditAssistanceSelection { return "kind" in value && value.kind === "s3_audit_review"; }
export function checkedAuditAssistanceContext(value: AssistanceContext, selected: AuditAssistanceSelection): AssistanceContext {
  if (!validAuditAssistanceSelection(selected) || !object(value) || value.schema_version !== "bluefire.assistance-context.v1" || !sameJson(value.selected, selected) || !/^sha256:[0-9a-f]{64}$/.test(value.context_digest) || value.analysis_only !== true || !Array.isArray(value.capabilities) || value.capabilities.length || !Array.isArray(value.limitations) || !value.limitations.length || value.limitations.length > 8 || value.limitations.some(row => typeof row !== "string" || row.length > 1000)) throw new Error("The saved audit explanation context changed or is unavailable.");
  return value;
}
export async function auditAssistanceContext(selected: AuditAssistanceSelection): Promise<AssistanceContext> {
  if (!validAuditAssistanceSelection(selected)) throw new Error("Select an exact saved audit review.");
  return checkedAuditAssistanceContext(await request<AssistanceContext>(`/s3-access/exercises/${selected.workflow_job_id}/audit-reviews/${selected.review_id}/assistant-context`), selected);
}
