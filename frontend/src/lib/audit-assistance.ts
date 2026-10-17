import { request } from "./api";
import type { AssistanceContext } from "./assistance";
import { validS3Job } from "./s3-access";
import { sameJson } from "./replay-review";

export interface AuditAssistanceSelection { kind: "s3_audit_review"; workflow_job_id: string; review_id: string; review_digest: string }
interface AuditReadSummary { purpose: "primary" | "health"; reader: "probe" | "legitimate"; status: string; worker_outcome: string; matched_event_count: number; full_object_bytes_proven: false }
interface ImportedAuditSummary {
  phase: "baseline" | "retest"; runner_source: "synthetic" | "runner_reported"; cleanup: "verified" | "unknown";
  collection_provenance: "operator_import"; reported_delivery_state: "unknown" | "incomplete" | "truncated" | "complete";
  source_event_count: number; counts: { excluded: number; unknown: number; duplicates: number }; reads: AuditReadSummary[];
  independent_collection_proven: false; effective_access_claim: false;
}
export interface CollectedAuditSummary {
  schema_version: "bluefire.s3-collected-audit-summary.v1"; phase: "baseline" | "retest";
  runner_source: "runner_reported"; cleanup: "verified"; collection_provenance: "authenticated_source_retrieval";
  reported_delivery_state: "unknown" | "incomplete" | "truncated"; source_event_count: number; collected_file_count: number;
  discovery_truncated: boolean; reads: AuditReadSummary[]; raw_bytes_retained: false; log_integrity_proven: false;
  independent_collection_proven: false; effective_access_claim: false;
}
export interface AuditAssistanceContext extends AssistanceContext {
  selected: AuditAssistanceSelection; analysis_only: true; reference_summary: ImportedAuditSummary | CollectedAuditSummary;
}
const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const bounded = (value: unknown, max: number): value is number => typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= max;
const statuses = new Set(["matched", "conflict", "worker_unreported", "truncated", "unknown", "awaiting_delivery", "missing"]);
const outcomes = new Set(["unreported", "service_success", "service_denied", "object_missing", "bucket_missing", "credential_error", "other_service_error"]);
function validRead(value: unknown, bound: number): value is AuditReadSummary {
  return exact(value, ["purpose", "reader", "status", "worker_outcome", "matched_event_count", "full_object_bytes_proven"])
    && (value.purpose === "primary" || value.purpose === "health") && (value.reader === "probe" || value.reader === "legitimate")
    && typeof value.status === "string" && statuses.has(value.status) && typeof value.worker_outcome === "string" && outcomes.has(value.worker_outcome)
    && bounded(value.matched_event_count, bound) && value.full_object_bytes_proven === false;
}
function validSummary(value: unknown): value is ImportedAuditSummary | CollectedAuditSummary {
  if (!object(value) || (value.phase !== "baseline" && value.phase !== "retest") || value.independent_collection_proven !== false || value.effective_access_claim !== false) return false;
  if (value.collection_provenance === "operator_import") {
    return exact(value, ["phase", "runner_source", "cleanup", "collection_provenance", "reported_delivery_state", "source_event_count", "counts", "reads", "independent_collection_proven", "effective_access_claim"])
      && (value.runner_source === "synthetic" || value.runner_source === "runner_reported") && (value.cleanup === "verified" || value.cleanup === "unknown")
      && typeof value.reported_delivery_state === "string" && ["unknown", "incomplete", "truncated", "complete"].includes(value.reported_delivery_state)
      && bounded(value.source_event_count, 1000) && exact(value.counts, ["excluded", "unknown", "duplicates"]) && Object.values(value.counts).every(n => bounded(n, 1000))
      && Array.isArray(value.reads) && value.reads.length >= 1 && value.reads.length <= 2 && value.reads.every(row => validRead(row, 1000));
  }
  return exact(value, ["schema_version", "phase", "runner_source", "cleanup", "collection_provenance", "reported_delivery_state", "source_event_count", "collected_file_count", "discovery_truncated", "reads", "raw_bytes_retained", "log_integrity_proven", "independent_collection_proven", "effective_access_claim"])
    && value.schema_version === "bluefire.s3-collected-audit-summary.v1" && value.collection_provenance === "authenticated_source_retrieval"
    && value.runner_source === "runner_reported" && value.cleanup === "verified" && value.raw_bytes_retained === false && value.log_integrity_proven === false
    && typeof value.reported_delivery_state === "string" && ["unknown", "incomplete", "truncated"].includes(value.reported_delivery_state)
    && bounded(value.source_event_count, 500) && bounded(value.collected_file_count, 4) && typeof value.discovery_truncated === "boolean"
    && (!value.discovery_truncated || value.reported_delivery_state === "truncated") && Array.isArray(value.reads) && value.reads.length === 3
    && value.reads.every(row => validRead(row, value.source_event_count as number))
    && sameJson(value.reads.map(row => [row.reader, row.purpose]), [["probe", "primary"], ["legitimate", "primary"], ["legitimate", "health"]]);
}
export function validAuditAssistanceSelection(value: unknown): value is AuditAssistanceSelection {
  return object(value) && Object.keys(value).length === 4 && value.kind === "s3_audit_review" && validS3Job(value.workflow_job_id) && validS3Job(value.review_id) && typeof value.review_digest === "string" && /^sha256:[0-9a-f]{64}$/.test(value.review_digest);
}
export function isAuditSelection(value: AssistanceContext["selected"]): value is AuditAssistanceSelection { return "kind" in value && value.kind === "s3_audit_review"; }
export function checkedAuditAssistanceContext(value: unknown, selected: AuditAssistanceSelection): AuditAssistanceContext {
  if (!validAuditAssistanceSelection(selected) || !exact(value, ["schema_version", "selected", "context_digest", "analysis_only", "capabilities", "reference_summary", "limitations"]) || value.schema_version !== "bluefire.assistance-context.v1" || !sameJson(value.selected, selected) || typeof value.context_digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.context_digest) || value.analysis_only !== true || !Array.isArray(value.capabilities) || value.capabilities.length || !Array.isArray(value.limitations) || !value.limitations.length || value.limitations.length > 8 || value.limitations.some(row => typeof row !== "string" || row.length > 1000) || !validSummary(value.reference_summary)) throw new Error("The saved audit explanation context changed or is unavailable.");
  return value as unknown as AuditAssistanceContext;
}
export async function auditAssistanceContext(selected: AuditAssistanceSelection): Promise<AuditAssistanceContext> {
  if (!validAuditAssistanceSelection(selected)) throw new Error("Select an exact saved audit review.");
  return checkedAuditAssistanceContext(await request<AssistanceContext>(`/s3-access/exercises/${selected.workflow_job_id}/audit-reviews/${selected.review_id}/assistant-context`), selected);
}
