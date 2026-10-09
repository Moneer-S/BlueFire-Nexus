import { DEMO_MODE, request } from "./api";
import { compositionJobId, compositionJobValid, type CompositionJob } from "./composition";
import { sameJson } from "./replay-review";

export type FileAccessOperation = "create" | "baseline" | "harden" | "rollback" | "reset";
export interface FileAccessReviewRequest { operation: FileAccessOperation; control_owner_id: string | null }
export interface FileAccessReview {
  schema_version: "bluefire.file-access-control-review.v1";
  operation: FileAccessOperation; control_owner_id: string | null;
  context_digest: string; enrollment_digest: string; control_digest: string | null;
  expires_at_ms: number; effect: string; review_digest: string;
}
export interface FileAccessSubmission { submission_id: string; review: FileAccessReviewRequest; review_digest: string; reviewed_by: string }
export interface FileAccessStatus {
  schema_version: "bluefire.file-access-status.v1"; available: boolean; problem: null | { code: string; message: string };
  enrollment: null | { enrollment_id: string; enrollment_digest: string; expires_at_ms: number; owner_uid: number; probe_uid: number };
  allowed_operations: FileAccessOperation[];
}
export type FileAccessControlState = "created" | "baseline_verified" | "hardened" | "rolled_back" | "reset" | "uncertain" | "recovery_required";
export interface FileAccessControlSummary { control_owner_id: string; status: FileAccessControlState; revision: number }
export interface FileAccessControl extends FileAccessControlSummary {
  schema_version: "bluefire.file-access-control.v1"; control_digest: string;
  resource: null | { resource_id: string; resource_generation: string; sha256: string; size: number; record_count: number; mode: "0640" | "0600" };
  baseline: null | { baseline_digest: string; non_owner: "allowed"; owner: "allowed"; record_count: number; sha256: string };
  usage_state: "settled" | "pending" | "unknown"; allowed_operations: FileAccessOperation[]; operations: CompositionJob[];
}
export interface FileAccessControlList { schema_version: "bluefire.file-access-control-list.v1"; controls: FileAccessControlSummary[] }
export interface FileAccessOperationEnvelope {
  schema_version: "bluefire.file-access-operation.v1"; job: CompositionJob; control: FileAccessControl | null;
  reconciliation: null | { outcome_digest: string; state: "unknown" | "complete" | "refused_no_effect" | "settled_partial"; available: boolean };
  reconciliation_receipt: FileAccessReconciliationReceipt | null;
}
export interface FileAccessReconciliationSubmission { submission_id: string; expected_outcome_digest: string; reviewed_by: string }
export interface FileAccessReconciliationReceipt { submission_id: string; submitted_request: FileAccessReconciliationSubmission; state: "completed" | "pending"; problem: null | { code: string; message: string } }
export interface FileAccessReconciliationEnvelope { schema_version: "bluefire.file-access-reconciliation.v1"; operation_job_id: string; receipt: FileAccessReconciliationReceipt }
export interface FileAccessObservation {
  schema_version: "bluefire.file-access-control-observation.v1"; operation: "baseline" | "rollback";
  non_owner: "allowed"; owner: "allowed"; resource_generation: string; record_count: number; sha256: string;
  mode: "0640"; source_digest: string; observed_at_ms: number;
}
export interface FileAccessPending { id: string; body: FileAccessSubmission }
export const fileAccessOperationLabels: Record<FileAccessOperation, string> = {
  create: "Create generated resource", baseline: "Verify baseline access", harden: "Apply owner-only access",
  rollback: "Restore baseline access", reset: "Reset generated resource",
};
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const bad = () => new Error("This file-access response is incomplete or belongs to different saved work.");
const controlStates = ["created", "baseline_verified", "hardened", "rolled_back", "reset", "uncertain", "recovery_required"];
const natural = (value: unknown) => Number.isSafeInteger(value) && Number(value) >= 0;
const operationsValid = (value: unknown, allowed: string[]) => Array.isArray(value) && new Set(value).size === value.length && value.every(item => typeof item === "string" && allowed.includes(item));
export const fileAccessJobActive = (job: CompositionJob) => !["completed", "failed", "cancelled", "interrupted"].includes(job.state);
export function fileAccessReviewRequestValid(value: FileAccessReviewRequest): boolean {
  return Boolean(value && Object.keys(value).sort().join(",") === "control_owner_id,operation"
    && Object.hasOwn(fileAccessOperationLabels, value.operation)
    && (value.operation === "create" ? value.control_owner_id === null : compositionJobValid(value.control_owner_id)));
}
export function checkedFileAccessReview(value: FileAccessReview, submitted: FileAccessReviewRequest): FileAccessReview {
  if (!fileAccessReviewRequestValid(submitted) || value?.schema_version !== "bluefire.file-access-control-review.v1"
    || value.operation !== submitted.operation || value.control_owner_id !== submitted.control_owner_id
    || !digest(value.context_digest) || !digest(value.enrollment_digest) || !digest(value.review_digest)
    || (submitted.operation === "create" ? value.control_digest !== null : !digest(value.control_digest))
    || !Number.isSafeInteger(value.expires_at_ms) || value.expires_at_ms <= 0
    || typeof value.effect !== "string" || !value.effect.trim() || value.effect.length > 8000) throw bad();
  return value;
}
export function checkedFileAccessStatus(value: FileAccessStatus): FileAccessStatus {
  if (value?.schema_version !== "bluefire.file-access-status.v1" || typeof value.available !== "boolean"
    || !operationsValid(value.allowed_operations, ["create"])
    || (value.problem !== null && (typeof value.problem?.code !== "string" || typeof value.problem?.message !== "string"))) throw bad();
  const enrollment = value.enrollment;
  if (enrollment !== null && (typeof enrollment?.enrollment_id !== "string" || !enrollment.enrollment_id || !digest(enrollment.enrollment_digest)
    || !Number.isSafeInteger(enrollment.expires_at_ms) || !natural(enrollment.owner_uid) || !natural(enrollment.probe_uid) || enrollment.owner_uid === enrollment.probe_uid)) throw bad();
  if (value.available && (!enrollment || value.problem !== null)) throw bad();
  if (!value.available && value.allowed_operations.length) throw bad();
  return value;
}
export function checkedFileAccessControl(value: FileAccessControl, owner: string): FileAccessControl {
  if (value?.schema_version !== "bluefire.file-access-control.v1" || value.control_owner_id !== owner || !compositionJobValid(owner)
    || !digest(value.control_digest) || !natural(value.revision) || value.revision < 1 || !controlStates.includes(value.status)
    || !["settled", "pending", "unknown"].includes(value.usage_state) || !operationsValid(value.allowed_operations, ["baseline", "harden", "rollback", "reset"])
    || !Array.isArray(value.operations) || value.operations.some(job => {
      const submitted = job.progress?.submitted_request as FileAccessSubmission;
      return !compositionJobValid(job.job_id) || job.kind !== "file_access.operation" || typeof job.state !== "string"
        || !fileAccessSubmissionValid(submitted) || compositionJobId(submitted.submission_id) !== job.job_id
        || (submitted.review.control_owner_id ?? job.job_id) !== owner;
    })) throw bad();
  const resource = value.resource;
  if (resource !== null && (typeof resource?.resource_id !== "string" || !resource.resource_id || typeof resource.resource_generation !== "string" || !resource.resource_generation
    || !digest(resource.sha256) || !natural(resource.size) || !natural(resource.record_count) || !["0600", "0640"].includes(resource.mode))) throw bad();
  const baseline = value.baseline;
  if (baseline !== null && (!digest(baseline?.baseline_digest) || baseline.non_owner !== "allowed" || baseline.owner !== "allowed" || !natural(baseline.record_count) || !digest(baseline.sha256))) throw bad();
  if (value.usage_state !== "settled" && value.allowed_operations.some(operation => operation === "rollback" || operation === "reset")) throw bad();
  if (value.status === "recovery_required" && (value.usage_state !== "settled" || value.allowed_operations.length !== 1 || value.allowed_operations[0] !== "reset")) throw bad();
  return value;
}
export function checkedFileAccessList(value: FileAccessControlList): FileAccessControlList {
  if (value?.schema_version !== "bluefire.file-access-control-list.v1" || !Array.isArray(value.controls)
    || new Set(value.controls.map(item => item.control_owner_id)).size !== value.controls.length
    || value.controls.some(item => !compositionJobValid(item.control_owner_id) || !controlStates.includes(item.status) || !natural(item.revision) || item.revision < 1)) throw bad();
  return value;
}
export function checkedFileAccessOperation(value: FileAccessOperationEnvelope, id: string, owner?: string): FileAccessOperationEnvelope {
  if (value?.schema_version !== "bluefire.file-access-operation.v1" || value.job?.job_id !== id || !compositionJobValid(id)
    || value.job.kind !== "file_access.operation" || typeof value.job.state !== "string") throw bad();
  const submitted = value.job.progress?.submitted_request as FileAccessSubmission;
  if (!fileAccessSubmissionValid(submitted) || compositionJobId(submitted.submission_id) !== id) throw bad();
  if (owner && (submitted.review.control_owner_id ?? id) !== owner) throw bad();
  if (value.reconciliation !== null && (!digest(value.reconciliation?.outcome_digest)
    || !["unknown", "complete", "refused_no_effect", "settled_partial"].includes(value.reconciliation.state)
    || typeof value.reconciliation.available !== "boolean" || (value.reconciliation.state !== "unknown" && value.reconciliation.available))) throw bad();
  if (value.job.progress.verified_observation !== undefined) {
    const observed = value.job.progress.verified_observation as FileAccessObservation;
    if (fileAccessJobActive(value.job) || (value.job.state !== "completed" && value.reconciliation?.state !== "complete")
      || (value.reconciliation !== null && value.reconciliation.state !== "complete")
      || observed?.schema_version !== "bluefire.file-access-control-observation.v1"
      || !["baseline", "rollback"].includes(observed.operation) || observed.operation !== submitted.review.operation
      || observed.non_owner !== "allowed" || observed.owner !== "allowed" || observed.mode !== "0640"
      || typeof observed.resource_generation !== "string" || !observed.resource_generation || !natural(observed.record_count) || observed.record_count < 1
      || !digest(observed.sha256) || !digest(observed.source_digest) || !Number.isSafeInteger(observed.observed_at_ms) || observed.observed_at_ms <= 0) throw bad();
  }
  if (value.control !== null) checkedFileAccessControl(value.control, submitted.review.control_owner_id ?? id);
  if (value.reconciliation_receipt !== null) checkedFileAccessReconciliationReceipt(value.reconciliation_receipt);
  return value;
}
export function checkedFileAccessReconciliationReceipt(value: FileAccessReconciliationReceipt): FileAccessReconciliationReceipt {
  if (!value || !reconciliationSubmissionValid(value.submitted_request) || value.submission_id !== value.submitted_request.submission_id
    || !["pending", "completed"].includes(value.state) || (value.problem !== null && (typeof value.problem?.code !== "string" || typeof value.problem?.message !== "string"))) throw bad();
  return value;
}
export function checkedFileAccessReconciliation(value: FileAccessReconciliationEnvelope, operation: string, submission: string): FileAccessReconciliationEnvelope {
  if (value?.schema_version !== "bluefire.file-access-reconciliation.v1" || value.operation_job_id !== operation || value.receipt?.submission_id !== submission) throw bad();
  checkedFileAccessReconciliationReceipt(value.receipt);
  return value;
}
function reconciliationSubmissionValid(value: FileAccessReconciliationSubmission): boolean {
  return Boolean(value && Object.keys(value).sort().join(",") === "expected_outcome_digest,reviewed_by,submission_id"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.submission_id)
    && digest(value.expected_outcome_digest) && typeof value.reviewed_by === "string" && value.reviewed_by.trim() && value.reviewed_by.length <= 128);
}
function fileAccessSubmissionValid(value: FileAccessSubmission): boolean {
  return Boolean(value && Object.keys(value).sort().join(",") === "review,review_digest,reviewed_by,submission_id"
    && typeof value.submission_id === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.submission_id)
    && fileAccessReviewRequestValid(value.review) && digest(value.review_digest)
    && typeof value.reviewed_by === "string" && value.reviewed_by.trim() && value.reviewed_by.length <= 128);
}
const pendingKey = "bluefire.file-access.pending.v1";
export function readFileAccessPending(): FileAccessPending | undefined {
  const raw = localStorage.getItem(pendingKey);
  if (!raw) return;
  if (raw.length > 100_000) throw new Error("The saved file-access request exceeds the recovery limit.");
  const value = JSON.parse(raw) as FileAccessPending;
  if (!value || Object.keys(value).sort().join(",") !== "body,id" || !fileAccessSubmissionValid(value.body) || value.id !== compositionJobId(value.body.submission_id)) throw new Error("The saved file-access request needs recovery. Nothing has been sent.");
  return value;
}
export function storeFileAccessPending(value: FileAccessPending) {
  if (!fileAccessSubmissionValid(value.body) || value.id !== compositionJobId(value.body.submission_id)) throw bad();
  const previous = readFileAccessPending();
  if (previous && !sameJson(previous, value)) throw new Error("Reconcile the original file-access request before another operation.");
  const raw = JSON.stringify(value);
  localStorage.setItem(pendingKey, raw);
  if (localStorage.getItem(pendingKey) !== raw) throw new Error("The exact operation could not be retained. Nothing was sent.");
}
export function clearFileAccessPending(value: FileAccessPending) {
  if (!sameJson(readFileAccessPending(), value)) throw new Error("The pending file-access request changed in another tab.");
  localStorage.removeItem(pendingKey);
}
export function fileAccessConfirmed(value: FileAccessOperationEnvelope, pending: FileAccessPending) {
  return value.job.job_id === pending.id && sameJson(value.job.progress.submitted_request, pending.body);
}
async function post<T>(path: string, body: unknown): Promise<T> {
  if (DEMO_MODE) throw new Error("Effective file access requires an explicitly enrolled Linux session. Demo mode cannot execute it.");
  return request<T>(`/file-access/${path}`, { method: "POST", body: JSON.stringify(body) });
}
export const fileAccessApi = {
  review: (body: FileAccessReviewRequest) => post<FileAccessReview>("review", body),
  status: () => request<FileAccessStatus>("/file-access/status"),
  list: () => post<FileAccessControlList>("control-list", {}),
  control: (id: string) => request<FileAccessControl>(`/file-access/controls/${encodeURIComponent(id)}`),
  operation: (id: string) => request<FileAccessOperationEnvelope>(`/file-access/operations/${encodeURIComponent(id)}`),
  submit: (body: FileAccessSubmission) => post<FileAccessOperationEnvelope>("operations", body),
  reconcile: (id: string, body: FileAccessReconciliationSubmission) => post<FileAccessOperationEnvelope>(`operations/${encodeURIComponent(id)}/reconcile`, body),
  reconciliation: (id: string, submission: string) => request<FileAccessReconciliationEnvelope>(`/file-access/operations/${encodeURIComponent(id)}/reconciliations/${encodeURIComponent(submission)}`),
};
export interface FileAccessReconciliationPending { operation_job_id: string; control_owner_id: string; body: FileAccessReconciliationSubmission }
const reconciliationKey = "bluefire.file-access.reconciliation.v1";
export function readFileAccessReconciliationPending(): FileAccessReconciliationPending | undefined {
  const raw = localStorage.getItem(reconciliationKey);
  if (!raw) return;
  if (raw.length > 100_000) throw new Error("The retained reconciliation request exceeds the recovery limit.");
  const value = JSON.parse(raw) as FileAccessReconciliationPending;
  if (!value || Object.keys(value).sort().join(",") !== "body,control_owner_id,operation_job_id" || !compositionJobValid(value.operation_job_id)
    || !compositionJobValid(value.control_owner_id) || !reconciliationSubmissionValid(value.body)) throw new Error("The saved evidence request needs recovery. Nothing was sent.");
  return value;
}
export function storeFileAccessReconciliationPending(value: FileAccessReconciliationPending) {
  if (!compositionJobValid(value.operation_job_id) || !compositionJobValid(value.control_owner_id) || !reconciliationSubmissionValid(value.body)) throw bad();
  const previous = readFileAccessReconciliationPending();
  if (previous && !sameJson(previous, value)) throw new Error("Reconcile the original evidence request before another request.");
  const raw = JSON.stringify(value); localStorage.setItem(reconciliationKey, raw);
  if (localStorage.getItem(reconciliationKey) !== raw) throw new Error("The exact evidence request could not be retained. Nothing was sent.");
}
export function clearFileAccessReconciliationPending(value: FileAccessReconciliationPending) {
  if (!sameJson(readFileAccessReconciliationPending(), value)) throw new Error("The pending evidence request changed in another tab.");
  localStorage.removeItem(reconciliationKey);
}
export function fileAccessReconciliationConfirmed(value: FileAccessReconciliationReceipt, pending: FileAccessReconciliationPending): boolean {
  return value.submission_id === pending.body.submission_id && value.state === "completed" && sameJson(value.submitted_request, pending.body);
}
