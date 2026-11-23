import { DEMO_MODE, request } from "./api";
import { s3JobId, validS3Job, validS3Run } from "./s3-access";
import { checkedAuditSourceDescriptor as checkedCollectionSource, checkedExecutionReceipt as checkedCollectionReceipt, checkedOriginalPair as checkedCollectionPair, type AuditExecutionReceipt, type AuditOriginalPair, type AuditSourceDescriptor } from "./s3-audit-collection";

export const auditDelivery = ["unknown", "incomplete", "truncated", "complete"] as const;
export type AuditDelivery = typeof auditDelivery[number];
export const auditStatuses = ["matched", "conflict", "worker_unreported", "truncated", "unknown", "awaiting_delivery", "missing"] as const;
export type AuditStatus = typeof auditStatuses[number];
export interface AuditSource { run_id: string; operation_job_id: string; phase: "baseline" | "retest"; reader: "probe" | "legitimate"; request_digest: string; worker_result_digest: string; outcome_digest: string; provenance: "synthetic" | "runner_reported"; cleanup: "verified" | "unknown" }
export interface AuditSummary { review_id: string; created_at: string; review_digest: string; source: AuditSource; reported_delivery_state: AuditDelivery; statuses: AuditStatus[] }
export interface AuditHistoryV1 { schema_version: "bluefire.s3-audit-reviews.v1"; workflow_job_id: string; reads: AuditSource[]; reviews: AuditSummary[]; maximum_reviews: 32; maximum_input_bytes: 524288; maximum_expanded_bytes: 1048576; collection_provenance: "operator_import"; independent_collection_proven: false }
export interface AuditCollectionSummary { review_id: string; created_at: string; review_digest: string; phase: "baseline" | "retest"; collection_run_id: string; original_run_ids: [string, string]; reported_delivery_state: Exclude<AuditDelivery, "complete">; statuses: [AuditStatus, AuditStatus, AuditStatus]; collection_provenance: "authenticated_source_retrieval" }
export interface AuditHistoryV2 { schema_version: "bluefire.s3-audit-reviews.v2"; workflow_job_id: string; reads: AuditSource[]; reviews: AuditSummary[]; maximum_reviews: 32; maximum_input_bytes: 524288; maximum_expanded_bytes: 1048576; collections: AuditCollectionSummary[]; maximum_collections: 2 }
export type AuditHistory = AuditHistoryV1 | AuditHistoryV2;
export interface AuditRead { purpose: "primary" | "health"; reader: "probe" | "legitimate"; status: AuditStatus; worker_outcome: string; worker_request_id: string | null; audit_event_ids: string[]; audit_outcomes: string[]; full_object_bytes_proven: false }
export interface AuditImportReview { input_digest: string; schema_version: "bluefire.s3-audit-review.v1"; workflow_job_id: string; review_id: string; created_at: string; review_digest: string; source: AuditSource; imports: Array<{ encoding: "json" | "gzip"; sha256: string; size_bytes: number; expanded_bytes: number }>; collection_provenance: "operator_import"; independent_collection_proven: false; effective_access_claim: false; raw_bytes_retained: false; correlation: { schema_version: "bluefire.s3-audit-correlation.v1"; request_digest: string; worker_result_digest: string; independent_collection_proven: false; effective_access_claim: false; reads: AuditRead[]; authorized_request_window: { from: string; through: string }; audit: { schema_version: "bluefire.s3-audit-projection.v1"; scope_digest: string; reported_delivery_state: AuditDelivery; source_bytes: number; source_event_count: number; sources: Array<{ sha256: string; size_bytes: number; event_count: number }>; events: unknown[]; counts: { excluded: number; unknown: number; duplicates: number }; independent_collection_proven: false; effective_access_claim: false } } }
export type AuditReview = AuditImportReview;
export interface AuditCollectedCorrelation extends Record<string, unknown> {
  schema_version: "bluefire.s3-audit-correlation.v1";
  request_digest: string;
  worker_result_digest: string;
  reads: AuditRead[];
  authorized_request_window: { from: string; through: string };
  independent_collection_proven: false;
  effective_access_claim: false;
}
export interface AuditCollectedObservation extends Record<string, unknown> {
  schema_version: "bluefire.s3-audit-collection-observation.v1";
  collection_digest: string;
  pair_digest: string;
  audit_source_digest: string;
  reservation_digest: string;
  delivery_state: Exclude<AuditDelivery, "complete">;
  normalized_digest: string;
  usage: Record<string, number>;
  objects: Array<{ selected_index: number; compressed_sha256: string; expanded_sha256: string; expanded_bytes: number; event_count: number }>;
  discovery: { schema_version: "bluefire.s3-audit-discovery.v1"; request_digest: string; collection_digest: string; pair_digest: string; reservation_digest: string; audit_source_digest: string; resource_key: string; phase: "baseline" | "retest"; frame_digest: string; prefixes: Array<[string, string]>; listings: Array<{ request_id: string; body_sha256: string; projection_digest: string; key_count: number; is_truncated: boolean }>; completed_list_count: number; next_send_sequence: number; candidate_count: number; selected: Array<{ key: string; etag: string; size_bytes: number }>; truncated: boolean };
  correlations: { probe: AuditCollectedCorrelation; legitimate: AuditCollectedCorrelation };
  effective_access_claim: false;
  log_integrity_proven: false;
}
export interface AuditCollectedReview { schema_version: "bluefire.s3-audit-collected-review.v1"; workflow_job_id: string; operation_job_id: string; phase: "baseline" | "retest"; collection_run_id: string; manifest_digest: string; request_digest: string; worker_result_digest: string; reservation_digest: string; outcome_digest: string; source: AuditSourceDescriptor; original_pair: AuditOriginalPair; receipt: AuditExecutionReceipt & { result: { data: AuditCollectedObservation } }; collection_provenance: "authenticated_source_retrieval"; raw_bytes_retained: false; log_integrity_proven: false; effective_access_claim: false; review_digest: string; review_id: string; created_at: string }
export type SavedAuditReview = AuditImportReview | AuditCollectedReview;
export interface AuditInput { submission_id: string; run_id: string; delivery_state: AuditDelivery; logs: Array<{ encoding: "json" | "gzip"; data: string }> }
export interface AuditPending { owner: string; submission_id: string; run_id: string; delivery_state: AuditDelivery; input_digest: string }
const fail = () => new Error("The saved audit review is incomplete or belongs to different work.");
const record = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const keys = (v: unknown, fields: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v, k));
const hash = (v: unknown) => typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v);
const digest = (v: unknown) => hash(v);
const correlationTime = (v: unknown) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00$/.test(v) && Number.isFinite(Date.parse(v));
const integer = (v: unknown, max: number) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= max;
const time = (v: unknown) => typeof v === "string" && v.length <= 40 && Number.isFinite(Date.parse(v));
const validAuditRun = (v: unknown) => typeof v === "string" && /^run-\d{8}T\d{6}Z-[0-9a-f]{16}$/.test(v) && Number.isFinite(Date.parse(`${v.slice(4, 8)}-${v.slice(8, 10)}-${v.slice(10, 12)}T${v.slice(13, 15)}:${v.slice(15, 17)}:${v.slice(17, 19)}Z`));
const uuid = (v: unknown) => typeof v === "string" && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(v);
const unique = (values: unknown[]) => new Set(values).size === values.length;
const sourceKeys = ["run_id", "operation_job_id", "phase", "reader", "request_digest", "worker_result_digest", "outcome_digest", "provenance", "cleanup"];
function source(v: AuditSource) { return keys(v, sourceKeys) && validS3Run(v.run_id) && validS3Job(v.operation_job_id) && ["baseline", "retest"].includes(v.phase) && ["probe", "legitimate"].includes(v.reader) && hash(v.request_digest) && hash(v.worker_result_digest) && hash(v.outcome_digest) && ["synthetic", "runner_reported"].includes(v.provenance) && ["verified", "unknown"].includes(v.cleanup); }
function statuses(v: unknown): v is AuditStatus[] { return Array.isArray(v) && v.length >= 1 && v.length <= 2 && v.every(s => auditStatuses.includes(s)); }
const sameSource = (a: AuditSource, b: AuditSource) => sourceKeys.every(key => a[key as keyof AuditSource] === b[key as keyof AuditSource]);

export function checkedAuditHistory(v: AuditHistory, owner: string): AuditHistory {
  if (!record(v) || !validS3Job(owner) || v.workflow_job_id !== owner || v.maximum_reviews !== 32 || v.maximum_input_bytes !== 524288 || v.maximum_expanded_bytes !== 1048576 || !Array.isArray(v.reads) || v.reads.length > 300 || !v.reads.every(source) || !unique(v.reads.map(r => r.run_id)) || !Array.isArray(v.reviews) || v.reviews.length > 32 || !unique(v.reviews.map(r => r?.review_id))) throw fail();
  if (v.reviews.some(r => !keys(r, ["review_id", "created_at", "review_digest", "source", "reported_delivery_state", "statuses"]) || !validS3Job(r.review_id) || !time(r.created_at) || !hash(r.review_digest) || !source(r.source) || !v.reads.some(s => sameSource(s, r.source)) || !auditDelivery.includes(r.reported_delivery_state) || !statuses(r.statuses) || r.statuses.length !== (r.source.reader === "probe" ? 1 : 2))) throw fail();
  if (v.schema_version === "bluefire.s3-audit-reviews.v1") {
    if (!keys(v, ["schema_version", "workflow_job_id", "reads", "reviews", "maximum_reviews", "maximum_input_bytes", "maximum_expanded_bytes", "collection_provenance", "independent_collection_proven"]) || v.collection_provenance !== "operator_import" || v.independent_collection_proven !== false) throw fail();
    return v;
  }
  if (!keys(v, ["schema_version", "workflow_job_id", "reads", "reviews", "maximum_reviews", "maximum_input_bytes", "maximum_expanded_bytes", "collections", "maximum_collections"]) || v.schema_version !== "bluefire.s3-audit-reviews.v2" || v.maximum_collections !== 2 || !Array.isArray(v.collections) || v.collections.length > 2 || !unique([...v.reviews.map(row => row.review_id), ...v.collections.map(row => row?.review_id)]) || !unique(v.collections.map(row => row?.phase))) throw fail();
  if (v.collections.some(row => !keys(row, ["review_id", "created_at", "review_digest", "phase", "collection_run_id", "original_run_ids", "reported_delivery_state", "statuses", "collection_provenance"]) || !validS3Job(row.review_id) || !time(row.created_at) || !hash(row.review_digest) || !["baseline", "retest"].includes(row.phase) || !validAuditRun(row.collection_run_id) || !Array.isArray(row.original_run_ids) || row.original_run_ids.length !== 2 || !row.original_run_ids.every(validAuditRun) || row.original_run_ids[0] === row.original_run_ids[1] || row.collection_run_id === row.original_run_ids[0] || row.collection_run_id === row.original_run_ids[1] || !["unknown", "incomplete", "truncated"].includes(row.reported_delivery_state) || !Array.isArray(row.statuses) || row.statuses.length !== 3 || !row.statuses.every(status => auditStatuses.includes(status)) || row.collection_provenance !== "authenticated_source_retrieval")) throw fail();
  return v;
}

export function checkedAuditReview(v: AuditReview, owner: string, id: string): AuditReview {
  if (!keys(v, ["input_digest", "schema_version", "workflow_job_id", "review_id", "created_at", "review_digest", "source", "imports", "collection_provenance", "independent_collection_proven", "effective_access_claim", "raw_bytes_retained", "correlation"]) || !validS3Job(owner) || !validS3Job(id) || v.workflow_job_id !== owner || v.review_id !== id || v.schema_version !== "bluefire.s3-audit-review.v1" || !hash(v.input_digest) || !time(v.created_at) || !hash(v.review_digest) || !source(v.source) || v.collection_provenance !== "operator_import" || v.independent_collection_proven !== false || v.effective_access_claim !== false || v.raw_bytes_retained !== false) throw fail();
  const c = v.correlation, a = c?.audit;
  if (!keys(c, ["schema_version", "request_digest", "worker_result_digest", "independent_collection_proven", "effective_access_claim", "reads", "authorized_request_window", "audit"]) || c.schema_version !== "bluefire.s3-audit-correlation.v1" || c.request_digest !== v.source.request_digest || c.worker_result_digest !== v.source.worker_result_digest || c.independent_collection_proven !== false || c.effective_access_claim !== false || !keys(c.authorized_request_window, ["from", "through"]) || !correlationTime(c.authorized_request_window.from) || !correlationTime(c.authorized_request_window.through) || Date.parse(c.authorized_request_window.from) > Date.parse(c.authorized_request_window.through) || !Array.isArray(c.reads) || c.reads.length !== (v.source.reader === "probe" ? 1 : 2) || !unique(c.reads.map(r => r?.purpose))) throw fail();
  const outcomes = ["unreported", "service_success", "service_denied", "object_missing", "bucket_missing", "credential_error", "other_service_error"];
  if (c.reads.some(r => !keys(r, ["purpose", "reader", "status", "worker_outcome", "worker_request_id", "audit_event_ids", "audit_outcomes", "full_object_bytes_proven"]) || !["primary", "health"].includes(r.purpose) || (r.reader === "probe" && r.purpose !== "primary") || r.reader !== v.source.reader || !auditStatuses.includes(r.status) || !outcomes.includes(r.worker_outcome) || (r.worker_request_id !== null && (typeof r.worker_request_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9+/=_:.-]{0,127}$/.test(r.worker_request_id))) || !Array.isArray(r.audit_event_ids) || r.audit_event_ids.length > 1000 || !r.audit_event_ids.every(x => typeof x === "string" && /^[0-9a-fA-F-]{36}$/.test(x)) || !unique(r.audit_event_ids) || !Array.isArray(r.audit_outcomes) || r.audit_outcomes.length > 7 || !r.audit_outcomes.every(x => outcomes.includes(x)) || r.full_object_bytes_proven !== false)) throw fail();
  if (!keys(a, ["schema_version", "scope_digest", "reported_delivery_state", "source_bytes", "source_event_count", "sources", "events", "counts", "independent_collection_proven", "effective_access_claim"]) || a.schema_version !== "bluefire.s3-audit-projection.v1" || !hash(a.scope_digest) || !auditDelivery.includes(a.reported_delivery_state) || !integer(a.source_bytes, 1048576) || !integer(a.source_event_count, 1000) || !keys(a.counts, ["excluded", "unknown", "duplicates"]) || !Object.values(a.counts).every(n => integer(n, a.source_event_count)) || !Array.isArray(a.events) || a.events.length > a.source_event_count || a.independent_collection_proven !== false || a.effective_access_claim !== false || !Array.isArray(a.sources) || !Array.isArray(v.imports) || v.imports.length < 1 || v.imports.length > 4 || v.imports.length !== a.sources.length) throw fail();
  if (v.imports.some((r, i) => !keys(r, ["encoding", "sha256", "size_bytes", "expanded_bytes"]) || !["json", "gzip"].includes(r.encoding) || !hash(r.sha256) || !integer(r.size_bytes, 524288) || !integer(r.expanded_bytes, 1048576) || !keys(a.sources[i], ["sha256", "size_bytes", "event_count"]) || !hash(a.sources[i]!.sha256) || a.sources[i]!.size_bytes !== r.expanded_bytes || !integer(a.sources[i]!.event_count, 1000)) || v.imports.reduce((n, r) => n + r.size_bytes, 0) > 524288 || v.imports.reduce((n, r) => n + r.expanded_bytes, 0) !== a.source_bytes || a.sources.reduce((n, r) => n + r.event_count, 0) !== a.source_event_count) throw fail();
  return v;
}

function utcMicroseconds(value: unknown): bigint {
  if (typeof value !== "string") throw fail();
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(?:Z|\+00:00)$/.exec(value);
  if (!match) throw fail();
  const seconds = Date.parse(`${match[1]}Z`);
  if (!Number.isFinite(seconds) || new Date(seconds).toISOString().slice(0, 19) !== match[1]) throw fail();
  // Retain microseconds when joining Python timestamps, rather than rounding to milliseconds.
  return BigInt(seconds) * 1000n + BigInt((match[2] ?? "").padEnd(6, "0"));
}

export function checkedCollectedAuditReview(v: AuditCollectedReview, owner: string, id: string): AuditCollectedReview {
  const fields = ["schema_version", "workflow_job_id", "operation_job_id", "phase", "collection_run_id", "manifest_digest", "request_digest", "worker_result_digest", "reservation_digest", "outcome_digest", "source", "original_pair", "receipt", "collection_provenance", "raw_bytes_retained", "log_integrity_proven", "effective_access_claim", "review_digest", "review_id", "created_at"];
  if (!keys(v, fields) || !validS3Job(owner) || !validS3Job(id) || v.schema_version !== "bluefire.s3-audit-collected-review.v1" || v.workflow_job_id !== owner || v.review_id !== id || v.operation_job_id !== id || !["baseline", "retest"].includes(v.phase) || !validAuditRun(v.collection_run_id) || ![v.manifest_digest, v.request_digest, v.worker_result_digest, v.reservation_digest, v.outcome_digest, v.review_digest].every(digest) || !time(v.created_at) || v.collection_provenance !== "authenticated_source_retrieval" || v.raw_bytes_retained !== false || v.log_integrity_proven !== false || v.effective_access_claim !== false) throw fail();
  const sourceValue = checkedCollectionSource(v.source);
  checkedCollectionPair(v.original_pair, sourceValue, owner, v.phase);
  const pair = v.original_pair;
  checkedCollectionReceipt(v.receipt, v);
  const reads = pair.reads;
  const probeRead = reads[0];
  const legitimateRead = reads[1];
  if (!probeRead || !legitimateRead) throw fail();
  const data: AuditCollectedObservation = v.receipt.result.data;
  const discovery = data.discovery;
  if (discovery.phase !== v.phase || probeRead.reader !== "probe" || legitimateRead.reader !== "legitimate" || v.operation_job_id === owner || v.operation_job_id === pair.operation_job_id || v.collection_run_id === probeRead.run_id || v.collection_run_id === legitimateRead.run_id || data.pair_digest !== discovery.pair_digest || data.audit_source_digest !== discovery.audit_source_digest) throw fail();
  const prefixRoot = sourceValue.exact_delivery_root_prefix;
  const accountRegionPrefix = `${sourceValue.source_account_id}_CloudTrail_${sourceValue.event_region}_`;
  const prefixes = discovery.prefixes;
  if (prefixes.some(([prefix, cursor]) => {
    const datePart = prefix.slice(prefixRoot.length);
    const cursorPart = cursor.slice((prefix + accountRegionPrefix).length);
    return !prefix.startsWith(prefixRoot) || !/^\d{4}\/\d{2}\/\d{2}\/$/.test(datePart) || !cursor.startsWith(prefix + accountRegionPrefix) || !/^\d{8}T\d{4}Z_$/.test(cursorPart) || cursor.length > 512;
  })) throw fail();
  const selected = discovery.selected;
  if (selected.some(row => !prefixes.some(([prefix]) => row.key.startsWith(prefix)))) throw fail();
  const correlations = data.correlations;
  for (const [index, reader] of (["probe", "legitimate"] as const).entries()) {
    const original = index === 0 ? probeRead : legitimateRead;
    const correlation = correlations[reader];
    const originalCalls = original.result.calls;
    const rows = correlation.reads;
    const originalScope = original.request.scope as { created_at: string; limits: { request_seconds: number } };
    const deadline = utcMicroseconds(original.request.deadline);
    const issued = deadline - BigInt(originalScope.limits.request_seconds) * 1000000n;
    const created = utcMicroseconds(originalScope.created_at);
    if (utcMicroseconds(correlation.authorized_request_window.through) !== deadline || utcMicroseconds(correlation.authorized_request_window.from) !== (created > issued ? created : issued)) throw fail();
    if (correlation.request_digest !== original.request_digest || correlation.worker_result_digest !== original.worker_result_digest || rows.length !== (index === 0 ? 1 : 2) || rows.some((row, readIndex) => {
      const call = originalCalls[readIndex + 3];
      if (!call) return row.worker_request_id !== null || row.worker_outcome !== "unreported" || row.status !== "worker_unreported" || row.audit_event_ids.length !== 0 || row.audit_outcomes.length !== 0;
      const workerOutcome = call.error_code === undefined ? "service_success" : call.error_code === "AccessDenied" ? "service_denied" : call.error_code === "NoSuchKey" ? "object_missing" : call.error_code === "NoSuchBucket" ? "bucket_missing" : ["ExpiredToken", "InvalidToken", "InvalidAccessKeyId", "SignatureDoesNotMatch", "RequestExpired", "AuthorizationHeaderMalformed"].includes(call.error_code) ? "credential_error" : "other_service_error";
      if (row.worker_request_id !== call.request_id || row.worker_outcome !== workerOutcome) return true;
      if (row.audit_event_ids.length) return !["matched", "conflict"].includes(row.status) || !row.audit_outcomes.length || (row.status === "matched" && (row.audit_outcomes.length !== 1 || row.audit_outcomes[0] !== workerOutcome));
      const absenceStatuses = data.delivery_state === "truncated" ? ["truncated"] : data.delivery_state === "unknown" ? ["unknown"] : ["awaiting_delivery", "unknown"];
      return row.audit_outcomes.length > 0 || !absenceStatuses.includes(row.status);
    })) throw fail();
  }
  return v;
}

const pendingKey = (owner: string) => `bluefire.s3.audit.pending.v1.${owner}`;
function checkedPending(v: AuditPending, owner: string) { if (!keys(v, ["owner", "submission_id", "run_id", "delivery_state", "input_digest"]) || !validS3Job(owner) || v.owner !== owner || !uuid(v.submission_id) || !validS3Run(v.run_id) || !auditDelivery.includes(v.delivery_state) || !hash(v.input_digest)) throw fail(); return v; }
export function readAuditPending(owner: string): AuditPending | null { const raw = localStorage.getItem(pendingKey(owner)); if (!raw) return null; if (raw.length > 1000) throw fail(); return checkedPending(JSON.parse(raw) as AuditPending, owner); }
export function saveAuditPending(value: AuditPending) { checkedPending(value, value.owner); const old = readAuditPending(value.owner); if (old && JSON.stringify(old) !== JSON.stringify(value)) throw fail(); localStorage.setItem(pendingKey(value.owner), JSON.stringify(value)); }
export function clearAuditPending(value: AuditPending) { const old = readAuditPending(value.owner); if (old && JSON.stringify(old) !== JSON.stringify(value)) throw fail(); localStorage.removeItem(pendingKey(value.owner)); }
export async function auditInputDigest(value: AuditInput) { const bytes = new TextEncoder().encode(JSON.stringify({ delivery_state: value.delivery_state, logs: value.logs.map(log => ({ data: log.data, encoding: log.encoding })), run_id: value.run_id, submission_id: value.submission_id })); const digest = await crypto.subtle.digest("SHA-256", bytes); return "sha256:" + Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join(""); }
export async function auditFiles(files: File[]): Promise<AuditInput["logs"]> {
  if (files.length < 1 || files.length > 4 || files.reduce((n, f) => n + f.size, 0) > 524288 || files.some(f => !f.size || !/\.(json|gz)$/i.test(f.name))) throw new Error("Select one to four JSON or gzip files, totaling at most 512 KiB.");
  const result: AuditInput["logs"] = [];
  for (const file of files) { const bytes = new Uint8Array(await file.arrayBuffer()); let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); result.push({ encoding: /\.gz$/i.test(file.name) ? "gzip" : "json", data: btoa(binary) }); }
  return result;
}
function path(owner: string, id?: string) { if (!validS3Job(owner) || (id !== undefined && !validS3Job(id))) throw fail(); if (DEMO_MODE) throw new Error("Saved audit reviews are unavailable in demo mode."); return `/s3-access/exercises/${owner}/audit-reviews${id ? `/${id}` : ""}`; }
export const s3AuditApi = {
  list: async (owner: string) => checkedAuditHistory(await request<AuditHistory>(path(owner)), owner),
  read: async (owner: string, id: string): Promise<SavedAuditReview> => {
    const value = await request<unknown>(path(owner, id));
    if (record(value) && value.schema_version === "bluefire.s3-audit-collected-review.v1") return checkedCollectedAuditReview(value as unknown as AuditCollectedReview, owner, id);
    return checkedAuditReview(value as AuditImportReview, owner, id);
  },
  save: async (owner: string, value: AuditInput) => checkedAuditReview(await request<AuditImportReview>(path(owner), { method: "POST", body: JSON.stringify(value) }), owner, s3JobId(value.submission_id)),
};
