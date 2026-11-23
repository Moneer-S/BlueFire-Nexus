import { checkedAuditSourceDescriptor, checkedOriginalPair, type AuditOriginalPair, type AuditSourceDescriptor } from "./s3-audit-collection";
import type { S3Exercise } from "./s3-access";

export const auditPhases = ["audit_baseline", "audit_retest"] as const;
export type AuditPhase = typeof auditPhases[number];
export const isAuditPhase = (value: string): value is AuditPhase => (auditPhases as readonly string[]).includes(value);
export const auditBudgetKeys = ["api_calls", "sessions", "files", "sdk_body_bytes", "compressed_bytes", "expanded_bytes", "events", "seconds"] as const;
const workflowKeys = [...auditBudgetKeys, "batches", "wire_plus_expansion_bytes"];
const reasons = ["source_changed", "profile_changed", "runtime_changed", "environment_changed", "runtime_unavailable", "access_reference_absent", "access_reference_expired", "scope_expired", "source_expired", "host_unavailable", "original_interval_expired", "budget_exhausted", "historical_authority_absent", "phase_consumed", "stopped", "operation_pending", "cleanup_unknown", "original_pair_unavailable", "collection_not_enabled"] as const;
export interface AuditSlot { phase: "baseline" | "retest"; stage: AuditPhase; state: "unavailable" | "ready" | "reserved" | "completed" | "failed"; problem: typeof reasons[number] | null; operation_job_id: string | null; review_id: string | null; original_pair: AuditOriginalPair | null }
export interface AuditWorkspace { schema_version: "bluefire.s3-audit-workspace.v1"; source: AuditSourceDescriptor; source_digest: string; workflow_digest: string; budget: { per_batch: Record<string, number>; workflow: Record<string, number> }; reserved: Record<string, number>; held: Record<string, number>; slots: [AuditSlot, AuditSlot] }
export interface AuditStageReview { schema_version: "bluefire.s3-audit-stage-review.v1"; source: AuditSourceDescriptor; source_digest: string; original_pair: AuditOriginalPair; pair_digest: string; listing_date: string; collection_expires_at: string; list_parameters: Array<{ Bucket: string; ExpectedBucketOwner: string; Prefix: string; StartAfter: string; MaxKeys: 16 }> }
const fail = () => new Error("The saved audit collection scope or paired evidence is incomplete.");
const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, fields: readonly string[]): value is Record<string, unknown> => record(value) && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
const integer = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const hash = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const job = (value: unknown) => typeof value === "string" && /^job-[0-9a-f]{32}$/.test(value);
const budget = (value: unknown, fields: readonly string[]): value is Record<string, number> => exact(value, fields) && fields.every(key => integer(value[key]));
export function sameAuditValue(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right)) return left.length === right.length && left.every((item, index) => sameAuditValue(item, right[index]));
  return record(left) && record(right) && Object.keys(left).length === Object.keys(right).length && Object.keys(left).every(key => Object.hasOwn(right, key) && sameAuditValue(left[key], right[key]));
}

export function checkedAuditWorkspace(value: unknown, exercise: S3Exercise): AuditWorkspace {
  if (!exact(value, ["schema_version", "source", "source_digest", "workflow_digest", "budget", "reserved", "held", "slots"]) || value.schema_version !== "bluefire.s3-audit-workspace.v1" || !hash(value.source_digest) || !hash(value.workflow_digest) || !exact(value.budget, ["per_batch", "workflow"]) || !budget(value.budget.per_batch, auditBudgetKeys) || !budget(value.budget.workflow, workflowKeys) || !budget(value.reserved, workflowKeys) || !budget(value.held, workflowKeys) || !Array.isArray(value.slots) || value.slots.length !== 2) throw fail();
  const source = checkedAuditSourceDescriptor(value.source);
  const scope = exercise.environment.scope;
  if (!sameAuditValue(source, exercise.environment.audit_source) || source.source_account_id !== scope.account_id || source.event_region !== scope.region || Date.parse(source.expires_at) > Date.parse(scope.expires_at)) throw fail();
  const per = value.budget.per_batch;
  const total = value.budget.workflow;
  const reserved = value.reserved;
  const held = value.held;
  const limits = scope.limits;
  if (!["api_calls", "sessions", "audit_events", "audit_bytes", "request_seconds", "audit_seconds"].every(key => integer(limits[key]) && limits[key]! > 0)) throw fail();
  const expected = { ...source.audit_limits };
  expected.api_calls = Math.min(expected.api_calls!, Math.floor(limits.api_calls! / 2));
  expected.sessions = Math.min(expected.sessions!, Math.floor(limits.sessions! / 2));
  expected.events = Math.min(expected.events!, Math.floor(limits.audit_events! / 2));
  expected.seconds = Math.min(expected.seconds!, limits.request_seconds!, Math.floor(limits.audit_seconds! / 2));
  expected.sdk_body_bytes = Math.min(expected.sdk_body_bytes!, Math.floor(limits.audit_bytes! / 2));
  expected.expanded_bytes = Math.min(expected.expanded_bytes!, Math.floor(limits.audit_bytes! / 2));
  expected.compressed_bytes = Math.min(expected.compressed_bytes!, expected.sdk_body_bytes, expected.files! * 65536);
  if (!sameAuditValue(per, expected) || per.api_calls !== 9 || per.sessions !== 1 || auditBudgetKeys.some(key => per[key]! <= 0 || total[key] !== per[key]! * 2) || total.batches !== 2 || total.wire_plus_expansion_bytes !== total.sdk_body_bytes! + total.expanded_bytes! || total.wire_plus_expansion_bytes! > limits.audit_bytes!) throw fail();
  const claimed = new Set<string>();
  const originalRuns = new Set<string>();
  const slots = value.slots.map((raw, index) => {
    const phase = index === 0 ? "baseline" : "retest";
    const stage = auditPhases[index]!;
    if (!exact(raw, ["phase", "stage", "state", "problem", "operation_job_id", "review_id", "original_pair"]) || raw.phase !== phase || raw.stage !== stage || !["unavailable", "ready", "reserved", "completed", "failed"].includes(String(raw.state)) || (raw.problem !== null && !(reasons as readonly unknown[]).includes(raw.problem))) throw fail();
    const used = ["reserved", "completed", "failed"].includes(String(raw.state));
    if (used) {
      if (!job(raw.operation_job_id) || raw.operation_job_id === exercise.workflow_job_id || claimed.has(String(raw.operation_job_id)) || raw.problem !== "phase_consumed" || raw.review_id !== (raw.state === "completed" ? raw.operation_job_id : null)) throw fail();
      claimed.add(String(raw.operation_job_id));
      const operation = exercise.operations.find(row => row.operation_job_id === raw.operation_job_id);
      if (raw.state === "reserved" ? operation !== undefined || exercise.active_job?.job_id !== raw.operation_job_id || exercise.active_job?.request.s3_access.phase !== stage : !operation || operation.phase !== stage || (raw.state === "completed") !== (operation.outcome.state === "observed")) throw fail();
    } else if (raw.operation_job_id !== null || raw.review_id !== null || (raw.state === "ready" ? raw.problem !== null || raw.original_pair === null : raw.problem === null)) throw fail();
    if (raw.original_pair !== null) {
      const pair = checkedOriginalPair(raw.original_pair, source, exercise.workflow_job_id, phase);
      const original = exercise.operations.find(row => row.operation_job_id === pair.operation_job_id);
      if (!original || original.phase !== phase || original.outcome_digest !== pair.outcome_digest || original.review_digest !== pair.review_digest || original.outcome.cleanup !== "verified" || original.outcome.provenance !== "runner_reported" || !sameAuditValue(original.run_ids, pair.reads.map(read => read.run_id)) || pair.reads.some(read => !sameAuditValue(read.request.scope, scope) || originalRuns.has(read.run_id))) throw fail();
      pair.reads.forEach(read => originalRuns.add(read.run_id));
    } else if (raw.state === "ready") throw fail();
    if (exercise.allowed_phases.includes(stage) && (raw.state !== "ready" || raw.problem !== null)) throw fail();
    return raw as unknown as AuditSlot;
  });
  if (workflowKeys.some(key => reserved[key] !== total[key]! * claimed.size / 2 || held[key] !== total[key]! - reserved[key]!)) throw fail();
  if (exercise.operations.some(row => isAuditPhase(row.phase) && !claimed.has(row.operation_job_id)) || (exercise.audit === "authenticated_retrieval") !== exercise.operations.some(row => isAuditPhase(row.phase) && row.outcome.audit === "authenticated_retrieval")) throw fail();
  return { ...value, source, slots } as AuditWorkspace;
}

export function checkedAuditStageReview(value: unknown, owner: string, phase: AuditPhase): AuditStageReview {
  if (!exact(value, ["schema_version", "source", "source_digest", "original_pair", "pair_digest", "listing_date", "collection_expires_at", "list_parameters"]) || value.schema_version !== "bluefire.s3-audit-stage-review.v1" || !hash(value.source_digest) || !hash(value.pair_digest) || typeof value.listing_date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value.listing_date) || typeof value.collection_expires_at !== "string" || !Number.isFinite(Date.parse(value.collection_expires_at)) || !Array.isArray(value.list_parameters)) throw fail();
  const source = checkedAuditSourceDescriptor(value.source);
  const pair = checkedOriginalPair(value.original_pair, source, owner, phase === "audit_baseline" ? "baseline" : "retest");
  const scope = pair.reads[0].request.scope;
  if (!record(scope) || !record(scope.limits) || typeof scope.created_at !== "string" || !integer(scope.limits.request_seconds) || !integer(scope.limits.audit_seconds) || !sameAuditValue(scope, pair.reads[1].request.scope)) throw fail();
  const created = Date.parse(scope.created_at);
  const requestSeconds = scope.limits.request_seconds;
  const auditSeconds = scope.limits.audit_seconds;
  const starts = pair.reads.map(read => Math.max(created, Date.parse(String(read.request.deadline)) - requestSeconds * 1000));
  const start = Math.min(...starts);
  const expiry = Math.min(Date.parse(source.expires_at), start + auditSeconds * 1000);
  const listed = Date.parse(value.listing_date + "T00:00:00Z");
  if (!Number.isFinite(start) || !Number.isFinite(listed) || new Date(listed).toISOString().slice(0, 10) !== value.listing_date || Date.parse(value.collection_expires_at) !== expiry || listed >= expiry) throw fail();
  const lower = Math.floor(start / 60000) * 60000;
  const firstDay = Math.floor(lower / 86400000) * 86400000;
  const days = (listed - firstDay) / 86400000;
  if (!Number.isInteger(days) || days < 0 || days > 1 || value.list_parameters.length !== days + 1) throw fail();
  value.list_parameters.forEach((row, index) => {
    const day = firstDay + index * 86400000;
    const prefix = source.exact_delivery_root_prefix + new Date(day).toISOString().slice(0, 10).replaceAll("-", "/") + "/";
    const stamp = new Date(Math.max(day, lower)).toISOString().slice(0, 16).replaceAll("-", "").replaceAll(":", "") + "Z_";
    const cursor = prefix + source.source_account_id + "_CloudTrail_" + source.event_region + "_" + stamp;
    if (!exact(row, ["Bucket", "ExpectedBucketOwner", "Prefix", "StartAfter", "MaxKeys"]) || row.Bucket !== source.audit_bucket || row.ExpectedBucketOwner !== source.source_account_id || row.Prefix !== prefix || row.StartAfter !== cursor || row.MaxKeys !== 16) throw fail();
  });
  return value as unknown as AuditStageReview;
}
