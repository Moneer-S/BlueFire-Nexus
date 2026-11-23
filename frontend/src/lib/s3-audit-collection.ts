export interface AuditSourceDescriptor extends Record<string, unknown> {
  schema_version: "bluefire.s3-audit-source.v1";
  audit_source_id: string;
  experiment_scope_digest: string;
  trail_arn: string;
  source_account_id: string;
  event_region: string;
  audit_bucket: string;
  audit_bucket_owner_account_id: string;
  audit_bucket_region: string;
  exact_delivery_root_prefix: string;
  collector_role_arn: string;
  managed_profile_digest: string;
  protected_runtime_digest: string;
  worker_generation: string;
  expires_at: string;
  audit_limits: Record<string, number>;
}

export interface AuditOriginalRead extends Record<string, unknown> {
  reader: "probe" | "legitimate";
  run_id: string;
  manifest_digest: string;
  request_digest: string;
  worker_result_digest: string;
  reservation_digest: string;
  cleanup: "verified";
  request: Record<string, unknown>;
  result: Record<string, unknown> & { calls: Array<{ request_id: string; http_status: number; error_code?: string }> };
}

export interface AuditOriginalPair extends Record<string, unknown> {
  schema_version: "bluefire.s3-audit-read-pair.v1";
  workflow_job_id: string;
  operation_job_id: string;
  phase: "baseline" | "retest";
  outcome_digest: string;
  review_digest: string;
  reads: [AuditOriginalRead, AuditOriginalRead];
}

export interface AuditExecutionReceipt extends Record<string, unknown> {
  schema_version: "bluefire.s3-execution.v1";
  request_digest: string;
  reservation_digest: string;
  result: Record<string, unknown> & {
    calls: Array<{ request_id: string; http_status: number; error_code?: string }>;
    data: Record<string, unknown> & {
      pair_digest: string;
      audit_source_digest: string;
      discovery: Record<string, unknown> & {
        schema_version: "bluefire.s3-audit-discovery.v1";
        request_digest: string;
        collection_digest: string;
        reservation_digest: string;
        resource_key: string;
        frame_digest: string;
        phase: "baseline" | "retest";
        pair_digest: string;
        audit_source_digest: string;
        prefixes: Array<[string, string]>;
        listings: Array<{ request_id: string; body_sha256: string; projection_digest: string; key_count: number; is_truncated: boolean }>;
        completed_list_count: number;
        next_send_sequence: number;
        candidate_count: number;
        selected: Array<{ key: string; etag: string; size_bytes: number }>;
        truncated: boolean;
      };
      correlations: {
        probe: { request_digest: string; worker_result_digest: string; reads: Array<{ worker_request_id: string | null; worker_outcome: string }> };
        legitimate: { request_digest: string; worker_result_digest: string; reads: Array<{ worker_request_id: string | null; worker_outcome: string }> };
      };
    };
  };
}

const fail = () => new Error("The saved audit review is incomplete or belongs to different work.");
const record = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const keys = (v: unknown, fields: readonly string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v, k));
const hash = (v: unknown) => typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v);
const digest = (v: unknown) => hash(v);
const integer = (v: unknown, max: number): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= max;
const time = (v: unknown): v is string => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(v) && Number.isFinite(Date.parse(v));
const correlationTime = (v: unknown): v is string => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00$/.test(v) && Number.isFinite(Date.parse(v));
const job = (v: unknown) => typeof v === "string" && /^job-[0-9a-f]{32}$/.test(v);
const run = (v: unknown): v is string => {
  if (typeof v !== "string" || !/^run-\d{8}T\d{6}Z-[0-9a-f]{16}$/.test(v)) return false;
  const stamp = v.slice(4, 20);
  return Number.isFinite(Date.parse(`${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(9, 11)}:${stamp.slice(11, 13)}:${stamp.slice(13, 15)}Z`));
};
const safeRequestId = (v: unknown): v is string => typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9+/=_:.-]{0,127}$/.test(v);
const unique = (values: unknown[]) => new Set(values).size === values.length;
const auditSourceDescriptorKeys = ["schema_version", "audit_source_id", "experiment_scope_digest", "trail_arn", "source_account_id", "event_region", "audit_bucket", "audit_bucket_owner_account_id", "audit_bucket_region", "exact_delivery_root_prefix", "collector_role_arn", "managed_profile_digest", "protected_runtime_digest", "worker_generation", "expires_at", "audit_limits"];
const auditLimitKeys = ["api_calls", "sessions", "files", "sdk_body_bytes", "compressed_bytes", "expanded_bytes", "events", "seconds"] as const;
const collectionReadKeys = ["reader", "run_id", "manifest_digest", "request_digest", "worker_result_digest", "reservation_digest", "cleanup", "request", "result"];
const collectionPairKeys = ["schema_version", "workflow_job_id", "operation_job_id", "phase", "outcome_digest", "review_digest", "reads"];
const workerResultKeys = ["schema_version", "request_digest", "outcome", "data", "problem", "send_permits_consumed", "calls", "runtime_isolation_proven"];
const requestKeys = ["schema_version", "launch_id", "request_id", "worker_generation", "runtime_digest", "scope", "scope_digest", "operation", "policy_change", "deadline", "max_sends", "exclusive_writer_digest"];
const scopeKeys = ["schema_version", "scope_id", "account_id", "region", "bucket", "prefix", "created_at", "expires_at", "limits", "objects", "ownership_receipt_digest", "roles", "policy"];
const scopeLimitKeys = ["api_calls", "business_attempts", "sessions", "policy_changes", "rollbacks", "request_seconds", "session_seconds", "business_seconds", "cleanup_seconds", "convergence_seconds", "object_bytes", "audit_bytes", "audit_events", "audit_seconds"] as const;
const scopeLimitCaps: Record<typeof scopeLimitKeys[number], number> = { api_calls: 300, business_attempts: 6, sessions: 6, policy_changes: 1, rollbacks: 1, request_seconds: 30, session_seconds: 900, business_seconds: 1800, cleanup_seconds: 900, convergence_seconds: 300, object_bytes: 65536, audit_bytes: 20971520, audit_events: 1000, audit_seconds: 1800 };
const workerCallKeys = ["operation", "role", "request_id", "http_status"];
const commercialRegion = /^(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9][0-9]?$/;

export function checkedAuditSourceDescriptor(v: unknown): AuditSourceDescriptor {
  if (!keys(v, auditSourceDescriptorKeys) || v.schema_version !== "bluefire.s3-audit-source.v1" || typeof v.audit_source_id !== "string" || v.audit_source_id.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(v.audit_source_id) || !hash(v.experiment_scope_digest) || !hash(v.managed_profile_digest) || !hash(v.protected_runtime_digest) || !hash(v.worker_generation) || !time(v.expires_at) || typeof v.source_account_id !== "string" || !/^\d{12}$/.test(v.source_account_id) || v.audit_bucket_owner_account_id !== v.source_account_id || typeof v.event_region !== "string" || !commercialRegion.test(v.event_region) || typeof v.audit_bucket_region !== "string" || !commercialRegion.test(v.audit_bucket_region) || typeof v.audit_bucket !== "string" || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(v.audit_bucket) || /^(xn--|sthree-|amzn-s3-demo-)/.test(v.audit_bucket) || /(-s3alias|--ol-s3|--x-s3|--table-s3)$/.test(v.audit_bucket) || typeof v.trail_arn !== "string" || !/^arn:aws:cloudtrail:[a-z0-9-]+:\d{12}:trail\/[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(v.trail_arn) || typeof v.collector_role_arn !== "string" || !/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_-]{1,64}$/.test(v.collector_role_arn) || typeof v.exact_delivery_root_prefix !== "string" || v.exact_delivery_root_prefix.length > 256 || !/^([A-Za-z0-9._-]+\/)*AWSLogs\/\d{12}\/CloudTrail\/[a-z0-9-]+\/$/.test(v.exact_delivery_root_prefix) || !keys(v.audit_limits, auditLimitKeys)) throw fail();
  const limits = v.audit_limits as Record<string, unknown>;
  const ceilings: Record<typeof auditLimitKeys[number], number> = { api_calls: 9, sessions: 1, files: 4, sdk_body_bytes: 393216, compressed_bytes: 262144, expanded_bytes: 1048576, events: 500, seconds: 30 };
  const trail = /^arn:aws:cloudtrail:([a-z0-9-]+):(\d{12}):trail\//.exec(String(v.trail_arn));
  const collector = /^arn:aws:iam::(\d{12}):role\//.exec(String(v.collector_role_arn));
  const validLimits = auditLimitKeys.every(key => {
    const value = limits[key];
    return integer(value, ceilings[key]) && value > 0;
  });
  if (!trail || trail[1] !== v.event_region || trail[2] !== v.source_account_id || !collector || collector[1] !== v.source_account_id || !String(v.exact_delivery_root_prefix).endsWith(`AWSLogs/${v.source_account_id}/CloudTrail/${v.event_region}/`) || String(v.exact_delivery_root_prefix).slice(0, -1).split("/").some(part => !part || part === "." || part === "..") || !validLimits || limits.api_calls !== 9 || limits.sessions !== 1) throw fail();
  return v as AuditSourceDescriptor;
}

export function checkedOriginalPair(v: unknown, sourceValue: AuditSourceDescriptor, owner: string, phase: string): AuditOriginalPair {
  if (!keys(v, collectionPairKeys) || v.schema_version !== "bluefire.s3-audit-read-pair.v1" || v.workflow_job_id !== owner || !job(v.operation_job_id) || !["baseline", "retest"].includes(String(v.phase)) || v.phase !== phase || !hash(v.outcome_digest) || !hash(v.review_digest) || !Array.isArray(v.reads) || v.reads.length !== 2) throw fail();
  const readers = ["probe", "legitimate"] as const;
  const runs: string[] = [];
  const reads: unknown[] = v.reads;
  const checkedReads: Record<string, unknown>[] = [];
  for (let index = 0; index < 2; index++) {
    const readValue = reads[index];
    if (!keys(readValue, collectionReadKeys)) throw fail();
    const read = readValue;
    if (!keys(read, collectionReadKeys) || read.reader !== readers[index] || !run(read.run_id) || read.cleanup !== "verified" || !digest(read.manifest_digest) || !digest(read.request_digest) || !digest(read.worker_result_digest) || !digest(read.reservation_digest) || !keys(read.request, requestKeys)) throw fail();
    const request = read.request;
    if (request.schema_version !== "bluefire.s3-worker-request.v1" || request.operation !== `${readers[index]}_read` || !/^[0-9a-f]{64}$/.test(String(request.launch_id)) || !/^[0-9a-f]{64}$/.test(String(request.request_id)) || !digest(request.worker_generation) || !digest(request.runtime_digest) || !digest(request.scope_digest) || !time(request.deadline) || request.max_sends !== (index === 0 ? 4 : 5) || request.policy_change !== null || request.exclusive_writer_digest !== null || !keys(request.scope, scopeKeys)) throw fail();
    const scope = request.scope;
    const createdAt = scope.created_at;
    const expiresAt = scope.expires_at;
    const sourceExpiresAt = sourceValue.expires_at;
    const scopeObjectsValue = scope.objects;
    if (scope.schema_version !== "bluefire.s3-access-scope.v1" || typeof scope.scope_id !== "string" || !/^s3-[0-9a-f]{32}$/.test(scope.scope_id) || typeof scope.account_id !== "string" || !/^\d{12}$/.test(scope.account_id) || typeof scope.region !== "string" || !commercialRegion.test(scope.region) || typeof scope.bucket !== "string" || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(scope.bucket) || /^(xn--|sthree-|amzn-s3-demo-)/.test(scope.bucket) || /(-s3alias|--ol-s3|--x-s3|--table-s3)$/.test(scope.bucket) || typeof scope.prefix !== "string" || scope.prefix.length > 512 || !time(createdAt) || !time(expiresAt) || Date.parse(createdAt) >= Date.parse(expiresAt) || !time(sourceExpiresAt) || Date.parse(sourceExpiresAt) > Date.parse(expiresAt) || !hash(scope.ownership_receipt_digest) || !keys(scope.limits, scopeLimitKeys) || !Object.entries(scopeLimitCaps).every(([key, cap]) => { const value = (scope.limits as Record<string, unknown>)[key]; return integer(value, cap) && value > 0; }) || (scope.limits as Record<string, unknown>).session_seconds !== 900 || Number((scope.limits as Record<string, unknown>).convergence_seconds) > Number((scope.limits as Record<string, unknown>).business_seconds) || !Array.isArray(scopeObjectsValue) || scopeObjectsValue.length !== 2 || !keys(scope.roles, ["controller", "legitimate", "probe"]) || !keys(scope.policy, ["baseline_digest", "legitimate_sid", "probe_sid"]) || scope.account_id !== sourceValue.source_account_id || scope.region !== sourceValue.event_region || request.scope_digest !== sourceValue.experiment_scope_digest || request.runtime_digest !== sourceValue.protected_runtime_digest || request.worker_generation !== sourceValue.worker_generation) throw fail();
    const roles = scope.roles as Record<string, unknown>;
    if (Object.values(roles).some(role => typeof role !== "string" || !new RegExp(`^arn:aws:iam::${scope.account_id}:role/[A-Za-z0-9+=,.@_-]{1,64}$`).test(role)) || new Set(Object.values(roles)).size !== 3) throw fail();
    const expectedPrefix = `bluefire/${scope.scope_id}/`;
    const scopeObjects = scopeObjectsValue;
    const objectLimit = (scope.limits as Record<string, unknown>).object_bytes;
    if (!integer(objectLimit, scopeLimitCaps.object_bytes)) throw fail();
    if (scope.prefix !== expectedPrefix || scopeObjects.some((obj: unknown, objectIndex: number) => {
      if (!keys(obj, ["purpose", "key", "sha256", "size_bytes"])) return true;
      const sizeBytes = obj.size_bytes;
      return obj.key !== `${expectedPrefix}${objectIndex === 0 ? "records.jsonl" : "health.jsonl"}` || obj.purpose !== (objectIndex === 0 ? "primary" : "health") || !digest(obj.sha256) || !integer(sizeBytes, objectLimit) || sizeBytes < 1;
    }) || scopeObjects.reduce((n, obj) => n + (record(obj) && typeof obj.size_bytes === "number" ? obj.size_bytes : 0), 0) > objectLimit) throw fail();
    const policy = scope.policy as Record<string, unknown>;
    const scopeSuffix = scope.scope_id.slice(3);
    if (policy.baseline_digest === undefined || !digest(policy.baseline_digest) || policy.probe_sid !== `BlueFireProbe${scopeSuffix}` || policy.legitimate_sid !== `BlueFireLegitimate${scopeSuffix}`) throw fail();
    const expectedObjectCount = index === 0 ? 1 : 2;
    const plannedCalls = index === 0 ? 4 : 5;
    const result = read.result;
    if (!keys(result, workerResultKeys) || result.schema_version !== "bluefire.s3-worker-result.v1" || result.request_digest !== read.request_digest || !["observed", "failed"].includes(String(result.outcome)) || result.runtime_isolation_proven !== false || !integer(result.send_permits_consumed, plannedCalls) || !Array.isArray(result.calls) || result.calls.length > result.send_permits_consumed) throw fail();
    if (result.outcome === "observed") {
      if (result.problem !== null || result.send_permits_consumed !== plannedCalls || result.calls.length !== plannedCalls || !keys(result.data, ["reader", "objects", "effective_access_claim"]) || result.data.reader !== read.reader || result.data.effective_access_claim !== false || !Array.isArray(result.data.objects) || result.data.objects.length !== expectedObjectCount) throw fail();
    } else if (result.problem !== "scoped_operation_failed" || result.data !== null) throw fail();
    const observedObjects = result.outcome === "observed" ? (result.data as Record<string, unknown>).objects as unknown[] : [];
    if (observedObjects.some((obj: unknown, objectIndex: number) => {
      const expected = (scopeObjects[objectIndex] ?? {}) as Record<string, unknown>;
      if (!record(obj)) return true;
      if (obj.result === "service_denied") return !keys(obj, ["purpose", "result"]) || obj.purpose !== expected.purpose;
      return !keys(obj, ["purpose", "result", "sha256", "size_bytes"]) || obj.purpose !== expected.purpose || obj.result !== "read" || obj.sha256 !== expected.sha256 || obj.size_bytes !== expected.size_bytes;
    })) throw fail();
    const calls = result.calls;
    const expectedOperations = index === 0 ? ["GetCallerIdentity", "AssumeRole", "GetCallerIdentity", "GetObject"] : ["GetCallerIdentity", "AssumeRole", "GetCallerIdentity", "GetObject", "GetObject"];
    const expectedRoles = index === 0 ? ["controller", "controller", "probe", "probe"] : ["controller", "controller", "legitimate", "legitimate", "legitimate"];
    if (calls.some((call, callIndex) => !validWorkerCall(call) || (call as Record<string, unknown>).operation !== expectedOperations[callIndex] || (call as Record<string, unknown>).role !== expectedRoles[callIndex])) throw fail();
    if (result.outcome === "observed" && calls.length !== expectedOperations.length) throw fail();
    const setupError = calls.slice(0, 3).some(call => Object.hasOwn(call as object, "error_code"));
    if ((result.outcome === "observed" && calls.slice(0, 3).some(call => (call as Record<string, unknown>).http_status !== 200 || Object.hasOwn(call as object, "error_code"))) || (setupError && calls.length > 3)) throw fail();
    const callIds = calls.map(call => (call as Record<string, unknown>).request_id);
    if (!unique(callIds)) throw fail();
    for (let objectIndex = 0; objectIndex < expectedObjectCount; objectIndex++) {
      const call = calls[objectIndex + 3] as Record<string, unknown> | undefined;
      if (!call && result.outcome === "failed") continue;
      if (!call) throw fail();
      const object = observedObjects[objectIndex] as Record<string, unknown>;
      if (result.outcome === "failed") continue;
      if (Object.hasOwn(call, "error_code")) {
        if (call.error_code !== "AccessDenied" || call.http_status !== 403 || object.result !== "service_denied") throw fail();
      } else if (call.http_status !== 200 || object.result !== "read") throw fail();
    }
    runs.push(read.run_id);
    checkedReads.push(read);
  }
  const probe = checkedReads[0];
  const legitimate = checkedReads[1];
  if (!probe || !legitimate) throw fail();
  const probeRequest = probe.request as Record<string, unknown>;
  const legitimateRequest = legitimate.request as Record<string, unknown>;
  if (v.operation_job_id === owner || runs[0] === runs[1] || probe.manifest_digest === legitimate.manifest_digest || probe.request_digest === legitimate.request_digest || probe.worker_result_digest === legitimate.worker_result_digest || probe.reservation_digest === legitimate.reservation_digest || probeRequest.launch_id === legitimateRequest.launch_id || probeRequest.request_id === legitimateRequest.request_id || probeRequest.runtime_digest !== legitimateRequest.runtime_digest || probeRequest.worker_generation !== legitimateRequest.worker_generation) throw fail();
  return v as AuditOriginalPair;
}

export function checkedExecutionReceipt(v: unknown, review: { request_digest: string; reservation_digest: string }): AuditExecutionReceipt {
  if (!keys(v, ["schema_version", "request_digest", "admission", "dispatch", "send_debits", "result", "cleanup", "provenance", "reservation_digest"]) || v.schema_version !== "bluefire.s3-execution.v1" || v.request_digest !== review.request_digest || !keys(v.admission, ["accepted", "problem"]) || v.admission.accepted !== true || v.admission.problem !== null || v.dispatch !== "permit_issued" || !integer(v.send_debits, 9) || v.send_debits < 1 || v.cleanup !== "verified" || v.provenance !== "runner_reported" || v.reservation_digest !== review.reservation_digest || !digest(v.reservation_digest) || !keys(v.result, workerResultKeys)) throw fail();
  const sendDebits = v.send_debits;
  const result = v.result as Record<string, unknown>;
  const data = result.data as Record<string, unknown>;
  if (result.schema_version !== "bluefire.s3-worker-result.v3" || result.request_digest !== review.request_digest || result.outcome !== "observed" || result.problem !== null || result.runtime_isolation_proven !== false || !integer(result.send_permits_consumed, 9) || !Array.isArray(result.calls) || result.calls.length !== result.send_permits_consumed || result.send_permits_consumed !== sendDebits || !keys(data, ["schema_version", "collection_digest", "pair_digest", "audit_source_digest", "reservation_digest", "discovery", "objects", "usage", "normalized_digest", "correlations", "delivery_state", "effective_access_claim", "log_integrity_proven"]) || data.schema_version !== "bluefire.s3-audit-collection-observation.v1" || !digest(data.collection_digest) || !digest(data.pair_digest) || !digest(data.audit_source_digest) || !digest(data.reservation_digest) || data.reservation_digest !== v.reservation_digest || !digest(data.normalized_digest) || !(data.delivery_state === "unknown" || data.delivery_state === "incomplete" || data.delivery_state === "truncated") || data.effective_access_claim !== false || data.log_integrity_proven !== false) throw fail();
  const discovery = data.discovery;
  if (!keys(discovery, ["schema_version", "request_digest", "collection_digest", "pair_digest", "reservation_digest", "audit_source_digest", "resource_key", "phase", "frame_digest", "prefixes", "listings", "completed_list_count", "next_send_sequence", "candidate_count", "selected", "truncated"]) || discovery.schema_version !== "bluefire.s3-audit-discovery.v1" || discovery.request_digest !== review.request_digest || discovery.collection_digest !== data.collection_digest || discovery.pair_digest !== data.pair_digest || discovery.reservation_digest !== data.reservation_digest || discovery.audit_source_digest !== data.audit_source_digest || !digest(discovery.frame_digest) || !digest(discovery.resource_key) || !["baseline", "retest"].includes(String(discovery.phase))) throw fail();
  const prefixRows = discovery.prefixes;
  const listingValues = discovery.listings;
  const selectedValues = discovery.selected;
  const candidateCount = discovery.candidate_count;
  const objectValues = data.objects;
  const usage = data.usage;
  const correlationsValue = data.correlations;
  if (!Array.isArray(prefixRows) || prefixRows.length < 1 || prefixRows.length > 2 || prefixRows.some((row: unknown) => !Array.isArray(row) || row.length !== 2 || !row.every(item => typeof item === "string" && item.length <= 512)) || !Array.isArray(listingValues) || listingValues.length < 1 || listingValues.length > 2 || prefixRows.length !== listingValues.length || !Array.isArray(selectedValues) || selectedValues.length > 4 || !integer(candidateCount, 32) || selectedValues.length > candidateCount || !integer(discovery.completed_list_count, 2) || discovery.completed_list_count !== listingValues.length || !integer(discovery.next_send_sequence, 6) || typeof discovery.truncated !== "boolean" || !Array.isArray(objectValues) || objectValues.length !== selectedValues.length || !keys(usage, ["sdk_body_bytes", "files", "compressed_bytes", "expanded_bytes", "events"]) || !keys(correlationsValue, ["probe", "legitimate"])) throw fail();
  const listingRows: Array<{ request_id: string; key_count: number }> = [];
  for (const row of listingValues) {
    if (!keys(row, ["request_id", "body_sha256", "projection_digest", "key_count", "is_truncated"]) || !digest(row.body_sha256) || !digest(row.projection_digest) || typeof row.is_truncated !== "boolean") throw fail();
    const requestId = row.request_id;
    const keyCount = row.key_count;
    if (!safeRequestId(requestId) || !integer(keyCount, 16)) throw fail();
    listingRows.push({ request_id: requestId, key_count: keyCount });
  }
  const selectedRows: Array<{ key: string; etag: string; size_bytes: number }> = [];
  for (const row of selectedValues) {
    if (!keys(row, ["key", "etag", "size_bytes"])) throw fail();
    const key = row.key;
    const etag = row.etag;
    const sizeBytes = row.size_bytes;
    if (typeof key !== "string" || key.length > 1024 || typeof etag !== "string" || etag.length > 128 || !integer(sizeBytes, 1048576) || sizeBytes < 1) throw fail();
    selectedRows.push({ key, etag, size_bytes: sizeBytes });
  }
  const objectRows: Array<{ selected_index: number; expanded_bytes: number; event_count: number }> = [];
  for (const [index, row] of objectValues.entries()) {
    if (!keys(row, ["selected_index", "compressed_sha256", "expanded_sha256", "expanded_bytes", "event_count"]) || row.selected_index !== index || !digest(row.compressed_sha256) || !digest(row.expanded_sha256)) throw fail();
    const expandedBytes = row.expanded_bytes;
    const eventCount = row.event_count;
    if (!integer(expandedBytes, 1048576) || !integer(eventCount, 500)) throw fail();
    objectRows.push({ selected_index: index, expanded_bytes: expandedBytes, event_count: eventCount });
  }
  const usageCaps = { sdk_body_bytes: 393216, files: 4, compressed_bytes: 262144, expanded_bytes: 1048576, events: 500 } as const;
  const calls = result.calls as unknown[];
  const sdkBodyBytes = usage.sdk_body_bytes;
  const fileCount = usage.files;
  const compressedBytes = usage.compressed_bytes;
  const expandedBytes = usage.expanded_bytes;
  const eventCount = usage.events;
  if (!integer(sdkBodyBytes, usageCaps.sdk_body_bytes) || !integer(fileCount, usageCaps.files) || !integer(compressedBytes, usageCaps.compressed_bytes) || !integer(expandedBytes, usageCaps.expanded_bytes) || !integer(eventCount, usageCaps.events)) throw fail();
  const usageNumbers = { sdk_body_bytes: sdkBodyBytes, files: fileCount, compressed_bytes: compressedBytes, expanded_bytes: expandedBytes, events: eventCount };
  if (usageNumbers.files !== objectRows.length || usageNumbers.files !== selectedRows.length || usageNumbers.expanded_bytes !== objectRows.reduce((n, row) => n + row.expanded_bytes, 0) || usageNumbers.events !== objectRows.reduce((n, row) => n + row.event_count, 0) || selectedRows.reduce((n, row) => n + row.size_bytes, 0) > usageNumbers.compressed_bytes || listingRows.reduce((n, row) => n + row.key_count, 0) !== candidateCount || listingRows.some((row, index) => (calls[3 + index] as Record<string, unknown>)?.request_id !== row.request_id) || (discovery.truncated && data.delivery_state !== "truncated")) throw fail();
  const correlationPairs: unknown[] = [correlationsValue.probe, correlationsValue.legitimate];
  for (const [index, pairValue] of correlationPairs.entries()) {
    if (!keys(pairValue, ["schema_version", "request_digest", "worker_result_digest", "reads", "authorized_request_window", "independent_collection_proven", "effective_access_claim"])) throw fail();
    const pair = pairValue;
    if (pair.schema_version !== "bluefire.s3-audit-correlation.v1" || !digest(pair.request_digest) || !digest(pair.worker_result_digest) || pair.independent_collection_proven !== false || pair.effective_access_claim !== false || !keys(pair.authorized_request_window, ["from", "through"])) throw fail();
    const window = pair.authorized_request_window;
    if (!correlationTime(window.from) || !correlationTime(window.through) || !Array.isArray(pair.reads)) throw fail();
    const correlationReads: unknown[] = pair.reads;
    if (correlationReads.length !== (index === 0 ? 1 : 2)) throw fail();
    for (const [readIndex, row] of correlationReads.entries()) {
      if (!keys(row, ["purpose", "reader", "status", "worker_outcome", "worker_request_id", "audit_event_ids", "audit_outcomes", "full_object_bytes_proven"]) || row.reader !== (index === 0 ? "probe" : "legitimate") || row.purpose !== (index === 0 ? "primary" : readIndex === 0 ? "primary" : "health") || typeof row.status !== "string" || !["matched", "conflict", "worker_unreported", "truncated", "unknown", "awaiting_delivery", "missing"].includes(row.status) || typeof row.worker_outcome !== "string" || !["unreported", "service_success", "service_denied", "object_missing", "bucket_missing", "credential_error", "other_service_error"].includes(row.worker_outcome) || (row.worker_request_id !== null && !safeRequestId(row.worker_request_id)) || !Array.isArray(row.audit_event_ids) || row.audit_event_ids.length > 500 || !row.audit_event_ids.every((id: unknown) => typeof id === "string" && /^[0-9a-f-]{36}$/.test(id)) || !unique(row.audit_event_ids) || !Array.isArray(row.audit_outcomes) || row.audit_outcomes.length > 7 || !row.audit_outcomes.every((outcome: unknown) => typeof outcome === "string" && ["service_success", "service_denied", "object_missing", "bucket_missing", "credential_error", "other_service_error"].includes(outcome)) || !unique(row.audit_outcomes) || row.full_object_bytes_proven !== false) throw fail();
      if (row.audit_event_ids.length > eventCount || !row.audit_event_ids.every(id => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) || JSON.stringify(row.audit_outcomes) !== JSON.stringify([...row.audit_outcomes].sort())) throw fail();
    }
  }
  const expectedOperations = ["GetCallerIdentity", "AssumeRole", "GetCallerIdentity", ...Array.from({ length: listingRows.length }, () => "ListObjectsV2"), ...Array.from({ length: selectedRows.length }, () => "GetObject")];
  const expectedRoles = ["controller", "controller", "collector", ...Array.from({ length: listingRows.length }, () => "collector"), ...Array.from({ length: selectedRows.length }, () => "collector")];
  if (calls.length !== expectedOperations.length || calls.some((call, index) => !validWorkerCall(call) || (call as Record<string, unknown>).operation !== expectedOperations[index] || (call as Record<string, unknown>).role !== expectedRoles[index] || Object.hasOwn(call as object, "error_code")) || !unique(calls.map(call => (call as Record<string, unknown>).request_id)) || discovery.next_send_sequence !== 4 + listingRows.length || selectedRows.length > 4 || candidateCount > 32) throw fail();
  return v as AuditExecutionReceipt;
}

function validWorkerCall(value: unknown) {
  if (!record(value) || !(keys(value, workerCallKeys) || keys(value, [...workerCallKeys, "error_code"])) || !safeRequestId(value.request_id) || typeof value.operation !== "string" || typeof value.role !== "string" || typeof value.http_status !== "number" || !Number.isSafeInteger(value.http_status)) return false;
  const errors = ["AccessDenied", "NoSuchKey", "NoSuchBucket", "ExpiredToken", "InvalidToken", "InvalidAccessKeyId", "SignatureDoesNotMatch", "RequestExpired", "AuthorizationHeaderMalformed", "PermanentRedirect", "SlowDown", "ServiceUnavailable", "InternalError", "PreconditionFailed", "OtherServiceError"];
  return Object.hasOwn(value, "error_code") ? errors.includes(String(value.error_code)) && value.http_status >= 400 && value.http_status <= 599 : value.http_status === 200;
}
