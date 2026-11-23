import type { AuditCollectedReview, AuditCollectionSummary, AuditRead } from "../src/lib/s3-audit";
import type { AuditExecutionReceipt, AuditOriginalPair, AuditOriginalRead, AuditSourceDescriptor } from "../src/lib/s3-audit-collection";

const digest = (digit: string) => `sha256:${digit.repeat(64)}`;
const job = (digit: string) => `job-${digit.repeat(32)}`;
const run = (digit: string) => `run-20261011T204432Z-${digit.repeat(16)}`;
const owner = job("1");
const operation = job("2");
const sourceDigest = digest("a");
const runtimeDigest = digest("d");
const generation = digest("c");

const scope = {
  schema_version: "bluefire.s3-access-scope.v1",
  scope_id: `s3-${"0".repeat(32)}`,
  account_id: "123456789012",
  region: "us-east-1",
  bucket: "bluefire-owned-fixture",
  prefix: `bluefire/s3-${"0".repeat(32)}/`,
  created_at: "2026-10-11T20:00:00Z",
  expires_at: "2026-10-11T21:00:00Z",
  limits: {
    api_calls: 300, business_attempts: 6, sessions: 6, policy_changes: 1, rollbacks: 1,
    request_seconds: 30, session_seconds: 900, business_seconds: 1800, cleanup_seconds: 900,
    convergence_seconds: 300, object_bytes: 65536, audit_bytes: 20971520, audit_events: 1000,
    audit_seconds: 1800,
  },
  objects: [
    { key: `bluefire/s3-${"0".repeat(32)}/records.jsonl`, purpose: "primary", sha256: digest("b"), size_bytes: 32 },
    { key: `bluefire/s3-${"0".repeat(32)}/health.jsonl`, purpose: "health", sha256: digest("e"), size_bytes: 32 },
  ],
  ownership_receipt_digest: digest("f"),
  roles: {
    controller: "arn:aws:iam::123456789012:role/bluefire-controller",
    legitimate: "arn:aws:iam::123456789012:role/bluefire-legitimate",
    probe: "arn:aws:iam::123456789012:role/bluefire-probe",
  },
  policy: {
    baseline_digest: digest("6"),
    legitimate_sid: `BlueFireLegitimate${"0".repeat(32)}`,
    probe_sid: `BlueFireProbe${"0".repeat(32)}`,
  },
};

const source: AuditSourceDescriptor = {
  schema_version: "bluefire.s3-audit-source.v1",
  audit_source_id: "synthetic-trail-delivery",
  experiment_scope_digest: sourceDigest,
  trail_arn: "arn:aws:cloudtrail:us-east-1:123456789012:trail/synthetic",
  source_account_id: "123456789012",
  event_region: "us-east-1",
  audit_bucket: "bluefire-audit-fixture",
  audit_bucket_owner_account_id: "123456789012",
  audit_bucket_region: "us-west-2",
  exact_delivery_root_prefix: "AWSLogs/123456789012/CloudTrail/us-east-1/",
  collector_role_arn: "arn:aws:iam::123456789012:role/bluefire-audit-reader",
  managed_profile_digest: digest("6"),
  protected_runtime_digest: runtimeDigest,
  worker_generation: generation,
  expires_at: "2026-10-11T21:00:00Z",
  audit_limits: {
    api_calls: 9, sessions: 1, files: 4, sdk_body_bytes: 393216,
    compressed_bytes: 262144, expanded_bytes: 1048576, events: 500, seconds: 30,
  },
};

function originalRead(reader: "probe" | "legitimate", index: number): AuditOriginalRead {
  const isProbe = reader === "probe";
  const requestDigest = digest(isProbe ? "1" : "2");
  const workerDigest = digest(isProbe ? "3" : "4");
  const reservationDigest = digest(isProbe ? "5" : "7");
  const purposes = isProbe ? ["primary"] : ["primary", "health"];
  const callCount = isProbe ? 4 : 5;
  const request = {
    schema_version: "bluefire.s3-worker-request.v1",
    launch_id: (index + 1).toString().repeat(64),
    request_id: (index + 3).toString().repeat(64),
    worker_generation: generation,
    runtime_digest: runtimeDigest,
    scope,
    scope_digest: sourceDigest,
    operation: `${reader}_read`,
    policy_change: null,
    deadline: "2026-10-11T20:44:50Z",
    max_sends: callCount,
    exclusive_writer_digest: null,
  };
  const operations = ["GetCallerIdentity", "AssumeRole", "GetCallerIdentity", ...Array.from({ length: isProbe ? 1 : 2 }, () => "GetObject")];
  const roles = ["controller", "controller", reader, ...Array.from({ length: isProbe ? 1 : 2 }, () => reader)];
  const calls = Array.from({ length: callCount }, (_, number) => ({
    operation: operations[number],
    role: roles[number],
    request_id: `${reader}-request-${number}`,
    http_status: 200,
  }));
  const result = {
    schema_version: "bluefire.s3-worker-result.v1",
    request_digest: requestDigest,
    outcome: "observed",
    data: {
      reader,
      objects: purposes.map((purpose, objectIndex) => ({
        purpose,
        result: "read",
        sha256: scope.objects[objectIndex]!.sha256,
        size_bytes: scope.objects[objectIndex]!.size_bytes,
      })),
      effective_access_claim: false,
    },
    problem: null,
    send_permits_consumed: callCount,
    calls,
    runtime_isolation_proven: false,
  };
  return {
    reader,
    run_id: run(isProbe ? "1" : "2"),
    manifest_digest: digest(isProbe ? "8" : "9"),
    request_digest: requestDigest,
    worker_result_digest: workerDigest,
    reservation_digest: reservationDigest,
    cleanup: "verified",
    request,
    result,
  };
}

const reads: [AuditOriginalRead, AuditOriginalRead] = [originalRead("probe", 0), originalRead("legitimate", 1)];
const pair: AuditOriginalPair = {
  schema_version: "bluefire.s3-audit-read-pair.v1",
  workflow_job_id: owner,
  operation_job_id: job("a"),
  phase: "baseline",
  outcome_digest: digest("b"),
  review_digest: digest("c"),
  reads: [reads[0], reads[1]],
};
const collectionRequestDigest = digest("e");
const collectionReservationDigest = digest("f");
const selected: Array<{ key: string; etag: string; size_bytes: number }> = [];
const discovery: AuditExecutionReceipt["result"]["data"]["discovery"] = {
  schema_version: "bluefire.s3-audit-discovery.v1",
  request_digest: collectionRequestDigest,
  collection_digest: digest("1"),
  pair_digest: digest("2"),
  reservation_digest: collectionReservationDigest,
  audit_source_digest: digest("3"),
  resource_key: digest("4"),
  phase: "baseline",
  frame_digest: digest("5"),
  prefixes: [
    ["AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/11/", "AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/11/123456789012_CloudTrail_us-east-1_20261011T2044Z_"],
    ["AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/12/", "AWSLogs/123456789012/CloudTrail/us-east-1/2026/10/12/123456789012_CloudTrail_us-east-1_20261012T0000Z_"],
  ],
  listings: [0, 1].map(index => ({
    request_id: `list-request-${index}`,
    body_sha256: digest(index ? "7" : "6"),
    projection_digest: digest(index ? "9" : "8"),
    key_count: 0,
    is_truncated: false,
  })),
  completed_list_count: 2,
  next_send_sequence: 6,
  candidate_count: 0,
  selected,
  truncated: false,
};

type CollectedCorrelation = AuditCollectedReview["receipt"]["result"]["data"]["correlations"]["probe"];
const correlation = (reader: "probe" | "legitimate"): CollectedCorrelation => {
  const original = reads[reader === "probe" ? 0 : 1];
  const purposes: AuditRead["purpose"][] = reader === "probe" ? ["primary"] : ["primary", "health"];
  return {
    schema_version: "bluefire.s3-audit-correlation.v1",
    request_digest: original.request_digest,
    worker_result_digest: original.worker_result_digest,
    reads: purposes.map(purpose => ({
      purpose,
      reader,
      status: "awaiting_delivery",
      worker_outcome: "service_success",
      worker_request_id: original.result.calls[3 + (purpose === "health" ? 1 : 0)]!.request_id,
      audit_event_ids: [],
      audit_outcomes: [],
      full_object_bytes_proven: false,
    })),
    authorized_request_window: { from: "2026-10-11T20:44:20+00:00", through: "2026-10-11T20:44:50+00:00" },
    independent_collection_proven: false,
    effective_access_claim: false,
  };
};

const resultCalls = Array.from({ length: 5 }, (_, index) => ({
  operation: ["GetCallerIdentity", "AssumeRole", "GetCallerIdentity", "ListObjectsV2", "ListObjectsV2"][index],
  role: ["controller", "controller", "collector", "collector", "collector"][index],
  request_id: index < 3 ? `audit-request-${index}` : `list-request-${index - 3}`,
  http_status: 200,
}));

export const collectedReview: AuditCollectedReview = {
  schema_version: "bluefire.s3-audit-collected-review.v1",
  workflow_job_id: owner,
  operation_job_id: operation,
  phase: "baseline",
  collection_run_id: run("3"),
  manifest_digest: digest("a"),
  request_digest: collectionRequestDigest,
  worker_result_digest: digest("b"),
  reservation_digest: collectionReservationDigest,
  outcome_digest: digest("c"),
  source,
  original_pair: pair,
  receipt: {
    schema_version: "bluefire.s3-execution.v1",
    request_digest: collectionRequestDigest,
    admission: { accepted: true, problem: null },
    dispatch: "permit_issued",
    send_debits: 5,
    result: {
      schema_version: "bluefire.s3-worker-result.v3",
      request_digest: collectionRequestDigest,
      outcome: "observed",
      data: {
        schema_version: "bluefire.s3-audit-collection-observation.v1",
        collection_digest: discovery.collection_digest,
        pair_digest: discovery.pair_digest,
        audit_source_digest: discovery.audit_source_digest,
        reservation_digest: collectionReservationDigest,
        discovery,
        objects: [],
        usage: { sdk_body_bytes: 0, files: 0, compressed_bytes: 0, expanded_bytes: 0, events: 0 },
        normalized_digest: digest("d"),
        correlations: { probe: correlation("probe"), legitimate: correlation("legitimate") },
        delivery_state: "incomplete",
        effective_access_claim: false,
        log_integrity_proven: false,
      },
      problem: null,
      send_permits_consumed: 5,
      calls: resultCalls,
      runtime_isolation_proven: false,
    },
    cleanup: "verified",
    provenance: "runner_reported",
    reservation_digest: collectionReservationDigest,
  },
  collection_provenance: "authenticated_source_retrieval",
  raw_bytes_retained: false,
  log_integrity_proven: false,
  effective_access_claim: false,
  review_digest: digest("e"),
  review_id: operation,
  created_at: "2026-10-11T20:44:53Z",
};

export const collectedSummary: AuditCollectionSummary = {
  review_id: collectedReview.review_id,
  created_at: collectedReview.created_at,
  review_digest: collectedReview.review_digest,
  phase: collectedReview.phase,
  collection_run_id: collectedReview.collection_run_id,
  original_run_ids: [reads[0].run_id, reads[1].run_id],
  reported_delivery_state: "incomplete",
  statuses: ["awaiting_delivery", "awaiting_delivery", "awaiting_delivery"],
  collection_provenance: "authenticated_source_retrieval",
};
