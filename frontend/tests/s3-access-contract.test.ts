import { expect, it, vi } from "vitest";
import { checkedEnvironments, checkedExercise, checkedList, checkedReview, clearS3Pending, confirmsS3Pending, readS3Pending, readS3Stops, s3Api, s3ReviewCurrent, s3StageAvailable, storeS3Pending, storeS3Stop, type S3Exercise, type S3Pending, type S3Review } from "../src/lib/s3-access";
import { s3Environment, s3Exercise, s3Hash, s3Observed, s3Operation, s3Owner, s3Review } from "./s3-access-fixture";
import { collectedReview } from "./s3-audit-collected-fixture";

function pending(): S3Pending {
  return { kind: "stage", owner: s3Owner, operation: s3Operation, request: { submission_id: "22222222-2222-2222-2222-222222222222", phase: "baseline", review_digest: s3Hash, reviewed_by: "operator" } };
}

it("rejects a response for another saved owner before rendering its evidence", () => {
  expect(() => checkedExercise(s3Exercise(), s3Operation)).toThrow(/different work/);
});

it.each(["../other", "https://example.invalid", "run-invalid"])("rejects unsafe retained run reference %s", reference => {
  const value = s3Observed(); value.operations[0]!.run_ids = [reference];
  expect(() => checkedExercise(value, s3Owner)).toThrow();
});

it("rejects duplicate operations and mismatched active-owner lineage", () => {
  const value = s3Observed(); value.operations.push(structuredClone(value.operations[0]!));
  expect(() => checkedExercise(value, s3Owner)).toThrow();
  const active = s3Exercise();
  active.active_job = { job_id: s3Operation, state: "running", request: { s3_access: { workflow_job_id: s3Operation, phase: "inspect", review: { review_digest: s3Hash } } } };
  expect(() => checkedExercise(active, s3Owner)).toThrow();
});

it("does not accept an unprovided independent-effectiveness claim", () => {
  const value = s3Exercise();
  expect(() => checkedExercise({ ...value, live_outcome_verified: true } as unknown as typeof value, s3Owner)).toThrow();
});

it("binds review owner and phase without accepting a substituted proposal", () => {
  expect(() => checkedReview(s3Review(), s3Operation, "inspect")).toThrow();
  expect(() => checkedReview(s3Review(), s3Owner, "apply")).toThrow();
  expect(checkedReview(s3Review(), s3Owner, "inspect")).toEqual(s3Review());
});

it("retains exact submission identity and clears only its own record", () => {
  const value = pending(); storeS3Pending(value);
  expect(readS3Pending()).toEqual(value);
  expect(() => clearS3Pending({ ...value, owner: s3Operation })).toThrow();
  expect(readS3Pending()).toEqual(value);
  clearS3Pending(value);
  expect(readS3Pending()).toBeNull();
});

it("requires the exact operation and reviewed digest before clearing uncertain work", () => {
  const value = s3Observed();
  expect(confirmsS3Pending(value, pending())).toBe(true);
  value.operations[0]!.review_digest = `sha256:${"9".repeat(64)}`;
  expect(confirmsS3Pending(value, pending())).toBe(false);
});

it("confirms creation only for the original enrolled context, not merely its label", () => {
  const value = s3Exercise();
  const request: S3Pending = { kind: "create", owner: s3Owner, request: { submission_id: "11111111-1111-1111-1111-111111111111", environment_id: value.environment.environment_id, context_digest: s3Hash } };
  expect(confirmsS3Pending(value, request)).toBe(true);
  value.context_digest = `sha256:${"9".repeat(64)}`;
  expect(confirmsS3Pending(value, request)).toBe(false);
});

it("retains canonical stop references without duplicating them", () => {
  storeS3Stop(s3Owner); storeS3Stop(s3Owner);
  expect(readS3Stops()).toEqual([s3Owner]);
  expect(() => storeS3Stop("../another-owner")).toThrow();
  expect(readS3Stops()).toEqual([s3Owner]);
});

it("requires bounded enrollment and saved-list structures before displaying controls", () => {
  const row = { environment: s3Environment, available: false, problem: "Unavailable", context_digest: s3Hash };
  const environments = { schema_version: "bluefire.s3-environments.v1" as const, environments: [row], problem: null };
  expect(checkedEnvironments(environments)).toEqual(environments);
  expect(() => checkedEnvironments({ ...environments, environments: [row, row] })).toThrow();
  expect(() => checkedEnvironments({ ...environments, environments: [{ ...row, available: true }] })).toThrow();
  expect(() => checkedList({ schema_version: "bluefire.s3-exercise-list.v1", truncated: false, exercises: [{ workflow_job_id: "../other", name: "Other", bucket: "test-bucket", policy_state: "baseline", updated_at: "2026-10-09" }] })).toThrow();
});

it.each(["stopped", "saved_result_recovery_available"] as const)("rejects non-boolean %s state", key => {
  const value = s3Exercise();
  expect(() => checkedExercise({ ...value, [key]: "true" } as unknown as typeof value, s3Owner)).toThrow();
});

it.each([-1, 1.5, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1])("rejects malformed remaining budget %s", amount => {
  const value = s3Exercise(); value.remaining.api_calls = amount;
  expect(() => checkedExercise(value, s3Owner)).toThrow();
});

it("rejects duplicate, unknown or unsupported reader facts rather than choosing one", () => {
  const value = s3Observed();
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  value.operations[0]!.outcome.facts[2]!.purpose = "canary";
  expect(() => checkedExercise(value, s3Owner)).toThrow();
  value.operations[0]!.outcome.facts[2]!.purpose = "primary";
  expect(() => checkedExercise(value, s3Owner)).toThrow();
  value.operations[0]!.outcome.facts = [{ reader: "probe", purpose: "health", result: "read" }];
  expect(() => checkedExercise(value, s3Owner)).toThrow();
});

it("rejects malformed active reviews and contradictory recovery controls", () => {
  const value = s3Exercise(); value.saved_result_recovery_available = true;
  expect(() => checkedExercise(value, s3Owner)).toThrow();
  value.active_job = { job_id: s3Operation, state: "running", request: { s3_access: { workflow_job_id: s3Owner, phase: "inspect", review: { review_digest: s3Hash } } } };
  value.allowed_phases = [];
  expect(() => checkedExercise(value, s3Owner)).toThrow();
  value.saved_result_recovery_available = false;
  expect(checkedExercise(value, s3Owner)).toEqual(value);
});

it("rejects missing or unaffordable follow-up allowance in a stage review", () => {
  const value = s3Review(); value.required_remaining.api_calls = 1;
  expect(() => checkedReview(value, s3Owner, "inspect")).toThrow();
  value.required_remaining.api_calls = 301;
  expect(() => checkedReview(value, s3Owner, "inspect")).toThrow();
});

it("rejects extra pending request fields and oversized local records", () => {
  const value = pending();
  Object.assign(value.request, { extra: true });
  expect(() => storeS3Pending(value)).toThrow();
  localStorage.setItem("bluefire.s3.pending.v1", " ".repeat(4097));
  expect(() => readS3Pending()).toThrow();
  localStorage.setItem("bluefire.s3.pending-stops.v1", " ".repeat(4097));
  expect(() => readS3Stops()).toThrow();
});

it("rejects noncanonical route and pending arguments before transport", async () => {
  const fetch = vi.spyOn(globalThis, "fetch");
  await expect(s3Api.read("../other")).rejects.toThrow();
  await expect(s3Api.review("../other", "inspect")).rejects.toThrow();
  await expect(s3Api.control("../other", "stop")).rejects.toThrow();
  await expect(s3Api.send({ ...pending(), owner: "../other" })).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
});

function auditExercise(): S3Exercise {
  const source = structuredClone(collectedReview.source);
  const pair = structuredClone(collectedReview.original_pair);
  const value = s3Exercise();
  value.schema_version = "bluefire.s3-exercise.v3";
  value.environment = { ...value.environment, scope: structuredClone(pair.reads[0].request.scope) as S3Exercise["environment"]["scope"], audit_source: structuredClone(source) };
  value.operations = [{ ...s3Observed().operations[0]!, operation_job_id: pair.operation_job_id, review_digest: pair.review_digest, outcome_digest: pair.outcome_digest, run_ids: pair.reads.map(read => read.run_id) }];
  value.operations[0]!.outcome.provenance = "runner_reported";
  value.allowed_phases = ["audit_baseline"];
  const workflow = { ...Object.fromEntries(Object.entries(source.audit_limits).map(([key, amount]) => [key, amount * 2])), batches: 2, wire_plus_expansion_bytes: (source.audit_limits.sdk_body_bytes! + source.audit_limits.expanded_bytes!) * 2 };
  value.audit_collection = {
    schema_version: "bluefire.s3-audit-workspace.v1", source, source_digest: s3Hash, workflow_digest: s3Hash,
    budget: { per_batch: { ...source.audit_limits }, workflow },
    reserved: Object.fromEntries(Object.keys(workflow).map(key => [key, 0])), held: { ...workflow },
    slots: [
      { phase: "baseline", stage: "audit_baseline", state: "ready", problem: null, operation_job_id: null, review_id: null, original_pair: pair },
      { phase: "retest", stage: "audit_retest", state: "unavailable", problem: "original_pair_unavailable", operation_job_id: null, review_id: null, original_pair: null },
    ],
  };
  return value;
}

function auditReview(value = auditExercise()): S3Review {
  const workspace = value.audit_collection!;
  const pair = workspace.slots[0].original_pair!;
  const prefix = `${workspace.source.exact_delivery_root_prefix}2026/10/11/`;
  const reserved = { api_calls: 9, business_attempts: 0, sessions: 1, policy_changes: 0, rollbacks: 0 };
  return { ...s3Review("audit_baseline"), schema_version: "bluefire.s3-stage-review.v3", fixture_lifecycle: null, reserved, required_remaining: { ...reserved }, prior_run_ids: pair.reads.map(read => read.run_id), audit_collection: {
    schema_version: "bluefire.s3-audit-stage-review.v1", source: structuredClone(workspace.source), source_digest: workspace.source_digest, original_pair: structuredClone(pair), pair_digest: s3Hash,
    listing_date: "2026-10-11", collection_expires_at: "2026-10-11T21:00:00Z",
    list_parameters: [{ Bucket: workspace.source.audit_bucket, ExpectedBucketOwner: workspace.source.source_account_id, Prefix: prefix, StartAfter: `${prefix}123456789012_CloudTrail_us-east-1_20261011T2044Z_`, MaxKeys: 16 }],
  } };
}

function completedAudit(): S3Exercise {
  const value = auditExercise();
  const workspace = value.audit_collection!;
  value.allowed_phases = [];
  value.audit = "authenticated_retrieval";
  value.operations.push({ ...structuredClone(value.operations[0]!), phase: "audit_baseline", operation_job_id: s3Operation, run_ids: [collectedReview.collection_run_id], outcome: { ...value.operations[0]!.outcome, facts: [], policy_observation: null, audit: "authenticated_retrieval" } });
  Object.assign(workspace.slots[0], { state: "completed", problem: "phase_consumed", operation_job_id: s3Operation, review_id: s3Operation });
  workspace.reserved = Object.fromEntries(Object.entries(workspace.budget.workflow).map(([key, amount]) => [key, amount / 2]));
  workspace.held = { ...workspace.reserved };
  return value;
}

it("accepts paired v3 collection scope without promoting it to independent effectiveness", () => {
  const value = auditExercise();
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  expect(s3StageAvailable(value, "audit_baseline")).toBe(true);
  expect(s3StageAvailable(value, "audit_retest")).toBe(false);
  expect(checkedReview(auditReview(value), s3Owner, "audit_baseline")).toEqual(auditReview(value));
  expect(s3ReviewCurrent(value, auditReview(value))).toBe(true);
  const completed = completedAudit();
  expect(checkedExercise(completed, s3Owner)).toEqual(completed);
  expect(completed.independent_observations).toBe(0);
  expect(completed.live_outcome_verified).toBe(false);
});

it("accepts manual recovery only for a failed consumed v3 collection with unknown cleanup", () => {
  const value = completedAudit();
  value.audit = "not_collected"; value.saved_result_recovery_available = true;
  Object.assign(value.operations[1]!.outcome, { state: "failed", cleanup: "unknown", complete: false, audit: "not_collected" });
  Object.assign(value.audit_collection!.slots[0], { state: "failed", problem: "phase_consumed", review_id: null });
  expect(checkedExercise(value, s3Owner)).toEqual(value);

  const forged = completedAudit(); forged.saved_result_recovery_available = true;
  expect(() => checkedExercise(forged, s3Owner)).toThrow();
});

it("does not grant finalized rechecks to legacy exercise schemas", () => {
  const legacyV1 = s3Exercise(); legacyV1.saved_result_recovery_available = true;
  expect(() => checkedExercise(legacyV1, s3Owner)).toThrow();

  const legacyV2 = s3Exercise();
  legacyV2.schema_version = "bluefire.s3-exercise.v2";
  legacyV2.environment.fixture_lifecycle = { schema_version: "bluefire.s3-fixture-enrollment.v2", scope_digest: s3Hash, generation_digest: s3Hash, exclusive_writer_digest: s3Hash, bucket_shape: "never_versioned_no_object_lock" };
  legacyV2.fixtures = (["primary", "health"] as const).map(purpose => ({ purpose, key: `bluefire/s3-${"a".repeat(32)}/${purpose === "primary" ? "records" : "health"}.jsonl`, state: "not_prepared" as const, etag: null, sha256: s3Hash, size_bytes: 3, intent_id: "b".repeat(64), request_ids: [], provenance: "not_observed" as const }));
  legacyV2.environment.scope.objects = legacyV2.fixtures.map(({ purpose, key, sha256, size_bytes }) => ({ purpose, key, sha256, size_bytes }));
  legacyV2.fixture_state = "not_prepared"; legacyV2.policy_retention = null; legacyV2.resource_disposition = "not_prepared";
  legacyV2.allowed_phases = []; legacyV2.saved_result_recovery_available = true;
  expect(() => checkedExercise(legacyV2, s3Owner)).toThrow();
});

it("keeps an affordable audit collection available alongside an apply budget warning", () => {
  const value = auditExercise();
  value.problem = "apply_budget_warning";
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  expect(s3StageAvailable(value, "audit_baseline")).toBe(true);
  expect(s3StageAvailable(value, "apply")).toBe(false);
});

it("binds the retest collection to its own original pair and stage", () => {
  const value = auditExercise(); const workspace = value.audit_collection!;
  const pair = workspace.slots[0].original_pair!; pair.phase = "retest";
  value.operations[0]!.phase = "retest"; value.allowed_phases = ["audit_retest"];
  Object.assign(workspace.slots[0], { state: "unavailable", problem: "original_pair_unavailable", original_pair: null });
  Object.assign(workspace.slots[1], { state: "ready", problem: null, original_pair: pair });
  const review = auditReview(); review.phase = "audit_retest"; review.audit_collection!.original_pair.phase = "retest";
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  expect(checkedReview(review, s3Owner, "audit_retest")).toEqual(review);
  expect(s3ReviewCurrent(value, review)).toBe(true);
  expect(s3StageAvailable(value, "audit_baseline")).toBe(false);
});

it("derives the per-batch budget from the narrower enrolled scope", () => {
  const value = auditExercise(); const workspace = value.audit_collection!;
  value.environment.scope.limits.audit_events = 800;
  workspace.slots[0].original_pair!.reads.forEach(read => { read.request.scope = structuredClone(value.environment.scope); });
  workspace.budget.per_batch.events = 400; workspace.budget.workflow.events = 800; workspace.held.events = 800;
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  workspace.budget.per_batch.events = 500; workspace.budget.workflow.events = 1000; workspace.held.events = 1000;
  expect(() => checkedExercise(value, s3Owner)).toThrow();
});

it("preserves unavailable historical and unreleased collection slots without offering authority", () => {
  const value = auditExercise(); value.allowed_phases = [];
  for (const problem of ["collection_not_enabled", "historical_authority_absent", "original_interval_expired"] as const) {
    Object.assign(value.audit_collection!.slots[0], { state: "unavailable", problem });
    expect(checkedExercise(value, s3Owner)).toEqual(value);
    expect(s3StageAvailable(value, "audit_baseline")).toBe(false);
  }
  Object.assign(value.audit_collection!.slots[0], { state: "ready", problem: null });
  expect(checkedExercise(value, s3Owner)).toEqual(value);
  expect(s3StageAvailable(value, "audit_baseline")).toBe(false);
});

it.each<[string, (value: S3Exercise) => void]>([
  ["missing workspace", value => { delete value.audit_collection; }],
  ["missing enrollment", value => { delete value.environment.audit_source; }],
  ["substituted source", value => { value.audit_collection!.source.audit_source_id = "other-source"; }],
  ["unknown slot state", value => { Object.assign(value.audit_collection!.slots[0], { state: "authorized" }); }],
  ["unknown readiness reason", value => { Object.assign(value.audit_collection!.slots[1], { problem: "automatically_retry" }); }],
  ["reversed slots", value => { value.audit_collection!.slots.reverse(); }],
  ["missing original pair", value => { value.audit_collection!.slots[0].original_pair = null; }],
  ["another original owner", value => { value.audit_collection!.slots[0].original_pair!.workflow_job_id = s3Operation; }],
  ["unjoined original operation", value => { value.audit_collection!.slots[0].original_pair!.operation_job_id = s3Operation; }],
  ["substituted original digest", value => { value.operations[0]!.outcome_digest = s3Hash; }],
  ["reordered original runs", value => { value.operations[0]!.run_ids.reverse(); }],
  ["unverified original cleanup", value => { value.operations[0]!.outcome.cleanup = "unknown"; value.allowed_phases = []; }],
  ["synthetic original reads", value => { value.operations[0]!.outcome.provenance = "synthetic"; }],
  ["different enrolled scope", value => { value.environment.scope.bucket = "different-owned-bucket"; }],
  ["unreleased allowed phase", value => { Object.assign(value.audit_collection!.slots[0], { state: "unavailable", problem: "collection_not_enabled" }); }],
  ["extra budget dimension", value => { value.audit_collection!.budget.per_batch.extra = 1; }],
  ["larger per batch", value => { value.audit_collection!.budget.per_batch.files = 5; }],
  ["inconsistent total", value => { value.audit_collection!.budget.workflow.events = 999; }],
  ["invented reservation", value => { value.audit_collection!.reserved.api_calls = 9; }],
  ["invented remaining allowance", value => { value.audit_collection!.held.api_calls = 19; }],
  ["claimed retrieval without result", value => { value.audit = "authenticated_retrieval"; }],
])("rejects v3 collection with %s", (_name, change) => {
  const value = auditExercise(); change(value);
  expect(() => checkedExercise(value, s3Owner)).toThrow();
});

it.each<[string, (value: S3Exercise) => void]>([
  ["refunded phase", value => { value.audit_collection!.reserved.api_calls = 0; }],
  ["wrong review identity", value => { value.audit_collection!.slots[0].review_id = s3Owner; }],
  ["missing saved collection", value => { value.operations.pop(); }],
  ["unexpected collection facts", value => { value.operations[1]!.outcome.facts = [{ reader: "probe", purpose: "primary", result: "read" }]; }],
  ["unverified collection cleanup", value => { value.operations[1]!.outcome.cleanup = "unknown"; }],
  ["synthetic retrieval", value => { value.operations[1]!.outcome.provenance = "synthetic"; }],
  ["wrong collection stage", value => { value.operations[1]!.phase = "audit_retest"; }],
  ["unclaimed retained collection", value => { Object.assign(value.audit_collection!.slots[0], { state: "unavailable", problem: "collection_not_enabled", operation_job_id: null, review_id: null }); }],
])("rejects consumed collection with %s", (_name, change) => {
  const value = completedAudit(); change(value);
  expect(() => checkedExercise(value, s3Owner)).toThrow();
});

it("keeps failed and interrupted collections claimed without a fresh retry identity", () => {
  const failed = completedAudit(); failed.audit = "not_collected";
  Object.assign(failed.operations[1]!.outcome, { state: "failed", audit: "not_collected", complete: false });
  Object.assign(failed.audit_collection!.slots[0], { state: "failed", review_id: null });
  expect(checkedExercise(failed, s3Owner)).toEqual(failed);
  const interrupted = completedAudit(); interrupted.audit = "not_collected"; interrupted.operations.pop();
  Object.assign(interrupted.audit_collection!.slots[0], { state: "reserved", review_id: null });
  interrupted.active_job = { job_id: s3Operation, state: "interrupted", request: { s3_access: { workflow_job_id: s3Owner, phase: "audit_baseline", review: { review_digest: s3Hash } } } };
  interrupted.saved_result_recovery_available = true;
  expect(checkedExercise(interrupted, s3Owner)).toEqual(interrupted);
  expect(s3StageAvailable(interrupted, "audit_baseline")).toBe(false);
  interrupted.active_job.job_id = `job-${"8".repeat(32)}`;
  expect(() => checkedExercise(interrupted, s3Owner)).toThrow();
});

it.each<[string, (value: S3Review) => void]>([
  ["missing collection", value => { delete value.audit_collection; }],
  ["wrong pair phase", value => { value.audit_collection!.original_pair.phase = "retest"; }],
  ["missing prior read", value => { value.prior_run_ids.pop(); }],
  ["excess sends", value => { value.reserved.api_calls = 10; value.required_remaining.api_calls = 10; }],
  ["business write allowance", value => { value.reserved.policy_changes = 1; value.required_remaining.policy_changes = 1; }],
  ["refreshed expiry", value => { value.audit_collection!.collection_expires_at = "2026-10-11T21:30:00Z"; }],
  ["invalid listing date", value => { value.audit_collection!.listing_date = "2026-02-30"; }],
  ["post-expiry listing", value => { value.audit_collection!.listing_date = "2026-10-12"; }],
  ["broader prefix", value => { value.audit_collection!.list_parameters[0]!.Prefix = "AWSLogs/"; }],
  ["earlier cursor", value => { value.audit_collection!.list_parameters[0]!.StartAfter = value.audit_collection!.list_parameters[0]!.StartAfter.replace("T2044", "T2043"); }],
  ["different bucket owner", value => { value.audit_collection!.list_parameters[0]!.ExpectedBucketOwner = "999999999999"; }],
  ["increased page size", value => { Object.assign(value.audit_collection!.list_parameters[0]!, { MaxKeys: 17 }); }],
  ["extra listing", value => { value.audit_collection!.list_parameters.push(structuredClone(value.audit_collection!.list_parameters[0]!)); }],
  ["unexpected parameters", value => { Object.assign(value.audit_collection!.list_parameters[0]!, { ContinuationToken: "next" }); }],
])("rejects audit stage review with %s", (_name, change) => {
  const value = auditReview(); change(value);
  expect(() => checkedReview(value, s3Owner, "audit_baseline")).toThrow();
});

it("invalidates current review authority when same-revision source, pair or phase readiness changes", () => {
  const value = auditExercise(); const review = auditReview(value);
  value.audit_collection!.source_digest = `sha256:${"7".repeat(64)}`;
  expect(s3ReviewCurrent(value, review)).toBe(false);
  value.audit_collection!.source_digest = review.audit_collection!.source_digest;
  value.audit_collection!.slots[0].original_pair!.review_digest = s3Hash;
  expect(s3ReviewCurrent(value, review)).toBe(false);
  value.audit_collection!.slots[0].original_pair = structuredClone(review.audit_collection!.original_pair);
  value.allowed_phases = [];
  expect(s3ReviewCurrent(value, review)).toBe(false);
});

it("does not grant legacy exercise or review schemas collection authority", () => {
  for (const schema_version of ["bluefire.s3-exercise.v1", "bluefire.s3-exercise.v2"] as const) {
    expect(() => checkedExercise({ ...auditExercise(), schema_version }, s3Owner)).toThrow();
  }
  for (const schema_version of ["bluefire.s3-stage-review.v1", "bluefire.s3-stage-review.v2"] as const) {
    expect(() => checkedReview({ ...auditReview(), schema_version }, s3Owner, "audit_baseline")).toThrow();
  }
  const value = auditReview(); value.phase = "inspect"; value.audit_collection = null;
  expect(checkedReview(value, s3Owner, "inspect")).toEqual(value);
});

it("retains a collection pending request using the existing exact identity format", () => {
  const value = pending(); if (value.kind !== "stage") throw new Error("Expected stage fixture");
  value.request.phase = "audit_baseline";
  storeS3Pending(value);
  expect(readS3Pending()).toEqual(value);
  const exercise = completedAudit(); exercise.operations[1]!.review_digest = value.request.review_digest;
  expect(confirmsS3Pending(exercise, value)).toBe(true);
  exercise.operations[1]!.phase = "audit_retest";
  expect(confirmsS3Pending(exercise, value)).toBe(false);
});
