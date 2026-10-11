import type { S3Environment, S3Exercise, S3Phase, S3Review } from "../src/lib/s3-access";

export const s3Owner = `job-${"1".repeat(32)}`;
export const s3Operation = `job-${"2".repeat(32)}`;
export const s3Run = `run-20261009T000000Z-${"3".repeat(16)}`;
export const s3Hash = `sha256:${"4".repeat(64)}`;
export const s3Budget = { api_calls: 300, business_attempts: 6, sessions: 6, policy_changes: 1, rollbacks: 1 };
export const s3Environment: S3Environment = {
  environment_id: "synthetic-s3", display_name: "Synthetic S3 review",
  scope: { bucket: "bluefire-synthetic-fixture", region: "us-east-1", account_id: "123456789012", expires_at: "2026-10-10T00:00:00Z", roles: {}, objects: [], limits: s3Budget },
  baseline_policy: {}, exclusive_writer_digest: s3Hash,
};

export function s3Exercise(): S3Exercise {
  return {
    schema_version: "bluefire.s3-exercise.v1", workflow_job_id: s3Owner, context_digest: s3Hash,
    environment: structuredClone(s3Environment), revision: 0, policy_state: "baseline", stopped: false,
    operations: [], active_job: null, allowed_phases: ["inspect"], saved_result_recovery_available: false,
    remaining: { ...s3Budget }, problem: null, audit: "not_collected", resource_disposition: "retained",
    independent_observations: 0, live_outcome_verified: false,
  };
}

export function s3Review(phase: S3Phase = "inspect"): S3Review {
  return { schema_version: "bluefire.s3-stage-review.v1", workflow_job_id: s3Owner, phase, revision: 0,
    review_digest: s3Hash, remaining: { ...s3Budget }, reserved: { ...s3Budget, api_calls: 2, business_attempts: 0, sessions: 0, policy_changes: 0, rollbacks: 0 },
    required_remaining: { api_calls: 2, business_attempts: 0, sessions: 0, policy_changes: 0, rollbacks: 0 },
    policy_change: null, prior_run_ids: [] };
}

export function s3Observed(): S3Exercise {
  const value = s3Exercise();
  value.operations = [{ phase: "baseline", operation_job_id: s3Operation, review_digest: s3Hash,
    run_ids: [s3Run, `run-20261009T000000Z-${"6".repeat(16)}`], outcome_digest: s3Hash, outcome: { state: "observed", cleanup: "verified", complete: true,
      facts: [{ reader: "probe", purpose: "primary", result: "read" }, { reader: "legitimate", purpose: "primary", result: "read" }, { reader: "legitimate", purpose: "health", result: "read" }],
      policy_observation: null, provenance: "synthetic", independent_observations: 0, audit: "not_collected", resource_disposition: "retained" } }];
  return value;
}
