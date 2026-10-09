import { FILE_ACCESS_PACK, type CompositionObjective, type CompositionReview } from "../src/lib/composition";
import type { FileAccessControl, FileAccessObservation, FileAccessOperationEnvelope, FileAccessReview, FileAccessStatus, FileAccessSubmission } from "../src/lib/file-access";
import { attemptFixture, controlId, objectiveFixture, proposalId, reviewFixture, testDigest } from "./composition-fixture";

// Authored presentation fixtures, not enrollment or effective-access proof.
export function fileAccessStatusFixture(): FileAccessStatus {
  return { schema_version: "bluefire.file-access-status.v1", available: true, problem: null, enrollment: { enrollment_id: "file-access-test-generation", enrollment_digest: testDigest, expires_at_ms: Date.now() + 600000, owner_uid: 1000, probe_uid: 1002 }, allowed_operations: ["create"] };
}
export function fileAccessControlFixture(): FileAccessControl {
  return { schema_version: "bluefire.file-access-control.v1", control_owner_id: controlId, control_digest: testDigest, revision: 3, status: "hardened", resource: { resource_id: "resource-test", resource_generation: "generation-test", sha256: testDigest, size: 512, record_count: 8, mode: "0600" }, baseline: { baseline_digest: testDigest, non_owner: "allowed", owner: "allowed", record_count: 8, sha256: testDigest }, usage_state: "settled", allowed_operations: ["rollback", "reset"], operations: [] };
}
export function fileAccessReviewFixture(): FileAccessReview {
  return { schema_version: "bluefire.file-access-control-review.v1", operation: "rollback", control_owner_id: controlId, context_digest: testDigest, enrollment_digest: testDigest, control_digest: testDigest, expires_at_ms: Date.now() + 60000, effect: "Restore only the retained generated file to its recorded 0640 baseline and verify fresh reads.", review_digest: testDigest };
}
export function fileAccessSubmissionFixture(): FileAccessSubmission {
  return { submission_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", review: { operation: "rollback", control_owner_id: controlId }, review_digest: testDigest, reviewed_by: "reviewer" };
}
export function fileAccessOperationFixture(): FileAccessOperationEnvelope {
  return { schema_version: "bluefire.file-access-operation.v1", job: { job_id: proposalId, kind: "file_access.operation", state: "completed", request: {}, progress: { submitted_request: fileAccessSubmissionFixture() } }, control: fileAccessControlFixture(), reconciliation: null, reconciliation_receipt: null };
}
export function fileAccessObservationFixture(operation: "baseline" | "rollback" = "rollback"): FileAccessObservation {
  return { schema_version: "bluefire.file-access-control-observation.v1", operation, non_owner: "allowed", owner: "allowed", resource_generation: "generation-test", record_count: 8, sha256: testDigest, mode: "0640", source_digest: testDigest, observed_at_ms: Date.now() };
}
export function fileAccessCompositionReviewFixture(): CompositionReview {
  const value = reviewFixture();
  return { ...value, schema_version: "bluefire.composition-review.v2", pack: FILE_ACCESS_PACK,
    snapshot: { ...value.snapshot, pack: FILE_ACCESS_PACK },
    objective: { question: "Prevent fresh non-owner reads and preserve owner access", predicate: { kind: "non_owner_denied_owner_preserves_records", data_class: "generated_public_jsonl", sha256: testDigest, record_count: 8 } },
    environment: { control_owner_id: controlId, runner_id: "local-runner", control_digest: testDigest, resource_id: "resource-test", resource_generation: "generation-test", resource_digest: testDigest, probe_enrollment_digest: testDigest, baseline_digest: testDigest, control_revision: 3, mode: "0600" },
  };
}
export function fileAccessObjectiveFixture(decision: "allowed" | "permission_denied" | "unknown" = "permission_denied", withAttempt = true): CompositionObjective {
  const value = objectiveFixture();
  value.grant.document = { ...value.grant.document, ...fileAccessCompositionReviewFixture(), schema_version: "bluefire.capability-grant.v2" };
  if (!withAttempt) return value;
  const attempt = attemptFixture();
  const checks = Object.fromEntries(["probe_authenticated", "non_owner_denied", "owner_read_verified", "same_resource", "same_control_revision", "same_probe_enrollment", "content_preserved", "identity_unchanged", "parents_unchanged", "acl_unchanged", "run_cleaned", "request_closed"].map(key => [key, key !== "non_owner_denied" || decision === "permission_denied"]));
  attempt.progress.verified_result = { run_id: "run-proof", source_binding: {}, file_access_result: { probe_verified: true, non_owner_decision: decision, owner_verified: true, owner_decision: "allowed", resource_digest: testDigest, resource_generation: "generation-test", control_revision: 3, probe_enrollment_digest: testDigest, mode: "0600", sha256: testDigest, record_count: 8, identity_unchanged: true, parents_unchanged: true, acl_unchanged: true }, cleanup: { run: "complete", request: "verified_closed" }, objective: { established: decision === "permission_denied", checks } };
  value.attempts = [attempt];
  return value;
}
