import { compositionJobId, type CompositionJob } from "../src/lib/composition";
import type { FileAccessOperationEnvelope, FileAccessReview, FileAccessSubmission, MacOSFileAccessControl, MacOSFileAccessControlState, MacOSFileAccessStatus } from "../src/lib/file-access";

// Authored contract fixtures only; no native workspace or access proof.
export const macOSOwner = `file-control-${"a".repeat(64)}`;
export const macOSDigest = (char = "b") => `sha256:${char.repeat(64)}`;
export function macOSStatusFixture(available = true): MacOSFileAccessStatus {
  return {
    schema_version: "bluefire.file-access-status.v1", platform: "macos", available,
    problem: available ? null : { code: "file_access_enrollment_unavailable", message: "The original protected macOS workspace is required." },
    enrollment: available ? { enrollment_id: `file-enrollment-${"c".repeat(32)}`, enrollment_digest: macOSDigest(), expires_at_ms: Date.now() + 60_000, owner_uid: 501, probe_uid: 502 } : null,
    allowed_operations: [],
  };
}
export function macOSSubmissionFixture(operation: "baseline" | "harden" | "rollback" = "baseline"): FileAccessSubmission {
  return { submission_id: "11111111-1111-4111-8111-111111111111", review: { operation, control_owner_id: macOSOwner }, review_digest: macOSDigest("d"), reviewed_by: "synthetic-reviewer" };
}
export function macOSJobFixture(body = macOSSubmissionFixture(), state = "completed"): CompositionJob {
  return { job_id: compositionJobId(body.submission_id), kind: "file_access.operation", state, request: { ...body.review }, progress: { submitted_request: body } };
}
export function macOSControlFixture(status: MacOSFileAccessControlState = "created"): MacOSFileAccessControl {
  const revision = status === "created" ? 1 : status === "baseline_verified" ? 2 : status === "rolled_back" ? 4 : 3;
  const operations = status === "created" ? [] : [macOSJobFixture()];
  if (["hardened", "rolled_back", "uncertain"].includes(status)) operations.push(macOSJobFixture({ ...macOSSubmissionFixture("harden"), submission_id: "22222222-2222-4222-8222-222222222222" }, status === "uncertain" ? "interrupted" : "completed"));
  if (status === "rolled_back") operations.push(macOSJobFixture({ ...macOSSubmissionFixture("rollback"), submission_id: "33333333-3333-4333-8333-333333333333" }));
  return {
    schema_version: "bluefire.file-access-control.v1", platform: "macos", control_owner_id: macOSOwner, control_digest: macOSDigest("e"), revision, status,
    resource: { resource_id: `file-generation-${"f".repeat(32)}`, resource_generation: `file-generation-${"f".repeat(32)}`, sha256: macOSDigest("0"), size: 512, record_count: 8, mode: status === "hardened" ? "0600" : "0640" },
    baseline: status === "created" ? null : { baseline_digest: macOSDigest("1"), non_owner: "allowed", owner: "allowed", record_count: 8, sha256: macOSDigest("0") },
    usage_state: status === "uncertain" ? "pending" : "settled",
    allowed_operations: status === "created" ? ["baseline"] : status === "baseline_verified" ? ["harden"] : status === "hardened" ? ["rollback"] : status === "rolled_back" ? ["baseline", "harden"] : [],
    operations,
  };
}
export function macOSReviewFixture(operation: "baseline" | "harden" | "rollback" = "baseline", control = macOSControlFixture()): FileAccessReview {
  return { schema_version: "bluefire.file-access-control-review.v1", operation, control_owner_id: macOSOwner, context_digest: macOSDigest("2"), enrollment_digest: macOSDigest(), control_digest: control.control_digest, expires_at_ms: Date.now() + 5000, effect: `Review the original macOS workspace ${operation} operation.`, review_digest: macOSDigest("d") };
}
export function macOSOperationFixture(body = macOSSubmissionFixture(), control = macOSControlFixture("baseline_verified")): FileAccessOperationEnvelope {
  return { schema_version: "bluefire.file-access-operation.v1", job: macOSJobFixture(body), control, reconciliation: null, reconciliation_receipt: null };
}
