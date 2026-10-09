import { beforeEach, expect, it } from "vitest";
import { checkedCompositionContext, checkedCompositionObjective, checkedCompositionReview, compositionCanRevise, compositionConfirmed, FILE_ACCESS_PACK } from "../src/lib/composition";
import { checkedFileAccessControl, checkedFileAccessList, checkedFileAccessOperation, checkedFileAccessReview, checkedFileAccessStatus, clearFileAccessPending, fileAccessConfirmed, fileAccessJobActive, readFileAccessPending, storeFileAccessPending } from "../src/lib/file-access";
import { contextFixture, controlId, ownerId, proposalId, reviewFixture } from "./composition-fixture";
import { fileAccessCompositionReviewFixture, fileAccessControlFixture, fileAccessObjectiveFixture, fileAccessObservationFixture, fileAccessOperationFixture, fileAccessReviewFixture, fileAccessStatusFixture, fileAccessSubmissionFixture } from "./file-access-fixture";

beforeEach(() => localStorage.clear());
it("retains the exact reviewed operation across reload and refuses replacing it", () => {
  const pending = { id: proposalId, body: fileAccessSubmissionFixture() };
  storeFileAccessPending(pending); expect(readFileAccessPending()).toEqual(pending);
  expect(() => storeFileAccessPending({ ...pending, body: { ...pending.body, reviewed_by: "other" } })).toThrow();
  expect(() => clearFileAccessPending({ ...pending, id: ownerId })).toThrow();
  expect(fileAccessConfirmed(fileAccessOperationFixture(), pending)).toBe(true);
  const swapped = fileAccessOperationFixture(); swapped.job.progress.submitted_request = { ...pending.body, review_digest: `sha256:${"f".repeat(64)}` };
  expect(fileAccessConfirmed(swapped, pending)).toBe(false);
  clearFileAccessPending(pending); expect(readFileAccessPending()).toBeUndefined();
});
it("rejects malformed pending state and path or identity selectors", () => {
  localStorage.setItem("bluefire.file-access.pending.v1", '{"id":"bad"}');
  expect(readFileAccessPending).toThrow(); localStorage.clear();
  const body = fileAccessSubmissionFixture(); Object.assign(body.review, { path: "/unreviewed", uid: 0 });
  expect(() => storeFileAccessPending({ id: proposalId, body })).toThrow();
});
it("requires distinct enrolled principals and refuses unavailable create authority", () => {
  const value = fileAccessStatusFixture(); expect(checkedFileAccessStatus(value)).toBe(value);
  value.enrollment!.probe_uid = value.enrollment!.owner_uid; expect(() => checkedFileAccessStatus(value)).toThrow();
  const unavailable = fileAccessStatusFixture(); unavailable.available = false;
  expect(() => checkedFileAccessStatus(unavailable)).toThrow();
});
it("requires exact review operation, owner and digest bindings", () => {
  const value = fileAccessReviewFixture(); expect(checkedFileAccessReview(value, fileAccessSubmissionFixture().review)).toBe(value);
  expect(() => checkedFileAccessReview(value, { operation: "reset", control_owner_id: controlId })).toThrow();
  expect(() => checkedFileAccessReview(value, { operation: "rollback", control_owner_id: ownerId })).toThrow();
  value.control_digest = null; expect(() => checkedFileAccessReview(value, fileAccessSubmissionFixture().review)).toThrow();
});
it("requires durable exact submitted authority and the correct returned control", () => {
  const value = fileAccessOperationFixture(); expect(checkedFileAccessOperation(value, proposalId)).toBe(value);
  expect(checkedFileAccessOperation(value, proposalId, controlId)).toBe(value);
  expect(() => checkedFileAccessOperation(value, proposalId, ownerId)).toThrow();
  value.control!.control_owner_id = ownerId; expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
  value.control = null; value.job.progress.submitted_request = undefined;
  expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
});
it("rejects saved control history with another control's operation or missing submitted request", () => {
  const value = fileAccessControlFixture(); value.operations = [fileAccessOperationFixture().job];
  expect(checkedFileAccessControl(value, controlId)).toBe(value);
  value.control_owner_id = ownerId; expect(() => checkedFileAccessControl(value, ownerId)).toThrow();
  value.control_owner_id = controlId; value.operations[0]!.progress.submitted_request = undefined;
  expect(() => checkedFileAccessControl(value, controlId)).toThrow();
});
it("requires fresh restored-read evidence to match the exact completed rollback", () => {
  const value = fileAccessOperationFixture(); const control = fileAccessControlFixture();
  value.job.progress.verified_observation = { schema_version: "bluefire.file-access-control-observation.v1", operation: "rollback", non_owner: "allowed", owner: "allowed", resource_generation: control.resource!.resource_generation, record_count: 8, sha256: control.resource!.sha256, mode: "0640", source_digest: control.control_digest, observed_at_ms: Date.now() };
  expect(checkedFileAccessOperation(value, proposalId)).toBe(value);
  value.job.state = "running"; expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
  value.job.state = "completed";
  (value.job.progress.verified_observation as Record<string, unknown>).operation = "baseline";
  expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
});
it("rejects rollback and reset projections while usage is unresolved", () => {
  const value = fileAccessControlFixture(); value.usage_state = "unknown";
  expect(() => checkedFileAccessControl(value, controlId)).toThrow();
  value.allowed_operations = []; expect(checkedFileAccessControl(value, controlId)).toBe(value);
});
it("accepts a settled reset-only recovery control without inventing a resource or baseline", () => {
  const value = fileAccessControlFixture();
  value.status = "recovery_required"; value.allowed_operations = ["reset"]; value.resource = null; value.baseline = null;
  expect(checkedFileAccessControl(value, controlId)).toBe(value);
  const list = { schema_version: "bluefire.file-access-control-list.v1" as const, controls: [value] };
  expect(checkedFileAccessList(list)).toBe(list);
  expect(value.resource).toBeNull(); expect(value.baseline).toBeNull();
  value.allowed_operations.push("rollback"); expect(() => checkedFileAccessControl(value, controlId)).toThrow();
  value.allowed_operations = []; expect(() => checkedFileAccessControl(value, controlId)).toThrow();
  value.allowed_operations = ["reset"]; value.usage_state = "pending";
  expect(() => checkedFileAccessControl(value, controlId)).toThrow();
});
it("accepts partial settlement without requiring a later current control to remain in recovery", () => {
  const value = fileAccessOperationFixture(); value.job.state = "interrupted";
  value.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state: "settled_partial", available: false };
  value.control!.status = "reset"; value.control!.allowed_operations = []; value.control!.resource = null;
  expect(checkedFileAccessOperation(value, proposalId)).toBe(value);
  expect(fileAccessJobActive(value.job)).toBe(false);
  expect(value.job.progress.verified_observation).toBeUndefined();
  value.reconciliation.available = true; expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
});
it.each(["failed", "interrupted", "cancelled"])("accepts recovered complete observations without rewriting the original %s job", state => {
  const value = fileAccessOperationFixture(); value.job.state = state;
  value.job.progress.verified_observation = fileAccessObservationFixture();
  value.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state: "complete", available: false };
  expect(checkedFileAccessOperation(value, proposalId)).toBe(value);
  expect(value.job.state).toBe(state); expect(fileAccessJobActive(value.job)).toBe(false);
  value.reconciliation = null; expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
});
it.each(["unknown", "refused_no_effect", "settled_partial"] as const)("rejects observations for %s even if the job is marked completed", state => {
  const value = fileAccessOperationFixture(); value.job.progress.verified_observation = fileAccessObservationFixture();
  value.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state, available: state === "unknown" };
  expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
  value.job.state = "failed"; expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
});
it("rejects recovered evidence while the original job remains active", () => {
  const value = fileAccessOperationFixture(); value.job.state = "running";
  value.job.progress.verified_observation = fileAccessObservationFixture();
  value.reconciliation = { outcome_digest: fileAccessReviewFixture().review_digest, state: "complete", available: false };
  expect(() => checkedFileAccessOperation(value, proposalId)).toThrow();
});
it("selects file access only from exact v2 review and snapshot pack", () => {
  const value = fileAccessCompositionReviewFixture();
  const request = { schema_version: "bluefire.composition-review-request.v2", pack: FILE_ACCESS_PACK, control_owner_id: controlId, question: value.objective.question, limits: null } as const;
  expect(checkedCompositionReview(value, request)).toBe(value);
  expect(() => checkedCompositionReview(reviewFixture(), request)).toThrow();
  value.snapshot.pack = "bluefire.receiver-composition-pack.v1";
  expect(() => checkedCompositionReview(value, request)).toThrow();
});
it.each(["allowed", "permission_denied", "unknown"] as const)("preserves the fresh %s result without receiver-shaped conclusions", decision => {
  const value = fileAccessObjectiveFixture(decision);
  expect(checkedCompositionObjective(value, ownerId, controlId, FILE_ACCESS_PACK)).toBe(value);
  expect(compositionCanRevise(value.attempts[0]!, value)).toBe(false);
});
it("rejects an established conclusion with an unknown probe or changed same-file binding", () => {
  const value = fileAccessObjectiveFixture();
  const result = value.attempts[0]!.progress.verified_result as { file_access_result: Record<string, unknown> };
  result.file_access_result.non_owner_decision = "unknown";
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
  result.file_access_result.non_owner_decision = "permission_denied"; result.file_access_result.resource_generation = "different";
  expect(() => checkedCompositionObjective(value, ownerId, controlId)).toThrow();
});
it("refuses cross-pack context and does not confirm a receiver grant for an endpoint review", () => {
  const value = contextFixture(); expect(() => checkedCompositionContext(value, value.grant_id, FILE_ACCESS_PACK)).toThrow();
  const objective = fileAccessObjectiveFixture("allowed", false);
  const body = { submission_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", reviewed_by: "operator", review_digest: "digest", review: { control_owner_id: controlId, question: objective.grant.document.objective.question, limits: null } };
  objective.owner.progress.submitted_request = body; objective.owner.progress.review_digest = body.review_digest;
  expect(compositionConfirmed(objective, { kind: "grant", id: ownerId, owner: ownerId, control: controlId, body })).toBe(false);
});
