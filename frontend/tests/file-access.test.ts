import { beforeEach, expect, it } from "vitest";
import { checkedCompositionContext, checkedCompositionObjective, checkedCompositionReview, compositionCanRevise, compositionConfirmed, FILE_ACCESS_PACK } from "../src/lib/composition";
import { checkedFileAccessControl, checkedFileAccessList, checkedFileAccessOperation, checkedFileAccessReview, checkedFileAccessStatus, clearFileAccessPending, fileAccessConfirmed, fileAccessControlIdValid, fileAccessJobActive, readFileAccessPending, storeFileAccessPending, type WindowsPairedFileAccessControl, type WindowsSetupFileAccessControl, type WindowsSetupFileAccessStatus, type WindowsPairFileAccessStatus } from "../src/lib/file-access";
import { contextFixture, controlId, ownerId, proposalId, reviewFixture, testDigest } from "./composition-fixture";
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
const windowsSetupStatus = (): WindowsSetupFileAccessStatus => ({
  schema_version: "bluefire.file-access-status.v1", available: false,
  problem: { code: "windows_native_admission_unavailable", message: "Protected setup is verified. Native task admission is not yet available." },
  enrollment: null, allowed_operations: [],
  setup: { enrollment_id: "win-file-enrollment-0123456789abcdef0123456789abcdef", enrollment_digest: testDigest, expires_at_ms: Date.now() + 60000, verification: "protected_setup_only" },
});
const windowsSetupControl = (): WindowsSetupFileAccessControl => ({
  schema_version: "bluefire.windows-file-access-control.v1", platform: "windows",
  control_owner_id: "win-file-control-0123456789abcdef0123456789abcdef", control_digest: testDigest,
  revision: 1, status: "setup_verified", expires_at_ms: Date.now() + 60000,
  provenance: { kind: "protected_setup", enrollment_id: "win-file-enrollment-0123456789abcdef0123456789abcdef", enrollment_digest: testDigest, setup_receipt_digest: testDigest },
  resource: { resource_id: "windows-resource", resource_generation: "0123456789abcdef0123456789abcdef", expected_sha256: testDigest, size_bytes: 1024, protection: "reader_readable" },
  baseline: null, operations: [], allowed_operations: [], task_usage_state: "none", account_object_cleanup: "required",
});
const windowsPairStatus = (): WindowsPairFileAccessStatus => ({
  schema_version: "bluefire.file-access-status.v1", available: true, problem: null,
  enrollment: null, allowed_operations: [], setup: windowsSetupStatus().setup,
});
const windowsPairJob = () => {
  const job = fileAccessOperationFixture().job;
  const submitted = { ...fileAccessSubmissionFixture(), submission_id: "dddddddd-dddd-dddd-dddd-dddddddddddd", review: { operation: "baseline" as const, control_owner_id: windowsSetupControl().control_owner_id } };
  job.job_id = `job-${submitted.submission_id.replaceAll("-", "")}`;
  job.progress.submitted_request = submitted;
  return job;
};
const windowsPairBaseline = () => ({ schema_version: "bluefire.windows-file-readable-baseline.v2" as const, non_owner: "allowed" as const, owner: "allowed" as const, size_bytes: 1024, sha256: testDigest, resource_generation: "0123456789abcdef0123456789abcdef", observed_at: new Date().toISOString(), native_cleanup: "verified" as const, owned_job_cleanup: "verified" as const, independent_observation: false as const, baseline_digest: testDigest });
const windowsPairControl = (state: "setup" | "uncertain" | "settled" = "setup"): WindowsPairedFileAccessControl => ({
  ...windowsSetupControl(), schema_version: "bluefire.windows-file-access-control.v2",
  revision: state === "settled" ? 2 : 1, status: state === "uncertain" ? "uncertain" : state === "settled" ? "baseline_verified" : "setup_verified",
  baseline: state === "settled" ? windowsPairBaseline() : null,
  operations: state === "setup" ? [] : [windowsPairJob()],
  allowed_operations: state === "setup" ? ["baseline"] : [],
  task_usage_state: state === "setup" ? "none" : state === "uncertain" ? "unresolved" : "settled",
});
it("checks Windows setup status as a distinct non-executable variant", () => {
  const status = windowsSetupStatus();
  expect(checkedFileAccessStatus(status)).toBe(status);
  expect(() => checkedFileAccessStatus({ ...status, available: true } as never)).toThrow();
  expect(() => checkedFileAccessStatus({ ...status, allowed_operations: ["create"] } as never)).toThrow();
  expect(() => checkedFileAccessStatus({ ...status, setup: { ...status.setup, owner_uid: 1000 } } as never)).toThrow();
  expect(() => checkedFileAccessStatus({ ...status, platform: "windows" } as never)).toThrow();
});
it("accepts only the exact positive paired-setup status without adding identities", () => {
  const status = windowsPairStatus();
  expect(checkedFileAccessStatus(status)).toBe(status);
  expect(() => checkedFileAccessStatus({ ...status, problem: { code: "stale", message: "not current" } } as never)).toThrow();
  expect(() => checkedFileAccessStatus({ ...status, allowed_operations: ["create"] } as never)).toThrow();
  expect(() => checkedFileAccessStatus({ ...status, setup: { ...status.setup, owner_uid: 1000 } } as never)).toThrow();
});
it("checks saved Windows setup without Linux execution fields and binds import selection", () => {
  const setup = { enrollment_id: windowsSetupStatus().setup.enrollment_id, enrollment_digest: testDigest };
  const value = windowsSetupControl();
  expect(fileAccessControlIdValid(value.control_owner_id)).toBe(true);
  expect(checkedFileAccessControl(value, value.control_owner_id, setup)).toBe(value);
  expect(() => checkedFileAccessControl({ ...value, provenance: { ...value.provenance, enrollment_id: "other" } }, undefined, setup)).toThrow();
  expect(() => checkedFileAccessControl({ ...value, usage_state: "none" } as never, value.control_owner_id)).toThrow();
  expect(() => checkedFileAccessControl({ ...value, baseline: { baseline_digest: testDigest } } as never, value.control_owner_id)).toThrow();
  expect(() => checkedFileAccessControl({ ...value, account_object_cleanup: "complete" } as never, value.control_owner_id)).toThrow();
  expect(fileAccessControlIdValid("not-a-control-id")).toBe(false);
});
it("checks paired Windows baseline, uncertainty, and settled projection as exact versions", () => {
  const initial = windowsPairControl();
  expect(checkedFileAccessControl(initial, initial.control_owner_id)).toBe(initial);
  expect(checkedFileAccessControl(windowsPairControl("uncertain"), initial.control_owner_id)).toBeTruthy();
  expect(checkedFileAccessControl(windowsPairControl("settled"), initial.control_owner_id)).toBeTruthy();
  expect(() => checkedFileAccessControl({ ...initial, status: "uncertain" } as never, initial.control_owner_id)).toThrow();
  const settled = windowsPairControl("settled");
  expect(() => checkedFileAccessControl({ ...settled, baseline: { ...settled.baseline!, independent_observation: true } } as never, settled.control_owner_id)).toThrow();
  expect(() => checkedFileAccessControl({ ...settled, baseline: { ...settled.baseline!, resource_generation: "ffffffffffffffffffffffffffffffff" } } as never, settled.control_owner_id)).toThrow();
  expect(() => checkedFileAccessControl({ ...settled, baseline: { ...settled.baseline!, record_count: 1 } } as never, settled.control_owner_id)).toThrow();
  expect(() => checkedFileAccessControl({ ...initial, operations: [fileAccessOperationFixture().job], task_usage_state: "unresolved", status: "uncertain", allowed_operations: [] } as never, initial.control_owner_id)).toThrow();
});
it("accepts a terminal no-use history only when the one-shot baseline action stays disabled", () => {
  const initial = windowsPairControl();
  const job = windowsPairJob();
  job.state = "failed";
  const historical = { ...initial, operations: [job], allowed_operations: [] };
  expect(checkedFileAccessControl(historical, initial.control_owner_id)).toBe(historical);
  expect(() => checkedFileAccessControl({ ...historical, allowed_operations: ["baseline"] } as never, initial.control_owner_id)).toThrow();
  expect(() => checkedFileAccessControl({ ...historical, status: "uncertain" } as never, initial.control_owner_id)).toThrow();
});
it("accepts Windows list summaries without projecting them as Linux controls", () => {
  const windows = windowsSetupControl();
  const list = { schema_version: "bluefire.file-access-control-list.v1" as const, controls: [
    { control_owner_id: controlId, status: "hardened" as const, revision: 3 },
    { control_owner_id: windows.control_owner_id, status: "setup_verified" as const, revision: 1 as const, platform: "windows" as const },
  ] };
  expect(checkedFileAccessList(list)).toBe(list);
  expect(() => checkedFileAccessList({ ...list, controls: [{ ...list.controls[1], owner_uid: 1000 }] } as never)).toThrow();
  const operation = fileAccessOperationFixture(); operation.control = windows as never;
  expect(() => checkedFileAccessOperation(operation, proposalId)).toThrow();
});
it("keeps Windows list summary state and revision paired", () => {
  const id = windowsSetupControl().control_owner_id;
  const list = { schema_version: "bluefire.file-access-control-list.v1" as const, controls: [
    { control_owner_id: id, status: "uncertain" as const, revision: 1 as const, platform: "windows" as const },
    { control_owner_id: `${id.slice(0, -1)}0`, status: "baseline_verified" as const, revision: 2 as const, platform: "windows" as const },
  ] };
  expect(checkedFileAccessList(list)).toBe(list);
  expect(() => checkedFileAccessList({ ...list, controls: [{ ...list.controls[0], status: "baseline_verified", revision: 1 }] } as never)).toThrow();
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
it("binds a paired Windows baseline operation to its exact v2 control and never Linux observations", () => {
  const control = windowsPairControl("settled");
  const job = windowsPairJob();
  const submission = job.progress.submitted_request as ReturnType<typeof fileAccessSubmissionFixture>;
  const response = { schema_version: "bluefire.file-access-operation.v1" as const, job, control: { ...control, operations: [job] }, reconciliation: null, reconciliation_receipt: null };
  expect(checkedFileAccessOperation(response, job.job_id, control.control_owner_id)).toBe(response);
  expect(() => checkedFileAccessOperation({ ...response, control: null }, job.job_id, control.control_owner_id)).toThrow();
  expect(() => checkedFileAccessOperation({ ...response, control: { ...control, control_owner_id: `${control.control_owner_id.slice(0, -1)}0` } }, job.job_id, control.control_owner_id)).toThrow();
  const wrongOperation = { ...job, progress: { ...job.progress, submitted_request: { ...submission, review: { operation: "rollback", control_owner_id: control.control_owner_id } } } };
  expect(() => checkedFileAccessOperation({ ...response, job: wrongOperation }, job.job_id, control.control_owner_id)).toThrow();
  const independent = { ...response, job: { ...job, progress: { ...job.progress, verified_observation: fileAccessObservationFixture("baseline") } } };
  expect(() => checkedFileAccessOperation(independent, job.job_id, control.control_owner_id)).toThrow();
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
  const list = { schema_version: "bluefire.file-access-control-list.v1" as const, controls: [{ control_owner_id: value.control_owner_id, status: value.status, revision: value.revision }] };
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
