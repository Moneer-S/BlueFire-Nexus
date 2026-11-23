import { expect, it } from "vitest";
import { checkedFileAccessControl, checkedFileAccessList, checkedFileAccessOperation, checkedFileAccessReview, checkedFileAccessStatus, fileAccessControlIdValid, fileAccessReviewRequestValid, type FileAccessControl, type FileAccessStatus } from "../src/lib/file-access";
import { macOSControlFixture, macOSDigest, macOSOperationFixture, macOSOwner, macOSReviewFixture, macOSStatusFixture } from "./macos-file-access-fixture";

it.each([true, false])("accepts explicitly tagged macOS status, available=%s", available => {
  const status = macOSStatusFixture(available);
  expect(checkedFileAccessStatus(status)).toEqual(status);
});

it.each(["created", "baseline_verified", "hardened", "rolled_back", "uncertain"] as const)("accepts the exact macOS %s projection and summary", state => {
  const control = macOSControlFixture(state);
  expect(fileAccessControlIdValid(macOSOwner)).toBe(true);
  expect(checkedFileAccessControl(control, macOSOwner)).toEqual(control);
  const summary = { platform: "macos" as const, control_owner_id: macOSOwner, status: state, revision: control.revision };
  expect(checkedFileAccessList({ schema_version: "bluefire.file-access-control-list.v1", controls: [summary] }).controls).toEqual([summary]);
});

it.each(["baseline", "harden", "rollback"] as const)("accepts a macOS %s review", operation => {
  const request = { operation, control_owner_id: macOSOwner };
  const review = macOSReviewFixture(operation);
  expect(fileAccessReviewRequestValid(request)).toBe(true);
  expect(checkedFileAccessReview(review, request)).toEqual(review);
});

it.each(["create", "reset"] as const)("refuses macOS %s requests", operation => {
  expect(fileAccessReviewRequestValid({ operation, control_owner_id: macOSOwner })).toBe(false);
});

it("does not reinterpret macOS controls as Linux or Windows", () => {
  const control = macOSControlFixture();
  expect(() => checkedFileAccessControl({ ...control, platform: undefined } as unknown as FileAccessControl, macOSOwner)).toThrow();
  expect(() => checkedFileAccessControl({ ...control, platform: "windows" } as unknown as FileAccessControl, macOSOwner)).toThrow();
  expect(() => checkedFileAccessControl(control, `file-control-${"9".repeat(64)}`)).toThrow();
});

it("refuses unknown platforms and malformed macOS status without weakening legacy status", () => {
  expect(() => checkedFileAccessStatus({ ...macOSStatusFixture(), platform: "other" } as unknown as FileAccessStatus)).toThrow();
  expect(() => checkedFileAccessStatus({ ...macOSStatusFixture(), allowed_operations: ["create"] } as unknown as FileAccessStatus)).toThrow();
  expect(() => checkedFileAccessStatus({ ...macOSStatusFixture(false), enrollment: macOSStatusFixture().enrollment })).toThrow();
});

it("refuses unsupported operations and inconsistent pending projections", () => {
  const control = macOSControlFixture("uncertain");
  expect(() => checkedFileAccessControl({ ...control, allowed_operations: ["rollback"] }, macOSOwner)).toThrow();
  expect(() => checkedFileAccessControl({ ...control, usage_state: "settled" }, macOSOwner)).toThrow();
  expect(() => checkedFileAccessControl({ ...macOSControlFixture(), allowed_operations: ["reset"] } as unknown as FileAccessControl, macOSOwner)).toThrow();
});

it("refuses mismatched resource, baseline, and operation ownership", () => {
  const control = macOSControlFixture("baseline_verified");
  expect(() => checkedFileAccessControl({ ...control, resource: { ...control.resource, resource_id: "other" } }, macOSOwner)).toThrow();
  expect(() => checkedFileAccessControl({ ...control, baseline: { ...control.baseline!, sha256: macOSDigest("9") } }, macOSOwner)).toThrow();
  control.operations[0]!.progress.submitted_request = { ...control.operations[0]!.progress.submitted_request as object, review: { operation: "baseline", control_owner_id: `file-control-${"9".repeat(64)}` } };
  expect(() => checkedFileAccessControl(control, macOSOwner)).toThrow();
});

it("accepts unknown macOS operation evidence only with reconciliation unavailable", () => {
  const operation = macOSOperationFixture(undefined, macOSControlFixture("uncertain"));
  operation.job.state = "interrupted";
  operation.reconciliation = { outcome_digest: macOSDigest(), state: "unknown", available: false };
  expect(checkedFileAccessOperation(operation, operation.job.job_id, macOSOwner)).toEqual(operation);
  expect(() => checkedFileAccessOperation({ ...operation, reconciliation: { ...operation.reconciliation!, available: true } }, operation.job.job_id, macOSOwner)).toThrow();
  expect(() => checkedFileAccessOperation({ ...operation, control: { ...macOSControlFixture(), platform: undefined } as unknown as FileAccessControl }, operation.job.job_id, macOSOwner)).toThrow();
});
