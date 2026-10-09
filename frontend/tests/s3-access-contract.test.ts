import { expect, it, vi } from "vitest";
import { checkedEnvironments, checkedExercise, checkedList, checkedReview, clearS3Pending, confirmsS3Pending, readS3Pending, readS3Stops, s3Api, storeS3Pending, storeS3Stop, type S3Pending } from "../src/lib/s3-access";
import { s3Environment, s3Exercise, s3Hash, s3Observed, s3Operation, s3Owner, s3Review } from "./s3-access-fixture";

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
