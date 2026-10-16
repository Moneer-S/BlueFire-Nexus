import { expect, it } from "vitest";
import { checkedFileAccessControl, checkedFileAccessList, checkedFileAccessOperation, fileAccessReviewRequestValid, type FileAccessOperationEnvelope, type WindowsCorrectionFileAccessControl } from "../src/lib/file-access";
import { compositionJobId, compositionJobValid, type CompositionJob } from "../src/lib/composition";

const digest = (char = "a") => "sha256:" + char.repeat(64);
const owner = "win-file-control-0123456789abcdef0123456789abcdef";
const submissionId = (char: string) => char.repeat(8) + "-" + char.repeat(4) + "-4" + char.repeat(3) + "-8" + char.repeat(3) + "-" + char.repeat(12);

function operationJob(operation: "baseline" | "harden", char: string): CompositionJob {
  const submission_id = submissionId(char);
  return {
    job_id: "job-" + submission_id.replaceAll("-", ""),
    kind: "file_access.operation",
    state: "completed",
    request: {},
    progress: {
      submitted_request: {
        submission_id,
        review: { operation, control_owner_id: owner },
        review_digest: digest("b"),
        reviewed_by: "synthetic-reviewer",
      },
    },
  } as CompositionJob;
}

function baselineJob(): CompositionJob { return operationJob("baseline", "1"); }
function hardenJob(): CompositionJob { return operationJob("harden", "2"); }

function control(revision: 2 | 3 = 2, unsettled = false): WindowsCorrectionFileAccessControl {
  const baseline = {
    schema_version: "bluefire.windows-file-readable-baseline.v2" as const,
    non_owner: "allowed" as const,
    owner: "allowed" as const,
    size_bytes: 1024,
    sha256: digest("c"),
    resource_generation: "0123456789abcdef0123456789abcdef",
    observed_at: "2026-10-13T12:00:00.000Z",
    native_cleanup: "verified" as const,
    owned_job_cleanup: "verified" as const,
    independent_observation: false as const,
    baseline_digest: digest("d"),
  };
  return {
    schema_version: "bluefire.windows-file-access-control.v3",
    platform: "windows",
    control_owner_id: owner,
    control_digest: digest("e"),
    revision,
    status: unsettled ? "uncertain" : revision === 2 ? "baseline_verified" : "hardened",
    expires_at_ms: Date.now() + 60000,
    provenance: {
      kind: "protected_setup",
      enrollment_id: "win-file-enrollment-0123456789abcdef0123456789abcdef",
      enrollment_digest: digest("f"),
      setup_receipt_digest: digest("0"),
    },
    resource: {
      resource_id: "windows-resource",
      resource_generation: baseline.resource_generation,
      expected_sha256: baseline.sha256,
      size_bytes: baseline.size_bytes,
      protection: unsettled ? "unknown" : revision === 2 ? "reader_readable" : "metadata_only",
    },
    baseline,
    operations: revision === 2 ? [baselineJob()] : [baselineJob(), hardenJob()],
    allowed_operations: revision === 2 && !unsettled ? ["harden"] : [],
    task_usage_state: unsettled ? "unresolved" : "settled",
    account_object_cleanup: "required",
    correction: revision === 2 ? null : {
      binding_digest: digest("1"),
      before_descriptor_sha256: digest("2"),
      after_descriptor_sha256: digest("3"),
      owned_control_cleanup: "verified",
    },
    retest: revision === 2 ? null : {
      schema_version: "bluefire.windows-file-correction-observation.v3",
      non_owner: "data_access_denied",
      owner: "allowed",
      size_bytes: baseline.size_bytes,
      sha256: baseline.sha256,
      observed_at: "2026-10-13T12:00:05.000Z",
      native_cleanup: "verified",
      owned_job_cleanup: "verified",
      independent_observation: false,
      evidence_digest: digest("4"),
    },
  };
}

it("accepts the exact settled v3 baseline projection and only its harden review operation", () => {
  const value = control();
  const baseline = baselineJob();
  const submitted = baseline.progress.submitted_request as { submission_id: string; review: { operation: "baseline"; control_owner_id: string } };
  expect(compositionJobValid(baseline.job_id)).toBe(true);
  expect(compositionJobId(submitted.submission_id)).toBe(baseline.job_id);
  expect(fileAccessReviewRequestValid(submitted.review)).toBe(true);
  expect(checkedFileAccessControl(value, owner)).toBe(value);
  expect(fileAccessReviewRequestValid({ operation: "harden", control_owner_id: owner })).toBe(true);
  expect(fileAccessReviewRequestValid({ operation: "baseline", control_owner_id: owner })).toBe(true);
  expect(fileAccessReviewRequestValid({ operation: "rollback", control_owner_id: owner })).toBe(false);
  expect(fileAccessReviewRequestValid({ operation: "reset", control_owner_id: owner })).toBe(false);
  expect(value.allowed_operations).toEqual(["harden"]);
});

it("keeps unresolved v3 baseline state unknown and actionless", () => {
  const value = control(2, true);
  value.operations.push(hardenJob());
  expect(checkedFileAccessControl(value, owner)).toBe(value);
  expect(value.resource.protection).toBe("unknown");
  expect(value.allowed_operations).toEqual([]);
});

it("accepts hardened v3 only with the paired denied/allowed retest and verified cleanup proof", () => {
  const value = control(3);
  expect(checkedFileAccessControl(value, owner)).toBe(value);
  expect(value.allowed_operations).toEqual([]);
});

const invalidV3Cases: Array<[string, (value: Record<string, any>) => void]> = [
  ["extra top-level key", (value: Record<string, any>) => { value.extra = true; }],
  ["missing correction binding", (value: Record<string, any>) => { delete value.correction.binding_digest; }],
  ["unchanged descriptor", (value: Record<string, any>) => { value.correction.after_descriptor_sha256 = value.correction.before_descriptor_sha256; }],
  ["missing retest", (value: Record<string, any>) => { value.retest = null; }],
  ["owner denied", (value: Record<string, any>) => { value.retest.owner = "denied"; }],
  ["non-owner allowed", (value: Record<string, any>) => { value.retest.non_owner = "allowed"; }],
  ["cleanup unknown", (value: Record<string, any>) => { value.retest.native_cleanup = "unknown"; }],
  ["owned control cleanup missing", (value: Record<string, any>) => { value.correction.owned_control_cleanup = "unknown"; }],
  ["independent observation asserted", (value: Record<string, any>) => { value.retest.independent_observation = true; }],
  ["resource digest mismatch", (value: Record<string, any>) => { value.retest.sha256 = digest("9"); }],
  ["retest predates baseline", (value: Record<string, any>) => { value.retest.observed_at = "2026-10-12T12:00:00.000Z"; }],
  ["metadata protection without settled proof", (value: Record<string, any>) => { value.task_usage_state = "unresolved"; value.status = "uncertain"; }],
  ["hardened status with unknown protection", (value: Record<string, any>) => { value.resource.protection = "unknown"; }],
  ["mutation offered after revision three", (value: Record<string, any>) => { value.allowed_operations = ["harden"]; }],
  ["baseline/harden operation missing", (value: Record<string, any>) => { value.operations = [baselineJob()]; }],
];

it.each(invalidV3Cases)("rejects v3 correction projection with %s", (_label, mutate) => {
  const value = structuredClone(control(3)) as unknown as Record<string, any>;
  mutate(value);
  expect(() => checkedFileAccessControl(value as never, owner)).toThrow();
});

it("allows the original baseline operation to return the current v3 projection and rejects Linux observations", () => {
  const value = control(3);
  const job = baselineJob();
  const envelope: FileAccessOperationEnvelope = {
    schema_version: "bluefire.file-access-operation.v1",
    job,
    control: value,
    reconciliation: null,
    reconciliation_receipt: null,
  };
  expect(checkedFileAccessOperation(envelope, job.job_id, owner)).toBe(envelope);
  const observed = structuredClone(envelope);
  observed.job.progress.verified_observation = {
    schema_version: "bluefire.file-access-control-observation.v1",
    operation: "baseline",
    non_owner: "allowed",
    owner: "allowed",
    resource_generation: value.resource.resource_generation,
    record_count: 1,
    sha256: value.resource.expected_sha256,
    mode: "0640",
    source_digest: value.control_digest,
    observed_at_ms: Date.now(),
  };
  expect(() => checkedFileAccessOperation(observed, job.job_id, owner)).toThrow();
});

it("binds Windows harden operation envelopes to a v3 control and its original owner", () => {
  const value = control(2, true);
  const job = hardenJob();
  value.operations.push(job);
  const envelope: FileAccessOperationEnvelope = {
    schema_version: "bluefire.file-access-operation.v1",
    job,
    control: value,
    reconciliation: null,
    reconciliation_receipt: null,
  };
  expect(checkedFileAccessOperation(envelope, job.job_id, owner)).toBe(envelope);
  expect(() => checkedFileAccessOperation(envelope, job.job_id, owner.slice(0, -1) + "0")).toThrow();
  expect(() => checkedFileAccessOperation({ ...envelope, control: { ...value, schema_version: "bluefire.windows-file-access-control.v2" } as never }, job.job_id, owner)).toThrow();
  const published = control(3);
  expect(checkedFileAccessOperation({ ...envelope, control: published }, job.job_id, owner).control).toBe(published);
});

it("adds only the consistent v3 Windows list summary states", () => {
  const list = {
    schema_version: "bluefire.file-access-control-list.v1" as const,
    controls: [
      { control_owner_id: owner, status: "baseline_verified" as const, revision: 2 as const, platform: "windows" as const },
      { control_owner_id: owner.slice(0, -1) + "3", status: "uncertain" as const, revision: 2 as const, platform: "windows" as const },
      { control_owner_id: owner.slice(0, -1) + "1", status: "hardened" as const, revision: 3 as const, platform: "windows" as const },
      { control_owner_id: owner.slice(0, -1) + "2", status: "uncertain" as const, revision: 3 as const, platform: "windows" as const },
    ],
  };
  expect(checkedFileAccessList(list)).toBe(list);
  expect(() => checkedFileAccessList({ ...list, controls: [{ ...list.controls[1], status: "hardened" }] } as never)).toThrow();
  expect(() => checkedFileAccessList({ ...list, controls: [{ ...list.controls[1], status: "baseline_verified", revision: 1 }] } as never)).toThrow();
});
