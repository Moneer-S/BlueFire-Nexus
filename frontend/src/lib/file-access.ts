import { DEMO_MODE, request } from "./api";
import { compositionJobId, compositionJobValid, type CompositionJob } from "./composition";
import { sameJson } from "./replay-review";

export type FileAccessOperation = "create" | "baseline" | "harden" | "rollback" | "reset";
export interface FileAccessReviewRequest { operation: FileAccessOperation; control_owner_id: string | null }
export interface FileAccessReview {
  schema_version: "bluefire.file-access-control-review.v1";
  operation: FileAccessOperation; control_owner_id: string | null;
  context_digest: string; enrollment_digest: string; control_digest: string | null;
  expires_at_ms: number; effect: string; review_digest: string;
}
export interface FileAccessSubmission { submission_id: string; review: FileAccessReviewRequest; review_digest: string; reviewed_by: string }
export interface WindowsSetupSummary { enrollment_id: string; enrollment_digest: string; expires_at_ms: number; verification: "protected_setup_only" }
export interface WindowsSetupImportRequest { enrollment_id: string; enrollment_digest: string }
export type FileAccessSetupImportRequest = WindowsSetupImportRequest;
interface FileAccessStatusBase { schema_version: "bluefire.file-access-status.v1"; available: boolean; problem: null | { code: string; message: string }; allowed_operations: FileAccessOperation[] }
export interface LinuxFileAccessStatus extends FileAccessStatusBase {
  platform?: never; setup?: never;
  enrollment: null | { enrollment_id: string; enrollment_digest: string; expires_at_ms: number; owner_uid: number; probe_uid: number };
}
export interface MacOSFileAccessStatus extends FileAccessStatusBase {
  platform: "macos"; setup?: never; allowed_operations: [];
  enrollment: LinuxFileAccessStatus["enrollment"];
}
export interface WindowsSetupFileAccessStatus extends FileAccessStatusBase {
  platform?: never;
  available: false; problem: { code: "windows_native_admission_unavailable"; message: string };
  enrollment: null; allowed_operations: [];
  setup: WindowsSetupSummary;
}
export interface WindowsPairFileAccessStatus extends FileAccessStatusBase {
  platform?: never;
  available: true; problem: null; enrollment: null; allowed_operations: [];
  setup: WindowsSetupSummary;
}
export type FileAccessStatus = LinuxFileAccessStatus | WindowsSetupFileAccessStatus | WindowsPairFileAccessStatus | MacOSFileAccessStatus;
export type FileAccessControlState = "created" | "baseline_verified" | "hardened" | "rolled_back" | "reset" | "uncertain" | "recovery_required";
interface FileAccessControlSummaryBase { control_owner_id: string; revision: number }
export interface LinuxFileAccessControlSummary extends FileAccessControlSummaryBase { platform?: never; status: FileAccessControlState }
export interface WindowsFileAccessControlSummary extends FileAccessControlSummaryBase { platform: "windows"; status: "setup_verified" | "uncertain" | "baseline_verified" | "hardened"; revision: 1 | 2 | 3 }
export type MacOSFileAccessControlState = "created" | "baseline_verified" | "hardened" | "rolled_back" | "uncertain";
export interface MacOSFileAccessControlSummary extends FileAccessControlSummaryBase { platform: "macos"; status: MacOSFileAccessControlState }
export type FileAccessControlSummary = LinuxFileAccessControlSummary | WindowsFileAccessControlSummary | MacOSFileAccessControlSummary;
export interface LinuxFileAccessControl extends LinuxFileAccessControlSummary {
  schema_version: "bluefire.file-access-control.v1"; control_digest: string;
  resource: null | { resource_id: string; resource_generation: string; sha256: string; size: number; record_count: number; mode: "0640" | "0600" };
  baseline: null | { baseline_digest: string; non_owner: "allowed"; owner: "allowed"; record_count: number; sha256: string };
  usage_state: "settled" | "pending" | "unknown"; allowed_operations: FileAccessOperation[]; operations: CompositionJob[];
}
export interface MacOSFileAccessControl extends MacOSFileAccessControlSummary {
  schema_version: "bluefire.file-access-control.v1"; control_digest: string;
  resource: NonNullable<LinuxFileAccessControl["resource"]>;
  baseline: LinuxFileAccessControl["baseline"];
  usage_state: "settled" | "pending"; allowed_operations: ("baseline" | "harden" | "rollback")[]; operations: CompositionJob[];
}
interface WindowsFileAccessControlBase {
  platform: "windows"; control_owner_id: string; control_digest: string; expires_at_ms: number;
  provenance: { kind: "protected_setup"; enrollment_id: string; enrollment_digest: string; setup_receipt_digest: string };
  resource: { resource_id: string; resource_generation: string; expected_sha256: string; size_bytes: number; protection: "reader_readable" };
  account_object_cleanup: "required";
}
export interface WindowsSetupFileAccessControl extends WindowsFileAccessControlBase {
  schema_version: "bluefire.windows-file-access-control.v1"; revision: 1; status: "setup_verified";
  baseline: null; operations: []; allowed_operations: []; task_usage_state: "none";
}
export interface WindowsReadableBaseline {
  schema_version: "bluefire.windows-file-readable-baseline.v2"; non_owner: "allowed"; owner: "allowed";
  size_bytes: number; sha256: string; resource_generation: string; observed_at: string;
  native_cleanup: "verified"; owned_job_cleanup: "verified"; independent_observation: false; baseline_digest: string;
}
export interface WindowsPairedFileAccessControl extends WindowsFileAccessControlBase {
  schema_version: "bluefire.windows-file-access-control.v2"; revision: 1 | 2;
  status: "setup_verified" | "uncertain" | "baseline_verified";
  baseline: WindowsReadableBaseline | null; operations: CompositionJob[]; allowed_operations: FileAccessOperation[];
  task_usage_state: "none" | "unresolved" | "settled";
}
export interface WindowsCorrectionRecord {
  binding_digest: string; before_descriptor_sha256: string; after_descriptor_sha256: string;
  owned_control_cleanup: "verified";
}
export interface WindowsCorrectionRetest {
  schema_version: "bluefire.windows-file-correction-observation.v3";
  non_owner: "data_access_denied"; owner: "allowed"; size_bytes: number; sha256: string;
  observed_at: string; native_cleanup: "verified"; owned_job_cleanup: "verified";
  independent_observation: false; evidence_digest: string;
}
export interface WindowsCorrectionFileAccessControl extends Omit<WindowsFileAccessControlBase, "resource"> {
  schema_version: "bluefire.windows-file-access-control.v3"; revision: 2 | 3;
  status: "baseline_verified" | "hardened" | "uncertain";
  resource: Omit<WindowsFileAccessControlBase["resource"], "protection"> & { protection: "reader_readable" | "metadata_only" | "unknown" };
  baseline: WindowsReadableBaseline; operations: CompositionJob[];
  allowed_operations: FileAccessOperation[]; task_usage_state: "unresolved" | "settled";
  correction: WindowsCorrectionRecord | null; retest: WindowsCorrectionRetest | null;
}
export type WindowsFileAccessControl = WindowsSetupFileAccessControl | WindowsPairedFileAccessControl | WindowsCorrectionFileAccessControl;
export type FileAccessControl = LinuxFileAccessControl | WindowsFileAccessControl | MacOSFileAccessControl;
export interface FileAccessControlList { schema_version: "bluefire.file-access-control-list.v1"; controls: FileAccessControlSummary[] }
export interface FileAccessOperationEnvelope {
  schema_version: "bluefire.file-access-operation.v1"; job: CompositionJob; control: FileAccessControl | null;
  reconciliation: null | { outcome_digest: string; state: "unknown" | "complete" | "refused_no_effect" | "settled_partial"; available: boolean };
  reconciliation_receipt: FileAccessReconciliationReceipt | null;
}
export interface FileAccessReconciliationSubmission { submission_id: string; expected_outcome_digest: string; reviewed_by: string }
export interface FileAccessReconciliationReceipt { submission_id: string; submitted_request: FileAccessReconciliationSubmission; state: "completed" | "pending"; problem: null | { code: string; message: string } }
export interface FileAccessReconciliationEnvelope { schema_version: "bluefire.file-access-reconciliation.v1"; operation_job_id: string; receipt: FileAccessReconciliationReceipt }
export interface FileAccessObservation {
  schema_version: "bluefire.file-access-control-observation.v1"; operation: "baseline" | "rollback";
  non_owner: "allowed"; owner: "allowed"; resource_generation: string; record_count: number; sha256: string;
  mode: "0640"; source_digest: string; observed_at_ms: number;
}
export interface FileAccessPending { id: string; body: FileAccessSubmission }
export const fileAccessOperationLabels: Record<FileAccessOperation, string> = {
  create: "Create generated resource", baseline: "Verify baseline access", harden: "Apply owner-only access",
  rollback: "Restore baseline access", reset: "Reset generated resource",
};
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const bad = () => new Error("This file-access response is incomplete or belongs to different saved work.");
const controlStates = ["created", "baseline_verified", "hardened", "rolled_back", "reset", "uncertain", "recovery_required"];
const natural = (value: unknown) => Number.isSafeInteger(value) && Number(value) >= 0;
const record = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const exactKeys = (value: unknown, keys: string[]) => record(value) && Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const windowsControlId = (value: unknown): value is string => typeof value === "string" && /^win-file-control-[0-9a-f]{32}$/.test(value);
export const macOSFileAccessControlIdValid = (value: unknown): value is string => typeof value === "string" && /^file-control-[0-9a-f]{64}$/.test(value);
export const fileAccessControlIdValid = (value: string) => compositionJobValid(value) || windowsControlId(value) || macOSFileAccessControlIdValid(value);
const macOSControlStates = ["created", "baseline_verified", "hardened", "rolled_back", "uncertain"];
const macOSOperations = { created: ["baseline"], baseline_verified: ["harden"], hardened: ["rollback"], rolled_back: ["baseline", "harden"], uncertain: [] };
const operationsValid = (value: unknown, allowed: string[]) => Array.isArray(value) && new Set(value).size === value.length && value.every(item => typeof item === "string" && allowed.includes(item));
function windowsPairJobValid(job: CompositionJob, owner: string): boolean {
  const submitted = job?.progress?.submitted_request as FileAccessSubmission | undefined;
  return compositionJobValid(job?.job_id) && job.kind === "file_access.operation" && typeof job.state === "string"
    && fileAccessSubmissionValid(submitted as FileAccessSubmission) && compositionJobId(submitted!.submission_id) === job.job_id
    && submitted!.review.operation === "baseline" && submitted!.review.control_owner_id === owner;
}
function windowsCorrectionJobValid(job: CompositionJob, owner: string): boolean {
  const submitted = job?.progress?.submitted_request as FileAccessSubmission | undefined;
  return compositionJobValid(job?.job_id) && job.kind === "file_access.operation" && typeof job.state === "string"
    && fileAccessSubmissionValid(submitted as FileAccessSubmission) && compositionJobId(submitted!.submission_id) === job.job_id
    && (submitted!.review.operation === "baseline" || submitted!.review.operation === "harden")
    && submitted!.review.control_owner_id === owner;
}
export const fileAccessJobActive = (job: CompositionJob) => !["completed", "failed", "cancelled", "interrupted"].includes(job.state);
export function fileAccessReviewRequestValid(value: FileAccessReviewRequest): boolean {
  return Boolean(value && Object.keys(value).sort().join(",") === "control_owner_id,operation"
    && Object.hasOwn(fileAccessOperationLabels, value.operation)
    && (value.operation === "create" ? value.control_owner_id === null
      : macOSFileAccessControlIdValid(value.control_owner_id) ? ["baseline", "harden", "rollback"].includes(value.operation)
      : (value.operation === "baseline" || value.operation === "harden") && windowsControlId(value.control_owner_id)
        ? true : compositionJobValid(value.control_owner_id)));
}
export function checkedFileAccessReview(value: FileAccessReview, submitted: FileAccessReviewRequest): FileAccessReview {
  if (!fileAccessReviewRequestValid(submitted) || value?.schema_version !== "bluefire.file-access-control-review.v1"
    || value.operation !== submitted.operation || value.control_owner_id !== submitted.control_owner_id
    || !digest(value.context_digest) || !digest(value.enrollment_digest) || !digest(value.review_digest)
    || (submitted.operation === "create" ? value.control_digest !== null : !digest(value.control_digest))
    || !Number.isSafeInteger(value.expires_at_ms) || value.expires_at_ms <= 0
    || typeof value.effect !== "string" || !value.effect.trim() || value.effect.length > 8000) throw bad();
  return value;
}
export function checkedFileAccessStatus(value: FileAccessStatus): FileAccessStatus {
  if (!record(value) || value.schema_version !== "bluefire.file-access-status.v1" || typeof value.available !== "boolean"
    || !operationsValid(value.allowed_operations, ["create"])
    || (value.problem !== null && (!record(value.problem) || typeof value.problem.code !== "string" || typeof value.problem.message !== "string"))) throw bad();
  if (value.platform === "macos") {
    const mac = value as MacOSFileAccessStatus;
    const enrollment = mac.enrollment;
    if (!exactKeys(mac, ["schema_version", "platform", "available", "problem", "enrollment", "allowed_operations"])
      || mac.allowed_operations.length !== 0
      || (mac.available ? mac.problem !== null || !exactKeys(enrollment, ["enrollment_id", "enrollment_digest", "expires_at_ms", "owner_uid", "probe_uid"])
        || !/^file-enrollment-[0-9a-f]{32}$/.test(enrollment?.enrollment_id ?? "") || !digest(enrollment?.enrollment_digest)
        || !Number.isSafeInteger(enrollment?.expires_at_ms) || Number(enrollment?.expires_at_ms) <= 0
        || !natural(enrollment?.owner_uid) || !natural(enrollment?.probe_uid) || Number(enrollment?.owner_uid) < 1 || Number(enrollment?.probe_uid) < 1
        || enrollment?.owner_uid === enrollment?.probe_uid
        : enrollment !== null || !exactKeys(mac.problem, ["code", "message"]) || mac.problem?.code !== "file_access_enrollment_unavailable")) throw bad();
    return mac;
  }
  if (Object.hasOwn(value, "setup")) {
    const windows = value as WindowsSetupFileAccessStatus | WindowsPairFileAccessStatus;
    if (!exactKeys(value, ["schema_version", "available", "problem", "enrollment", "allowed_operations", "setup"])
      || windows.enrollment !== null
      || windows.allowed_operations.length !== 0 || !exactKeys(windows.setup, ["enrollment_id", "enrollment_digest", "expires_at_ms", "verification"])
      || typeof windows.setup.enrollment_id !== "string" || !windows.setup.enrollment_id || !digest(windows.setup.enrollment_digest)
      || !Number.isSafeInteger(windows.setup.expires_at_ms) || windows.setup.expires_at_ms <= 0
      || windows.setup.verification !== "protected_setup_only") throw bad();
    if (windows.available ? windows.problem !== null : windows.problem?.code !== "windows_native_admission_unavailable") throw bad();
    return windows;
  }
  const linux = value as LinuxFileAccessStatus;
  if (!exactKeys(value, ["schema_version", "available", "problem", "enrollment", "allowed_operations"])) throw bad();
  const enrollment = linux.enrollment;
  if (enrollment !== null && (!record(enrollment) || typeof enrollment.enrollment_id !== "string" || !enrollment.enrollment_id || !digest(enrollment.enrollment_digest)
    || !Number.isSafeInteger(enrollment.expires_at_ms) || !natural(enrollment.owner_uid) || !natural(enrollment.probe_uid) || enrollment.owner_uid === enrollment.probe_uid)) throw bad();
  if (linux.available && (!enrollment || linux.problem !== null)) throw bad();
  if (!linux.available && linux.allowed_operations.length) throw bad();
  return linux;
}
export function checkedFileAccessControl(value: FileAccessControl, owner?: string, expectedSetup?: FileAccessSetupImportRequest): FileAccessControl {
  if (!record(value)) throw bad();
  if (value.platform === "macos") {
    const mac = value as MacOSFileAccessControl;
    if (!exactKeys(mac, ["schema_version", "platform", "control_owner_id", "control_digest", "revision", "status", "resource", "baseline", "usage_state", "allowed_operations", "operations"])
      || mac.schema_version !== "bluefire.file-access-control.v1" || !macOSFileAccessControlIdValid(mac.control_owner_id)
      || (owner !== undefined && mac.control_owner_id !== owner) || !digest(mac.control_digest)
      || !natural(mac.revision) || mac.revision < 1 || mac.revision > 2 ** 31 - 1 || !macOSControlStates.includes(mac.status)
      || !["settled", "pending"].includes(mac.usage_state)
      || !operationsValid(mac.allowed_operations, macOSOperations[mac.status] ?? [])
      || (mac.usage_state === "pending") !== (mac.status === "uncertain")
      || !Array.isArray(mac.operations) || new Set(mac.operations.map(job => job?.job_id)).size !== mac.operations.length
      || mac.operations.some(job => {
        const submitted = job?.progress?.submitted_request as FileAccessSubmission;
        return !compositionJobValid(job?.job_id) || job.kind !== "file_access.operation" || typeof job.state !== "string"
          || !fileAccessSubmissionValid(submitted) || compositionJobId(submitted.submission_id) !== job.job_id
          || submitted.review.control_owner_id !== mac.control_owner_id;
      })) throw bad();
    const resource = mac.resource;
    if (!exactKeys(resource, ["resource_id", "resource_generation", "sha256", "size", "record_count", "mode"])
      || !/^file-generation-[0-9a-f]{32}$/.test(resource.resource_generation) || resource.resource_id !== resource.resource_generation
      || !digest(resource.sha256) || !natural(resource.size) || resource.size < 1 || !natural(resource.record_count) || resource.record_count < 1
      || !["0640", "0600"].includes(resource.mode)
      || (mac.status !== "uncertain" && resource.mode !== (mac.status === "hardened" ? "0600" : "0640"))) throw bad();
    const baseline = mac.baseline;
    if (baseline !== null && (!exactKeys(baseline, ["baseline_digest", "non_owner", "owner", "record_count", "sha256"])
      || !digest(baseline.baseline_digest) || baseline.non_owner !== "allowed" || baseline.owner !== "allowed"
      || baseline.record_count !== resource.record_count || baseline.sha256 !== resource.sha256)) throw bad();
    if ((mac.status === "created" && (baseline !== null || mac.revision !== 1))
      || (["baseline_verified", "hardened", "rolled_back"].includes(mac.status) && (baseline === null || mac.revision < 2))
      || (mac.status === "hardened" && mac.revision < 3) || (mac.status === "rolled_back" && mac.revision < 4)) throw bad();
    return mac;
  }
  if (value.platform === "windows") {
    const windows = value as WindowsFileAccessControl;
    if (windows.schema_version === "bluefire.windows-file-access-control.v3") {
      const correction = windows as WindowsCorrectionFileAccessControl;
      if (!exactKeys(correction, ["schema_version", "platform", "control_owner_id", "control_digest", "revision", "status", "expires_at_ms", "provenance", "resource", "baseline", "operations", "allowed_operations", "task_usage_state", "account_object_cleanup", "correction", "retest"])
        || !windowsControlId(correction.control_owner_id) || (owner !== undefined && correction.control_owner_id !== owner)
        || !digest(correction.control_digest) || !Number.isSafeInteger(correction.expires_at_ms) || correction.expires_at_ms <= 0
        || !exactKeys(correction.provenance, ["kind", "enrollment_id", "enrollment_digest", "setup_receipt_digest"])
        || correction.provenance.kind !== "protected_setup" || typeof correction.provenance.enrollment_id !== "string" || !correction.provenance.enrollment_id
        || !digest(correction.provenance.enrollment_digest) || !digest(correction.provenance.setup_receipt_digest)
        || (expectedSetup !== undefined && (correction.provenance.enrollment_id !== expectedSetup.enrollment_id || correction.provenance.enrollment_digest !== expectedSetup.enrollment_digest))
        || !exactKeys(correction.resource, ["resource_id", "resource_generation", "expected_sha256", "size_bytes", "protection"])
        || typeof correction.resource.resource_id !== "string" || !correction.resource.resource_id
        || typeof correction.resource.resource_generation !== "string" || !/^[0-9a-f]{32}$/.test(correction.resource.resource_generation)
        || !digest(correction.resource.expected_sha256) || !Number.isSafeInteger(correction.resource.size_bytes) || correction.resource.size_bytes < 1
        || !["reader_readable", "metadata_only", "unknown"].includes(correction.resource.protection)
        || correction.account_object_cleanup !== "required" || ![2, 3].includes(correction.revision)
        || !["baseline_verified", "hardened", "uncertain"].includes(correction.status)
        || !["unresolved", "settled"].includes(correction.task_usage_state)
        || !operationsValid(correction.allowed_operations, ["harden"])
        || !Array.isArray(correction.operations) || new Set(correction.operations.map(job => job?.job_id)).size !== correction.operations.length
        || correction.operations.some(job => !windowsCorrectionJobValid(job, correction.control_owner_id))) throw bad();
      const baseline = correction.baseline;
      if (!exactKeys(baseline, ["schema_version", "non_owner", "owner", "size_bytes", "sha256", "resource_generation", "observed_at", "native_cleanup", "owned_job_cleanup", "independent_observation", "baseline_digest"])
        || baseline.schema_version !== "bluefire.windows-file-readable-baseline.v2" || baseline.non_owner !== "allowed" || baseline.owner !== "allowed"
        || !natural(baseline.size_bytes) || baseline.size_bytes < 1 || !digest(baseline.sha256)
        || baseline.size_bytes !== correction.resource.size_bytes || baseline.sha256 !== correction.resource.expected_sha256
        || baseline.resource_generation !== correction.resource.resource_generation || typeof baseline.observed_at !== "string"
        || !Number.isFinite(Date.parse(baseline.observed_at)) || baseline.native_cleanup !== "verified"
        || baseline.owned_job_cleanup !== "verified" || baseline.independent_observation !== false || !digest(baseline.baseline_digest)) throw bad();
      const hasBaseline = correction.operations.some(job => (job.progress.submitted_request as FileAccessSubmission).review.operation === "baseline");
      const hasHarden = correction.operations.some(job => (job.progress.submitted_request as FileAccessSubmission).review.operation === "harden");
      if (!hasBaseline || (correction.revision === 2 && (correction.correction !== null || correction.retest !== null
          || (correction.task_usage_state === "settled" && (correction.status !== "baseline_verified"
            || correction.resource.protection !== "reader_readable"
            || (correction.allowed_operations.length && correction.allowed_operations[0] !== "harden")))
          || (correction.task_usage_state === "unresolved" && (correction.status !== "uncertain"
            || correction.resource.protection !== "unknown" || correction.allowed_operations.length !== 0))))
        || (correction.revision === 3 && (!hasHarden || correction.correction === null || correction.retest === null
          || correction.allowed_operations.length !== 0
          || (correction.task_usage_state === "settled" && (correction.status !== "hardened" || correction.resource.protection !== "metadata_only"))
          || (correction.task_usage_state === "unresolved" && (correction.status !== "uncertain" || correction.resource.protection !== "unknown"))))) throw bad();
      if (correction.revision === 3) {
        const change = correction.correction!;
        const retest = correction.retest!;
        if (!exactKeys(change, ["binding_digest", "before_descriptor_sha256", "after_descriptor_sha256", "owned_control_cleanup"])
          || !digest(change.binding_digest) || !digest(change.before_descriptor_sha256) || !digest(change.after_descriptor_sha256)
          || change.before_descriptor_sha256 === change.after_descriptor_sha256
          || change.owned_control_cleanup !== "verified"
          || !exactKeys(retest, ["schema_version", "non_owner", "owner", "size_bytes", "sha256", "observed_at", "native_cleanup", "owned_job_cleanup", "independent_observation", "evidence_digest"])
          || retest.schema_version !== "bluefire.windows-file-correction-observation.v3" || retest.non_owner !== "data_access_denied"
          || retest.owner !== "allowed" || retest.size_bytes !== baseline.size_bytes || retest.sha256 !== baseline.sha256
          || typeof retest.observed_at !== "string" || !Number.isFinite(Date.parse(retest.observed_at))
          || Date.parse(retest.observed_at) < Date.parse(baseline.observed_at)
          || retest.native_cleanup !== "verified" || retest.owned_job_cleanup !== "verified"
          || retest.independent_observation !== false || !digest(retest.evidence_digest)) throw bad();
      }
      return correction;
    }
    if (!exactKeys(windows, ["schema_version", "platform", "control_owner_id", "control_digest", "revision", "status", "expires_at_ms", "provenance", "resource", "baseline", "operations", "allowed_operations", "task_usage_state", "account_object_cleanup"])
      || !["bluefire.windows-file-access-control.v1", "bluefire.windows-file-access-control.v2"].includes(windows.schema_version) || !windowsControlId(windows.control_owner_id)
      || (owner !== undefined && windows.control_owner_id !== owner) || !digest(windows.control_digest)
      || !Number.isSafeInteger(windows.expires_at_ms) || windows.expires_at_ms <= 0
      || !exactKeys(windows.provenance, ["kind", "enrollment_id", "enrollment_digest", "setup_receipt_digest"])
      || windows.provenance.kind !== "protected_setup" || typeof windows.provenance.enrollment_id !== "string" || !windows.provenance.enrollment_id
      || !digest(windows.provenance.enrollment_digest) || !digest(windows.provenance.setup_receipt_digest)
      || !exactKeys(windows.resource, ["resource_id", "resource_generation", "expected_sha256", "size_bytes", "protection"])
      || typeof windows.resource.resource_id !== "string" || !windows.resource.resource_id
      || typeof windows.resource.resource_generation !== "string" || !/^[0-9a-f]{32}$/.test(windows.resource.resource_generation)
      || !digest(windows.resource.expected_sha256) || !Number.isSafeInteger(windows.resource.size_bytes) || windows.resource.size_bytes < 1
      || windows.resource.protection !== "reader_readable" || windows.account_object_cleanup !== "required"
      || (expectedSetup !== undefined && (windows.provenance.enrollment_id !== expectedSetup.enrollment_id
        || windows.provenance.enrollment_digest !== expectedSetup.enrollment_digest))) throw bad();
    if (windows.schema_version === "bluefire.windows-file-access-control.v1") {
      if (windows.revision !== 1 || windows.status !== "setup_verified" || windows.baseline !== null
        || !Array.isArray(windows.operations) || windows.operations.length !== 0
        || !Array.isArray(windows.allowed_operations) || windows.allowed_operations.length !== 0
        || windows.task_usage_state !== "none") throw bad();
    } else {
      const paired = windows as WindowsPairedFileAccessControl;
      if (![1, 2].includes(paired.revision) || !["setup_verified", "uncertain", "baseline_verified"].includes(paired.status)
        || !["none", "unresolved", "settled"].includes(paired.task_usage_state)
        || !operationsValid(paired.allowed_operations, ["baseline"]) || !Array.isArray(paired.operations)
        || new Set(paired.operations.map(job => job?.job_id)).size !== paired.operations.length
        || paired.operations.some(job => !windowsPairJobValid(job, paired.control_owner_id))) throw bad();
      const baseline = paired.baseline;
      const baselineValid = baseline === null || (exactKeys(baseline, ["schema_version", "non_owner", "owner", "size_bytes", "sha256", "resource_generation", "observed_at", "native_cleanup", "owned_job_cleanup", "independent_observation", "baseline_digest"])
        && baseline.schema_version === "bluefire.windows-file-readable-baseline.v2" && baseline.non_owner === "allowed" && baseline.owner === "allowed"
        && natural(baseline.size_bytes) && baseline.size_bytes > 0 && digest(baseline.sha256)
        && baseline.size_bytes === paired.resource.size_bytes && baseline.sha256 === paired.resource.expected_sha256
        && baseline.resource_generation === paired.resource.resource_generation && typeof baseline.observed_at === "string"
        && Number.isFinite(Date.parse(baseline.observed_at)) && baseline.native_cleanup === "verified"
        && baseline.owned_job_cleanup === "verified" && baseline.independent_observation === false && digest(baseline.baseline_digest));
      if (!baselineValid) throw bad();
      if (paired.revision === 1) {
        if (baseline !== null || paired.status === "baseline_verified"
          || (paired.task_usage_state === "none" && (paired.status !== "setup_verified"
            || (paired.operations.length > 0 ? paired.allowed_operations.length !== 0
              : paired.allowed_operations.some(op => op !== "baseline"))))
          || (paired.task_usage_state === "unresolved" && (paired.status !== "uncertain" || paired.operations.length === 0 || paired.allowed_operations.length !== 0))
          || paired.task_usage_state === "settled") throw bad();
      } else if (paired.status !== "baseline_verified" || baseline === null
        || paired.task_usage_state !== "settled" || paired.allowed_operations.length !== 0 || paired.operations.length === 0) throw bad();
    }
    return windows;
  }
  const linux = value as LinuxFileAccessControl;
  if (!exactKeys(linux, ["schema_version", "control_owner_id", "status", "revision", "control_digest", "resource", "baseline", "usage_state", "allowed_operations", "operations"])
    || linux.schema_version !== "bluefire.file-access-control.v1" || owner === undefined || linux.control_owner_id !== owner || !compositionJobValid(owner)
    || !digest(linux.control_digest) || !natural(linux.revision) || linux.revision < 1 || !controlStates.includes(linux.status)
    || !["settled", "pending", "unknown"].includes(linux.usage_state) || !operationsValid(linux.allowed_operations, ["baseline", "harden", "rollback", "reset"])
    || !Array.isArray(linux.operations) || linux.operations.some(job => {
      const submitted = job.progress?.submitted_request as FileAccessSubmission;
      return !compositionJobValid(job.job_id) || job.kind !== "file_access.operation" || typeof job.state !== "string"
        || !fileAccessSubmissionValid(submitted) || compositionJobId(submitted.submission_id) !== job.job_id
        || (submitted.review.control_owner_id ?? job.job_id) !== owner;
    })) throw bad();
  const resource = linux.resource;
  if (resource !== null && (typeof resource?.resource_id !== "string" || !resource.resource_id || typeof resource.resource_generation !== "string" || !resource.resource_generation
    || !digest(resource.sha256) || !natural(resource.size) || !natural(resource.record_count) || !["0600", "0640"].includes(resource.mode))) throw bad();
  const baseline = linux.baseline;
  if (baseline !== null && (!digest(baseline?.baseline_digest) || baseline.non_owner !== "allowed" || baseline.owner !== "allowed" || !natural(baseline.record_count) || !digest(baseline.sha256))) throw bad();
  if (linux.usage_state !== "settled" && linux.allowed_operations.some(operation => operation === "rollback" || operation === "reset")) throw bad();
  if (linux.status === "recovery_required" && (linux.usage_state !== "settled" || linux.allowed_operations.length !== 1 || linux.allowed_operations[0] !== "reset")) throw bad();
  return linux;
}
export function checkedFileAccessList(value: FileAccessControlList): FileAccessControlList {
  if (!exactKeys(value, ["schema_version", "controls"]) || value.schema_version !== "bluefire.file-access-control-list.v1" || !Array.isArray(value.controls)
    || new Set(value.controls.map(item => item.control_owner_id)).size !== value.controls.length
    || value.controls.some(item => {
      if (!record(item)) return true;
      if (item.platform === "macos") return !exactKeys(item, ["control_owner_id", "status", "revision", "platform"])
        || !macOSFileAccessControlIdValid(item.control_owner_id) || !macOSControlStates.includes(String(item.status))
        || !natural(item.revision) || Number(item.revision) < 1;
      if (item.platform === "windows") return !exactKeys(item, ["control_owner_id", "status", "revision", "platform"])
        || !windowsControlId(item.control_owner_id)
        || !(
          (item.revision === 1 && ["setup_verified", "uncertain"].includes(String(item.status)))
          || (item.revision === 2 && ["baseline_verified", "uncertain"].includes(String(item.status)))
          || (item.revision === 3 && ["hardened", "uncertain"].includes(String(item.status)))
        );
      return !exactKeys(item, ["control_owner_id", "status", "revision"]) || !compositionJobValid(String(item.control_owner_id))
        || !controlStates.includes(String(item.status)) || !natural(item.revision) || Number(item.revision) < 1;
    })) throw bad();
  return value;
}
export function checkedFileAccessOperation(value: FileAccessOperationEnvelope, id: string, owner?: string): FileAccessOperationEnvelope {
  if (value?.schema_version !== "bluefire.file-access-operation.v1" || value.job?.job_id !== id || !compositionJobValid(id)
    || value.job.kind !== "file_access.operation" || typeof value.job.state !== "string") throw bad();
  const submitted = value.job.progress?.submitted_request as FileAccessSubmission;
  if (!fileAccessSubmissionValid(submitted) || compositionJobId(submitted.submission_id) !== id) throw bad();
  if (owner && (submitted.review.control_owner_id ?? id) !== owner) throw bad();
  const submittedOwner = submitted.review.control_owner_id;
  if (value.reconciliation !== null && (!digest(value.reconciliation?.outcome_digest)
    || !["unknown", "complete", "refused_no_effect", "settled_partial"].includes(value.reconciliation.state)
    || typeof value.reconciliation.available !== "boolean" || (value.reconciliation.state !== "unknown" && value.reconciliation.available))) throw bad();
  if (value.job.progress.verified_observation !== undefined) {
    const observed = value.job.progress.verified_observation as FileAccessObservation;
    if (windowsControlId(submittedOwner) || macOSFileAccessControlIdValid(submittedOwner) || fileAccessJobActive(value.job) || (value.job.state !== "completed" && value.reconciliation?.state !== "complete")
      || (value.reconciliation !== null && value.reconciliation.state !== "complete")
      || observed?.schema_version !== "bluefire.file-access-control-observation.v1"
      || !["baseline", "rollback"].includes(observed.operation) || observed.operation !== submitted.review.operation
      || observed.non_owner !== "allowed" || observed.owner !== "allowed" || observed.mode !== "0640"
      || typeof observed.resource_generation !== "string" || !observed.resource_generation || !natural(observed.record_count) || observed.record_count < 1
      || !digest(observed.sha256) || !digest(observed.source_digest) || !Number.isSafeInteger(observed.observed_at_ms) || observed.observed_at_ms <= 0) throw bad();
  }
  if (value.control !== null) {
    if (record(value.control) && value.control.platform === "windows"
      && !["bluefire.windows-file-access-control.v2", "bluefire.windows-file-access-control.v3"].includes(String(value.control.schema_version))) throw bad();
    checkedFileAccessControl(value.control, submittedOwner ?? id);
  }
  if (windowsControlId(submittedOwner) && (
    !["baseline", "harden"].includes(submitted.review.operation)
    || !record(value.control) || value.control.platform !== "windows"
    || (submitted.review.operation === "harden" && value.control.schema_version !== "bluefire.windows-file-access-control.v3")
    || (submitted.review.operation === "baseline" && !["bluefire.windows-file-access-control.v2", "bluefire.windows-file-access-control.v3"].includes(String(value.control.schema_version)))
  )) throw bad();
  if (macOSFileAccessControlIdValid(submittedOwner) && ((!record(value.control) || value.control.platform !== "macos")
    || value.reconciliation?.available || value.reconciliation_receipt !== null)) throw bad();
  if (value.reconciliation_receipt !== null) checkedFileAccessReconciliationReceipt(value.reconciliation_receipt);
  return value;
}
export function checkedFileAccessReconciliationReceipt(value: FileAccessReconciliationReceipt): FileAccessReconciliationReceipt {
  if (!value || !reconciliationSubmissionValid(value.submitted_request) || value.submission_id !== value.submitted_request.submission_id
    || !["pending", "completed"].includes(value.state) || (value.problem !== null && (typeof value.problem?.code !== "string" || typeof value.problem?.message !== "string"))) throw bad();
  return value;
}
export function checkedFileAccessReconciliation(value: FileAccessReconciliationEnvelope, operation: string, submission: string): FileAccessReconciliationEnvelope {
  if (value?.schema_version !== "bluefire.file-access-reconciliation.v1" || value.operation_job_id !== operation || value.receipt?.submission_id !== submission) throw bad();
  checkedFileAccessReconciliationReceipt(value.receipt);
  return value;
}
function reconciliationSubmissionValid(value: FileAccessReconciliationSubmission): boolean {
  return Boolean(value && Object.keys(value).sort().join(",") === "expected_outcome_digest,reviewed_by,submission_id"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.submission_id)
    && digest(value.expected_outcome_digest) && typeof value.reviewed_by === "string" && value.reviewed_by.trim() && value.reviewed_by.length <= 128);
}
function fileAccessSubmissionValid(value: FileAccessSubmission): boolean {
  return Boolean(value && Object.keys(value).sort().join(",") === "review,review_digest,reviewed_by,submission_id"
    && typeof value.submission_id === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.submission_id)
    && fileAccessReviewRequestValid(value.review) && digest(value.review_digest)
    && typeof value.reviewed_by === "string" && value.reviewed_by.trim() && value.reviewed_by.length <= 128);
}
const pendingKey = "bluefire.file-access.pending.v1";
export function readFileAccessPending(): FileAccessPending | undefined {
  const raw = localStorage.getItem(pendingKey);
  if (!raw) return;
  if (raw.length > 100_000) throw new Error("The saved file-access request exceeds the recovery limit.");
  const value = JSON.parse(raw) as FileAccessPending;
  if (!value || Object.keys(value).sort().join(",") !== "body,id" || !fileAccessSubmissionValid(value.body) || value.id !== compositionJobId(value.body.submission_id)) throw new Error("The saved file-access request needs recovery. Nothing has been sent.");
  return value;
}
export function storeFileAccessPending(value: FileAccessPending) {
  if (!fileAccessSubmissionValid(value.body) || value.id !== compositionJobId(value.body.submission_id)) throw bad();
  const previous = readFileAccessPending();
  if (previous && !sameJson(previous, value)) throw new Error("Reconcile the original file-access request before another operation.");
  const raw = JSON.stringify(value);
  localStorage.setItem(pendingKey, raw);
  if (localStorage.getItem(pendingKey) !== raw) throw new Error("The exact operation could not be retained. Nothing was sent.");
}
export function clearFileAccessPending(value: FileAccessPending) {
  if (!sameJson(readFileAccessPending(), value)) throw new Error("The pending file-access request changed in another tab.");
  localStorage.removeItem(pendingKey);
}
export function fileAccessConfirmed(value: FileAccessOperationEnvelope, pending: FileAccessPending) {
  return value.job.job_id === pending.id && sameJson(value.job.progress.submitted_request, pending.body);
}
async function live<T>(callback: () => Promise<T>): Promise<T> {
  if (DEMO_MODE) throw new Error("Effective file access requires an explicitly prepared session. Demo mode cannot execute it.");
  return callback();
}
function post<T>(path: string, body: unknown): Promise<T> {
  return live(() => request<T>(`/file-access/${path}`, { method: "POST", body: JSON.stringify(body) }));
}
export const fileAccessApi = {
  review: (body: FileAccessReviewRequest) => post<FileAccessReview>("review", body),
  status: (): Promise<FileAccessStatus> => DEMO_MODE ? Promise.resolve({ schema_version: "bluefire.file-access-status.v1", available: false, enrollment: null, allowed_operations: [], problem: { code: "demo_no_enrollment", message: "Demo mode has no enrolled test identity or generated application file." } }) : request<FileAccessStatus>("/file-access/status"),
  list: (): Promise<FileAccessControlList> => DEMO_MODE ? Promise.resolve({ schema_version: "bluefire.file-access-control-list.v1", controls: [] }) : post<FileAccessControlList>("control-list", {}),
  importSetup: (body: FileAccessSetupImportRequest) => post<WindowsFileAccessControl | MacOSFileAccessControl>("setup-import", body),
  control: (id: string) => live(() => request<FileAccessControl>(`/file-access/controls/${encodeURIComponent(id)}`)),
  operation: (id: string) => live(() => request<FileAccessOperationEnvelope>(`/file-access/operations/${encodeURIComponent(id)}`)),
  submit: (body: FileAccessSubmission) => post<FileAccessOperationEnvelope>("operations", body),
  reconcile: (id: string, body: FileAccessReconciliationSubmission) => post<FileAccessOperationEnvelope>(`operations/${encodeURIComponent(id)}/reconcile`, body),
  reconciliation: (id: string, submission: string) => live(() => request<FileAccessReconciliationEnvelope>(`/file-access/operations/${encodeURIComponent(id)}/reconciliations/${encodeURIComponent(submission)}`)),
};
export interface FileAccessReconciliationPending { operation_job_id: string; control_owner_id: string; body: FileAccessReconciliationSubmission }
const reconciliationKey = "bluefire.file-access.reconciliation.v1";
export function readFileAccessReconciliationPending(): FileAccessReconciliationPending | undefined {
  const raw = localStorage.getItem(reconciliationKey);
  if (!raw) return;
  if (raw.length > 100_000) throw new Error("The retained reconciliation request exceeds the recovery limit.");
  const value = JSON.parse(raw) as FileAccessReconciliationPending;
  if (!value || Object.keys(value).sort().join(",") !== "body,control_owner_id,operation_job_id" || !compositionJobValid(value.operation_job_id)
    || !fileAccessControlIdValid(value.control_owner_id) || macOSFileAccessControlIdValid(value.control_owner_id) || !reconciliationSubmissionValid(value.body)) throw new Error("The saved evidence request needs recovery. Nothing was sent.");
  return value;
}
export function storeFileAccessReconciliationPending(value: FileAccessReconciliationPending) {
  if (!compositionJobValid(value.operation_job_id) || !fileAccessControlIdValid(value.control_owner_id) || macOSFileAccessControlIdValid(value.control_owner_id) || !reconciliationSubmissionValid(value.body)) throw bad();
  const previous = readFileAccessReconciliationPending();
  if (previous && !sameJson(previous, value)) throw new Error("Reconcile the original evidence request before another request.");
  const raw = JSON.stringify(value); localStorage.setItem(reconciliationKey, raw);
  if (localStorage.getItem(reconciliationKey) !== raw) throw new Error("The exact evidence request could not be retained. Nothing was sent.");
}
export function clearFileAccessReconciliationPending(value: FileAccessReconciliationPending) {
  if (!sameJson(readFileAccessReconciliationPending(), value)) throw new Error("The pending evidence request changed in another tab.");
  localStorage.removeItem(reconciliationKey);
}
export function fileAccessReconciliationConfirmed(value: FileAccessReconciliationReceipt, pending: FileAccessReconciliationPending): boolean {
  return value.submission_id === pending.body.submission_id && value.state === "completed" && sameJson(value.submitted_request, pending.body);
}
