import { request } from "./api";
import { compositionPack, compositionRecord, FILE_ACCESS_PACK, type CompositionAttempt, type CompositionObjective } from "./composition";

export interface FileAccessRetestLinkage {
  schema_version: "bluefire.file-access-composed-retest-linkage.v1";
  objective_owner_id: string;
  attempt_id: string;
  control_owner_id: string;
  linkage_digest: string;
  baseline: {
    operation_job_id: string; control_revision: number; control_digest: string; baseline_digest: string;
    mode: "0640"; resource_generation: string; non_owner: "allowed"; owner: "allowed";
    record_count: number; sha256: string;
  };
  change: {
    operation_job_id: string; control_revision: number; control_digest: string; previous_control_digest: string;
    mode: "0600"; resource_generation: string;
  };
  retest: {
    attempt_job_id: string; run_id: string; state: "verified" | "unknown";
    non_owner_decision: "allowed" | "permission_denied" | "unknown" | null;
    owner_decision: "allowed" | "unknown" | null; record_count: number | null; sha256: string | null;
    run_cleanup: "complete" | "incomplete" | null; request_cleanup: "verified_closed" | null;
    objective_established: boolean | null; result_digest: string | null;
  };
  comparison: {
    state: "established" | "not_established" | "unknown";
    non_owner_change: "allowed_to_denied" | "still_allowed" | "unknown";
    owner_preserved: boolean | null; content_preserved: boolean | null; cleanup_verified: boolean | null;
  };
}

const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const job = (value: unknown): value is string => typeof value === "string" && /^job-[0-9a-f]{32}$/.test(value);
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) > 0 && Number(value) <= 100;
const nullableBoolean = (value: unknown) => value === null || typeof value === "boolean";
const oneOf = (value: unknown, choices: readonly string[]): value is string => typeof value === "string" && choices.includes(value);

export function checkedFileAccessRetestLinkage(value: unknown, objective: CompositionObjective, attempt: CompositionAttempt): FileAccessRetestLinkage {
  const record = compositionRecord(value);
  const baseline = compositionRecord(record.baseline);
  const change = compositionRecord(record.change);
  const retest = compositionRecord(record.retest);
  const comparison = compositionRecord(record.comparison);
  const grant = objective.grant.document;
  const environment = grant.environment;
  const binding = attempt.request.composition_attempt;
  const invalid = () => { throw new Error("This saved comparison does not match the selected file-access attempt."); };
  if (compositionPack(grant) !== FILE_ACCESS_PACK || record.schema_version !== "bluefire.file-access-composed-retest-linkage.v1"
    || record.objective_owner_id !== objective.owner.job_id || record.attempt_id !== binding.attempt_id
    || record.control_owner_id !== environment.control_owner_id || !digest(record.linkage_digest)
    || !job(baseline.operation_job_id) || !job(change.operation_job_id) || baseline.operation_job_id === change.operation_job_id
    || !Number.isSafeInteger(baseline.control_revision) || Number(baseline.control_revision) < 1
    || change.control_revision !== environment.control_revision || Number(change.control_revision) <= Number(baseline.control_revision)
    || !digest(baseline.control_digest) || baseline.baseline_digest !== environment.baseline_digest
    || change.control_digest !== environment.control_digest || !digest(change.previous_control_digest)
    || baseline.mode !== "0640" || change.mode !== "0600"
    || baseline.resource_generation !== environment.resource_generation || change.resource_generation !== environment.resource_generation
    || baseline.non_owner !== "allowed" || baseline.owner !== "allowed" || !count(baseline.record_count)
    || baseline.record_count !== grant.objective.predicate.record_count || baseline.sha256 !== grant.objective.predicate.sha256
    || retest.attempt_job_id !== attempt.job_id || retest.run_id !== binding.run_id
    || !oneOf(retest.state, ["verified", "unknown"])
    || !oneOf(comparison.state, ["established", "not_established", "unknown"])
    || !oneOf(comparison.non_owner_change, ["allowed_to_denied", "still_allowed", "unknown"])
    || ![comparison.owner_preserved, comparison.content_preserved, comparison.cleanup_verified].every(nullableBoolean)) invalid();
  if (retest.state === "unknown") {
    if (["non_owner_decision", "owner_decision", "record_count", "sha256", "run_cleanup", "request_cleanup", "objective_established", "result_digest"].some(key => retest[key] !== null)
      || comparison.state !== "unknown" || comparison.non_owner_change !== "unknown"
      || [comparison.owner_preserved, comparison.content_preserved, comparison.cleanup_verified].some(item => item !== null)) invalid();
  } else {
    if (!oneOf(retest.non_owner_decision, ["allowed", "permission_denied", "unknown"])
      || !oneOf(retest.owner_decision, ["allowed", "unknown"]) || !count(retest.record_count)
      || !digest(retest.sha256) || !digest(retest.result_digest)
      || (attempt.progress.verified_result_digest !== undefined && retest.result_digest !== attempt.progress.verified_result_digest)
      || typeof retest.objective_established !== "boolean"
      || !oneOf(retest.run_cleanup, ["complete", "incomplete"]) || retest.request_cleanup !== "verified_closed"
      || comparison.state !== (retest.objective_established ? "established" : "not_established")
      || comparison.non_owner_change !== (retest.non_owner_decision === "permission_denied" ? "allowed_to_denied" : retest.non_owner_decision === "allowed" ? "still_allowed" : "unknown")
      || comparison.owner_preserved !== (retest.owner_decision === "allowed" ? true : null)
      || comparison.content_preserved !== (retest.owner_decision === "allowed" ? retest.sha256 === baseline.sha256 && retest.record_count === baseline.record_count : null)
      || comparison.cleanup_verified !== (retest.run_cleanup === "complete" && retest.request_cleanup === "verified_closed")) invalid();
    if (comparison.state === "established" && (comparison.non_owner_change !== "allowed_to_denied"
      || comparison.owner_preserved !== true || comparison.content_preserved !== true || comparison.cleanup_verified !== true)) invalid();
  }
  return value as FileAccessRetestLinkage;
}

export const fileAccessLinkageApi = {
  read: (objective: string, attempt: string): Promise<unknown> => request(`/composition/objectives/${encodeURIComponent(objective)}/file-access-linkage/${encodeURIComponent(attempt)}`),
};
