import { checkedCompositionContext, compositionJobId, compositionJobValid, compositionRecord, type CompositionContext, type CompositionObjective, type CompositionProposal } from "./composition";
import { checkedCompositionCandidate } from "./composition-evidence";
import { sameJson } from "./replay-review";

export const RECEIVER_RETAINED_PACK = "bluefire.receiver-composition-pack.v2";
export const RETAINED_MATERIALIZE_METHOD = "sandbox.collection.materialize-retained.v1";
export const retainedPolicy = {
  max_artifacts_per_attempt: 1, max_bytes_per_artifact: 262_144, max_bytes_per_attempt: 262_144,
  data_class: "generated_public_jsonl", producer: "sandbox.collection.stage.v1", output: "bundle",
  disposition: "sealed_until_run_bundle_deleted",
  materialization_payload_disposition: "retained_in_existing_task_and_transport_stores_until_those_stores_are_deleted",
  materialization_payload_copy_reservation: 2,
  materialization_wire: { encoding: "canonical_hex_chunks", max_chunks: 32, max_chunk_chars: 16_384, max_encoded_chars: 524_288 },
  workspace_cleanup: "owned_receipts_only",
  payload_storage: "fixed_private_child_of_source_run",
  payload_export: "excluded_metadata_only",
} as const;
export type RetainedPolicy = typeof retainedPolicy;
export interface RetainedCompositionSource { run_id: string; attempt_id: string; lineage_id: string; step_id: string; artifact: "bundle"; artifact_type: "artifact.sandbox.bundle.v1"; sha256: string; size_bytes: number; source_ref: string }
export interface RetainedCompositionArtifacts { policy: RetainedPolicy; available_sources: RetainedCompositionSource[]; availability: "available" | "none_available" }
export interface RetainedCompositionContinuation { schema_version: "bluefire.retained-continuation.v1"; source: RetainedCompositionSource; prior_run_id: string; later_failure: { step_id: string; outcome: "blocked" | "failed" | "partial" }; receiver_decision: "unknown"; cleanup: { run: "complete"; receiver: "verified_closed" }; continuation_digest: string }
const bad = () => new Error("The retained result could not be matched to this reviewed objective and verified source.");
const exact = (value: unknown, keys: string[]) => Object.keys(compositionRecord(value)).sort().join(",") === [...keys].sort().join(",");
const text = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 200 && [...value].every(character => character.charCodeAt(0) >= 32);
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);

export function checkedRetainedPolicy(value: unknown): RetainedPolicy {
  if (!sameJson(value, retainedPolicy)) throw bad();
  return value as RetainedPolicy;
}
export function checkedRetainedSource(value: unknown): RetainedCompositionSource {
  const row = compositionRecord(value);
  if (!exact(row, ["run_id", "attempt_id", "lineage_id", "step_id", "artifact", "artifact_type", "sha256", "size_bytes", "source_ref"]) || typeof row.run_id !== "string" || !/^run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$/.test(row.run_id) || typeof row.attempt_id !== "string" || !/^attempt-[0-9a-f]{32}$/.test(row.attempt_id) || !text(row.lineage_id) || !text(row.step_id) || row.artifact !== "bundle" || row.artifact_type !== "artifact.sandbox.bundle.v1" || typeof row.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(row.sha256) || !Number.isSafeInteger(row.size_bytes) || Number(row.size_bytes) < 1 || Number(row.size_bytes) > 262_144 || !digest(row.source_ref)) throw bad();
  return value as RetainedCompositionSource;
}
export function checkedRetainedArtifacts(value: unknown, objective?: CompositionObjective): RetainedCompositionArtifacts {
  const row = compositionRecord(value);
  if (!exact(row, ["policy", "available_sources", "availability"]) || !Array.isArray(row.available_sources) || row.available_sources.length > 32 || row.availability !== (row.available_sources.length ? "available" : "none_available")) throw bad();
  checkedRetainedPolicy(row.policy);
  const ids = new Set<string>(), attempts = new Set<string>();
  for (const raw of row.available_sources) {
    const source = checkedRetainedSource(raw);
    if (ids.has(source.source_ref) || attempts.has(source.attempt_id) || objective && !objective.attempts.some(attempt => attempt.request.composition_attempt.attempt_id === source.attempt_id && attempt.request.composition_attempt.run_id === source.run_id)) throw bad();
    ids.add(source.source_ref);
    attempts.add(source.attempt_id);
  }
  return value as RetainedCompositionArtifacts;
}
export function checkedRetainedContinuation(value: unknown, run: string): RetainedCompositionContinuation {
  const row = compositionRecord(value);
  const failure = compositionRecord(row.later_failure), cleanup = compositionRecord(row.cleanup);
  if (!exact(row, ["schema_version", "source", "prior_run_id", "later_failure", "receiver_decision", "cleanup", "continuation_digest"]) || row.schema_version !== "bluefire.retained-continuation.v1" || row.prior_run_id !== run || !exact(failure, ["step_id", "outcome"]) || !text(failure.step_id) || !["blocked", "failed", "partial"].includes(String(failure.outcome)) || row.receiver_decision !== "unknown" || !exact(cleanup, ["run", "receiver"]) || cleanup.run !== "complete" || cleanup.receiver !== "verified_closed" || !digest(row.continuation_digest)) throw bad();
  checkedRetainedSource(row.source);
  return value as RetainedCompositionContinuation;
}
export function checkedRetainedCandidate(proposal: NonNullable<CompositionProposal["proposal"]>, context: Pick<CompositionContext, "snapshot" | "facts" | "retained_artifacts">) {
  checkedCompositionCandidate(proposal, context);
  const artifacts = checkedRetainedArtifacts(context.retained_artifacts);
  for (const step of proposal.candidate.steps) {
    if (step.behavior_id === RETAINED_MATERIALIZE_METHOD && (!exact(step.parameters, ["source_ref"]) || !artifacts.available_sources.some(source => source.source_ref === step.parameters.source_ref))) throw bad();
  }
}
export function checkedRetainedProposal(value: CompositionProposal, owner: string) {
  const result = value.proposal!;
  const context = value.job.request.context as CompositionContext;
  const submitted = compositionRecord(value.job.request.submitted_request);
  checkedCompositionContext(context, context?.grant_id, RECEIVER_RETAINED_PACK);
  checkedRetainedCandidate(result, context);
  if (!compositionJobValid(owner) || !exact(result, ["schema_version", "proposal_job_id", "owner_id", "context_digest", "prior_attempt_id", "candidate", "scenario", "proposal_digest", "provider", "model_context_digest", "reconsideration"]) || !digest(result.model_context_digest) || result.reconsideration !== null || result.knowledge_digest !== undefined || !exact(submitted, ["submission_id", "provider_id", "context_digest", "prior_attempt_id"]) || typeof submitted.submission_id !== "string" || compositionJobId(submitted.submission_id) !== value.job.job_id || submitted.provider_id !== result.provider.provider_id || submitted.context_digest !== context.context_digest || result.context_digest !== context.context_digest || submitted.prior_attempt_id !== result.prior_attempt_id || context.facts.prior_attempt_id !== submitted.prior_attempt_id || submitted.prior_attempt_id !== null && (typeof submitted.prior_attempt_id !== "string" || !/^attempt-[0-9a-f]{32}$/.test(submitted.prior_attempt_id))) throw bad();
}
