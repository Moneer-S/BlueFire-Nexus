import type { ActionDefinition, Behavior, Scenario } from "../types";
import { request, DEMO_MODE } from "./api";
import { sameJson } from "./replay-review";
import { parseScenarioDocument } from "./scenario";
import { checkedCompositionEvidenceResult, type CompositionReconsideration } from "./composition-evidence";
import type { CompositionKnowledge } from "./composition-knowledge";
import { checkedRetainedArtifacts, checkedRetainedContinuation, checkedRetainedPolicy, checkedRetainedProposal, RECEIVER_RETAINED_PACK, RETAINED_MATERIALIZE_METHOD, type RetainedCompositionArtifacts, type RetainedPolicy } from "./composition-retained";
import type { CompositionEvidenceContext } from "./composition-evidence";

export const FILE_ACCESS_PACK = "bluefire.linux-file-access-pack.v1";
export const MACOS_FILE_ACCESS_PACK = "bluefire.macos-file-access-pack.v1";
export const RECEIVER_PACK = "bluefire.receiver-composition-pack.v1";
export type CompositionPack = typeof FILE_ACCESS_PACK | typeof MACOS_FILE_ACCESS_PACK | typeof RECEIVER_PACK | typeof RECEIVER_RETAINED_PACK;
export type CompositionReviewRequest = { control_owner_id: string; question: string; limits: Record<string, number> | null } & ({ schema_version?: never; pack?: never } | { schema_version: "bluefire.composition-review-request.v2"; pack: typeof FILE_ACCESS_PACK | typeof MACOS_FILE_ACCESS_PACK | typeof RECEIVER_RETAINED_PACK });
export interface CompositionMethod { behavior_id: string; action_id: string; behavior: Behavior; action: ActionDefinition; implementation_digest: string; parameter_domains: Record<string, unknown[]>; cost: Record<string, unknown> }
export interface CompositionReview {
  schema_version: string; pack?: CompositionPack; objective: { question: string; predicate: Record<string, unknown> };
  environment: { control_owner_id: string; runner_id: string; [key: string]: unknown };
  limits: Record<string, number>; snapshot: { schema_version?: string; platform?: string; pack?: CompositionPack; snapshot_digest: string; methods: CompositionMethod[]; artifact_context: Record<string, unknown> };
  retention?: RetainedPolicy; native_materialization?: { method: string; readiness: "ready"; implementation_digest: string };
  limitations: string[]; review_digest: string;
}
export interface CompositionJob { job_id: string; kind: string; state: string; request: Record<string, unknown>; progress: Record<string, unknown>; error?: unknown }
export interface CompositionAttempt extends CompositionJob {
  request: { composition_attempt: { parent_job_id: string; grant_id: string; grant_digest: string; attempt_id: string; compiled_digest: string; run_id: string } };
}
export interface CompositionObjective {
  schema_version: "bluefire.composition-objective.v1"; owner: CompositionJob;
  grant: { document: Omit<CompositionReview, "review_digest" | "limitations"> & { grant_id: string; grant_digest: string; approved_by: string; created_at_ms: number; expires_at_ms: number }; status: string; usage: Record<string, number>; cleanup_state: unknown };
  attempts: CompositionAttempt[];
}
export interface CompositionRefusal { schema_version: "bluefire.composition-objective.v1"; owner: CompositionJob; grant: null; attempts: [] }
export type CompositionObjectiveState = CompositionObjective | CompositionRefusal;
export interface CompositionCandidate { schema_version: "bluefire.composition-proposal.v1"; title: string; start: string; steps: Array<{ id: string; behavior_id: string; parameters: Record<string, unknown>; inputs?: Record<string, { from_step: string; artifact: string }> }>; edges: Array<{ from_step: string; outcome: string; to_step: string }>; evidence_refs: string[]; rationale: string }
export interface CompositionContext { schema_version: "bluefire.composition-proposal-context.v1" | "bluefire.retained-composition-proposal-context.v1"; retained_artifacts?: RetainedCompositionArtifacts; grant_id: string; context_digest: string; objective: CompositionReview["objective"]; snapshot: CompositionReview["snapshot"]; facts: { facts: Array<{ fact_id: string; kind: string; value: unknown; [key: string]: unknown }>; [key: string]: unknown }; initial_proposal: CompositionCandidate | null; initial_scenario: Scenario | null }
export interface CompositionProposal { job: CompositionJob; candidate_ready: boolean; provider_outcome: string; proposal: null | { schema_version: string; knowledge_digest?: string; model_context_digest?: string; reconsideration?: CompositionReconsideration | null; proposal_job_id: string; owner_id: string; context_digest: string; prior_attempt_id: string | null; candidate: CompositionCandidate; scenario: Scenario; proposal_digest: string; provider: { provider_id: string; kind: string; model: string; used_fallback: false; attempts: number } } }
export interface CompositionList { schema_version: "bluefire.composition-objective-list.v1"; objectives: Array<{ owner_id: string; title: string; status: string; job_state: string }> }

export const compositionJobValid = (value: unknown): value is string => typeof value === "string" && /^job-[0-9a-f]{32}$/.test(value);
export function compositionControlValid(value: unknown, pack?: CompositionPack): value is string {
  const mac = typeof value === "string" && /^file-control-[0-9a-f]{64}$/.test(value);
  return pack === MACOS_FILE_ACCESS_PACK ? mac : pack === undefined ? mac || compositionJobValid(value) : compositionJobValid(value);
}
export const compositionJobId = (submission: string) => `job-${submission.replaceAll("-", "")}`;
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
export const compositionRecord = (value: unknown): Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const bad = () => new Error("This composition response is incomplete or belongs to different saved work.");
const exactKeys = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const macMethods = ["macos.file_access.probe.v1", "macos.file_access.verify_owner.v1", "macos.file_access.close_attempt.v1"];
const macChecks = ["probe_authenticated", "non_owner_denied", "owner_read_verified", "same_resource", "same_control_revision", "same_original_binding", "content_preserved", "requests_closed", "no_attempt_artifacts", "enrollment_retained"];

export function compositionPack(value: Pick<CompositionReview, "schema_version" | "pack" | "snapshot">): CompositionPack {
  if (["bluefire.composition-review.v2", "bluefire.capability-grant.v2"].includes(value.schema_version)
    && value.pack === MACOS_FILE_ACCESS_PACK && value.snapshot?.pack === MACOS_FILE_ACCESS_PACK
    && value.snapshot.schema_version === "bluefire.macos-file-access-capability-snapshot.v1" && value.snapshot.platform === "macos") return MACOS_FILE_ACCESS_PACK;
  if (["bluefire.composition-review.v2", "bluefire.capability-grant.v2"].includes(value.schema_version)
    && value.pack === FILE_ACCESS_PACK && value.snapshot?.pack === FILE_ACCESS_PACK) return FILE_ACCESS_PACK;
  if (["bluefire.composition-review.v2", "bluefire.capability-grant.v2"].includes(value.schema_version)
    && value.pack === RECEIVER_RETAINED_PACK && value.snapshot?.pack === RECEIVER_RETAINED_PACK
    && value.snapshot.schema_version === "bluefire.retained-receiver-capability-snapshot.v1") return RECEIVER_RETAINED_PACK;
  if (["bluefire.composition-review.v1", "bluefire.capability-grant.v1"].includes(value.schema_version)
    && value.pack === undefined && value.snapshot?.pack === RECEIVER_PACK) return RECEIVER_PACK;
  throw bad();
}

export function checkedCompositionReview(value: CompositionReview, submitted: CompositionReviewRequest): CompositionReview {
  const pack = compositionPack(value);
  if (compositionRequestPack(submitted) !== pack || value.schema_version !== (pack === RECEIVER_PACK ? "bluefire.composition-review.v1" : "bluefire.composition-review.v2") || !digest(value.review_digest) || value.environment?.control_owner_id !== submitted.control_owner_id || value.objective?.question !== submitted.question || !Array.isArray(value.snapshot?.methods) || !value.snapshot.methods.length || !digest(value.snapshot.snapshot_digest) || !Array.isArray(value.limitations) || !Object.entries(value.limits ?? {}).every(([key, item]) => Number.isSafeInteger(item) && item >= (key === "max_edges_per_attempt" ? 0 : 1)) || (submitted.limits !== null && !sameJson(submitted.limits, value.limits))) throw bad();
  if (pack === RECEIVER_RETAINED_PACK) {
    checkedRetainedSnapshot(value.snapshot); checkedRetainedPolicy(value.retention);
    if (!value.native_materialization || !exactKeys(compositionRecord(value.native_materialization), ["method", "readiness", "implementation_digest"]) || value.native_materialization.method !== RETAINED_MATERIALIZE_METHOD || value.native_materialization.readiness !== "ready" || !digest(value.native_materialization.implementation_digest) || !value.snapshot.methods.some(method => method.behavior_id === RETAINED_MATERIALIZE_METHOD && method.implementation_digest === value.native_materialization!.implementation_digest)) throw bad();
  }
  if (pack === FILE_ACCESS_PACK) checkedFileAccessScope(value);
  if (pack === MACOS_FILE_ACCESS_PACK) checkedMacOSFileAccessScope(value);
  return value;
}
export function checkedCompositionObjective<T extends CompositionObjectiveState>(value: T, id: string, control?: string, expectedPack?: CompositionPack): T {
  if (value?.schema_version !== "bluefire.composition-objective.v1" || value.owner?.job_id !== id || value.owner.kind !== "composition.objective" || !Array.isArray(value.attempts)) throw bad();
  if (value.grant === null) {
    const admission = compositionRecord(value.owner.progress.admission);
    const problem = compositionRecord(admission.problem);
    const submitted = compositionRecord(value.owner.progress.submitted_request);
    const review = compositionRecord(submitted.review);
    if (value.owner.state !== "completed" || admission.accepted !== false || !["composition_review_changed", "composition_admission_unavailable", "composition_admission_interrupted"].includes(String(problem.code)) || typeof problem.message !== "string" || value.attempts.length || typeof submitted.submission_id !== "string" || compositionJobId(submitted.submission_id) !== id || typeof review.question !== "string" || (review.limits !== null && (typeof review.limits !== "object" || Array.isArray(review.limits))) || (control && review.control_owner_id !== control)) throw bad();
    const pack = compositionRequestPack(review);
    if (!compositionControlValid(review.control_owner_id, pack)) throw bad();
    if (expectedPack && pack !== expectedPack) throw bad();
    return value;
  }
  const grant = value?.grant?.document;
  if (value?.schema_version !== "bluefire.composition-objective.v1" || value.owner?.job_id !== id || value.owner.kind !== "composition.objective" || !grant || !digest(grant.grant_digest) || !Array.isArray(value.attempts) || !Array.isArray(grant.snapshot?.methods) || !Number.isSafeInteger(grant.expires_at_ms) || !Number.isSafeInteger(grant.created_at_ms) || grant.expires_at_ms <= grant.created_at_ms || (control && grant.environment?.control_owner_id !== control) || value.owner.request.grant_id !== grant.grant_id || value.owner.request.grant_digest !== grant.grant_digest) throw bad();
  const pack = compositionPack(grant);
  if (grant.schema_version !== (pack === RECEIVER_PACK ? "bluefire.capability-grant.v1" : "bluefire.capability-grant.v2")) throw bad();
  if (expectedPack && pack !== expectedPack) throw bad();
  if (pack === RECEIVER_RETAINED_PACK) checkedRetainedSnapshot(grant.snapshot);
  if (pack === FILE_ACCESS_PACK) checkedFileAccessScope(grant);
  if (pack === MACOS_FILE_ACCESS_PACK) checkedMacOSFileAccessScope(grant);
  const ids = new Set<string>();
  for (const attempt of value.attempts) {
    const binding = attempt?.request?.composition_attempt;
    if (!compositionJobValid(attempt.job_id) || attempt.kind !== "composition.attempt" || !binding || binding.parent_job_id !== id || binding.grant_id !== grant.grant_id || binding.grant_digest !== grant.grant_digest || !/^attempt-[0-9a-f]{32}$/.test(binding.attempt_id) || ids.has(attempt.job_id)) throw bad();
    ids.add(attempt.job_id);
    if (attempt.progress.retained_continuation !== undefined) {
      if (pack !== RECEIVER_RETAINED_PACK || attempt.progress.settlement !== "settled") throw bad();
      const continuation = checkedRetainedContinuation(attempt.progress.retained_continuation, binding.run_id);
      checkedRetainedArtifacts({ policy: grant.snapshot.artifact_context.retention, available_sources: [continuation.source], availability: "available" }, value);
    }
    if (attempt.progress.verified_result !== undefined) {
      const result = compositionRecord(attempt.progress.verified_result);
      const outcome = compositionRecord(result.objective);
      const checks = compositionRecord(outcome.checks);
      const required = pack === MACOS_FILE_ACCESS_PACK ? macChecks : pack === FILE_ACCESS_PACK ? ["probe_authenticated", "non_owner_denied", "owner_read_verified", "same_resource", "same_control_revision", "same_probe_enrollment", "content_preserved", "identity_unchanged", "parents_unchanged", "acl_unchanged", "run_cleaned", "request_closed"] : ["receiver_verified", "policy_unchanged", "data_class_preserved", "record_count_preserved", "all_records_redacted", "accepted", "run_cleaned", "receiver_closed"];
      if (!digest(attempt.progress.verified_result_digest) || result.run_id !== binding.run_id || typeof outcome.established !== "boolean" || required.some(key => typeof checks[key] !== "boolean") || outcome.established !== required.every(key => checks[key] === true)) throw bad();
      if (pack === FILE_ACCESS_PACK) checkedFileAccessResult(result, grant, checks);
      if (pack === MACOS_FILE_ACCESS_PACK) checkedMacOSFileAccessResult(result, grant, checks);
    }
  }
  return value;
}
function checkedRetainedSnapshot(snapshot: CompositionReview["snapshot"]) {
  checkedRetainedPolicy(snapshot.artifact_context?.retention);
  if (snapshot.artifact_context?.materialization !== "sealed_generated_jsonl_fresh_materialization" || snapshot.artifact_context.data_class !== "generated_public_jsonl" || !digest(snapshot.artifact_context.environment_digest) || !snapshot.methods.some(method => method.behavior_id === RETAINED_MATERIALIZE_METHOD && digest(method.implementation_digest))) throw bad();
}
function checkedFileAccessScope(value: Pick<CompositionReview, "environment" | "objective">) {
  const environment = value.environment;
  const predicate = value.objective.predicate;
  if (["control_digest", "resource_digest", "probe_enrollment_digest", "baseline_digest"].some(key => !digest(environment[key]))
    || ["resource_id", "resource_generation"].some(key => typeof environment[key] !== "string" || !environment[key])
    || !Number.isSafeInteger(environment.control_revision) || Number(environment.control_revision) < 1 || environment.mode !== "0600"
    || predicate.kind !== "non_owner_denied_owner_preserves_records" || predicate.data_class !== "generated_public_jsonl" || !digest(predicate.sha256)
    || !Number.isSafeInteger(predicate.record_count) || Number(predicate.record_count) < 1 || Number(predicate.record_count) > 100) throw bad();
}
function checkedMacOSSnapshot(snapshot: CompositionReview["snapshot"]) {
  if (snapshot.schema_version !== "bluefire.macos-file-access-capability-snapshot.v1" || snapshot.pack !== MACOS_FILE_ACCESS_PACK
    || snapshot.platform !== "macos" || !digest(snapshot.snapshot_digest) || !Array.isArray(snapshot.methods) || snapshot.methods.length !== 3
    || snapshot.artifact_context?.materialization !== "original_workspace_metadata_only"
    || snapshot.artifact_context.data_class !== "generated_public_jsonl" || !digest(snapshot.artifact_context.environment_digest)) throw bad();
  const inputs = [[], [["probe", "artifact.macos_file_access.probe.v1", false, true]], [["workspace", "artifact.macos_file_access.attempt.v1", false, true]]];
  const outputs = [[["probe", "artifact.macos_file_access.probe.v1", false], ["workspace", "artifact.macos_file_access.attempt.v1", false]], [["verification", "artifact.macos_file_access.verification.v1", false]], [["closure", "artifact.macos_file_access.attempt_closure.v1", false]]];
  for (const [index, method] of snapshot.methods.entries()) {
    const id = macMethods[index];
    if (method.behavior_id !== id || method.action_id !== id || method.behavior?.id !== id || method.action?.id !== id
      || method.behavior.execution_state !== "action" || !method.behavior.platforms?.includes("macos") || !method.action.platforms?.includes("macos")
      || !sameJson(method.behavior.action_ids, [id]) || method.behavior.safety_tier !== "controlled" || method.action.safety_tier !== "controlled"
      || !sameJson(method.behavior.capabilities, [index === 2 ? "cleanup" : "filesystem.read"]) || !sameJson(method.action.capabilities, [index === 2 ? "cleanup" : "filesystem.read"])
      || method.action.mutates !== false || method.action.cleanup_action_id !== (index === 2 ? null : macMethods[2])
      || !digest(method.implementation_digest) || !sameJson(method.parameter_domains, {})
      || !sameJson(method.behavior.parameters, []) || !sameJson(method.action.parameters, [])
      || !Array.isArray(method.behavior.inputs) || !Array.isArray(method.behavior.outputs)
      || !sameJson(method.behavior.inputs.map(port => [port.name, port.type, port.multiple, port.required]), inputs[index])
      || !sameJson(method.behavior.outputs.map(port => [port.name, port.type, port.multiple]), outputs[index])
      || !Array.isArray(method.action.inputs) || !Array.isArray(method.action.outputs)
      || !sameJson(method.action.inputs.map(port => [port.name, port.type, port.multiple, port.required]), inputs[index])
      || !sameJson(method.action.outputs.map(port => [port.name, port.type, port.multiple]), outputs[index])
      || method.cost.schema_version !== "bluefire.macos-file-access-method-cost.v1" || method.cost.pack !== MACOS_FILE_ACCESS_PACK
      || method.cost.method_id !== id || !digest(method.cost.cost_digest) || method.cost.native_primitive_requests !== (index === 2 ? 0 : 1)
      || method.cost.generated_bytes !== 0 || method.cost.network_bytes !== 0 || !sameJson(method.cost.writes, [])
      || !sameJson(method.cost.material_directories, []) || method.cost.removes !== null) throw bad();
  }
}
function checkedMacOSFileAccessScope(value: Pick<CompositionReview, "environment" | "objective" | "snapshot">) {
  checkedFileAccessScope(value);
  const environment = value.environment;
  if (!compositionControlValid(environment.control_owner_id, MACOS_FILE_ACCESS_PACK) || environment.runner_id !== "bluefire-macos-workspace.v1"
    || ["enrollment_digest", "profile_digest", "target_scope_digest", "collector_digest", "workspace_custody_digest", "binding_digest"].some(key => !digest(environment[key]))
    || value.objective.predicate.record_count !== 8) throw bad();
  checkedMacOSSnapshot(value.snapshot);
}
function checkedMacOSFileAccessResult(result: Record<string, unknown>, grant: CompositionObjective["grant"]["document"], checks: Record<string, unknown>) {
  const evidence = compositionRecord(result.macos_file_access_result);
  const cleanup = compositionRecord(result.cleanup);
  const source = compositionRecord(result.source_binding);
  if (!exactKeys(result, ["run_id", "source_binding", "macos_file_access_result", "cleanup", "objective"])
    || source.run_id !== result.run_id || source.mode !== "execute" || typeof source.finalized_at !== "string" || !Number.isFinite(Date.parse(source.finalized_at))
    || ["manifest_digest", "evidence_digest", "observed_records_digest"].some(key => !digest(source[key]))
    || !Number.isSafeInteger(source.evidence_count) || Number(source.evidence_count) < 0 || source.observed_count !== 0
    || !exactKeys(evidence, ["probe_verified", "non_owner_decision", "owner_verified", "owner_decision", "resource_digest", "resource_generation", "control_revision", "binding_digest", "sha256", "record_count", "request_closure", "attempt_artifacts", "workers_retained", "whole_enrollment_cleanup"])
    || !exactKeys(checks, macChecks) || !exactKeys(cleanup, ["request", "attempt_artifacts", "workers", "whole_enrollment"])
    || ["probe_verified", "owner_verified", "workers_retained", "whole_enrollment_cleanup"].some(key => typeof evidence[key] !== "boolean")
    || !["allowed", "denied", "unknown"].includes(String(evidence.non_owner_decision)) || !["allowed", "denied", "unknown"].includes(String(evidence.owner_decision))
    || !Number.isSafeInteger(evidence.record_count) || Number(evidence.record_count) < 0 || Number(evidence.record_count) > 8
    || !Number.isSafeInteger(evidence.control_revision) || Number(evidence.control_revision) < 1
    || !digest(evidence.resource_digest) || !digest(evidence.binding_digest) || !digest(evidence.sha256)
    || typeof evidence.resource_generation !== "string" || !evidence.resource_generation
    || evidence.probe_verified !== true || evidence.owner_verified !== true || evidence.owner_decision !== "allowed" || evidence.non_owner_decision === "unknown"
    || evidence.resource_digest !== grant.environment.resource_digest || evidence.resource_generation !== grant.environment.resource_generation
    || evidence.control_revision !== grant.environment.control_revision || evidence.binding_digest !== grant.environment.binding_digest
    || evidence.sha256 !== grant.objective.predicate.sha256 || evidence.record_count !== grant.objective.predicate.record_count
    || evidence.request_closure !== "verified_closed" || evidence.attempt_artifacts !== "not_created" || evidence.workers_retained !== true || evidence.whole_enrollment_cleanup !== false
    || cleanup.request !== evidence.request_closure || cleanup.attempt_artifacts !== evidence.attempt_artifacts || cleanup.workers !== "retained" || cleanup.whole_enrollment !== false) throw bad();
  const expected = {
    probe_authenticated: evidence.probe_verified,
    non_owner_denied: evidence.non_owner_decision === "denied",
    owner_read_verified: evidence.owner_verified === true && evidence.owner_decision === "allowed",
    same_resource: evidence.resource_digest === grant.environment.resource_digest && evidence.resource_generation === grant.environment.resource_generation,
    same_control_revision: evidence.control_revision === grant.environment.control_revision,
    same_original_binding: evidence.binding_digest === grant.environment.binding_digest,
    content_preserved: evidence.sha256 === grant.objective.predicate.sha256 && evidence.record_count === grant.objective.predicate.record_count,
    requests_closed: evidence.request_closure === "verified_closed",
    no_attempt_artifacts: evidence.attempt_artifacts === "not_created",
    enrollment_retained: evidence.workers_retained && !evidence.whole_enrollment_cleanup,
  };
  if (Object.entries(expected).some(([key, value]) => checks[key] !== value)) throw bad();
}
function checkedFileAccessResult(result: Record<string, unknown>, grant: CompositionObjective["grant"]["document"], checks: Record<string, unknown>) {
  const evidence = compositionRecord(result.file_access_result);
  const cleanup = compositionRecord(result.cleanup);
  if (!["allowed", "permission_denied", "unknown"].includes(String(evidence.non_owner_decision)) || !["allowed", "unknown"].includes(String(evidence.owner_decision))
    || ["probe_verified", "owner_verified", "identity_unchanged", "parents_unchanged", "acl_unchanged"].some(key => typeof evidence[key] !== "boolean")
    || !Number.isSafeInteger(evidence.record_count) || Number(evidence.record_count) < 0 || Number(evidence.record_count) > 100
    || !["complete", "incomplete"].includes(String(cleanup.run)) || !["verified_closed", "unknown"].includes(String(cleanup.request))) throw bad();
  const expected = {
    probe_authenticated: evidence.probe_verified, non_owner_denied: evidence.non_owner_decision === "permission_denied",
    owner_read_verified: evidence.owner_verified === true && evidence.owner_decision === "allowed",
    same_resource: evidence.resource_digest === grant.environment.resource_digest && evidence.resource_generation === grant.environment.resource_generation,
    same_control_revision: evidence.control_revision === grant.environment.control_revision && evidence.mode === grant.environment.mode,
    same_probe_enrollment: evidence.probe_enrollment_digest === grant.environment.probe_enrollment_digest,
    content_preserved: evidence.sha256 === grant.objective.predicate.sha256 && evidence.record_count === grant.objective.predicate.record_count,
    identity_unchanged: evidence.identity_unchanged, parents_unchanged: evidence.parents_unchanged, acl_unchanged: evidence.acl_unchanged,
    run_cleaned: cleanup.run === "complete", request_closed: cleanup.request === "verified_closed",
  };
  if (Object.entries(expected).some(([key, value]) => checks[key] !== value)) throw bad();
}
export function checkedCompositionContext(value: CompositionContext, grant: string, pack: CompositionPack = RECEIVER_PACK): CompositionContext {
  if (value?.schema_version !== (pack === RECEIVER_RETAINED_PACK ? "bluefire.retained-composition-proposal-context.v1" : "bluefire.composition-proposal-context.v1") || value.grant_id !== grant || !digest(value.context_digest) || !Array.isArray(value.snapshot?.methods) || !Array.isArray(value.facts?.facts) || value.facts.facts.some(fact => typeof fact.fact_id !== "string" || typeof fact.kind !== "string") || Boolean(value.initial_proposal) !== Boolean(value.initial_scenario)) throw bad();
  if (value.snapshot.pack !== pack) throw bad();
  if (pack === RECEIVER_RETAINED_PACK) { checkedRetainedSnapshot(value.snapshot); checkedRetainedArtifacts(value.retained_artifacts); }
  if (pack === MACOS_FILE_ACCESS_PACK) {
    checkedMacOSSnapshot(value.snapshot);
    const facts = compositionRecord(value.facts);
    const fact = compositionRecord(value.facts.facts[0]);
    const source = compositionRecord(fact.source);
    const dependency = compositionRecord(fact.value);
    if (facts.schema_version !== "bluefire.macos-file-access-composition-facts.v1" || facts.pack !== MACOS_FILE_ACCESS_PACK
      || facts.grant_id !== grant || facts.prior_attempt_id !== null || facts.prior_graph_digest !== null || !digest(facts.facts_digest)
      || facts.environment_digest !== value.snapshot.artifact_context.environment_digest || !digest(facts.control_digest)
      || value.facts.facts.length !== 1 || fact.fact_id !== "control" || fact.kind !== "retained_macos_file_control" || fact.provenance !== "observed"
      || fact.attempt_id !== null || source.kind !== "control_record" || !compositionControlValid(source.id, MACOS_FILE_ACCESS_PACK)
      || source.digest !== facts.control_digest || fact.control_digest !== facts.control_digest || fact.environment_digest !== facts.environment_digest
      || dependency.control_owner_id !== source.id || dependency.control_digest !== facts.control_digest
      || ["resource_digest", "probe_enrollment_digest", "baseline_digest", "workspace_custody_digest", "binding_digest"].some(key => !digest(dependency[key]))) throw bad();
  }
  if (value.initial_scenario) parseScenarioDocument(value.initial_scenario);
  return value;
}
export function checkedCompositionProposal(value: CompositionProposal, id: string, owner: string): CompositionProposal {
  if (value?.job?.job_id !== id || value.job.kind !== "composition.proposal" || value.job.request.owner_id !== owner || typeof value.candidate_ready !== "boolean") throw bad();
  if (value.proposal) {
    const proposal = value.proposal;
    if ((proposal.schema_version === "bluefire.composition-ai-result.v3") !== (compositionRecord(compositionRecord(value.job.request.context).snapshot).pack === RECEIVER_RETAINED_PACK)) throw bad();
    if (!["bluefire.composition-ai-result.v1", "bluefire.composition-ai-result.v2", "bluefire.composition-ai-result.v3"].includes(proposal.schema_version) || proposal.proposal_job_id !== id || proposal.owner_id !== owner || !digest(proposal.context_digest) || !digest(proposal.proposal_digest) || proposal.provider?.used_fallback !== false || proposal.candidate?.schema_version !== "bluefire.composition-proposal.v1") throw bad();
    if (proposal.schema_version === "bluefire.composition-ai-result.v3") {
      if (compositionRecord(value.job.request.context).historical_context !== undefined) checkedCompositionEvidenceResult(value, owner);
      else checkedRetainedProposal(value, owner);
    }
    else if (proposal.schema_version === "bluefire.composition-ai-result.v2") checkedCompositionEvidenceResult(value, owner);
    else if (compositionRecord(value.job.request.submitted_request).schema_version === "bluefire.composition-evidence-proposal-request.v1" || proposal.knowledge_digest !== undefined || proposal.reconsideration !== undefined) throw bad();
    parseScenarioDocument(proposal.scenario);
  }
  return value;
}
export function checkedCompositionList(value: CompositionList): CompositionList {
  if (value?.schema_version !== "bluefire.composition-objective-list.v1" || !Array.isArray(value.objectives) || value.objectives.some(item => !compositionJobValid(item.owner_id) || typeof item.title !== "string")) throw bad();
  return value;
}
export function compositionCanRevise(attempt: CompositionAttempt, objective: CompositionObjective): boolean {
  const pack = compositionPack(objective.grant.document);
  if (pack === RECEIVER_RETAINED_PACK && attempt.progress.retained_continuation !== undefined) {
    try { checkedRetainedContinuation(attempt.progress.retained_continuation, attempt.request.composition_attempt.run_id); return attempt.progress.settlement === "settled"; } catch { return false; }
  }
  if (pack !== RECEIVER_PACK && pack !== RECEIVER_RETAINED_PACK) return false;
  const result = compositionRecord(attempt.progress.verified_result);
  const receiver = compositionRecord(result.receiver_result);
  const cleanup = compositionRecord(result.cleanup);
  return attempt.progress.settlement === "settled" && digest(attempt.progress.verified_result_digest)
    && result.run_id === attempt.request.composition_attempt.run_id
    && compositionRecord(result.objective).established === false
    && receiver.decision === "policy_refused"
    && digest(objective.grant.document.environment.policy_digest)
    && receiver.policy_digest === objective.grant.document.environment.policy_digest
    && receiver.record_count === objective.grant.document.objective.predicate.record_count
    && cleanup.run === "complete" && cleanup.receiver === "verified_closed";
}
export function compositionEstablished(objective: CompositionObjective): boolean {
  return objective.attempts.some(attempt => attempt.progress.settlement === "settled"
    && digest(attempt.progress.verified_result_digest)
    && compositionRecord(attempt.progress.verified_result).run_id === attempt.request.composition_attempt.run_id
    && compositionRecord(compositionRecord(attempt.progress.verified_result).objective).established === true);
}
export type CompositionPending = { kind: "grant" | "attempt" | "proposal"; owner: string; control: string; id: string; body: Record<string, unknown> };
const pendingKey = "bluefire.composition.pending.v1";
const recentKey = "bluefire.composition.proposals.v1";
export function readCompositionProposals(): Record<string, string> {
  const raw = localStorage.getItem(recentKey);
  if (!raw) return {};
  if (raw.length > 100_000) throw new Error("Saved proposal references exceed the recovery limit.");
  const value = JSON.parse(raw) as Record<string, string>;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.entries(value).some(([owner, job]) => !compositionJobValid(owner) || !compositionJobValid(job))) throw new Error("Saved proposal references need recovery.");
  return value;
}
export function rememberCompositionProposal(owner: string, job: string) {
  if (!compositionJobValid(owner) || !compositionJobValid(job)) throw bad();
  const raw = JSON.stringify({ ...readCompositionProposals(), [owner]: job });
  localStorage.setItem(recentKey, raw);
  if (localStorage.getItem(recentKey) !== raw) throw new Error("The proposal reference could not be retained.");
}
export type CompositionControl = "stop" | "revoke" | "continue";
const cancellationKey = "bluefire.composition.cancellations.v1";
export function readCompositionCancellations(): Record<string, string> {
  const raw = localStorage.getItem(cancellationKey);
  if (!raw) return {};
  if (raw.length > 100_000) throw new Error("Saved cancellation requests exceed the recovery limit.");
  const value = JSON.parse(raw) as Record<string, string>;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.entries(value).some(([owner, job]) => !compositionJobValid(owner) || !compositionJobValid(job))) throw new Error("A saved proposal cancellation needs recovery.");
  return value;
}
export function storeCompositionCancellation(owner: string, job: string) {
  if (!compositionJobValid(owner) || !compositionJobValid(job)) throw bad();
  const previous = readCompositionCancellations();
  if (previous[owner] && previous[owner] !== job) throw new Error("Reconcile the previous proposal cancellation first.");
  const raw = JSON.stringify({ ...previous, [owner]: job });
  localStorage.setItem(cancellationKey, raw);
  if (localStorage.getItem(cancellationKey) !== raw) throw new Error("Cancellation could not be retained; nothing was sent.");
}
export function clearCompositionCancellation(owner: string, job: string) {
  const previous = readCompositionCancellations();
  if (previous[owner] !== job) throw new Error("The proposal cancellation changed in another tab.");
  delete previous[owner]; localStorage.setItem(cancellationKey, JSON.stringify(previous));
}
export function compositionCancellationConfirmed(value: CompositionProposal, owner: string, job: string) {
  return value.job.job_id === job && value.job.request.owner_id === owner && value.job.progress.stopped === true && value.candidate_ready === false;
}
const controlKey = "bluefire.composition.controls.v1";
export function readCompositionControls(): Record<string, CompositionControl> {
  const raw = localStorage.getItem(controlKey);
  if (!raw) return {};
  if (raw.length > 100_000) throw new Error("Saved control requests exceed the recovery limit.");
  const value = JSON.parse(raw) as Record<string, CompositionControl>;
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.entries(value).some(([id, operation]) => !compositionJobValid(id) || !["stop", "revoke", "continue"].includes(operation))) throw new Error("A saved control request needs recovery.");
  return value;
}
export function storeCompositionControl(id: string, operation: CompositionControl) {
  if (!compositionJobValid(id)) throw bad();
  const previous = readCompositionControls();
  if ((previous[id] === "revoke" && operation !== "revoke") || (operation === "continue" && previous[id] && previous[id] !== "continue")) throw new Error("Reconcile the original control request before changing its intent.");
  const raw = JSON.stringify({ ...previous, [id]: operation });
  localStorage.setItem(controlKey, raw);
  if (localStorage.getItem(controlKey) !== raw) throw new Error("Control request could not be retained; nothing was sent.");
}
export function clearCompositionControl(id: string, operation: CompositionControl) {
  const previous = readCompositionControls();
  if (previous[id] !== operation) throw new Error("Control request changed in another tab.");
  delete previous[id]; localStorage.setItem(controlKey, JSON.stringify(previous));
}
export function compositionControlConfirmed(value: CompositionObjectiveState, operation: CompositionControl) {
  return value.grant?.status === ({ stop: "paused", revoke: "revoked", continue: "active" } as const)[operation];
}
export function readCompositionPending(): CompositionPending | undefined {
  const raw = localStorage.getItem(pendingKey);
  if (!raw) return;
  if (raw.length > 500_000) throw new Error("The saved composition request needs recovery.");
  const value = JSON.parse(raw) as CompositionPending;
  if (!["grant", "attempt", "proposal"].includes(value.kind) || !compositionJobValid(value.owner) || !compositionControlValid(value.control) || !compositionJobValid(value.id) || typeof value.body?.submission_id !== "string" || compositionJobId(value.body.submission_id) !== value.id) throw new Error("The saved composition request is malformed; it has not been sent.");
  if (value.kind === "grant") {
    const review = compositionRecord(value.body.review);
    if (!compositionControlValid(value.control, compositionRequestPack(review)) || review.control_owner_id !== value.control) throw bad();
  }
  return value;
}
export function storeCompositionPending(value: CompositionPending) {
  const raw = JSON.stringify(value);
  if (raw.length > 500_000) throw new Error("The request exceeds the durable recovery limit.");
  const previous = readCompositionPending();
  if (previous && !sameJson(previous, value)) throw new Error("Resolve the original pending request before creating another.");
  localStorage.setItem(pendingKey, raw);
  if (localStorage.getItem(pendingKey) !== raw) throw new Error("The exact request could not be retained; nothing was sent.");
}
export function clearCompositionPending(value: CompositionPending) {
  if (!sameJson(readCompositionPending(), value)) throw new Error("The pending request changed in another tab.");
  localStorage.removeItem(pendingKey);
}
export function compositionConfirmed(value: CompositionObjectiveState | CompositionProposal, pending: CompositionPending): boolean {
  if (pending.kind === "proposal") return "job" in value && value.job.job_id === pending.id && value.job.request.owner_id === pending.owner && sameJson(value.job.request.submitted_request, pending.body);
  if (!("owner" in value) || value.owner.job_id !== pending.owner) return false;
  if (pending.kind === "grant") {
    if (!sameJson(value.owner.progress.submitted_request, pending.body)) return false;
    if (value.grant === null) return compositionRecord(value.owner.progress.admission).accepted === false;
    const submitted = pending.body.review as CompositionReviewRequest;
    return compositionPack(value.grant.document) === compositionRequestPack(submitted) && value.owner.progress.review_digest === pending.body.review_digest && value.grant.document.objective.question === submitted.question && value.grant.document.environment.control_owner_id === submitted.control_owner_id && value.grant.document.approved_by === pending.body.reviewed_by && (submitted.limits === null || sameJson(submitted.limits, value.grant.document.limits));
  }
  return value.attempts.some(attempt => attempt.job_id === pending.id && sameJson(attempt.progress.submitted_request, pending.body));
}
export function compositionRequestPack(value: Record<string, unknown>): CompositionPack {
  if (value.schema_version === "bluefire.composition-review-request.v2" && value.pack === MACOS_FILE_ACCESS_PACK
    && exactKeys(value, ["schema_version", "pack", "control_owner_id", "question", "limits"])
    && typeof value.question === "string" && Boolean(value.question.trim()) && value.question.length <= 4000
    && (value.limits === null || (typeof value.limits === "object" && !Array.isArray(value.limits)
      && Object.entries(compositionRecord(value.limits)).every(([key, item]) => Number.isSafeInteger(item) && Number(item) >= (key === "max_edges_per_attempt" ? 0 : 1))))
    && compositionControlValid(value.control_owner_id, MACOS_FILE_ACCESS_PACK)) return MACOS_FILE_ACCESS_PACK;
  if (value.schema_version === "bluefire.composition-review-request.v2" && value.pack === RECEIVER_RETAINED_PACK
    && exactKeys(value, ["schema_version", "pack", "control_owner_id", "question", "limits"]) && typeof value.question === "string" && Boolean(value.question.trim()) && value.question.length <= 4000
    && (value.limits === null || typeof value.limits === "object" && !Array.isArray(value.limits) && Object.entries(compositionRecord(value.limits)).every(([key, item]) => Number.isSafeInteger(item) && Number(item) >= (key === "max_edges_per_attempt" ? 0 : 1)))
    && compositionControlValid(value.control_owner_id, RECEIVER_RETAINED_PACK)) return RECEIVER_RETAINED_PACK;
  if (value.schema_version === "bluefire.composition-review-request.v2" && value.pack === FILE_ACCESS_PACK) return FILE_ACCESS_PACK;
  if (value.schema_version === undefined && value.pack === undefined) return RECEIVER_PACK;
  throw bad();
}
async function post<T>(path: string, body: unknown): Promise<T> {
  if (DEMO_MODE) throw new Error("Composition requires an authenticated local runner and retained control. Demo mode cannot execute it.");
  return request<T>(`/composition/${path}`, { method: "POST", body: JSON.stringify(body) });
}
export const compositionApi = {
  review: (body: CompositionReviewRequest) => post<CompositionReview>("context", body),
  list: (control_owner_id: string) => post<CompositionList>("objective-list", { control_owner_id }),
  objective: (id: string) => request<CompositionObjectiveState>(`/composition/objectives/${encodeURIComponent(id)}`),
  context: (id: string, prior_attempt_id: string | null) => post<CompositionContext>(`objectives/${encodeURIComponent(id)}/proposal-context`, { prior_attempt_id }),
  evidenceContext: (id: string, prior_attempt_id: string, knowledge: CompositionKnowledge) => post<CompositionEvidenceContext>(`objectives/${encodeURIComponent(id)}/proposal-context`, { schema_version: "bluefire.composition-evidence-context-query.v1", prior_attempt_id, attempt_ids: knowledge.attempts.map(attempt => attempt.attempt_id), knowledge_digest: knowledge.knowledge_digest }),
  proposal: (id: string) => request<CompositionProposal>(`/composition/proposals/${encodeURIComponent(id)}`),
  submit: (value: CompositionPending) => post<CompositionObjectiveState | CompositionProposal>(value.kind === "grant" ? "objectives" : `objectives/${encodeURIComponent(value.owner)}/${value.kind === "attempt" ? "attempts" : "proposals"}`, value.body),
  control: (id: string, operation: "stop" | "revoke" | "continue") => post<CompositionObjectiveState>(`objectives/${encodeURIComponent(id)}/${operation}`, {}),
  recover: (id: string, attempt_id: string) => post<CompositionObjectiveState>(`objectives/${encodeURIComponent(id)}/recover`, { attempt_id }),
  cancel: (id: string) => post<CompositionProposal>(`proposals/${encodeURIComponent(id)}/cancel`, {}),
};
