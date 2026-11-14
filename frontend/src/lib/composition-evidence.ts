import { checkedCompositionContext, compositionJobId, compositionRecord, RECEIVER_PACK, type CompositionContext, type CompositionProposal } from "./composition";
import { checkedCompositionKnowledge, type CompositionFinding, type CompositionKnowledge, type CompositionKnowledgeAttempt } from "./composition-knowledge";
import { checkedRetainedCandidate, RECEIVER_RETAINED_PACK } from "./composition-retained";
import { sameJson } from "./replay-review";

export interface CompositionEvidenceChoice { attempt_id: string; compiled_digest: string; semantic_digest: string; step_id: string; behavior_id: string; parameters: Record<string, unknown>; inputs: Record<string, unknown> }
export interface CompositionEvidenceContext extends Omit<CompositionContext, "schema_version"> {
  schema_version: "bluefire.composition-evidence-proposal-context.v1" | "bluefire.retained-composition-evidence-context.v1";
  historical_context: { knowledge_digest: string; attempt_ids: string[]; attempts: CompositionKnowledgeAttempt[]; choices: CompositionEvidenceChoice[] };
}
export interface CompositionReconsideration {
  reconsidered_choices: Array<{ attempt_id: string; compiled_digest: string; step_id: string; finding_refs: Array<{ finding_id: string; record_ref: CompositionFinding["record_ref"] }>; reason: string }>;
  refresh_requirements: Array<{ prerequisite: "retained_receiver_control" | "runner_environment" | "attempt_cleanup"; explanation: string }>;
}
const bad = () => new Error("This history-aware proposal could not be matched to its captured findings and choices.");
const exact = (value: unknown, keys: string[]) => Object.keys(compositionRecord(value)).sort().join(",") === [...keys].sort().join(",");
const digest = (value: unknown) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const text = (value: unknown, limit = 4000): value is string => typeof value === "string" && value.trim().length > 0 && value.length <= limit && [...value].every(character => { const code = character.charCodeAt(0); return code >= 32 && code !== 127 || [9, 10, 13].includes(code); });
const object = (value: unknown) => value !== null && typeof value === "object" && !Array.isArray(value);
const node = (value: unknown): value is string => typeof value === "string" && /^[a-z][a-z0-9_]{0,99}$/.test(value);

export function checkedCompositionCandidate(value: NonNullable<CompositionProposal["proposal"]>, context: Pick<CompositionContext, "snapshot" | "facts">) {
  const candidate = value!.candidate;
  if (!exact(candidate, ["schema_version", "title", "start", "steps", "edges", "evidence_refs", "rationale"]) || candidate.schema_version !== "bluefire.composition-proposal.v1" || !text(candidate.title, 200) || !text(candidate.rationale, 2000) || !node(candidate.start) || !Array.isArray(candidate.steps) || !candidate.steps.length || candidate.steps.length > 64 || !Array.isArray(candidate.edges) || candidate.edges.length > 256 || !Array.isArray(candidate.evidence_refs) || !candidate.evidence_refs.length || candidate.evidence_refs.length > 64 || candidate.evidence_refs.some(ref => !text(ref, 200) || !context.facts.facts.some(fact => fact.fact_id === ref))) throw bad();
  const ids = new Set<string>();
  for (const step of candidate.steps) {
    const raw = compositionRecord(step);
    if (!(exact(step, ["id", "behavior_id", "parameters"]) || exact(step, ["id", "behavior_id", "parameters", "inputs"])) || !node(step.id) || ids.has(step.id) || !context.snapshot.methods.some(method => method.behavior_id === step.behavior_id) || !object(step.parameters) || raw.inputs !== undefined && !object(raw.inputs)) throw bad();
    ids.add(step.id);
  }
  if (!ids.has(candidate.start)) throw bad();
  for (const step of candidate.steps) {
    for (const input of Object.values(compositionRecord(compositionRecord(step).inputs))) {
      const ref = compositionRecord(input);
      if (!exact(input, ["from_step", "artifact"]) || !ids.has(String(ref.from_step)) || !text(ref.artifact, 200)) throw bad();
    }
  }
  for (const edge of candidate.edges) {
    if (!exact(edge, ["from_step", "outcome", "to_step"]) || !ids.has(edge.from_step) || !ids.has(edge.to_step) || !["success", "partial", "blocked", "failed"].includes(edge.outcome)) throw bad();
  }
}

export function compositionEvidenceKnowledge(context: CompositionEvidenceContext, owner: string): CompositionKnowledge {
  const history = context?.historical_context;
  if (!history || !exact(history, ["knowledge_digest", "attempt_ids", "attempts", "choices"]) || !Array.isArray(history.attempts) || !Array.isArray(history.attempt_ids)) throw bad();
  return checkedCompositionKnowledge({ schema_version: "bluefire.composition-knowledge.v1", owner_id: owner, knowledge_digest: history.knowledge_digest, attempts: history.attempts }, {
    owner: { job_id: owner }, attempts: history.attempts.map(attempt => ({ job_id: attempt?.job_id, request: { composition_attempt: { attempt_id: attempt?.attempt_id, run_id: attempt?.run_id } } })),
  }, history.attempt_ids);
}

export function checkedCompositionEvidenceContext(value: CompositionEvidenceContext, grant: string, owner: string, knowledge?: CompositionKnowledge, prior?: string): CompositionEvidenceContext {
  const retained = value?.schema_version === "bluefire.retained-composition-evidence-context.v1";
  if ((!retained && value?.schema_version !== "bluefire.composition-evidence-proposal-context.v1") || typeof value.grant_id !== "string" || !/^grant-[0-9a-f]{32}$/.test(value.grant_id) || !object(value.objective) || !text(value.objective.question) || !object(value.objective.predicate) || prior !== undefined && value.facts?.prior_attempt_id !== prior) throw bad();
  checkedCompositionContext({ ...value, schema_version: retained ? "bluefire.retained-composition-proposal-context.v1" : "bluefire.composition-proposal-context.v1" }, grant, retained ? RECEIVER_RETAINED_PACK : RECEIVER_PACK);
  const saved = compositionEvidenceKnowledge(value, owner);
  if (knowledge && !sameJson(saved, knowledge)) throw bad();
  const history = value.historical_context;
  if (!Array.isArray(history.choices) || !history.choices.length || history.choices.length > 512 || history.attempts.some(attempt => attempt.source_status !== "verified") || JSON.stringify(history).length > 1_048_576) throw bad();
  const keys = new Set<string>();
  for (const choice of history.choices) {
    const key = `${choice?.attempt_id}:${choice?.step_id}`;
    if (!exact(choice, ["attempt_id", "compiled_digest", "semantic_digest", "step_id", "behavior_id", "parameters", "inputs"]) || !history.attempt_ids.includes(choice.attempt_id) || !digest(choice.compiled_digest) || !digest(choice.semantic_digest) || !text(choice.step_id, 200) || !text(choice.behavior_id, 200) || keys.has(key) || !object(choice.parameters) || !object(choice.inputs)) throw bad();
    keys.add(key);
  }
  return value;
}

export function checkedCompositionEvidenceResult(value: CompositionProposal, owner: string) {
  const result = value.proposal!;
  const submitted = compositionRecord(value.job.request.submitted_request);
  const rawContext = value.job.request.context as CompositionEvidenceContext;
  const context = checkedCompositionEvidenceContext(rawContext, rawContext?.grant_id, owner);
  const retained = context.schema_version === "bluefire.retained-composition-evidence-context.v1";
  if (result.schema_version !== (retained ? "bluefire.composition-ai-result.v3" : "bluefire.composition-ai-result.v2")) throw bad();
  if (retained) checkedRetainedCandidate(result, context); else checkedCompositionCandidate(result, context);
  const history = context.historical_context;
  const reconsideration = result.reconsideration;
  if (!exact(result, ["schema_version", "proposal_job_id", "owner_id", "context_digest", "prior_attempt_id", "candidate", "scenario", "proposal_digest", "provider", "knowledge_digest", "model_context_digest", "reconsideration"]) || !digest(result.model_context_digest) || !exact(submitted, ["schema_version", "submission_id", "provider_id", "context_digest", "prior_attempt_id", "attempt_ids", "knowledge_digest"]) || submitted.schema_version !== "bluefire.composition-evidence-proposal-request.v1" || typeof submitted.submission_id !== "string" || compositionJobId(submitted.submission_id) !== value.job.job_id || submitted.provider_id !== result.provider.provider_id || submitted.context_digest !== context.context_digest || result.context_digest !== context.context_digest || submitted.knowledge_digest !== history.knowledge_digest || result.knowledge_digest !== history.knowledge_digest || !sameJson(submitted.attempt_ids, history.attempt_ids) || typeof submitted.prior_attempt_id !== "string" || !/^attempt-[0-9a-f]{32}$/.test(submitted.prior_attempt_id) || result.prior_attempt_id !== submitted.prior_attempt_id || context.facts.prior_attempt_id !== submitted.prior_attempt_id || !reconsideration || !exact(reconsideration, ["reconsidered_choices", "refresh_requirements"]) || !Array.isArray(reconsideration.reconsidered_choices) || !reconsideration.reconsidered_choices.length || reconsideration.reconsidered_choices.length > 8 || !Array.isArray(reconsideration.refresh_requirements) || reconsideration.refresh_requirements.length !== 3) throw bad();
  const reconsidered = new Set<string>();
  for (const choice of reconsideration.reconsidered_choices) {
    const key = `${choice?.attempt_id}:${choice?.step_id}`;
    if (!exact(choice, ["attempt_id", "compiled_digest", "step_id", "finding_refs", "reason"]) || reconsidered.has(key) || !history.choices.some(saved => saved.attempt_id === choice.attempt_id && saved.compiled_digest === choice.compiled_digest && saved.step_id === choice.step_id) || !text(choice.reason, 2000) || !Array.isArray(choice.finding_refs) || !choice.finding_refs.length || choice.finding_refs.length > 16) throw bad();
    reconsidered.add(key);
    const findings = history.attempts.flatMap(attempt => attempt.findings);
    const refs = new Set<string>();
    for (const reference of choice.finding_refs) {
      if (!exact(reference, ["finding_id", "record_ref"]) || refs.has(reference.finding_id) || !findings.some(finding => finding.finding_id === reference.finding_id && sameJson(finding.record_ref, reference.record_ref))) throw bad();
      refs.add(reference.finding_id);
    }
  }
  const prerequisites = new Set<string>();
  for (const item of reconsideration.refresh_requirements) {
    if (!exact(item, ["prerequisite", "explanation"]) || !["retained_receiver_control", "runner_environment", "attempt_cleanup"].includes(item.prerequisite) || prerequisites.has(item.prerequisite) || !text(item.explanation, 1000)) throw bad();
    prerequisites.add(item.prerequisite);
  }
}
