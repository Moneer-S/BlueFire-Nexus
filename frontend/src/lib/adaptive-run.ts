import type { CatalogResponse, RunRecord, RunStep } from "../types";
import { displayTitle } from "./display-title";

export type RuntimeRecord = NonNullable<RunRecord["ai_proposals"]>[number];
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
const integer = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value);
const finiteNonnegative = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0;
export const adaptiveRecords = (run: RunRecord) => (run.ai_proposals ?? []).filter(record =>
  record.schema_version === "bluefire.ai-proposal-record.v4" || record.schema_version === "bluefire.ai-proposal-record.v5");

function v5BudgetProjection(record: RuntimeRecord): { steps: number; seconds: number; retries: number; stepRetries: number } | undefined {
  const policy = object(record.proposal_policy), planner = object(record.planner_state), observations = object(planner.observations);
  const budgets = object(observations.remaining_budgets);
  const maxRetries = policy.maximum_adaptive_retries, usedRetries = policy.adaptive_retries_used;
  const maxStepRetries = policy.maximum_step_retries, usedStepRetries = policy.step_retries_used;
  const steps = policy.remaining_steps, seconds = budgets.seconds;
  const attempted = policy.attempted_methods;
  if (policy.schema_version !== "bluefire.ai-proposal-policy.v3" || !digest(record.proposal_policy_digest)
    || !digest(record.planner_state_digest) || !digest(policy.adaptive_policy_digest)
    || planner.schema_version !== "bluefire.planner-state.v3" || observations.schema_version !== "bluefire.runtime-observations.v2"
    || !integer(maxRetries) || maxRetries < 1 || maxRetries > 8
    || !integer(usedRetries) || usedRetries < 0 || usedRetries > maxRetries
    || !integer(maxStepRetries) || maxStepRetries < 1 || maxStepRetries > 3
    || !integer(usedStepRetries) || usedStepRetries < 0
    || usedStepRetries > Math.min(maxStepRetries, usedRetries)
    || !integer(steps) || steps < 0
    || !finiteNonnegative(seconds)
    || !Array.isArray(attempted) || attempted.length < 1 || attempted.length > 256
    || !integer(budgets.steps) || budgets.steps !== steps
    || !integer(budgets.retries) || budgets.retries !== maxRetries - usedRetries
    || !integer(budgets.step_retries) || budgets.step_retries !== maxStepRetries - usedStepRetries) return undefined;
  const seen = new Set<string>();
  const attemptsByStep = new Map<string, number>();
  for (const row of attempted) {
    const identity = object(row);
    if (Object.keys(identity).length !== 3 || Object.keys(identity).some(key => !["step_id", "behavior_id", "action_id"].includes(key))
      || ![identity.step_id, identity.behavior_id, identity.action_id].every(value => typeof value === "string" && value.length > 0 && value.length <= 200)) return undefined;
    const key = `${identity.step_id as string}\u0000${identity.behavior_id as string}\u0000${identity.action_id as string}`;
    if (seen.has(key)) return undefined;
    seen.add(key);
    const stepId = identity.step_id as string;
    attemptsByStep.set(stepId, (attemptsByStep.get(stepId) ?? 0) + 1);
  }
  const currentStepId = record.current_step_id;
  const currentStepAttempts = typeof currentStepId === "string" ? attemptsByStep.get(currentStepId) : undefined;
  if (currentStepAttempts === undefined || attemptsByStep.size > 64 || [...attemptsByStep.values()].some(count => count > 4)
    || usedStepRetries > currentStepAttempts || usedStepRetries < currentStepAttempts - 1
    || usedRetries > attempted.length
    || usedRetries < [...attemptsByStep.values()].reduce((sum, count) => sum + count - 1, 0)) return undefined;
  return { steps, seconds, retries: budgets.retries as number, stepRetries: budgets.step_retries as number };
}
export const recordedMethodName = (catalog: CatalogResponse, behavior?: string | null, action?: string | null) =>
  displayTitle(catalog.actions.find(item => item.id === action)?.title ?? catalog.behaviors.find(item => item.id === behavior)?.title ?? "Method unavailable in this catalog");

export function decisionOrigin(run: RunRecord, record: RuntimeRecord): number {
  if (record.run_id !== run.run_id || typeof record.deterministic_decision_id !== "string") return -1;
  return run.steps.findIndex(step => step.step_id === record.current_step_id && step.planner_decision_id === record.deterministic_decision_id);
}

/** Selection is not dispatch. Only a later exact step result can establish an attempt. */
export function selectedAttempt(run: RunRecord, record: RuntimeRecord): RunStep | undefined {
  const origin = decisionOrigin(run, record), selected = record.proposal;
  if (origin < 0 || record.application_status !== "applied_reviewed_method" || !selected) return undefined;
  const applied = object(record.applied_step);
  if (applied.step_id !== selected.selected_step_id || applied.behavior_id !== selected.selected_behavior_id || applied.action_id !== selected.selected_action_id) return undefined;
  return run.steps.slice(origin + 1).find(step => step.execution_disposition !== "counterfactual"
    && step.step_id === selected.selected_step_id && step.behavior_id === selected.selected_behavior_id && step.action_id === selected.selected_action_id);
}

export function dispatchDescription(step: RunStep, run: RunRecord): string {
  if (run.mode !== "execute" || step.execution_disposition === "counterfactual") return "Synthetic result; no execution established";
  if (step.interruption?.schema_version === "bluefire.execution-interruption.v1") {
    if (step.interruption.dispatch_requested === true) return "Dispatch interrupted; effects unknown";
    if (step.interruption.dispatch_requested === false) return "Cancelled before dispatch; no runner result";
    return "Interruption recorded; dispatch and effects unknown";
  }
  if (step.runner_status && step.request_hash) return `Runner returned ${step.runner_status.replaceAll("_", " ")}`;
  if (step.policy?.allowed === false) return "Refused before dispatch";
  return "Dispatch or runner result not established";
}

export function decisionProvenance(record: RuntimeRecord): { label: string; provider: string; model: string } {
  const receipt = object(record.provider), attempt = object(record.provider_attempt);
  const provider = String(receipt.effective_provider_id ?? attempt.provider_id ?? "Not recorded");
  const model = String(receipt.model ?? attempt.model ?? "Not recorded");
  if (receipt.used_fallback === true || String(record.decision_source).includes("fallback")) return { label: "Configured fallback · not live model evidence", provider, model };
  if (record.provider_called === false) return { label: "No provider call", provider, model };
  if (record.decision_source === "deterministic_provider" || attempt.kind === "deterministic") return { label: "Deterministic provider · software evidence", provider, model };
  if (record.decision_source === "provider" && record.provider_called === true && record.provider && record.proposal) return { label: "Live provider response", provider, model };
  // provider_called records the planner invocation; it does not establish wire dispatch.
  return { label: record.provider_called === true ? "Provider request did not produce a permitted choice" : "Provider provenance not established", provider, model };
}

export function decisionObservations(record: RuntimeRecord) {
  const projection = object(object(record.planner_state).observations);
  const attempts = Array.isArray(projection.attempts) ? projection.attempts.map(object) : [];
  const latest = attempts.filter(attempt => attempt.step_id === record.current_step_id).at(-1);
  const budgets = record.schema_version === "bluefire.ai-proposal-record.v5" ? v5BudgetProjection(record) : object(projection.remaining_budgets);
  const unknowns = Array.isArray(projection.unknowns) ? projection.unknowns.filter((item): item is string => typeof item === "string") : [];
  if (record.schema_version === "bluefire.ai-proposal-record.v5" && !budgets) unknowns.push("The retained v5 retry budget projection is inconsistent; remaining adaptive allowance is unknown.");
  return { classification: object(latest?.failure).classification, budgets: budgets ?? {},
    evidence: Array.isArray(latest?.evidence) ? latest.evidence.map(object).filter(item => typeof item.evidence_id === "string") : [],
    unknowns };
}

export function recordedPathNodes(run: RunRecord) {
  const groups = new Map<string, { stepId: string; attempts: Array<{ step: RunStep; index: number }>; decisions: RuntimeRecord[] }>();
  run.steps.forEach((step, index) => {
    if (!groups.has(step.step_id)) groups.set(step.step_id, { stepId: step.step_id, attempts: [], decisions: [] });
    groups.get(step.step_id)!.attempts.push({ step, index });
  });
  for (const record of adaptiveRecords(run)) {
    if (decisionOrigin(run, record) >= 0) groups.get(String(record.current_step_id))?.decisions.push(record);
  }
  return [...groups.values()];
}
