import type { ActionDefinition, Behavior, Scenario, ScenarioStep } from "../types";

export type AdaptiveOutcome = "blocked" | "failed" | "partial";
export interface AdaptiveMethod { behavior_id: string; action_id: string }
export interface AdaptiveExecution {
  schema_version: "bluefire.adaptive-execution.v1";
  steps: Array<{ step_id: string; methods: AdaptiveMethod[] }>;
  eligible_outcomes: AdaptiveOutcome[];
  max_retries: 1;
  on_provider_failure: "stop" | "deterministic";
}
export interface AdaptiveAuthorization {
  schema_version: "bluefire.adaptive-authorization.v1";
  scenario_digest: string; plan_digest: string; objective: string; profile_digest: string;
  target_scope: { scope_refs: string[] }; platform: string; catalog_authority_digest: string;
  policy: AdaptiveExecution; parameter_policy: "exact_reviewed_values_and_inputs";
  limits: { max_steps: number; max_seconds: number; max_artifacts: number; max_bytes: number };
  cleanup_policy: string; authorization_digest: string;
  steps: Array<{ step_id: string; methods: Array<{
    plan_step: { step_id: string; behavior_id: string; action_id: string; parameters: Record<string, unknown>;
      inputs: Record<string, { from_step: string; artifact: string }>; expected_outputs: string[];
      required_capabilities: string[]; safety_tier: string; [key: string]: unknown };
    plan_step_digest: string; behavior_contract_digest: string; action_contract_digest: string;
    execution_binding_digest: string; capabilities: string[]; mutates: boolean;
    cleanup_action_id: string | null; cleanup_contract_digest: string | null;
  }> }>;
}

const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, fields: string[]): value is Record<string, unknown> => record(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
const identity = (value: unknown, step = false): value is string => typeof value === "string" && value.length <= 200 && (step ? /^[a-z][a-z0-9_]*$/ : /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$/).test(value);
export const methodKey = (method: AdaptiveMethod) => `${method.behavior_id}:${method.action_id}`;
export const adaptiveOutcomeLabels: Record<AdaptiveOutcome, string> = { blocked: "Blocked", failed: "Failed", partial: "Partial result" };

/** Structural restoration preserves semantically stale drafts for visible repair. */
export function parseAdaptiveExecution(value: unknown): AdaptiveExecution {
  if (!exact(value, ["schema_version", "steps", "eligible_outcomes", "max_retries", "on_provider_failure"])
    || value.schema_version !== "bluefire.adaptive-execution.v1" || value.max_retries !== 1
    || (value.on_provider_failure !== "stop" && value.on_provider_failure !== "deterministic")
    || !Array.isArray(value.steps) || value.steps.length < 1 || value.steps.length > 64
    || !Array.isArray(value.eligible_outcomes) || !value.eligible_outcomes.length || value.eligible_outcomes.length > 3
    || value.eligible_outcomes.some(outcome => !["blocked", "failed", "partial"].includes(outcome))
    || new Set(value.eligible_outcomes).size !== value.eligible_outcomes.length) throw new Error("Saved adaptive retry choices are malformed. Their original data has been retained.");
  const stepIds = new Set<string>();
  for (const step of value.steps) {
    if (!exact(step, ["step_id", "methods"]) || !identity(step.step_id, true) || stepIds.has(step.step_id)
      || !Array.isArray(step.methods) || step.methods.length < 2 || step.methods.length > 4) throw new Error("Adaptive retry requires 2–4 distinct methods for each selected step.");
    stepIds.add(step.step_id);
    const methods = new Set<string>();
    for (const method of step.methods) {
      if (!exact(method, ["behavior_id", "action_id"]) || !identity(method.behavior_id) || !identity(method.action_id)) throw new Error("An adaptive method must identify one registered behavior and action.");
      const key = methodKey(method as unknown as AdaptiveMethod);
      if (methods.has(key)) throw new Error("Adaptive retry choices contain a duplicate method.");
      methods.add(key);
    }
  }
  return structuredClone(value) as unknown as AdaptiveExecution;
}

export function availableAdaptiveMethods(step: ScenarioStep, behaviors: ReadonlyMap<string, Behavior>, actions: ReadonlyMap<string, ActionDefinition>): AdaptiveMethod[] {
  const primary = behaviors.get(step.behavior_id);
  if (!primary) return [];
  return [...new Set([step.behavior_id, ...step.alternates, ...(primary.compatible_behaviors ?? [])])]
    .filter(id => id !== "sandbox.cleanup.v1")
    .flatMap(behavior_id => (behaviors.get(behavior_id)?.action_ids ?? [])
      .filter(action_id => actions.has(action_id) && action_id !== "sandbox.cleanup.v1")
      .map(action_id => ({ behavior_id, action_id })));
}

export interface AdaptiveIssue { stepId: string; message: string; missingStep?: boolean }
export function adaptiveExecutionIssues(scenario: Scenario, behaviors: ReadonlyMap<string, Behavior>, actions: ReadonlyMap<string, ActionDefinition>, overrides: Record<string, string> = {}): AdaptiveIssue[] {
  if (!scenario.adaptive_execution) return [];
  const result: AdaptiveIssue[] = [];
  for (const entry of scenario.adaptive_execution.steps) {
    const step = scenario.steps.find(item => item.id === entry.step_id);
    if (!step) { result.push({ stepId: entry.step_id, missingStep: true, message: "Retry choices still refer to a removed step. Remove those choices or undo the deletion." }); continue; }
    const title = behaviors.get(step.behavior_id)?.title ?? "This step";
    const owned = new Set([step.behavior_id, ...step.alternates]);
    const invalid = entry.methods.some(method => !owned.has(method.behavior_id) || !actions.has(method.action_id)
      || !behaviors.get(method.behavior_id)?.action_ids.includes(method.action_id));
    if (invalid) result.push({ stepId: step.id, message: `${title}: a saved retry method is unavailable or was removed from this step. Review and apply repaired choices.` });
    if (!entry.methods.some(method => method.behavior_id === step.behavior_id && (!overrides[step.id] || overrides[step.id] === method.action_id))) {
      result.push({ stepId: step.id, message: `${title}: include the current primary method in the retry choices, or restore the previous primary method.` });
    }
  }
  return result;
}

export function removeAdaptiveStep(scenario: Scenario, stepId: string): Scenario {
  if (!scenario.adaptive_execution) return scenario;
  const steps = scenario.adaptive_execution.steps.filter(step => step.step_id !== stepId);
  const { adaptive_execution: previous, ...rest } = scenario;
  return steps.length ? { ...rest, adaptive_execution: { ...previous, steps } } : rest;
}

/** Explicit apply registers only the exact choices the operator selected. */
export function applyAdaptiveStep(scenario: Scenario, stepId: string, methods: AdaptiveMethod[], options: Pick<AdaptiveExecution, "eligible_outcomes" | "on_provider_failure">, behaviors: ReadonlyMap<string, Behavior>, actions: ReadonlyMap<string, ActionDefinition>, selectedAction = ""): Scenario {
  const step = scenario.steps.find(item => item.id === stepId);
  if (!step) throw new Error("Select a step before configuring retry choices.");
  const available = new Set(availableAdaptiveMethods(step, behaviors, actions).map(methodKey));
  if (methods.some(method => !available.has(methodKey(method)))) throw new Error("Remove unavailable choices and select registered compatible methods.");
  if (!methods.some(method => method.behavior_id === step.behavior_id && (!selectedAction || method.action_id === selectedAction))) throw new Error("Include the current primary method before applying retry choices.");
  const entry = { step_id: step.id, methods };
  const previous = scenario.adaptive_execution;
  const steps = previous?.steps.some(item => item.step_id === stepId)
    ? previous.steps.map(item => item.step_id === stepId ? entry : item) : [...(previous?.steps ?? []), entry];
  const policy = parseAdaptiveExecution({ schema_version: "bluefire.adaptive-execution.v1", ...options, max_retries: 1, steps });
  return { ...scenario, adaptive_execution: policy, steps: scenario.steps.map(item => item.id === stepId
    ? { ...item, alternates: [...new Set([...item.alternates, ...methods.map(method => method.behavior_id)])].filter(id => id !== item.behavior_id) } : item) };
}
