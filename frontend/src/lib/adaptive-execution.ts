import type { ActionDefinition, Behavior, Scenario, ScenarioStep } from "../types";

export type AdaptiveOutcome = "blocked" | "failed" | "partial";
export interface AdaptiveMethod { behavior_id: string; action_id: string }
export interface AdaptiveExecutionV1 {
  schema_version: "bluefire.adaptive-execution.v1";
  steps: Array<{ step_id: string; methods: AdaptiveMethod[] }>;
  eligible_outcomes: AdaptiveOutcome[];
  max_retries: 1;
  on_provider_failure: "stop" | "deterministic";
}
export interface AdaptiveExecutionV2 {
  schema_version: "bluefire.adaptive-execution.v2";
  steps: Array<{ step_id: string; methods: AdaptiveMethod[]; max_retries: number }>;
  eligible_outcomes: AdaptiveOutcome[];
  max_retries: number;
  on_provider_failure: "stop" | "deterministic";
}
export type AdaptiveExecution = AdaptiveExecutionV1 | AdaptiveExecutionV2;

interface AdaptiveAuthorizationFields {
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
export interface AdaptiveAuthorizationV1 extends AdaptiveAuthorizationFields {
  schema_version: "bluefire.adaptive-authorization.v1";
  policy: AdaptiveExecutionV1;
}
export interface AdaptiveAuthorizationV2 extends AdaptiveAuthorizationFields {
  schema_version: "bluefire.adaptive-authorization.v2";
  policy: AdaptiveExecutionV2;
}
export type AdaptiveAuthorization = AdaptiveAuthorizationV1 | AdaptiveAuthorizationV2;

const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const exact = (value: unknown, fields: string[]): value is Record<string, unknown> => record(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
const identity = (value: unknown, step = false): value is string => typeof value === "string" && value.length <= 200 && (step ? /^[a-z][a-z0-9_]*$/ : /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$/).test(value);
export const methodKey = (method: AdaptiveMethod) => `${method.behavior_id}:${method.action_id}`;
export const adaptiveOutcomeLabels: Record<AdaptiveOutcome, string> = { blocked: "Blocked", failed: "Failed", partial: "Partial result" };

/** Structural restoration preserves semantically stale drafts for visible repair. */
export function parseAdaptiveExecution(value: unknown): AdaptiveExecution {
  if (!record(value) || (value.schema_version !== "bluefire.adaptive-execution.v1" && value.schema_version !== "bluefire.adaptive-execution.v2")) {
    throw new Error("Saved adaptive retry choices are malformed. Their original data has been retained.");
  }
  const version = value.schema_version;
  const rootFields = ["schema_version", "steps", "eligible_outcomes", "max_retries", "on_provider_failure"];
  const validRoot = version === "bluefire.adaptive-execution.v1"
    ? exact(value, rootFields) && value.max_retries === 1
    : exact(value, rootFields) && Number.isInteger(value.max_retries) && Number(value.max_retries) >= 1 && Number(value.max_retries) <= 8;
  if (!validRoot
    || (value.on_provider_failure !== "stop" && value.on_provider_failure !== "deterministic")
    || !Array.isArray(value.steps) || value.steps.length < 1 || value.steps.length > 64
    || !Array.isArray(value.eligible_outcomes) || !value.eligible_outcomes.length || value.eligible_outcomes.length > 3
    || value.eligible_outcomes.some(outcome => !["blocked", "failed", "partial"].includes(outcome))
    || new Set(value.eligible_outcomes).size !== value.eligible_outcomes.length) throw new Error("Saved adaptive retry choices are malformed. Their original data has been retained.");
  const stepIds = new Set<string>();
  let stepRetryBudget = 0;
  for (const step of value.steps) {
    if (!record(step)) throw new Error("Adaptive retry requires 2–4 distinct methods for each selected step.");
    const validStep = version === "bluefire.adaptive-execution.v1"
      ? exact(step, ["step_id", "methods"])
      : exact(step, ["step_id", "methods", "max_retries"]);
    if (!validStep || !identity(step.step_id, true) || stepIds.has(step.step_id)
      || !Array.isArray(step.methods) || step.methods.length < 2 || step.methods.length > 4) throw new Error("Adaptive retry requires 2–4 distinct methods for each selected step.");
    if (version === "bluefire.adaptive-execution.v2") {
      const maximum = Math.min(3, step.methods.length - 1);
      if (!Number.isInteger(step.max_retries) || Number(step.max_retries) < 1 || Number(step.max_retries) > maximum) {
        throw new Error("Each adaptive step needs an explicit retry cap within its number of distinct methods.");
      }
      stepRetryBudget += Number(step.max_retries);
    }
    stepIds.add(step.step_id);
    const methods = new Set<string>();
    for (const method of step.methods) {
      if (!exact(method, ["behavior_id", "action_id"]) || !identity(method.behavior_id) || !identity(method.action_id)) throw new Error("An adaptive method must identify one registered behavior and action.");
      const key = methodKey(method as unknown as AdaptiveMethod);
      if (methods.has(key)) throw new Error("Adaptive retry choices contain a duplicate method.");
      methods.add(key);
    }
  }
  if (version === "bluefire.adaptive-execution.v2" && Number(value.max_retries) > stepRetryBudget) {
    throw new Error("The experiment-wide retry cap cannot exceed the sum of its per-step caps.");
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
  const v2Policy = scenario.adaptive_execution.schema_version === "bluefire.adaptive-execution.v2" ? scenario.adaptive_execution : undefined;
  const result: AdaptiveIssue[] = [];
  for (const entry of scenario.adaptive_execution.steps) {
    const step = scenario.steps.find(item => item.id === entry.step_id);
    if (!step) { result.push({ stepId: entry.step_id, missingStep: true, message: "Retry choices still refer to a removed step. Remove those choices or undo the deletion." }); continue; }
    const title = behaviors.get(step.behavior_id)?.title ?? "This step";
    const owned = new Set([step.behavior_id, ...step.alternates]);
    const invalid = entry.methods.some(method => !owned.has(method.behavior_id) || !actions.has(method.action_id)
      || !behaviors.get(method.behavior_id)?.action_ids.includes(method.action_id));
    if (invalid) result.push({ stepId: step.id, message: `${title}: a saved retry method is unavailable or was removed from this step. Review and apply repaired choices.` });
    const stepRetryCap = v2Policy?.steps.find(item => item.step_id === entry.step_id)?.max_retries;
    if (stepRetryCap !== undefined && stepRetryCap > Math.min(3, entry.methods.length - 1)) {
      result.push({ stepId: step.id, message: `${title}: its retry cap exceeds the remaining distinct methods. Lower the cap or restore more methods.` });
    }
    if (!entry.methods.some(method => method.behavior_id === step.behavior_id && (!overrides[step.id] || overrides[step.id] === method.action_id))) {
      result.push({ stepId: step.id, message: `${title}: include the current primary method in the retry choices, or restore the previous primary method.` });
    }
  }
  return result;
}

export function removeAdaptiveStep(scenario: Scenario, stepId: string): Scenario {
  if (!scenario.adaptive_execution) return scenario;
  const { adaptive_execution: previous, ...rest } = scenario;
  if (previous.schema_version === "bluefire.adaptive-execution.v2") {
    const steps = previous.steps.filter(step => step.step_id !== stepId);
    if (!steps.length) return rest;
    const retained = steps.map(step => ({ ...step, max_retries: step.max_retries }));
    const maximum = retained.reduce((sum, step) => sum + step.max_retries, 0);
    return { ...rest, adaptive_execution: { ...previous, max_retries: Math.min(previous.max_retries, maximum), steps: retained } };
  }
  const steps = previous.steps.filter(step => step.step_id !== stepId);
  if (!steps.length) return rest;
  return { ...rest, adaptive_execution: { ...previous, steps } };
}

/** Explicit apply registers only the exact choices the operator selected. */
export function applyAdaptiveStep(scenario: Scenario, stepId: string, methods: AdaptiveMethod[], options: Pick<AdaptiveExecutionV1, "eligible_outcomes" | "on_provider_failure">, behaviors: ReadonlyMap<string, Behavior>, actions: ReadonlyMap<string, ActionDefinition>, selectedAction = ""): Scenario {
  const step = scenario.steps.find(item => item.id === stepId);
  if (!step) throw new Error("Select a step before configuring retry choices.");
  const available = new Set(availableAdaptiveMethods(step, behaviors, actions).map(methodKey));
  if (methods.some(method => !available.has(methodKey(method)))) throw new Error("Remove unavailable choices and select registered compatible methods.");
  if (!methods.some(method => method.behavior_id === step.behavior_id && (!selectedAction || method.action_id === selectedAction))) throw new Error("Include the current primary method before applying retry choices.");
  const entry = { step_id: step.id, methods };
  const previous = scenario.adaptive_execution;
  const retained = previous?.schema_version === "bluefire.adaptive-execution.v2"
    ? previous.steps.map(item => ({ step_id: item.step_id, methods: item.methods }))
    : previous?.steps ?? [];
  const steps = retained.some(item => item.step_id === stepId)
    ? retained.map(item => item.step_id === stepId ? entry : item)
    : [...retained, entry];
  const policy = parseAdaptiveExecution({ schema_version: "bluefire.adaptive-execution.v1", ...options, max_retries: 1, steps });
  return { ...scenario, adaptive_execution: policy, steps: scenario.steps.map(item => item.id === stepId
    ? { ...item, alternates: [...new Set([...item.alternates, ...methods.map(method => method.behavior_id)])].filter(id => id !== item.behavior_id) } : item) };
}

/** Explicit opt-in writes v2 and assigns unchanged legacy steps a one-try cap. */
export function applyAdaptiveV2Step(
  scenario: Scenario,
  stepId: string,
  methods: AdaptiveMethod[],
  options: Pick<AdaptiveExecutionV2, "eligible_outcomes" | "on_provider_failure" | "max_retries"> & { step_max_retries: number },
  behaviors: ReadonlyMap<string, Behavior>,
  actions: ReadonlyMap<string, ActionDefinition>,
  selectedAction = "",
): Scenario {
  const step = scenario.steps.find(item => item.id === stepId);
  if (!step) throw new Error("Select a step before configuring retry choices.");
  const available = new Set(availableAdaptiveMethods(step, behaviors, actions).map(methodKey));
  if (methods.some(method => !available.has(methodKey(method)))) throw new Error("Remove unavailable choices and select registered compatible methods.");
  if (!methods.some(method => method.behavior_id === step.behavior_id && (!selectedAction || method.action_id === selectedAction))) {
    throw new Error("Include the current primary method before applying retry choices.");
  }
  const stepMaximum = Math.min(3, methods.length - 1);
  if (!Number.isInteger(options.step_max_retries) || options.step_max_retries < 1 || options.step_max_retries > stepMaximum) {
    throw new Error("Set this step's retry cap between one and its available distinct alternatives.");
  }
  const previous = scenario.adaptive_execution;
  const existing = previous?.schema_version === "bluefire.adaptive-execution.v2"
    ? previous.steps
    : previous?.steps.map(item => ({ ...item, max_retries: 1 })) ?? [];
  const steps = existing.some(item => item.step_id === stepId)
    ? existing.map(item => item.step_id === stepId
      ? { step_id: step.id, methods, max_retries: options.step_max_retries }
      : { step_id: item.step_id, methods: item.methods, max_retries: item.max_retries })
    : [...existing.map(item => ({ step_id: item.step_id, methods: item.methods, max_retries: item.max_retries })),
      { step_id: step.id, methods, max_retries: options.step_max_retries }];
  const policy = parseAdaptiveExecution({
    schema_version: "bluefire.adaptive-execution.v2",
    eligible_outcomes: options.eligible_outcomes,
    max_retries: options.max_retries,
    on_provider_failure: options.on_provider_failure,
    steps,
  });
  return {
    ...scenario,
    adaptive_execution: policy,
    steps: scenario.steps.map(item => item.id === stepId
      ? { ...item, alternates: [...new Set([...item.alternates, ...methods.map(method => method.behavior_id)])].filter(id => id !== item.behavior_id) }
      : item),
  };
}
